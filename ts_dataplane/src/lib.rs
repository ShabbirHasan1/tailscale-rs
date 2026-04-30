#![doc = include_str!("../README.md")]

use std::{collections::HashMap, sync::Arc, time::Instant};

use ts_bart::RoutingTable;
use ts_overlay_router as or;
use ts_packet::PacketMut;
use ts_packetfilter::{FilterExt, IpProto};
use ts_time::{Handle, Scheduler};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};
use ts_tunnel::{Endpoint, NodeKeyPair};
use ts_underlay_router as ur;

pub mod async_tokio;
mod peer_map;

pub use peer_map::{PeerDb, PeerInfo};

/// A data plane subsystem that can be the subject of timer events.
pub enum Subsystem {
    /// The wireguard component.
    Wireguard,
}

/// Transforms packets to make tailscale happen.
pub struct DataPlane {
    /// Wireguard encryption/decryption.
    pub wireguard: Endpoint,

    /// Mapping from [`PeerId`] to public key and wireguard id.
    pub peer_db: Arc<PeerDb>,

    /// Outbound overlay router.
    pub or_out: or::outbound::Router,
    /// Outbound underlay router.
    pub ur_out: ur::outbound::Router,

    /// Inbound source filter.
    pub src_filter_in: Arc<ts_bart::Table<PeerId>>,
    /// Inbound overlay router.
    pub or_in: or::inbound::Router,

    /// The packet filter.
    pub packet_filter: Arc<dyn ts_packetfilter::Filter + Send + Sync>,

    /// Events queued for future processing.
    pub events: Scheduler<Subsystem>,

    /// Next event for the wireguard subsystem.
    pub wg_next: Option<Handle<Subsystem>>,
}

impl DataPlane {
    /// Creates a new data plane for a wireguard node key.
    pub fn new(my_key: NodeKeyPair, peer_db: Arc<PeerDb>) -> Self {
        DataPlane {
            wireguard: Endpoint::new(my_key),
            peer_db,
            or_out: Default::default(),
            ur_out: Default::default(),
            src_filter_in: Default::default(),
            or_in: Default::default(),
            events: Default::default(),
            packet_filter: Arc::new(ts_packetfilter::DropAllFilter),
            wg_next: None,
        }
    }

    /// Processes packets originating from the local device.
    #[tracing::instrument(skip_all, fields(n_packets = packets.len()))]
    pub fn process_outbound(&mut self, packets: Vec<PacketMut>) -> OutboundResult {
        let or::outbound::Result {
            to_wireguard,
            loopback,
        } = self.or_out.route(packets);

        let to_wireguard = to_wireguard
            .into_iter()
            .filter_map(|(k, v)| {
                let info = self.peer_db.get_by_id(k)?;

                // unwrap: either we add the peer or it's in the map, no failure case
                let wg_id = self
                    .wireguard
                    .add_peer(ts_tunnel::PeerConfig {
                        key: info.node_key,
                        psk: [0u8; 32].into(),
                    })
                    .or_else(|| self.wireguard.peer_id(info.node_key))
                    .unwrap();

                Some((wg_id, v))
            })
            .collect::<Vec<_>>();

        let ts_tunnel::SendResult {
            to_peers: encrypted,
        } = self.wireguard.send(to_wireguard);

        let to_peers = self
            .ur_out
            .route(encrypted.into_iter().filter_map(|(k, v)| {
                let info = self.get_wg(k)?;
                Some((info.peer_id, v))
            }));

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        OutboundResult { to_peers, loopback }
    }

    /// Processes packets received from elsewhere.
    pub fn process_inbound(
        &mut self,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> InboundResult {
        let ts_tunnel::RecvResult { to_local, to_peers } = self.wireguard.recv(packets);

        let to_local = to_local
            .into_iter()
            .map(|(peer_id, mut packets)| -> Vec<PacketMut> {
                let span = tracing::trace_span!(
                    "src_filter_inbound",
                    wg_peer_id = ?peer_id,
                    peer_id = tracing::field::Empty,
                    n_packet = packets.len(),
                    peer_key = tracing::field::Empty,
                )
                .entered();

                let Some(info) = self.get_wg(peer_id) else {
                    tracing::warn!("no nodekey for peer");
                    return vec![];
                };

                span.record("peer_key", tracing::field::display(&info.node_key));
                // TODO: span.record("peer_id", info.peer_id);

                packets.retain(|packet| {
                    let Some(src) = packet.get_src_addr() else {
                        tracing::trace!("does not look like ip packet");
                        return false;
                    };
                    let verdict = if let Some(allowed_peer) = self.src_filter_in.lookup(src) {
                        *allowed_peer == info.peer_id
                    } else {
                        false
                    };
                    tracing::trace!(?src, verdict);
                    verdict
                });

                packets
            })
            .map(|mut v| {
                let _span =
                    tracing::trace_span!("packet_filter_inbound", n_packet = v.len()).entered();

                v.retain(|pkt| {
                    let Ok(pkt) = etherparse::SlicedPacket::from_ip(pkt.as_ref()) else {
                        tracing::trace!("does not look like ip packet");
                        return false;
                    };

                    let (proto, src, dst) = match pkt.net {
                        Some(etherparse::NetSlice::Ipv4(ipv4)) => (
                            IpProto::new(ipv4.payload().ip_number.0 as _),
                            ipv4.header().source_addr().into(),
                            ipv4.header().destination_addr().into(),
                        ),
                        Some(etherparse::NetSlice::Ipv6(ipv6)) => (
                            IpProto::new(ipv6.payload().ip_number.0 as _),
                            ipv6.header().source_addr().into(),
                            ipv6.header().destination_addr().into(),
                        ),
                        _ => {
                            unreachable!("unexpected packet kind");
                        }
                    };

                    let (_src_port, dst_port) = match pkt.transport {
                        Some(etherparse::TransportSlice::Udp(udp)) => {
                            (udp.source_port(), udp.destination_port())
                        }
                        Some(etherparse::TransportSlice::Tcp(tcp)) => {
                            (tcp.source_port(), tcp.destination_port())
                        }
                        _ => (0, 0),
                    };

                    let info = ts_packetfilter::PacketInfo {
                        ip_proto: proto,
                        port: dst_port,
                        src,
                        dst,
                    };

                    // TODO(npry): wire in nodecaps
                    let caps = [];
                    let verdict = self.packet_filter.can_access(&info, caps);

                    tracing::trace!(?info, ?caps, verdict);

                    verdict
                });

                v
            });

        let to_peers = to_peers.into_iter().filter_map(|(k, v)| {
            let info = self.get_wg(k)?;
            Some((info.peer_id, v))
        });

        let to_local = self.or_in.route(to_local.flatten());
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        InboundResult { to_local, to_peers }
    }

    /// Return the next time at which [`DataPlane::process_events`] must be called.
    ///
    /// [`DataPlane::process_outbound`], [`DataPlane::process_inbound`] and
    /// [`DataPlane::process_events`] may all update the next event time. Callers should prefer
    /// calling `next_event` as needed to get a correct result, rather than store the returned
    /// value.
    pub fn next_event(&self) -> Option<Instant> {
        self.events.next_dispatch()
    }

    /// Process all queued events that are due for processing.
    ///
    /// Must be called at least as often as dictated by [`DataPlane::next_event`] for the
    /// data plane to function correctly. It is harmless to call it more frequently.
    pub fn process_events(&mut self) -> EventResult {
        let mut to_peers = HashMap::new();
        let now = Instant::now();
        for event in self.events.dispatch(now) {
            match event {
                Subsystem::Wireguard => {
                    let res = self.wireguard.dispatch_events(now);
                    to_peers.extend(res.to_peers.into_iter().filter_map(|(id, pkts)| {
                        let info = self.get_wg(id)?;
                        Some((info.peer_id, pkts))
                    }));
                }
            }
        }
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        EventResult { to_peers }
    }

    fn get_wg(&self, wg: ts_tunnel::PeerId) -> Option<PeerInfo> {
        // unwrap: the peer must have just been in the map, it still must be
        let key = self.wireguard.peer_key(wg)?;
        let info = self.peer_db.get_or_insert(&key);

        Some(info)
    }
}

/// The result of processing outbound packets.
pub struct OutboundResult {
    /// Packets to be sent into underlay transports for transmission.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
    /// Packets to be looped back and delivered to overlay transports.
    pub loopback: HashMap<OverlayTransportId, Vec<PacketMut>>,
}

/// The result of processing inbound packets.
pub struct InboundResult {
    /// Decrypted packets to be delivered to overlay transports.
    pub to_local: HashMap<OverlayTransportId, Vec<PacketMut>>,
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
}

/// The result of processing an event.
#[derive(Default)]
pub struct EventResult {
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
}
