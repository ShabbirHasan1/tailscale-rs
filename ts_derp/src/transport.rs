use ts_keys::NodePublicKey;
use ts_packet::PacketMut;
use ts_transport::{PeerId, UnderlayTransport};

use crate::{Error, PeerLookup};

pub trait NodekeyTransport: Send + Sync {
    /// Send a message addressed to the given node key.
    fn send_one(
        &self,
        node_key: NodePublicKey,
        body: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Receive a frame from a particular node key.
    fn recv_one(&self) -> impl Future<Output = Result<(NodePublicKey, PacketMut), Error>> + Send;
}

/// An implementation of [`UnderlayTransport`] wrapping a `NodekeyTransport` with a
/// [`PeerLookup`].
pub struct Transport<NkT, Lookup> {
    inner: NkT,
    peer_lookup: Lookup,
}

impl<NkT, Lookup> Transport<NkT, Lookup> {
    /// Construct a new [`Transport`] with the given `NodekeyTransport` and [`PeerLookup`].
    pub fn new(client: NkT, lookup: Lookup) -> Self {
        Self {
            inner: client,
            peer_lookup: lookup,
        }
    }

    /// Destruct this [`Transport`] into its constituent parts.
    pub fn into_parts(self) -> (NkT, Lookup) {
        (self.inner, self.peer_lookup)
    }
}

impl<NkT, Lookup> UnderlayTransport for Transport<NkT, Lookup>
where
    NkT: NodekeyTransport,
    Lookup: PeerLookup,
{
    type Error = Error;

    async fn recv(
        &self,
    ) -> impl IntoIterator<Item = Result<(PeerId, impl IntoIterator<Item = PacketMut>), Self::Error>>
    {
        let result = self.inner.recv_one().await.map(|(k, pkt)| {
            let id = self.peer_lookup.key_to_id(&k);
            (id, [pkt])
        });

        [result]
    }

    /// Send a batch of packets to a peer via this DERP server.
    async fn send<BatchIter, PacketIter>(&self, peer_packets: BatchIter) -> Result<(), Self::Error>
    where
        BatchIter: IntoIterator<Item = (PeerId, PacketIter)> + Send,
        BatchIter::IntoIter: Send,
        PacketIter: IntoIterator<Item = PacketMut> + Send,
        PacketIter::IntoIter: Send,
    {
        for (peer, packets) in peer_packets {
            let Some(node_key) = self.peer_lookup.id_to_key(peer) else {
                tracing::warn!(peer_id = %peer, "no node key known for peer");
                continue;
            };

            for packet in packets {
                self.inner.send_one(node_key, packet.as_ref()).await?;
            }
        }

        Ok(())
    }
}
