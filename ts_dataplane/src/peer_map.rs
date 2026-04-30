use std::sync::atomic::{AtomicU32, Ordering};

use redb::{ReadableDatabase, ReadableTable, TypeName};
use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, IntoBytes};

/// Info about a Tailscale peer.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
)]
pub struct PeerInfo {
    /// The peer's id.
    pub peer_id: ts_transport::PeerId,
    /// The peer's node key.
    pub node_key: NodePublicKey,
}

impl redb::Value for &PeerInfo {
    type SelfType<'a>
        = &'a PeerInfo
    where
        Self: 'a;

    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(size_of::<PeerInfo>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        PeerInfo::ref_from_bytes(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.as_bytes()
    }

    fn type_name() -> TypeName {
        TypeName::new("PeerInfo")
    }
}

type PeerId = u32;
type Nodekey<'a> = &'a [u8];

/// A database that maps [`ts_transport::PeerId`] to [`NodePublicKey`] and vice versa.
pub struct PeerDb {
    db: redb::Database,
    next_id: AtomicU32,
}

impl Default for PeerDb {
    fn default() -> Self {
        let db = redb::Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .unwrap();

        Self {
            db,
            next_id: AtomicU32::new(0),
        }
    }
}

pub const TABLE_PEERS: redb::TableDefinition<PeerId, &PeerInfo> =
    redb::TableDefinition::new("peers");
pub const TABLE_NODEKEY: redb::TableDefinition<Nodekey, PeerId> =
    redb::TableDefinition::new("peers_nodekey");

// NOTE(npry): the functions here wrap inner helpers that return Result<T, redb::Error>, while the
// outer function returns T by unwrapping. This is because any error redb may throw while in memory
// storage mode is panic-worthy: it is unrecoverable for our use-case if we have corruption or
// transaction contention in-memory. The inner function just allows a more concise expression of the
// bubble-up error semantics than sprinkling unwraps everywhere (and #![feature(try_blocks)] is
// stuck forever in nightly).

impl PeerDb {
    /// Get a [`PeerInfo`] by its [`NodePublicKey`], allocating a new entry if required.
    pub fn get_or_insert(&self, node_key: &NodePublicKey) -> PeerInfo {
        fn _get_or_insert(slf: &PeerDb, node_key: &NodePublicKey) -> Result<PeerInfo, redb::Error> {
            let txn = slf.db.begin_write()?;

            let info = {
                let mut nodekey = txn.open_table(TABLE_NODEKEY)?;
                let mut peers = txn.open_table(TABLE_PEERS)?;

                if let Some(x) = nodekey.get(node_key.as_bytes())? {
                    // invariant: always an entry in both dbs
                    let info = peers.get(x.value())?.unwrap();
                    return Ok(*info.value());
                }

                let id = slf.next_id.fetch_add(1, Ordering::Relaxed);

                let info = PeerInfo {
                    node_key: *node_key,
                    peer_id: ts_transport::PeerId(id),
                };
                peers.insert(id, &info)?;
                nodekey.insert(node_key.as_bytes(), id)?;

                info
            };

            txn.commit()?;

            Ok(info)
        }

        _get_or_insert(self, node_key).unwrap()
    }

    /// Remove a peer by [`NodePublicKey`].
    pub fn remove(&self, node_key: &NodePublicKey) {
        fn _remove(slf: &PeerDb, node_key: &NodePublicKey) -> Result<(), redb::Error> {
            let txn = slf.db.begin_write()?;

            {
                let mut nodekey = txn.open_table(TABLE_NODEKEY)?;
                let mut peers = txn.open_table(TABLE_PEERS)?;

                let Some(id) = nodekey.remove(node_key.as_bytes())? else {
                    return Ok(());
                };

                peers.remove(id.value())?;
            }

            txn.commit()?;

            Ok(())
        }

        _remove(self, node_key).unwrap()
    }

    /// Get a [`PeerInfo`] by its [`ts_transport::PeerId`].
    pub fn get_by_id(&self, transport_id: ts_transport::PeerId) -> Option<PeerInfo> {
        fn _get_by_id(
            slf: &PeerDb,
            transport_id: ts_transport::PeerId,
        ) -> Result<Option<PeerInfo>, redb::Error> {
            let txn = slf.db.begin_read()?;

            let peers = txn.open_table(TABLE_PEERS)?;
            let Some(result) = peers.get(transport_id.0)? else {
                return Ok(None);
            };

            Ok(Some(*result.value()))
        }

        _get_by_id(self, transport_id).unwrap()
    }
}
