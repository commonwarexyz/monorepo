use crate::{
    adb::any::{
        sync::{
            client::{Client, Config},
            resolver::Resolver,
        },
        Any,
    },
    mmr,
    translator::Translator,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::mpsc;
use std::fmt;

pub mod client;
mod metrics;
pub mod resolver;

/// The target state to sync to.
#[derive(Debug, Clone)]
pub struct SyncTarget<D: Digest> {
    /// Root digest of the target database
    pub root: D,
    /// Lower bound of operations to sync (inclusive)
    /// This will be the pruning boundary of the synced database.
    pub lower_bound_ops: u64,
    /// Upper bound of operations to sync (inclusive)
    pub upper_bound_ops: u64,
}

/// Channel for sending sync target updates
pub type SyncTargetUpdateSender<D> = mpsc::Sender<SyncTarget<D>>;

/// Channel for receiving sync target updates
pub type SyncTargetUpdateReceiver<D> = mpsc::Receiver<SyncTarget<D>>;

/// Synchronization errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch {
        expected: Box<dyn fmt::Debug + Send + Sync>,
        actual: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Invalid target parameters
    #[error("invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: u64,
        upper_bound_pos: u64,
    },
    /// Invalid client state
    #[error("invalid client state")]
    InvalidState,
    /// Sync target root unchanged
    #[error("sync target root unchanged")]
    SyncTargetRootUnchanged,
    /// Sync target moved backward
    #[error("sync target moved backward: {old:?} -> {new:?}")]
    SyncTargetMovedBackward {
        old: Box<dyn fmt::Debug + Send + Sync>,
        new: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Sync already completed
    #[error("sync already completed")]
    AlreadyComplete,
    /// Error from the database
    #[error("database error: {0}")]
    Adb(crate::adb::Error),
    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(Box<dyn fmt::Debug + Send + Sync>),
    /// Sync stalled
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Error extracting pinned nodes
    #[error("error extracting pinned nodes: {0}")]
    PinnedNodes(mmr::Error),
}

impl<D: Digest> Write for SyncTarget<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.lower_bound_ops.write(buf);
        self.upper_bound_ops.write(buf);
    }
}

impl<D: Digest> EncodeSize for SyncTarget<D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size()
            + self.lower_bound_ops.encode_size()
            + self.upper_bound_ops.encode_size()
    }
}

impl<D: Digest> Read for SyncTarget<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let lower_bound_ops = u64::read(buf)?;
        let upper_bound_ops = u64::read(buf)?;
        Ok(Self {
            root,
            lower_bound_ops,
            upper_bound_ops,
        })
    }
}

/// Synchronizes a database by fetching, verifying, and applying operations from a remote source.
///
/// We repeatedly:
/// 1. Fetch operations in batches from a Resolver (i.e. a server of operations)
/// 2. Verify cryptographic proofs for each batch to ensure correctness
/// 3. Apply operations to reconstruct the database's operation log.
///
/// When the database's operation log is complete, we reconstruct the database's MMR and snapshot.
pub async fn sync<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    let client = Client::new(config).await?;
    client.sync().await
}
