use crate::{
    adb::{
        any::{
            sync::client::{Client, Config},
            Any,
        },
        operation::Fixed,
        sync::{engine::SyncTarget, resolver::Resolver},
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::mpsc;

pub mod client;
mod metrics;

/// Channel for sending sync target updates
pub type SyncTargetUpdateSender<D> = mpsc::Sender<SyncTarget<D>>;

/// Synchronization errors for Any database sync
pub type Error = crate::adb::sync::error::SyncError<crate::adb::Error>;

/// Helper functions for Any sync error conversion
impl Error {
    /// Create a database error from an ADB error
    pub fn adb(err: crate::adb::Error) -> Self {
        Self::Database(err)
    }

    /// Create a pinned nodes error from an MMR error
    pub fn pinned_nodes_mmr(err: crate::mmr::Error) -> Self {
        Self::PinnedNodes(err.to_string())
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
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    let client = Client::new(config).await?;
    client.sync().await
}
