use crate::{
    adb::{
        any::{
            sync::client::{Client, Config},
            Any,
        },
        operation::Fixed,
        sync::{
            engine::{SyncTarget, SyncVerifier},
            resolver::Resolver,
        },
    },
    mmr::{hasher::Standard, iterator::leaf_num_to_pos, verification::Proof},
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

/// Verifier for Any database operations using the database's built-in proof verification
pub struct AnyVerifier<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    hasher: Standard<H>,
    // Phantom data to maintain type information
    _phantom: std::marker::PhantomData<(E, K, V, T)>,
}

impl<E, K, V, H, T> AnyVerifier<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    /// Create a new verifier with the given hasher
    pub fn new(hasher: Standard<H>) -> Self {
        Self {
            hasher,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E, K, V, H, T> SyncVerifier<Fixed<K, V>, H::Digest> for AnyVerifier<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Error = crate::mmr::Error;

    fn verify_proof(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations: &[Fixed<K, V>],
        target_root: &H::Digest,
    ) -> bool {
        Any::<E, K, V, H, T>::verify_proof(
            &mut self.hasher,
            proof,
            start_loc,
            operations,
            target_root,
        )
    }

    fn extract_pinned_nodes(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<Option<Vec<H::Digest>>, Self::Error> {
        // Always try to extract pinned nodes - the engine will decide when to use them
        let start_pos_mmr = leaf_num_to_pos(start_loc);
        let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
        proof
            .extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
            .map(Some)
    }
}

/// Configuration for building Any database from completed sync
pub struct AnySyncConfig<E, T>
where
    E: Storage + Clock + Metrics,
    T: Translator,
{
    pub context: E,
    pub db_config: crate::adb::any::Config<T>,
    pub apply_batch_size: usize,
}

/// Implementation of SyncDatabase for Any database
impl<E, K, V, H, T>
    crate::adb::sync::engine::SyncDatabase<
        crate::journal::fixed::Journal<E, Fixed<K, V>>,
        H::Digest,
    > for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Config = AnySyncConfig<E, T>;
    type Error = crate::adb::sync::error::SyncError<crate::adb::Error>;

    async fn from_sync_result(
        config: Self::Config,
        journal: crate::journal::fixed::Journal<E, Fixed<K, V>>,
        pinned_nodes: Option<Vec<H::Digest>>,
        target: crate::adb::sync::engine::SyncTarget<H::Digest>,
    ) -> Result<Self, Self::Error> {
        use crate::adb::any::SyncConfig;

        // Build the complete database from the journal
        let db = Any::init_synced(
            config.context,
            SyncConfig {
                db_config: config.db_config,
                log: journal,
                lower_bound: target.lower_bound_ops,
                upper_bound: target.upper_bound_ops,
                pinned_nodes,
                apply_batch_size: config.apply_batch_size,
            },
        )
        .await
        .map_err(crate::adb::sync::error::SyncError::database)?;

        Ok(db)
    }

    fn root(
        &self,
        _hasher: &mut impl commonware_cryptography::Hasher<Digest = H::Digest>,
    ) -> H::Digest {
        // Any database requires its own Standard hasher, so we ignore the passed hasher
        let mut standard_hasher = Standard::<H>::new();
        Any::root(self, &mut standard_hasher)
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
