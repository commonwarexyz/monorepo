use crate::{
    adb::{
        any::{Any, SyncConfig},
        operation::Fixed,
        sync::{
            engine::{Journal, SyncEngine, SyncEngineConfig, SyncTarget, SyncVerifier},
            error::SyncError,
            resolver::Resolver,
        },
    },
    journal::fixed,
    mmr::{hasher::Standard, iterator::leaf_num_to_pos, verification::Proof},
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::mpsc;

pub mod client;

/// Channel for sending sync target updates
pub type SyncTargetUpdateSender<D> = mpsc::Sender<SyncTarget<D>>;

pub type Error = crate::adb::Error;

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
#[derive(Clone)]
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
impl<E, K, V, H, T> crate::adb::sync::engine::SyncDatabase for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    // Core associated types
    type Op = Fixed<K, V>;
    type Journal = crate::journal::fixed::Journal<E, Fixed<K, V>>;
    type Verifier = AnyVerifier<E, K, V, H, T>;
    type Error = crate::adb::Error;
    type Config = AnySyncConfig<E, T>;
    type Digest = H::Digest;
    type Context = E;

    /// Create a journal for syncing with the given bounds
    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as Journal>::Error> {
        let journal_config = fixed::Config {
            partition: config.db_config.log_journal_partition.clone(),
            items_per_blob: config.db_config.log_items_per_blob,
            write_buffer: config.db_config.log_write_buffer,
            buffer_pool: config.db_config.buffer_pool.clone(),
        };

        fixed::Journal::<E, Fixed<K, V>>::init_sync(
            context.with_label("log"),
            journal_config,
            lower_bound,
            upper_bound,
        )
        .await
    }

    /// Create a verifier for proof validation  
    fn create_verifier() -> Self::Verifier {
        AnyVerifier::new(Standard::<H>::new())
    }

    async fn from_sync_result(
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: crate::adb::sync::engine::SyncTarget<Self::Digest>,
    ) -> Result<Self, Self::Error> {
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
        .await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        let mut standard_hasher = Standard::<H>::new();
        Any::root(self, &mut standard_hasher)
    }
}

/// Creates a new sync client (SyncEngine) for Any database synchronization.
///
/// This sets up all the necessary components for syncing:
/// - Validates configuration
/// - Initializes the operations journal
/// - Creates the journal wrapper, verifier, and sync engine
///
/// Returns a SyncEngine ready to start syncing operations.
pub async fn new_client<E, K, V, H, T, R>(
    mut config: client::Config<E, K, V, H, T, R>,
) -> Result<SyncEngine<Any<E, K, V, H, T>, R>, SyncError<Error, R::Error>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    // Validate configuration
    config.validate()?;

    // Create sync engine using the simplified configuration
    let db_config = AnySyncConfig::<E, T> {
        context: config.context.clone(),
        db_config: config.db_config.clone(),
        apply_batch_size: config.apply_batch_size,
    };

    let engine_config = SyncEngineConfig {
        context: config.context,
        resolver: config.resolver,
        target: config.target.clone(),
        max_outstanding_requests: config.max_outstanding_requests,
        fetch_batch_size: config.fetch_batch_size,
        db_config,
        update_receiver: config.update_receiver.take(),
    };

    SyncEngine::new(engine_config).await
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
    config: client::Config<E, K, V, H, T, R>,
) -> Result<Any<E, K, V, H, T>, SyncError<Error, R::Error>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    // Create sync engine using the new_client function
    let mut engine = new_client(config).await?;

    // Make initial requests to start the sync process
    engine.schedule_requests().await?;

    // Run sync to completion using generic engine
    engine.sync().await
}
