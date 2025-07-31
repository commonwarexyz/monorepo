use crate::{
    adb::{
        any::Any,
        operation::Fixed,
        sync::{
            engine::{SyncEngine, SyncTarget, SyncVerifier},
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

/// Wrapper around Journal that converts errors to sync errors
pub struct JournalWrapper<E, K, V>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
{
    journal: crate::journal::fixed::Journal<E, Fixed<K, V>>,
}

impl<E, K, V> crate::adb::sync::engine::SyncJournal for JournalWrapper<E, K, V>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
{
    type Op = Fixed<K, V>;
    type Error = Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        self.journal
            .size()
            .await
            .map_err(|e| Error::adb(crate::adb::Error::JournalError(e)))
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        self.journal
            .append(op)
            .await
            .map(|_| ())
            .map_err(|e| Error::adb(crate::adb::Error::JournalError(e)))
    }
}

/// Implementation of SyncDatabase for Any database
impl<E, K, V, H, T> crate::adb::sync::engine::SyncDatabase<JournalWrapper<E, K, V>, H::Digest>
    for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Config = AnySyncConfig<E, T>;
    type Error = Error;

    fn from_sync_result(
        config: Self::Config,
        journal_wrapper: JournalWrapper<E, K, V>,
        pinned_nodes: Option<Vec<H::Digest>>,
        target: crate::adb::sync::engine::SyncTarget<H::Digest>,
    ) -> impl std::future::Future<Output = Result<Self, Self::Error>> {
        async move {
            use crate::adb::any::SyncConfig;

            // Extract the journal from the wrapper
            let journal = journal_wrapper.journal;

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
            .map_err(Error::adb)?;

            Ok(db)
        }
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

/// Creates a new sync client (SyncEngine) for Any database synchronization.
///
/// This sets up all the necessary components for syncing:
/// - Validates configuration
/// - Initializes the operations journal
/// - Creates the journal wrapper, verifier, and sync engine
///
/// Returns a SyncEngine ready to start syncing operations.
pub async fn new_client<E, K, V, H, T, R>(
    config: client::Config<E, K, V, H, T, R>,
) -> Result<
    SyncEngine<JournalWrapper<E, K, V>, R, AnyVerifier<E, K, V, H, T>, H::Digest, Error>,
    Error,
>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    use crate::journal::fixed::{Config as JConfig, Journal};

    // Validate configuration
    config.validate()?;

    // Initialize the operations journal
    let journal = Journal::<E, Fixed<K, V>>::init_sync(
        config.context.clone().with_label("log"),
        JConfig {
            partition: config.db_config.log_journal_partition.clone(),
            items_per_blob: config.db_config.log_items_per_blob,
            write_buffer: config.db_config.log_write_buffer,
            buffer_pool: config.db_config.buffer_pool.clone(),
        },
        config.target.lower_bound_ops,
        config.target.upper_bound_ops,
    )
    .await
    .map_err(|e| Error::adb(crate::adb::Error::JournalError(e)))?;

    // Validate journal size
    let log_size = journal
        .size()
        .await
        .map_err(|e| Error::adb(crate::adb::Error::JournalError(e)))?;
    assert!(log_size <= config.target.upper_bound_ops + 1);

    // Create a journal wrapper that converts errors to sync errors
    let wrapped_journal = JournalWrapper { journal };

    // Create verifier
    let verifier = AnyVerifier::<E, K, V, H, T>::new(config.hasher);

    // Create sync engine
    Ok(SyncEngine::new(
        wrapped_journal,
        config.resolver,
        verifier,
        config.target.clone(),
        config.max_outstanding_requests,
        config.fetch_batch_size,
    ))
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
    mut config: client::Config<E, K, V, H, T, R>,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    // Store fields we'll need after creating the engine
    let context = config.context.clone();
    let db_config = config.db_config.clone();
    let apply_batch_size = config.apply_batch_size;
    let mut update_receiver = config.update_receiver.take();

    // Create sync engine using the new_client function
    let mut engine = new_client(config).await?;

    // Make initial requests to start the sync process
    engine.schedule_requests().await?;

    // Create database configuration for final build step
    let db_config = AnySyncConfig {
        context,
        db_config,
        apply_batch_size,
    };

    // Run sync to completion using generic engine
    // Extract the underlying hasher from the Standard wrapper
    let hasher = H::new();
    let database = engine.sync(db_config, &mut update_receiver, hasher).await?;

    Ok(database)
}
