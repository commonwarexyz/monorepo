use crate::{
    adb::{
        any::{sync::verifier::Verifier, Any, SyncConfig},
        operation::Fixed,
        sync::{
            engine::EngineConfig, resolver::Resolver, Engine, Error as SyncError, Journal, Target,
        },
    },
    journal::fixed,
    mmr::hasher::Standard,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

pub mod config;
mod verifier;

pub type Error = crate::adb::Error;

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

impl<E, K, V, H, T> crate::adb::sync::Database for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Op = Fixed<K, V>;
    type Journal = crate::journal::fixed::Journal<E, Fixed<K, V>>;
    type Verifier = Verifier<E, K, V, H, T>;
    type Error = crate::adb::Error;
    type Config = AnySyncConfig<E, T>;
    type Digest = H::Digest;
    type Context = E;

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

    fn create_verifier() -> Self::Verifier {
        Verifier::new(Standard::<H>::new())
    }

    async fn from_sync_result(
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: Target<Self::Digest>,
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

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        let log_size = journal.size().await.map_err(crate::adb::Error::from)?;

        if log_size <= lower_bound {
            // Close the existing journal before creating a new one
            journal.close().await.map_err(crate::adb::Error::from)?;

            // Create a new journal with the new bounds
            Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(crate::adb::Error::from)
        } else {
            // Just prune to the lower bound
            journal
                .prune(lower_bound)
                .await
                .map_err(crate::adb::Error::from)?;
            Ok(journal)
        }
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
    mut config: config::Config<E, K, V, H, T, R>,
) -> Result<Engine<Any<E, K, V, H, T>, R>, SyncError<Error, R::Error>>
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

    let engine_config = EngineConfig {
        context: config.context,
        resolver: config.resolver,
        target: config.target.clone(),
        max_outstanding_requests: config.max_outstanding_requests,
        fetch_batch_size: config.fetch_batch_size,
        db_config,
        update_receiver: config.update_receiver.take(),
    };

    Engine::new(engine_config).await
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
    config: config::Config<E, K, V, H, T, R>,
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
