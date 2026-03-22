//! Startup bootstrap for the [`Stateful`](crate::stateful::Stateful) actor.
//!
//! The [`bootstrap`] function runs on every startup before the actor can
//! process blocks. It initializes the databases, optionally runs state sync
//! (at most once), and transitions the actor into processing mode.
//!
//! A durable `sync_done` flag in a
//! [`Metadata`] store tracks whether
//! state sync has already completed. The combination of this flag and the
//! [`Mode`] in [`BootstrapConfig`] determines which path is taken:
//!
//! ## Already synced (`sync_done = true`, [`Mode::MarshalSync`])
//!
//! A previous run already completed state sync. The databases are opened from
//! their existing on-disk state, the current processed digest is fetched from
//! marshal, and the actor transitions to processing mode via
//! [`ApplicationMailbox::sync_complete`].
//!
//! ## Fresh start (`sync_done = false`, [`Mode::MarshalSync`])
//!
//! No sync target was provided. Databases are initialized, the genesis block
//! digest is used as the last processed digest, `sync_done` is persisted, and
//! the actor transitions.
//!
//! ## State sync (`sync_done = false`, [`Mode::StateSync`])
//!
//! A sync target block and a channel of anchored target updates are provided.
//! State sync runs at most once; subsequent boots take the "already synced"
//! path above. The procedure is:
//!
//! 1. Extract the initial anchor (height, digest) and sync targets from the
//!    seed block.
//! 2. Run [`StateSyncSet::sync`],
//!    which initializes and populates all databases via the provided
//!    resolvers. Tip updates stream in via the `target_updates` channel as
//!    new blocks finalize during the sync, so the final synced height is
//!    determined by the sync routine itself, not pre-determined.
//! 3. Raise the marshal floor to the synced height via
//!    [`MarshalMailbox::set_floor`], then assert that the marshal's processed
//!    height is at that floor.
//! 4. Persist `sync_done = true` so subsequent boots skip state sync.
//! 5. Call [`ApplicationMailbox::sync_complete`] with the constructed databases
//!    and the synced digest, transitioning the actor into block-processing
//!    mode.

use crate::stateful::{
    db::{DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application, Mailbox as ApplicationMailbox,
};
use commonware_consensus::{
    marshal::{
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
        Identifier,
    },
    types::Height,
    Application as ConsensusApplication, Heightable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{channel::mpsc, sequence::U64};
use rand::Rng;

/// Durable metadata key for "state sync completed".
const SYNC_DONE_KEY: U64 = U64::new(0);

type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type AnchoredUpdate<A, E> = ((Height, BlockDigest<A, E>), SyncTargets<A, E>);

/// Startup inputs for bootstrap.
pub(super) enum Mode<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
{
    /// Initialize databases without running startup state sync, transitioning directly
    /// to marshal sync
    MarshalSync,

    /// Run startup state sync from initial targets and follow target updates.
    StateSync {
        /// The block whose embedded targets seed the initial sync pass.
        block: A::Block,
        /// Channel of anchored target updates as new blocks finalize during sync.
        target_updates: mpsc::Receiver<AnchoredUpdate<A, E>>,
        /// Per-database resolvers used to fetch state from peers.
        resolvers: R,
    },
}

/// Configuration for startup bootstrap.
pub(super) struct BootstrapConfig<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
{
    /// Runtime context used for metadata and database initialization.
    pub(super) context: E,

    /// Database configuration for the managed set.
    pub(super) db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Metadata partition that stores the durable "state sync done" bit.
    pub(super) metadata_partition: String,

    /// Per-database sync engine parameters.
    pub(super) sync_config: SyncEngineConfig,

    /// Startup mode and required inputs for that mode.
    pub(super) mode: Mode<E, A, R>,
}

/// Initialize databases and transition the actor into processing mode.
///
/// See the [module documentation](self) for the full procedure.
///
/// # Panics
///
/// Every failure in this function is intentionally a panic. A node that
/// cannot complete bootstrap has no valid state to operate on; continuing
/// with partial or corrupt databases risks consensus violations or silently
/// diverging from the network. Crashing is the safest response.
///
/// - Metadata store unreachable. The durable `sync_done` flag lives in
///   a [`Metadata`] store. If it
///   cannot be opened or written, the node has no way to track whether sync
///   already ran, so it cannot start safely.
/// - `sync_done = true` with [`Mode::StateSync`]. This is a
///   configuration contradiction: the caller is requesting state sync for a
///   node that already completed it. This indicates a bug in the caller.
/// - State sync fails. The sync engine validates every batch of
///   operations against MMR proofs rooted at the target. Errors that reach
///   this point are not retryable: root mismatches after full sync
///   (operations do not reconstruct the expected root), journal or storage
///   I/O failures (disk full, corruption), invalid target updates (target
///   moved backward or stalled), and resolver errors that the engine could
///   not recover from internally. The sync engine already retries individual
///   fetch failures; errors that propagate here are terminal.
/// - Marshal unreachable after `set_floor`. After state sync the marshal
///   floor must be raised so that the node does not attempt to re-process
///   blocks below the synced height. If the marshal does not respond, or
///   reports a processed height that does not equal the floor, the node
///   cannot safely determine where to resume.
pub(super) async fn bootstrap<E, A, S, V, R>(
    marshal: MarshalMailbox<S, V>,
    mut application: ApplicationMailbox<E, A>,
    config: BootstrapConfig<E, A, R>,
) where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Context: Send,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
    R: Clone + Send + 'static,
{
    let mut metadata = Metadata::<E, U64, bool>::init(
        config.context.with_label("state_sync_metadata"),
        MetadataConfig {
            partition: config.metadata_partition,
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize state sync metadata store");

    if metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false) {
        assert!(
            matches!(config.mode, Mode::MarshalSync),
            "state sync bootstrap received a sync startup target after state sync was already marked complete",
        );

        let databases = A::Databases::init(config.context.clone(), config.db_config).await;
        let (height, digest) = current_anchor(&marshal, &mut application).await;
        application.sync_complete(databases, height, digest).await;
        return;
    }

    let (databases, last_processed_height, last_processed_digest, new_marshal_floor) = match config.mode {
        Mode::MarshalSync => {
            let databases = A::Databases::init(config.context.clone(), config.db_config).await;
            let genesis_digest = application.genesis().await.digest();
            (databases, Height::zero(), genesis_digest, None)
        }
        Mode::StateSync {
            block,
            target_updates,
            resolvers,
        } => {
            let initial_anchor = (block.height(), block.digest());
            let initial_targets = A::sync_targets(&block);
            let (databases, (sync_height, sync_digest)) =
                <A::Databases as StateSyncSet<E, R, BlockDigest<A, E>>>::sync(
                    config.context.clone(),
                    config.db_config,
                    resolvers,
                    initial_anchor,
                    initial_targets,
                    target_updates,
                    config.sync_config,
                )
                .await
                .unwrap_or_else(|err| panic!("state sync failed: {err:?}"));
            (databases, sync_height, sync_digest, Some(sync_height))
        }
    };

    if let Some(floor_height) = new_marshal_floor {
        // Raising the marshal floor also clears marshal's pending application
        // acknowledgements below that floor.
        marshal.set_floor(floor_height).await;
        let processed_height = marshal
            .get_processed_height()
            .await
            .expect("marshal must respond with processed height after set_floor");
        assert!(
            processed_height == floor_height,
            "marshal processed height must equal floor after set_floor"
        );
    }

    metadata
        .put_sync(SYNC_DONE_KEY, true)
        .await
        .expect("must persist state sync completion metadata");

    application
        .sync_complete(databases, last_processed_height, last_processed_digest)
        .await;
}

/// Fetches the latest processed block's height and digest from `marshal`.
///
/// # Panics
///
/// Panics if the latest processed block could not be fetched from marshal.
async fn current_anchor<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    application: &mut ApplicationMailbox<E, A>,
) -> (Height, <A::Block as Digestible>::Digest)
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Context: Send,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
{
    let processed_height = marshal
        .get_processed_height()
        .await
        .expect("state sync bootstrap failed to fetch marshal processed height");
    if processed_height == Height::zero() {
        let genesis_digest = application.genesis().await.digest();
        return (Height::zero(), genesis_digest);
    }
    let (_, digest) = marshal
        .get_info(Identifier::Height(processed_height))
        .await
        .unwrap_or_else(|| {
            panic!(
                "state sync bootstrap missing processed block digest at height {}",
                processed_height.get()
            )
        });
    (processed_height, digest)
}
