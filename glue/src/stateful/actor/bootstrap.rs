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
//! their existing on-disk state and reconciled with marshal's processed block:
//!
//! - Bootstrap loads sync targets for marshal's processed block and compares
//!   them with the databases' committed targets.
//! - If they differ, bootstrap rewinds every database in the set to those
//!   processed-block targets.
//! - This reconciliation assumes databases were not manually rolled back or
//!   replaced out-of-band.
//! - Any rewind failure is fatal and causes a panic.
//! - Bootstrap then hands the processed anchor and databases to the actor.
//!
//! The marshal only advances its processed height after it has durably stored
//! the floor block, so reconciliation can read the processed block directly.
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
//! 1. Extract the initial anchor and sync targets from the
//!    seed block.
//! 2. Raise marshal's floor to the initial target so finalized blocks stream
//!    contiguously while state sync runs.
//! 3. Run [`StateSyncSet::sync`], which initializes and populates all databases
//!    via the provided resolvers. Finalized blocks acknowledged by the actor
//!    stream in via the `target_updates` channel during the sync, so the final
//!    synced height is determined by the sync routine itself, not pre-determined.
//! 4. Persist `sync_done = true` so subsequent boots skip state sync.
//! 5. Send the constructed databases and synced digest to the actor. The actor
//!    keeps acknowledging finalized blocks until marshal has delivered through
//!    the synced height, then transitions into block-processing mode.
//!
//! ## Crash during state sync
//!
//! If the node crashes while state sync is in progress (before `sync_done` is
//! persisted), the database partitions may contain partial sync data that is
//! incompatible with a fresh [`ManagedDb::init`](crate::stateful::db::ManagedDb::init).
//! The operator must delete the database storage directory before restarting.
//! A future version may automate this cleanup.

use crate::stateful::{
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_consensus::{
    marshal::{
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
        Identifier,
    },
    simplex::types::Finalization,
    types::{Height, Round},
    CertifiableBlock, Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{
    telemetry::metrics::{MetricsExt, Registered},
    Clock, Metrics, Spawner, Storage,
};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot, ring},
    sequence::U64,
};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;

/// Durable metadata key for "state sync completed".
const SYNC_DONE_KEY: U64 = U64::new(0);

type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type AnchoredUpdate<A, E> = (Anchor<BlockDigest<A, E>>, SyncTargets<A, E>);

/// Startup bootstrap completion delivered directly to the actor.
pub(super) struct Completion<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Databases initialized by bootstrap.
    pub(super) databases: A::Databases,

    /// Last block whose state is already represented by the databases.
    pub(super) last_processed: Anchor<BlockDigest<A, E>>,
}

/// Startup inputs for bootstrap.
pub(super) enum Mode<E, A, F>
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
        /// The finalization for `block`.
        finalization: F,
        /// Channel of anchored target updates as new blocks finalize during sync.
        target_updates: ring::Receiver<AnchoredUpdate<A, E>>,
    },
}

/// Configuration for startup bootstrap.
pub(super) struct BootstrapConfig<E, A, R, F>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
{
    /// Runtime context used for metadata and database initialization.
    pub(super) context: E,

    /// Database configuration for the managed set.
    pub(super) db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Application used to load genesis during bootstrap.
    pub(super) app: A,

    /// Metadata partition that stores the durable "state sync done" bit.
    pub(super) metadata_partition: String,

    /// Per-database sync engine parameters.
    pub(super) sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    pub(super) resolvers: R,

    /// Startup mode and required inputs for that mode.
    pub(super) mode: Mode<E, A, F>,

    /// Actor handoff for initialized databases.
    pub(super) completion: oneshot::Sender<Completion<E, A>>,
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
/// - Rewind to marshal-processed targets fails. Bootstrap recovery rewinds all
///   databases to marshal's processed block targets. Rewind errors indicate
///   unrecoverable local history loss/corruption (for example pruned rewind
///   boundaries or invalid commit targets), so startup must stop.
/// - Marshal unreachable after `set_floor`. Before state sync the marshal
///   floor must be raised to the initial target so the finalized block stream
///   starts at the first block that may advance synced state. If the marshal
///   does not respond, or reports a processed height below the initial floor,
///   the node cannot safely determine where to resume.
pub(super) async fn bootstrap<E, A, S, V, R>(
    marshal: MarshalMailbox<S, V>,
    config: BootstrapConfig<E, A, R, Finalization<S, V::Commitment>>,
) where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
{
    let BootstrapConfig {
        context,
        db_config,
        mut app,
        metadata_partition,
        sync_config,
        resolvers,
        mode,
        completion,
    } = config;

    let state_sync_done: Registered<Gauge> =
        context.gauge("state_sync_done", "Whether state sync has completed");
    state_sync_done.set(0);

    let mut metadata = Metadata::<E, U64, bool>::init(
        context.child("state_sync_metadata"),
        MetadataConfig {
            partition: metadata_partition,
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize state sync metadata store");

    if metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false) {
        state_sync_done.set(1);
        assert!(
            matches!(mode, Mode::MarshalSync),
            "state sync bootstrap received a sync startup target after state sync was already marked complete",
        );

        let genesis = app.genesis().await;
        let databases = A::Databases::init(context.child("db_set"), db_config).await;

        let (processed_anchor, processed_targets) =
            processed_anchor_targets::<E, A, S, V>(&marshal, &genesis)
                .await
                .expect("marshal processed block must be available");

        let db_targets = databases.committed_targets().await;
        if db_targets != processed_targets {
            databases.rewind_to_targets(processed_targets.clone()).await;
            let rewound_targets = databases.committed_targets().await;
            assert!(
                rewound_targets == processed_targets,
                "database targets must match marshal processed targets after rewind",
            );
        }

        assert!(
            completion.send_lossy(Completion {
                databases,
                last_processed: processed_anchor,
            }),
            "stateful actor dropped during bootstrap completion",
        );
        return;
    }

    let completion_message = match mode {
        Mode::MarshalSync => {
            let databases = A::Databases::init(context.child("db_set"), db_config).await;
            let genesis = app.genesis().await;
            let genesis_context = genesis.context();
            let last_processed = Anchor {
                height: Height::zero(),
                round: Round::new(genesis_context.epoch(), genesis_context.view()),
                digest: genesis.digest(),
            };
            Completion {
                databases,
                last_processed,
            }
        }
        Mode::StateSync {
            block,
            finalization,
            target_updates,
        } => {
            let block_context = block.context();
            let initial_anchor = Anchor {
                height: block.height(),
                round: Round::new(block_context.epoch(), block_context.view()),
                digest: block.digest(),
            };
            let initial_targets = A::sync_targets(&block);
            // Move marshal to the initial target before state sync starts so
            // the actor sees a contiguous finalized stream after target
            // selection. Every later finalized block can then become both a
            // sync target update and an acknowledgement toward handoff.
            marshal.set_floor(finalization.clone());
            let (databases, last_processed) = A::Databases::sync(
                context.child("state_sync"),
                db_config,
                resolvers,
                initial_anchor,
                initial_targets,
                target_updates,
                sync_config,
            )
            .await
            .unwrap_or_else(|err| panic!("state sync failed: {err:?}"));
            Completion {
                databases,
                last_processed,
            }
        }
    };

    metadata
        .put_sync(SYNC_DONE_KEY, true)
        .await
        .expect("must persist state sync completion metadata");
    state_sync_done.set(1);

    assert!(
        completion.send_lossy(completion_message),
        "stateful actor dropped during bootstrap completion",
    );
}

/// Load marshal's current processed anchor and derived sync targets.
///
/// Returns `None` when the marshal's processed height is non-zero but the
/// block is missing from the archive. With current floor semantics this should
/// only happen if marshal storage is inconsistent: [`MarshalMailbox::set_floor`]
/// does not advance the processed height until the floor block is stored.
///
/// # Panics
///
/// - Marshal does not return its processed height.
async fn processed_anchor_targets<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    genesis: &A::Block,
) -> Option<(Anchor<BlockDigest<A, E>>, SyncTargets<A, E>)>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
{
    let processed_height = marshal
        .get_processed_height()
        .await
        .expect("state sync bootstrap must fetch marshal processed height");
    if processed_height.is_zero() {
        let genesis_context = genesis.context();
        return Some((
            Anchor {
                height: Height::zero(),
                round: Round::new(genesis_context.epoch(), genesis_context.view()),
                digest: genesis.digest(),
            },
            A::sync_targets(genesis),
        ));
    }

    let block = marshal
        .get_block(Identifier::Height(processed_height))
        .await
        .map(V::into_inner)?;

    Some((
        Anchor {
            height: processed_height,
            round: Round::new(block.context().epoch(), block.context().view()),
            digest: block.digest(),
        },
        A::sync_targets(&block),
    ))
}
