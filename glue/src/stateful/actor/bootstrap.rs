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
//! their existing on-disk state and reconciled with marshal:
//!
//! - Normal case: the current processed digest is fetched from marshal and the
//!   actor transitions to processing mode via [`ApplicationMailbox::sync_complete`].
//! - Recovery case: if no exact anchor match exists, bootstrap runs a one-block
//!   repair state sync to targets derived from marshal height `processed + 1`.
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
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
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
use commonware_cryptography::{certificate::Scheme, Digest, Digestible};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{channel::mpsc, sequence::U64};
use rand::Rng;

/// Durable metadata key for "state sync completed".
const SYNC_DONE_KEY: U64 = U64::new(0);

type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type AnchoredUpdate<A, E> = (Anchor<BlockDigest<A, E>>, SyncTargets<A, E>);

/// Startup inputs for bootstrap.
pub(super) enum Mode<E, A>
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

    /// Per-database resolvers used to fetch state from peers.
    pub(super) resolvers: R,

    /// Startup mode and required inputs for that mode.
    pub(super) mode: Mode<E, A>,
}

enum AnchorResolution<T, D: Digest> {
    Matched(Anchor<D>),
    RepairToNext { anchor: Anchor<D>, targets: T },
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
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
{
    let BootstrapConfig {
        context,
        db_config,
        metadata_partition,
        sync_config,
        resolvers,
        mode,
    } = config;

    let mut metadata = Metadata::<E, U64, bool>::init(
        context.with_label("state_sync_metadata"),
        MetadataConfig {
            partition: metadata_partition,
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize state sync metadata store");

    if metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false) {
        assert!(
            matches!(mode, Mode::MarshalSync),
            "state sync bootstrap received a sync startup target after state sync was already marked complete",
        );

        let genesis = application.genesis().await;
        let databases = A::Databases::init(context.clone(), db_config.clone()).await;
        let db_targets = databases.committed_targets().await;
        let anchor_resolution =
            reconcile_anchor::<E, A, S, V>(&marshal, db_targets, &genesis).await;

        match anchor_resolution {
            AnchorResolution::Matched(anchor) => {
                application.sync_complete(databases, anchor).await;
            }
            AnchorResolution::RepairToNext { anchor, targets } => {
                drop(databases);
                let (tip_updates_tx, tip_updates_rx) = mpsc::channel(1);
                drop(tip_updates_tx);

                let (databases, sync_anchor) = A::Databases::sync(
                    context.clone(),
                    db_config,
                    resolvers,
                    anchor,
                    targets,
                    tip_updates_rx,
                    sync_config,
                )
                .await
                .unwrap_or_else(|err| panic!("state sync repair to processed+1 failed: {err:?}"));

                marshal.set_floor(sync_anchor.height, false).await;
                marshal
                    .get_processed_height()
                    .await
                    .expect("marshal must respond with processed height after one-block repair");

                application.sync_complete(databases, sync_anchor).await;
            }
        }

        return;
    }

    let (databases, last_processed, new_marshal_floor) = match mode {
        Mode::MarshalSync => {
            let databases = A::Databases::init(context.clone(), db_config).await;
            let genesis_digest = application.genesis().await.digest();
            let anchor = Anchor {
                height: Height::zero(),
                digest: genesis_digest,
            };
            (databases, anchor, None)
        }
        Mode::StateSync {
            block,
            target_updates,
        } => {
            let initial_anchor = Anchor {
                height: block.height(),
                digest: block.digest(),
            };
            let initial_targets = A::sync_targets(&block);
            let (databases, sync_anchor) = A::Databases::sync(
                context.clone(),
                db_config,
                resolvers,
                initial_anchor,
                initial_targets,
                target_updates,
                sync_config,
            )
            .await
            .unwrap_or_else(|err| panic!("state sync failed: {err:?}"));
            (databases, sync_anchor, Some(sync_anchor.height))
        }
    };

    if let Some(floor_height) = new_marshal_floor {
        // Raising the marshal floor also clears marshal's pending application
        // acknowledgements below that floor.
        marshal.set_floor(floor_height, true).await;
        marshal
            .get_processed_height()
            .await
            .expect("marshal must respond with processed height after set_floor");
    }

    metadata
        .put_sync(SYNC_DONE_KEY, true)
        .await
        .expect("must persist state sync completion metadata");

    application.sync_complete(databases, last_processed).await;
}

/// Reconciles marshal's processed frontier with committed database state.
///
/// The restart path treats the database as the source of truth for what was
/// durably committed and then finds the earliest marshal height that matches it.
///
/// 1. Read the database's committed sync targets.
/// 2. Read marshal's current processed height.
/// 3. Walk forward by height starting at that processed height.
///    - At height `0`, compare against the application's genesis sync targets.
///    - At height `> 0`, fetch the marshal block for that height and derive
///      sync targets from that block.
/// 4. When targets match:
///    - If the match is exactly at marshal's processed height, return it.
///    - If the match is ahead, raise marshal's floor to that height so marshal
///      and the database resume from the same anchor.
/// 5. If no matching anchor is found before marshal stops returning blocks:
///    - Require marshal block `processed + 1`.
///    - Return a one-block repair target derived from that block's sync targets.
///
/// # Panics
///
/// - Marshal does not return its processed height.
/// - Marshal does not have the block at its own processed height.
/// - No matching anchor is found and marshal does not have block `processed + 1`.
async fn reconcile_anchor<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    db_targets: SyncTargets<A, E>,
    genesis: &A::Block,
) -> AnchorResolution<SyncTargets<A, E>, BlockDigest<A, E>>
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
    let genesis_digest = genesis.digest();

    let mut search_height = processed_height;
    loop {
        let (anchor_targets, anchor_digest) = if search_height.is_zero() {
            (A::sync_targets(genesis), genesis_digest)
        } else {
            let Some(block) = marshal
                .get_block(Identifier::Height(search_height))
                .await
                .map(V::into_inner)
            else {
                if search_height == processed_height {
                    panic!(
                        "state sync bootstrap missing processed block at height {}",
                        processed_height.get()
                    );
                }

                let repair_height = processed_height.next();
                let repair_block = marshal
                    .get_block(Identifier::Height(repair_height))
                    .await
                    .map(V::into_inner)
                    .unwrap_or_else(|| panic!(
                        "database state does not match marshal processed block at height {}; no matching block found before height {}; expected block at height {} for one-block repair",
                        processed_height.get(),
                        search_height.get(),
                        repair_height.get(),
                    ));

                return AnchorResolution::RepairToNext {
                    anchor: Anchor {
                        height: repair_height,
                        digest: repair_block.digest(),
                    },
                    targets: A::sync_targets(&repair_block),
                };
            };

            (A::sync_targets(&block), block.digest())
        };

        if anchor_targets == db_targets {
            if search_height != processed_height {
                marshal.set_floor(search_height, false).await;
                marshal
                    .get_processed_height()
                    .await
                    .expect("marshal must respond with processed height");
            }
            return AnchorResolution::Matched(Anchor {
                height: search_height,
                digest: anchor_digest,
            });
        }

        search_height = search_height.next();
    }
}
