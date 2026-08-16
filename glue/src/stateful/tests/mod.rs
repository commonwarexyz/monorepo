//! E2E tests for `stateful`

use self::{
    common::{EPOCH_LENGTH, IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, archive_config},
    multi_db_app::{
        App as MultiApp, Block as MultiBlock, MultiDatabaseSet, MultiDbEngine, QmdbB,
        qmdb_config as multi_qmdb_config,
    },
    single_db_app::{App, Block, Qmdb, SingleDatabaseSet, SingleDbEngine, qmdb_config},
};
use crate::{
    simulate::{
        action::{Action, Crash, Schedule},
        engine::EngineDefinition,
        exit::{ExitCondition, ProcessedHeightAtLeast},
        plan::PlanBuilder,
        processed::ProcessedHeight,
        property::Property,
    },
    stateful::{
        Application, Config as StatefulConfig, Input, Proposed, PruneConfig,
        Stateful as StatefulActor, SyncPlan,
        db::{
            AttachableResolver, DatabaseSet, ManagedDb, Merkleized as _, Shared, SyncEngineConfig,
        },
    },
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Application as _, CertifiableAutomaton as _, Reporter,
    marshal::{
        self,
        ancestry::Ancestry,
        core::Actor as MarshalActor,
        resolver::handler,
        standard::{Deferred, Standard},
    },
    simplex::{
        mocks::scheme as scheme_mocks,
        types::{Activity, Context},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _, PublicKey, Signer as _, certificate::ConstantProvider, ed25519, sha256,
};
use commonware_macros::{select, test_group, test_traced};
use commonware_p2p::simulated::Link;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Spawner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
};
use commonware_storage::{
    Context as StorageContext,
    archive::prunable,
    mmr,
    qmdb::{
        any::unordered::fixed,
        immutable::fixed as immutable_fixed,
        sync::{FeedbackTx, Request, Response, Source as QmdbSource},
    },
};
use commonware_utils::{
    Acknowledgement as _, NZU64, NZUsize,
    acknowledgement::{Exact, ExactWaiter},
    channel::oneshot,
    non_empty_range,
    sync::Mutex,
};
use properties::{
    BlockAgreementAtHeight, CrashDuringStateSyncRecovery, LateJoinerStateSyncHandoff,
    MarshalPrunedBelow, QmdbPruned,
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

mod common;
pub(crate) mod fixtures;
pub(crate) mod mocks;
mod multi_db_app;
mod properties;
mod single_db_app;

const NUM_VALIDATORS: u32 = 5;

fn delay_first<P: PublicKey>(participants: &[P], view: u64) -> Crash<P> {
    Crash::DelayRound {
        participants: vec![participants[0].clone()],
        round: Round::new(Epoch::zero(), View::new(view)),
    }
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    run_finalize(SingleDbEngine::new(NUM_VALIDATORS));
    run_finalize(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit_with_storage_faults() {
    run_finalize_with_storage_faults(SingleDbEngine::new(NUM_VALIDATORS));
    run_finalize_with_storage_faults(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    run_determinism(SingleDbEngine::new(NUM_VALIDATORS));
    run_determinism(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn crash_and_restart_one_validator() {
    run_crash_restart(SingleDbEngine::new(NUM_VALIDATORS));
    run_crash_restart(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn pruning_bounds_finalized_history() {
    run_pruning(SingleDbEngine::new(NUM_VALIDATORS));
    run_pruning(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn delayed_start_one_validator() {
    run_delayed_start(SingleDbEngine::new(NUM_VALIDATORS));
    run_delayed_start(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_hands_off_to_marshal() {
    run_state_sync(SingleDbEngine::new(NUM_VALIDATORS).with_state_sync());
    run_state_sync(MultiDbEngine::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_hands_off_to_marshal_with_storage_faults() {
    run_state_sync_with_storage_faults(SingleDbEngine::new(NUM_VALIDATORS).with_state_sync());
    run_state_sync_with_storage_faults(MultiDbEngine::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_deterministic() {
    run_state_sync_deterministic(SingleDbEngine::new(NUM_VALIDATORS).with_state_sync());
    run_state_sync_deterministic(MultiDbEngine::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_random_crashes() {
    run_state_sync_random_crashes(SingleDbEngine::new(NUM_VALIDATORS).with_state_sync());
    run_state_sync_random_crashes(MultiDbEngine::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_lossy_network() {
    let link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.7,
    };
    run_state_sync_lossy(
        SingleDbEngine::new(NUM_VALIDATORS).with_state_sync(),
        link.clone(),
    );
    run_state_sync_lossy(MultiDbEngine::new(NUM_VALIDATORS).with_state_sync(), link);
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn lossy_network() {
    let link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.7,
    };
    run_lossy(SingleDbEngine::new(NUM_VALIDATORS), link.clone());
    run_lossy(MultiDbEngine::new(NUM_VALIDATORS), link);
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn random_crashes() {
    run_random_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_random_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn many_concurrent_crashes() {
    run_many_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_many_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn full_cluster_outage_and_recovery() {
    run_total_shutdown(SingleDbEngine::new(NUM_VALIDATORS));
    run_total_shutdown(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_crash_during_sync() {
    run_state_sync_crash_during_sync(
        SingleDbEngine::new(NUM_VALIDATORS)
            .with_state_sync()
            .with_slow_state_sync(),
    );
    run_state_sync_crash_during_sync(
        MultiDbEngine::new(NUM_VALIDATORS)
            .with_state_sync()
            .with_slow_state_sync(),
    );
}

#[test_group("slow")]
#[test_traced("DEBUG")]
#[should_panic(expected = "runtime timeout")]
fn state_sync_partitioned_restart_stays_stuck_until_network_heals_single_db() {
    run_state_sync_partitioned_restart_stays_stuck_until_network_heals(
        SingleDbEngine::new(NUM_VALIDATORS)
            .with_state_sync()
            .with_slow_state_sync(),
    );
}

#[test_group("slow")]
#[test_traced("DEBUG")]
#[should_panic(expected = "runtime timeout")]
fn state_sync_partitioned_restart_stays_stuck_until_network_heals_multi_db() {
    run_state_sync_partitioned_restart_stays_stuck_until_network_heals(
        MultiDbEngine::new(NUM_VALIDATORS)
            .with_state_sync()
            .with_slow_state_sync(),
    );
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn rapid_crashes() {
    run_rapid_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_rapid_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn network_partition_and_rejoin() {
    run_network_partition(SingleDbEngine::new(NUM_VALIDATORS));
    run_network_partition(MultiDbEngine::new(NUM_VALIDATORS));
}

fn run_finalize<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    finalize_plan(engine).run().unwrap();
}

fn run_finalize_with_storage_faults<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let participants = engine.participants();
    finalize_plan(engine)
        .crash(Crash::Schedule(default_storage_fault_schedule(
            participants,
        )))
        .timeout(Duration::from_secs(45))
        .run()
        .unwrap();
}

fn finalize_plan<D>(engine: D) -> PlanBuilder<D>
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight::new(100))
}

fn storage_fault_config() -> deterministic::FaultConfig {
    deterministic::FaultConfig::default().sync(0.01)
}

fn default_storage_fault_schedule<P>(restart_order: impl IntoIterator<Item = P>) -> Schedule<P>
where
    P: PublicKey,
{
    storage_fault_schedule(
        restart_order,
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_millis(2500),
    )
}

fn storage_fault_schedule<P>(
    restart_order: impl IntoIterator<Item = P>,
    fault_at: Duration,
    clear_at: Duration,
    restart_at: Duration,
) -> Schedule<P>
where
    P: PublicKey,
{
    let mut schedule = Schedule::new()
        .at(fault_at, Action::SetStorageFault(storage_fault_config()))
        .at(
            clear_at,
            Action::SetStorageFault(deterministic::FaultConfig::default()),
        );

    for (index, participant) in restart_order.into_iter().enumerate() {
        schedule = schedule.at(
            restart_at + Duration::from_millis(250 * index as u64),
            Action::Restart(participant),
        );
    }

    schedule
}

fn run_determinism<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey> + Clone,
    D::State: ProcessedHeight + PartialEq,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let seeds = 0..5;
    let r1 = PlanBuilder::new(engine.clone())
        .seeds(seeds.clone())
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
    let r2 = PlanBuilder::new(engine)
        .seeds(seeds.clone())
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
    for (seed, (left, right)) in seeds.zip(r1.iter().zip(r2.iter())) {
        assert_eq!(
            left.state, right.state,
            "seed {seed} produced different state"
        );
    }
}

fn run_crash_restart<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let validator = engine.participants()[0].clone();
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(2500),
                    Action::Crash(validator.clone()),
                )
                .at(Duration::from_millis(5000), Action::Restart(validator)),
        ))
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

/// Run long enough to cross the prune maintenance interval many times and
/// assert pruning actually discarded durable history through the live actor.
///
/// The engines enable pruning with `max_pending_acks = 1`,
/// `retained_marshal_blocks = 10`, and `retained_qmdb_blocks = 0`, so marshal
/// retains a 12 block window. Running to height 100:
/// - marshal must prune the block at height 1 while still serving height 95, and
/// - each QMDB must advance its oldest retained operation past location 0.
///
/// A QMDB log only ever starts at location 0, so a non-zero oldest retained
/// location can only be produced by the deferred `Step::Prune` path running.
fn run_pruning<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    MarshalPrunedBelow: Property<ed25519::PublicKey, D::State>,
    QmdbPruned: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight::new(100))
        .property(MarshalPrunedBelow::new(1, 95))
        .property(QmdbPruned::new(1))
        .run()
        .unwrap();
}

fn run_delayed_start<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let delay = delay_first(&engine.participants(), 5);
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(delay)
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
}

fn run_state_sync<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    state_sync_plan(engine).run().unwrap();
}

fn run_state_sync_with_storage_faults<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let participants = engine.participants();
    state_sync_plan(engine)
        .crash(Crash::Schedule(default_storage_fault_schedule(
            state_sync_restart_order(&participants),
        )))
        .timeout(Duration::from_secs(90))
        .run()
        .unwrap();
}

fn state_sync_plan<D>(engine: D) -> PlanBuilder<D>
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let delay = delay_first(&engine.participants(), 80);
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(delay)
        .exit_condition(ProcessedHeightAtLeast::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(150))
}

fn state_sync_restart_order<P: PublicKey>(participants: &[P]) -> Vec<P> {
    let Some((late_joiner, active)) = participants.split_first() else {
        return Vec::new();
    };

    let mut restart_order = active.to_vec();
    restart_order.push(late_joiner.clone());
    restart_order
}

fn state_sync_partitioned_restart_schedule<P>(participants: &[P], late_joiner: P) -> Schedule<P>
where
    P: PublicKey,
{
    let dead_link = Link {
        latency: Duration::from_secs(1),
        jitter: Duration::ZERO,
        success_rate: 0.0,
    };

    let mut schedule = Schedule::new();
    for peer in participants {
        if peer == &late_joiner {
            continue;
        }

        schedule = schedule
            .at(
                Duration::from_millis(4500),
                Action::UpdateLink {
                    from: late_joiner.clone(),
                    to: peer.clone(),
                    link: dead_link.clone(),
                },
            )
            .at(
                Duration::from_millis(4500),
                Action::UpdateLink {
                    from: peer.clone(),
                    to: late_joiner.clone(),
                    link: dead_link.clone(),
                },
            );
    }

    schedule
        .at(Duration::from_secs(5), Action::Crash(late_joiner.clone()))
        .at(Duration::from_secs(7), Action::Restart(late_joiner))
}

fn run_lossy<D>(engine: D, link: Link)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .link(link)
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
}

fn run_random_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Random {
            frequency: Duration::from_millis(1500),
            downtime: Duration::from_secs(1),
            count: 1,
        })
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_many_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Random {
            frequency: Duration::from_millis(1500),
            downtime: Duration::from_secs(1),
            count: 3,
        })
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_total_shutdown<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let total = engine.participants().len();

    PlanBuilder::new(engine)
        .seeds(0..5)
        // Slow the links so views take long enough that the run spans many
        // full-cluster outages before reaching the exit height.
        .link(Link {
            latency: Duration::from_millis(100),
            jitter: Duration::from_millis(5),
            success_rate: 1.0,
        })
        .crash(Crash::Random {
            // A full-cluster crash discards all in-flight votes, and a
            // restarted node that replayed its own proposal waits out the
            // full certification_timeout before nullifying. Keep frequency -
            // downtime comfortably above certification_timeout (plus replay
            // and vote exchange) so the cluster can assemble a certificate
            // between outages; otherwise the run livelocks, never completing
            // a view.
            frequency: Duration::from_millis(5000),
            downtime: Duration::from_millis(500),
            count: total,
        })
        .exit_condition(ProcessedHeightAtLeast::new(300))
        .property(BlockAgreementAtHeight::new(300))
        .run()
        .unwrap();
}

fn run_state_sync_deterministic<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey> + Clone,
    D::State: ProcessedHeight + PartialEq,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let seeds = 0..5;
    let delay = delay_first(&engine.participants(), 80);
    let r1 = PlanBuilder::new(engine.clone())
        .seeds(seeds.clone())
        .crash(delay.clone())
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
    let r2 = PlanBuilder::new(engine)
        .seeds(seeds.clone())
        .crash(delay)
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
    for (seed, (left, right)) in seeds.zip(r1.iter().zip(r2.iter())) {
        assert_eq!(
            left.state, right.state,
            "seed {seed} produced different state"
        );
    }
}

fn run_state_sync_random_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let delay = delay_first(&engine.participants(), 80);
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(delay)
        .crash(Crash::Random {
            frequency: Duration::from_secs(3),
            downtime: Duration::from_secs(1),
            count: 1,
        })
        .exit_condition(ProcessedHeightAtLeast::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(150))
        .run()
        .unwrap();
}

fn run_state_sync_lossy<D>(engine: D, link: Link)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let delay = delay_first(&engine.participants(), 30);
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(delay)
        .link(link)
        .exit_condition(ProcessedHeightAtLeast::new(60))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(60))
        .run()
        .unwrap();
}

/// Crash the late joiner mid-sync and restart it without clearing any state-sync
/// partitions. The restarted node should resume state sync from a compatible floor.
fn run_state_sync_crash_during_sync<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    CrashDuringStateSyncRecovery: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let late_joiner = engine.participants()[0].clone();
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::DelayRound {
            participants: vec![late_joiner.clone()],
            round: Round::new(Epoch::zero(), View::new(80)),
        })
        // Crash the late joiner while it is still catching up through startup
        // state sync, then restart it without clearing any partitions.
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_secs(5), Action::Crash(late_joiner.clone()))
                .at(Duration::from_secs(7), Action::Restart(late_joiner)),
        ))
        .exit_condition(ProcessedHeightAtLeast::new(130))
        .property(CrashDuringStateSyncRecovery)
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(130))
        .run()
        .unwrap();
}

/// Partition the late joiner, crash it mid-sync, then restart it into the same
/// partition. Even with restartable state sync, the late joiner still cannot
/// recover until the network partition heals.
fn run_state_sync_partitioned_restart_stays_stuck_until_network_heals<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    LateJoinerStateSyncHandoff: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let participants = engine.participants();
    let late_joiner = participants[0].clone();
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::DelayRound {
            participants: vec![late_joiner.clone()],
            round: Round::new(Epoch::zero(), View::new(20)),
        })
        .crash(Crash::Schedule(state_sync_partitioned_restart_schedule(
            &participants,
            late_joiner,
        )))
        .timeout(Duration::from_secs(20))
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
}

/// Rapid successive crashes with very short downtime, targeting the
/// processor's lazy recovery path being interrupted by cancellation.
fn run_rapid_crashes<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Random {
            frequency: Duration::from_millis(500),
            downtime: Duration::from_millis(100),
            count: 1,
        })
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

/// Temporarily partition one validator from the network, then heal,
/// testing lazy recovery without a full restart.
fn run_network_partition<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    let participants = engine.participants();
    let isolated = participants[0].clone();
    let good_link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 1.0,
    };
    let dead_link = Link {
        latency: Duration::from_secs(1),
        jitter: Duration::ZERO,
        success_rate: 0.0,
    };

    // Build a schedule that kills all links to/from the isolated node at
    // 500ms, then heals all links at 2s.
    let mut schedule = Schedule::new();
    for peer in &participants[1..] {
        schedule = schedule
            .at(
                Duration::from_millis(500),
                Action::UpdateLink {
                    from: isolated.clone(),
                    to: peer.clone(),
                    link: dead_link.clone(),
                },
            )
            .at(
                Duration::from_millis(500),
                Action::UpdateLink {
                    from: peer.clone(),
                    to: isolated.clone(),
                    link: dead_link.clone(),
                },
            );
    }
    schedule = schedule.at(Duration::from_secs(2), Action::Heal(good_link));

    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Schedule(schedule))
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

#[derive(Clone)]
struct NoopQmdbResolver;

type DelayedContext = DelayedSyncContext<deterministic::Context>;

impl QmdbSource for NoopQmdbResolver {
    type Family = mmr::Family;
    type Digest = sha256::Digest;
    type Op = fixed::Operation<mmr::Family, sha256::Digest, sha256::Digest>;
    type Error = Infallible;

    fn serve<'a>(
        &'a self,
        _request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error>,
    > + Send
    + 'a {
        std::future::pending()
    }
}

impl AttachableResolver<Qmdb<deterministic::Context>> for NoopQmdbResolver {
    async fn attach_database(&self, _db: Shared<Qmdb<deterministic::Context>>) {}
}

impl AttachableResolver<Qmdb<DelayedContext>> for NoopQmdbResolver {
    async fn attach_database(&self, _db: Shared<Qmdb<DelayedContext>>) {}
}

#[derive(Clone)]
struct NoopCompactQmdbResolver;

impl QmdbSource for NoopCompactQmdbResolver {
    type Family = mmr::Family;
    type Digest = sha256::Digest;
    type Op = immutable_fixed::Operation<mmr::Family, sha256::Digest, sha256::Digest>;
    type Error = Infallible;

    fn serve<'a>(
        &'a self,
        _request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error>,
    > + Send
    + 'a {
        std::future::pending()
    }
}

impl AttachableResolver<QmdbB<deterministic::Context>> for NoopCompactQmdbResolver {
    async fn attach_database(&self, _db: Shared<QmdbB<deterministic::Context>>) {}
}

#[derive(Clone)]
struct NoopMarshalApplication;

impl Reporter for NoopMarshalApplication {
    type Activity = marshal::Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone)]
struct NoopMultiMarshalApplication;

impl Reporter for NoopMultiMarshalApplication {
    type Activity = marshal::Update<MultiBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone)]
struct ExactTap<R> {
    inner: R,
    dispatched: Arc<Mutex<Vec<Height>>>,
    pending: Arc<Mutex<VecDeque<PendingExact>>>,
}

struct PendingExact {
    height: Height,
    marshal: Exact,
    stateful: ExactWaiter,
}

fn exact_is_pending(waiter: &mut ExactWaiter) -> bool {
    let waker = futures::task::noop_waker();
    let mut context = TaskContext::from_waker(&waker);
    matches!(Pin::new(waiter).poll(&mut context), Poll::Pending)
}

impl<R> Reporter for ExactTap<R>
where
    R: Reporter<Activity = marshal::Update<MultiBlock>>,
{
    type Activity = marshal::Update<MultiBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            marshal::Update::Block(block, marshal) if block.height > Height::zero() => {
                let (stateful, waiter) = Exact::handle();
                self.dispatched.lock().push(block.height);
                self.pending.lock().push_back(PendingExact {
                    height: block.height,
                    marshal,
                    stateful: waiter,
                });
                self.inner.report(marshal::Update::Block(block, stateful))
            }
            activity => self.inner.report(activity),
        }
    }
}

struct ApplicationGate {
    started: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

fn application_gate() -> (ApplicationGate, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (started, started_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    (
        ApplicationGate {
            started,
            release: release_rx,
        },
        started_rx,
        release,
    )
}

#[derive(Clone)]
struct GatedMultiApp {
    inner: MultiApp,
    proposal_gate: Arc<Mutex<Option<ApplicationGate>>>,
    proposal_calls: Arc<Mutex<usize>>,
    verify_gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
    verify_height_gates: Arc<Mutex<BTreeMap<Height, ApplicationGate>>>,
    apply_height_gates: Arc<Mutex<BTreeMap<Height, ApplicationGate>>>,
    finalize_gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
    finalized_hooks: Arc<Mutex<Vec<Height>>>,
    verify_calls: Arc<Mutex<BTreeMap<Height, usize>>>,
    apply_calls: Arc<Mutex<BTreeMap<Height, usize>>>,
}

impl<E: Rng + Spawner + StorageContext> Application<E> for GatedMultiApp {
    type SigningScheme = <MultiApp as Application<E>>::SigningScheme;
    type Context = <MultiApp as Application<E>>::Context;
    type Block = MultiBlock;
    type Databases = MultiDatabaseSet<E>;
    type Provider = ();
    type Input = ();

    async fn genesis(&mut self) -> Self::Block {
        <MultiApp as Application<E>>::genesis(&mut self.inner).await
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        *self.proposal_calls.lock() += 1;
        let gate = self.proposal_gate.lock().take();
        if let Some(mut gate) = gate {
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
        }
        let proposed = <MultiApp as Application<E>>::propose(
            &mut self.inner,
            context,
            ancestry,
            batches,
            input,
        )
        .await?;
        Some(Proposed {
            block: proposed.block,
            merkleized: proposed.merkleized,
        })
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let height = Height::new(context.1.round.view().get());
        *self.verify_calls.lock().entry(height).or_default() += 1;
        let gate = self.verify_height_gates.lock().remove(&height);
        let gate = gate.or_else(|| self.verify_gates.lock().pop_front());
        if let Some(mut gate) = gate {
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
        }
        <MultiApp as Application<E>>::verify(&mut self.inner, context, ancestry, batches).await
    }

    async fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        *self.apply_calls.lock().entry(block.height).or_default() += 1;
        let gate = self.apply_height_gates.lock().remove(&block.height);
        if let Some(mut gate) = gate {
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
        }
        <MultiApp as Application<E>>::apply(&mut self.inner, context, block, batches).await
    }

    async fn finalized(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
        let gate = self.finalize_gates.lock().pop_front();
        if let Some(mut gate) = gate {
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
        }
        let expected = <Self as Application<E>>::sync_targets(block);
        let actual_a = {
            let database = readers.0.read().await;
            ManagedDb::sync_target(&*database)
        };
        let actual_b = {
            let database = readers.1.read().await;
            ManagedDb::sync_target(&*database)
        };
        assert_eq!(
            (actual_a, actual_b),
            expected,
            "a finalized hook must observe the reported block's database state",
        );
        <MultiApp as Application<E>>::finalized(&mut self.inner, context, block, readers).await;
        self.finalized_hooks.lock().push(block.height);
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        <MultiApp as Application<E>>::sync_targets(block)
    }
}

async fn build_chain(context: &deterministic::Context, blocks: u64) -> (Block, Vec<Block>) {
    let initial_target =
        <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::initial_sync_targets();
    let genesis = Block::genesis(initial_target.root, initial_target.range);
    let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let databases = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::init(
        context.child("chain_builder"),
        qmdb_config("certify-chain-builder", page_cache),
    )
    .await;
    let mut batches = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<
        deterministic::Context,
    >>::new_batches(&databases)
    .await;
    let mut parent = genesis.clone();
    let mut chain = Vec::with_capacity(blocks as usize);

    // QMDB descendants retain uncommitted ancestry by weak reference after
    // merkleization, so keep the complete speculative chain alive here.
    let mut speculative = Vec::with_capacity(blocks as usize);

    for height in 1..=blocks {
        let height = Height::new(height);
        let merkleized = App::execute(height, batches).await;
        let bounds = merkleized.bounds();
        let block = Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height.get())),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (parent.context.round.view(), parent.digest()),
            },
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
        };
        speculative.push(merkleized);
        batches = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::fork_batches(
            speculative.last().expect("speculative batch missing"),
        );
        parent = block.clone();
        chain.push(block);
    }

    (genesis, chain)
}

async fn build_multi_chain<E>(context: &E, blocks: u64) -> (MultiBlock, Vec<MultiBlock>)
where
    E: Rng + Spawner + StorageContext,
{
    let (initial_a, initial_b) = <MultiDatabaseSet<E> as DatabaseSet<_>>::initial_sync_targets();
    let genesis = MultiBlock::genesis(
        initial_a.root,
        initial_a.range,
        initial_b.root,
        non_empty_range!(mmr::Location::new(0), initial_b.size),
    );
    let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let databases = <MultiDatabaseSet<E> as DatabaseSet<_>>::init(
        context.child("multi_chain_builder"),
        multi_qmdb_config("certify-multi-chain-builder", page_cache),
    )
    .await;
    let mut batches = <MultiDatabaseSet<E> as DatabaseSet<E>>::new_batches(&databases).await;
    let mut parent = genesis.clone();
    let mut chain = Vec::with_capacity(blocks as usize);
    let mut speculative = Vec::with_capacity(blocks as usize);

    for height in 1..=blocks {
        let height = Height::new(height);
        let (merkleized_a, merkleized_b) = MultiApp::execute(height, batches).await;
        let bounds_a = merkleized_a.bounds();
        let bounds_b = merkleized_b.bounds();
        let block = MultiBlock {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height.get())),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (parent.context.round.view(), parent.digest()),
            },
            parent: parent.digest(),
            height,
            root_a: merkleized_a.root(),
            range_a: non_empty_range!(bounds_a.inactivity_floor, bounds_a.tip.size),
            root_b: merkleized_b.root(),
            range_b: non_empty_range!(bounds_b.inactivity_floor, bounds_b.tip.size),
        };
        speculative.push((merkleized_a, merkleized_b));
        batches = <MultiDatabaseSet<E> as DatabaseSet<_>>::fork_batches(
            speculative.last().expect("speculative batches missing"),
        );
        parent = block.clone();
        chain.push(block);
    }

    (genesis, chain)
}

#[test]
fn out_of_order_certifications_complete_on_qmdb() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (genesis, blocks) = build_chain(&context, 6).await;
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(
            &mut signing_context,
            b"_COMMONWARE_GLUE_QMDB_OUT_OF_ORDER_CERTIFY",
            1,
        );
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                "certify-qmdb-marshal",
                "finalizations",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config("certify-qmdb-marshal", "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal::Start::Genesis(genesis.clone()),
                    partition_prefix: "certify-qmdb-marshal".to_string(),
                    mailbox_size: NZUsize!(8),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;
        let (resolver_receiver, _resolver_handler) =
            handler::init(context.child("marshal_resolver"), NZUsize!(8));
        let marshal_actor = marshal_actor.start_unbuffered(
            NoopMarshalApplication,
            (resolver_receiver, fixtures::IgnoreResolver),
        );

        let plan = SyncPlan::init(&context, "certify-qmdb-stateful".to_string()).await;
        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: App::new(genesis),
                db_config: qmdb_config("certify-qmdb-stateful", page_cache),
                provider: (),
                marshal: (marshal.clone(), floor),
                mailbox_size: NZUsize!(1),
                plan,
                resolvers: NoopQmdbResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
                prune_config: None,
            },
        );
        let stateful_actor = stateful.start();

        for block in &blocks {
            assert!(marshal.verified(block.context.round, block.clone()).await);
        }

        let mut deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox,
            marshal,
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let mut certifications = Vec::with_capacity(blocks.len());
        for index in [5, 1, 4, 0, 3, 2] {
            let block = &blocks[index];
            certifications.push(deferred.certify(block.context.round, block.digest()).await);
        }

        select! {
            results = futures::future::join_all(certifications) => {
                for result in results {
                    assert!(result.expect("certification result missing"));
                }
            },
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("out-of-order QMDB certifications did not all complete");
            },
        }

        stateful_actor.abort();
        marshal_actor.abort();
        let _ = stateful_actor.await;
        let _ = marshal_actor.await;
    });
}

#[test]
fn stable_leader_finalizations_do_not_wait_for_qmdb_sync() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        const BLOCKS: u64 = 32;
        const BLOCK_INTERVAL: Duration = Duration::from_millis(10);

        let (genesis, blocks) = build_chain(&context, BLOCKS).await;
        let leader = blocks[0].context.leader.clone();
        assert!(
            blocks.iter().all(|block| block.context.leader == leader),
            "test chain must model one stable leader",
        );

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(
            &mut signing_context,
            b"_COMMONWARE_GLUE_QMDB_STABLE_LEADER",
            1,
        );
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                "stable-leader-qmdb-marshal",
                "finalizations",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(
                "stable-leader-qmdb-marshal",
                "blocks",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal::Start::Genesis(genesis.clone()),
                    partition_prefix: "stable-leader-qmdb-marshal".to_string(),
                    mailbox_size: NZUsize!(64),
                    view_retention: ViewDelta::new(BLOCKS),
                    prunable_items_per_section: NZU64!(64),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(64),
                    max_pending_acks: NZUsize!(64),
                    strategy: Sequential,
                },
            )
            .await;
        let (resolver_receiver, _resolver_handler) =
            handler::init(context.child("marshal_resolver"), NZUsize!(8));
        let marshal_actor = marshal_actor.start_unbuffered(
            NoopMarshalApplication,
            (resolver_receiver, fixtures::IgnoreResolver),
        );

        let pending = PendingSyncs::default();
        let delayed = DelayedContext {
            inner: context.child("delayed"),
            pending: pending.clone(),
        };
        let plan = drive_pending_syncs(
            &pending,
            SyncPlan::<
                DelayedContext,
                scheme_mocks::Scheme<ed25519::PublicKey>,
                Standard<Block>,
            >::init(&delayed, "stable-leader-qmdb-stateful"),
        )
        .await;
        let mut db_config = qmdb_config("stable-leader-qmdb-stateful", page_cache);
        db_config.journal_config.items_per_blob = NZU64!(1024);
        db_config.merkle_config.items_per_blob = NZU64!(1024);
        let (stateful, mut stateful_mailbox) = StatefulActor::init(
            delayed.child("stateful"),
            StatefulConfig {
                application: App::new(genesis),
                db_config,
                provider: (),
                marshal: (marshal, floor),
                mailbox_size: NZUsize!(64),
                plan,
                resolvers: NoopQmdbResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
                prune_config: None,
            },
        );
        let stateful_actor = stateful.start();
        let databases = drive_pending_syncs(&pending, stateful_mailbox.subscribe_databases()).await;
        drive_pending_syncs(&pending, async {
            while pending.starts() != pending.completions() || !pending.lock().is_empty() {
                context.sleep(Duration::from_millis(1)).await;
            }
        })
        .await;

        // Any durability operation after startup remains blocked. Finalized apply and
        // acknowledgement must still advance because no pruning boundary is due.
        pending.arm();

        let mut waiters = Vec::with_capacity(BLOCKS as usize);
        for block in &blocks {
            let (acknowledgement, waiter) = Exact::handle();
            let _ = stateful_mailbox.report(marshal::Update::Block(
                Arc::new(block.clone()),
                acknowledgement,
            ));
            waiters.push(waiter);
            context.sleep(BLOCK_INTERVAL).await;
        }

        let expected = <App as Application<DelayedContext>>::sync_targets(
            blocks.last().expect("stable-leader chain is non-empty"),
        );
        select! {
            _ = async {
                loop {
                    let committed = <SingleDatabaseSet<DelayedContext> as DatabaseSet<
                        DelayedContext,
                    >>::committed_targets(&databases).await;
                    if committed == expected {
                        break;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }
            } => {},
            _ = context.sleep(Duration::from_millis(500)) => {
                panic!(
                    "stable-leader finalization stalled behind QMDB durability (calls={}, starts={}, entered={}, completions={})",
                    pending.calls(),
                    pending.starts(),
                    pending.entered(),
                    pending.completions(),
                );
            },
        }
        let calls_at_tip = pending.calls();
        assert_eq!(calls_at_tip, 0, "routine finalization started QMDB sync");

        select! {
            results = futures::future::join_all(waiters) => {
                for result in results {
                    result.expect("stable-leader finalization should be applied");
                }
            },
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("stable-leader QMDB apply did not catch up");
            },
        }
        let committed = <SingleDatabaseSet<DelayedContext> as DatabaseSet<DelayedContext>>::committed_targets(
            &databases,
        )
        .await;
        assert_eq!(committed, expected, "stable-leader QMDB target diverged");

        pending.unblock();
        stateful_actor.abort();
        marshal_actor.abort();
        let _ = stateful_actor.await;
        let _ = marshal_actor.await;
    });
}

#[test_traced]
fn ordered_finalizations_complete_on_multi_qmdb() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        const ACK_WINDOW: usize = 8;
        const FINALIZED_PREFIX: usize = ACK_WINDOW * 2 + 3;
        const DESCENDANTS: usize = 1;
        type TestContext = deterministic::Context;
        let (genesis, blocks) =
            build_multi_chain(&context, (FINALIZED_PREFIX + DESCENDANTS) as u64).await;
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(
            &mut signing_context,
            b"_COMMONWARE_GLUE_MULTI_QMDB_OVERLAPPING_FINALIZATION",
            1,
        );
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                "certify-multi-qmdb-marshal",
                "finalizations",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(
                "certify-multi-qmdb-marshal",
                "blocks",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, floor) =
            MarshalActor::<_, Standard<MultiBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal::Start::Genesis(genesis.clone()),
                    partition_prefix: "certify-multi-qmdb-marshal".to_string(),
                    mailbox_size: NZUsize!(64),
                    view_retention: ViewDelta::new(64),
                    prunable_items_per_section: NZU64!(64),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(64),
                    max_pending_acks: NZUsize!(8),
                    strategy: Sequential,
                },
            )
            .await;
        assert_eq!(marshal.max_pending_acks(), ACK_WINDOW);
        let (resolver_receiver, _resolver_handler) =
            handler::init(context.child("marshal_resolver"), NZUsize!(8));

        let verify_gates = Arc::new(Mutex::new(VecDeque::new()));
        let verify_height_gates = Arc::new(Mutex::new(BTreeMap::new()));
        let apply_height_gates = Arc::new(Mutex::new(BTreeMap::new()));
        let proposal_gate = Arc::new(Mutex::new(None));
        let proposal_calls = Arc::new(Mutex::new(0));
        let finalize_gates = Arc::new(Mutex::new(VecDeque::new()));
        let finalized_hooks = Arc::new(Mutex::new(Vec::new()));
        let verify_calls = Arc::new(Mutex::new(BTreeMap::new()));
        let apply_calls = Arc::new(Mutex::new(BTreeMap::new()));
        let application = GatedMultiApp {
            inner: MultiApp::new(genesis),
            proposal_gate: proposal_gate.clone(),
            proposal_calls: proposal_calls.clone(),
            verify_gates: verify_gates.clone(),
            verify_height_gates: verify_height_gates.clone(),
            apply_height_gates: apply_height_gates.clone(),
            finalize_gates: finalize_gates.clone(),
            finalized_hooks: finalized_hooks.clone(),
            verify_calls: verify_calls.clone(),
            apply_calls: apply_calls.clone(),
        };
        let plan = SyncPlan::init(&context, "certify-multi-qmdb-stateful".to_string()).await;
        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config: multi_qmdb_config("certify-multi-qmdb-stateful", page_cache),
                provider: (),
                marshal: (marshal.clone(), floor),
                mailbox_size: NZUsize!(16),
                plan,
                resolvers: (NoopQmdbResolver, NoopCompactQmdbResolver),
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
                prune_config: None,
            },
        );
        let dispatched = Arc::new(Mutex::new(Vec::new()));
        let pending = Arc::new(Mutex::new(VecDeque::new()));
        let marshal_actor = marshal_actor.start_unbuffered(
            ExactTap {
                inner: stateful_mailbox.clone(),
                dispatched: dispatched.clone(),
                pending: pending.clone(),
            },
            (resolver_receiver, fixtures::IgnoreResolver),
        );
        let stateful_actor = stateful.start();
        let databases = stateful_mailbox.subscribe_databases().await;
        while marshal.get_processed_height().await != Some(Height::zero()) {
            context.sleep(Duration::from_millis(1)).await;
        }
        finalized_hooks.lock().clear();

        for block in &blocks {
            assert!(marshal.verified(block.context.round, block.clone()).await);
        }

        let mut deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );

        // Seed the first two pending states through normal independent verification. The
        // transitive-wait regression is covered at the processing boundary, where replay can be
        // gated deterministically without depending on QMDB buffering behavior.
        for block in &blocks[..2] {
            let certification = deferred.certify(block.context.round, block.digest()).await;
            select! {
                result = certification => {
                    assert!(result.expect("prefix certification result missing"));
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("prefix certification did not complete at height {}", block.height.get());
                },
            }
        }

        let descendant = blocks
            .last()
            .expect("multi-QMDB chain has a descendant")
            .clone();
        let (verify_gate, verify_started, verify_release) = application_gate();
        assert!(
            verify_height_gates
                .lock()
                .insert(descendant.height, verify_gate)
                .is_none(),
            "descendant verification gate already installed",
        );
        let replay_root = &blocks[2];
        let (replay_gate, replay_started, mut replay_release) = application_gate();
        assert!(
            apply_height_gates
                .lock()
                .insert(replay_root.height, replay_gate)
                .is_none(),
            "replay-root gate already installed",
        );

        // Reproduce a full optimistic window above the two cached blocks. Three out-of-order
        // requests share the same deep replay, while an independent verification of its root
        // supplies state that makes the original replay owner redundant.
        let mut descendant_certification = deferred
            .certify(descendant.context.round, descendant.digest())
            .await;
        let mut prefix_certifications = Vec::new();
        for index in [FINALIZED_PREFIX - 2, FINALIZED_PREFIX - 1] {
            let block = &blocks[index];
            prefix_certifications.push(deferred.certify(block.context.round, block.digest()).await);
        }
        select! {
            result = replay_started => {
                result.expect("deep replay should start at the first block");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("deep replay did not reach its first block");
            },
        }

        let replay_root_certification = deferred
            .certify(replay_root.context.round, replay_root.digest())
            .await;
        select! {
            result = replay_root_certification => {
                assert!(result.expect("replay-root certification result missing"));
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("independent replay-root verification did not complete");
            },
        }
        select! {
            _ = replay_release.closed() => {},
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("cached replay-root state did not stop its redundant replay");
            },
        }
        select! {
            results = futures::future::join_all(prefix_certifications) => {
                for result in results {
                    assert!(result.expect("out-of-order prefix certification result missing"));
                }
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("out-of-order prefix certifications stalled behind stale replay");
            },
        }
        select! {
            result = verify_started => {
                result.expect("multi-QMDB descendant verification should reach its application gate");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("deep descendant verification did not start after replay");
            },
        }
        assert!(
            futures::poll!(&mut descendant_certification).is_pending(),
            "descendant certification completed before finalization",
        );
        for height in 3..=FINALIZED_PREFIX as u64 {
            assert!(
                apply_calls
                    .lock()
                    .get(&Height::new(height))
                    .copied()
                    .unwrap_or_default()
                    <= 1,
                "a missing ancestor was replayed more than once at height {height}",
            );
        }
        for height in [
            1,
            2,
            3,
            FINALIZED_PREFIX as u64 - 1,
            FINALIZED_PREFIX as u64,
            blocks.len() as u64,
        ] {
            assert_eq!(
                verify_calls.lock().get(&Height::new(height)).copied(),
                Some(1),
                "each independent candidate should be fully verified once",
            );
        }
        let replay_apply_calls = apply_calls.lock().clone();
        let expected_verify_calls = verify_calls.lock().clone();

        verify_release
            .send(())
            .expect("compatible descendant verification should remain active");
        select! {
            certification = &mut descendant_certification => {
                assert!(certification.expect("descendant certification result missing"));
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("descendant certification did not complete before finalization");
            },
        }

        let mut finalization_controls = VecDeque::new();
        for _ in 0..=FINALIZED_PREFIX {
            let (gate, started, release) = application_gate();
            finalize_gates.lock().push_back(gate);
            finalization_controls.push_back((started, release));
        }
        let (mut finalize_started, finalize_release) = finalization_controls
            .pop_front()
            .expect("first finalization gate missing");

        let finalized_tip = &blocks[FINALIZED_PREFIX - 1];
        let mut marshal_reporter = marshal.clone();
        let _ = marshal_reporter.report(Activity::Finalization(fixtures::finalization(
            &fixture,
            finalized_tip.height.get(),
            finalized_tip.digest(),
        )));
        select! {
            started = &mut finalize_started => {
                started.expect("first finalization should reach its hook after apply and flush");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("first finalization did not reach its hook after apply and flush");
            },
        }

        // The real QMDBs have completed apply and flush, but the processing actor still owns the
        // finalized hook. A queued proposal cannot cross that ordered finalization boundary.
        let (gate, proposal_started, proposal_release) = application_gate();
        assert!(
            proposal_gate.lock().replace(gate).is_none(),
            "proposal gate already installed",
        );
        let mut proposer = stateful_mailbox.clone();
        let mut proposal = Box::pin(proposer.propose(
            (
                context.child("proposal_during_finalized_hook"),
                descendant.context.clone(),
            ),
            marshal::ancestry::from_iter([Arc::new(finalized_tip.clone())]),
            (),
        ));
        assert!(
            futures::poll!(&mut proposal).is_pending(),
            "proposal bypassed its application gate",
        );
        let mut proposal_started = Box::pin(proposal_started);
        let mut proposal_release = Some(proposal_release);
        select! {
            started = &mut proposal_started => {
                started.expect("proposal start signal should remain connected");
                panic!("proposal entered the application during the finalized hook");
            },
            _ = context.sleep(Duration::from_millis(10)) => {},
        }
        assert_eq!(
            *proposal_calls.lock(),
            0,
            "active finalized hook must retain the proposal in the actor mailbox",
        );

        let admitted = (1..=ACK_WINDOW as u64).map(Height::new).collect::<Vec<_>>();
        loop {
            let observed = pending
                .lock()
                .iter()
                .map(|pending| pending.height)
                .collect::<Vec<_>>();
            assert!(
                observed.len() <= ACK_WINDOW,
                "marshal exceeded its acknowledgement window: {observed:?}",
            );
            if observed.len() == ACK_WINDOW {
                assert_eq!(observed, admitted, "marshal dispatch order diverged");
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*dispatched.lock(), admitted);
        assert_eq!(marshal.get_processed_height().await, Some(Height::zero()));
        assert_eq!(
            marshal.get_info(Height::new(FINALIZED_PREFIX as u64)).await,
            Some((Height::new(FINALIZED_PREFIX as u64), finalized_tip.digest(),)),
        );
        assert!(
            marshal
                .get_finalization(Height::new(FINALIZED_PREFIX as u64))
                .await
                .is_some()
        );
        assert!(finalized_hooks.lock().is_empty());
        assert_eq!(marshal.get_processed_height().await, Some(Height::zero()));
        {
            let mut pending = pending.lock();
            for acknowledgement in pending.iter_mut() {
                assert!(
                    exact_is_pending(&mut acknowledgement.stateful),
                    "Stateful acknowledged height {} before its finalized hook completed",
                    acknowledgement.height,
                );
            }
        }

        let (mut second_finalize_started, second_finalize_release) = finalization_controls
            .pop_front()
            .expect("second finalization gate missing");
        finalize_release
            .send(())
            .expect("first multi-QMDB finalization should remain active");

        select! {
            _ = async {
                loop {
                    if finalized_hooks.lock().first() == Some(&Height::new(1)) {
                        break;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }
            } => {},
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("first finalized hook did not complete");
            },
        }

        let mut first_acknowledgement = loop {
            if let Some(pending) = pending.lock().pop_front() {
                break pending;
            }
            context.sleep(Duration::from_millis(1)).await;
        };
        assert_eq!(first_acknowledgement.height, Height::new(1));
        select! {
            result = &mut first_acknowledgement.stateful => {
                result.expect("first Stateful acknowledgement was cancelled");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("first Exact acknowledgement did not follow its finalized hook");
            },
        }
        let mut first_acknowledgement = Some((
            first_acknowledgement.height,
            first_acknowledgement.marshal,
        ));

        select! {
            started = &mut second_finalize_started => {
                started.expect("second finalization should reach its hook after apply and flush");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("second finalization did not reach its hook after apply and flush");
            },
        }
        assert_eq!(marshal.get_processed_height().await, Some(Height::zero()));
        second_finalize_release
            .send(())
            .expect("second multi-QMDB finalization should remain active");

        let finalized_heights = (1..=FINALIZED_PREFIX as u64)
            .map(Height::new)
            .collect::<Vec<_>>();
        for (index, &height) in finalized_heights.iter().enumerate() {
            if index > 1 {
                let (mut started, release) = finalization_controls
                    .pop_front()
                    .expect("finalization gate missing");
                select! {
                    result = &mut started => {
                        result.expect("finalization should reach its application gate");
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("finalization did not reach its application gate at height {height}");
                    },
                }
                {
                    let mut pending = pending.lock();
                    assert_eq!(pending.front().map(|pending| pending.height), Some(height));
                    for acknowledgement in pending.iter_mut() {
                        assert!(
                            exact_is_pending(&mut acknowledgement.stateful),
                            "Stateful acknowledged height {} before its finalized hook completed",
                            acknowledgement.height,
                        );
                    }
                }
                release
                    .send(())
                    .expect("finalization should remain active at its application gate");
            }
            loop {
                let hooks = finalized_hooks.lock().clone();
                if hooks.len() > index {
                    assert_eq!(
                        &hooks[..=index],
                        &finalized_heights[..=index],
                        "application hooks must complete FIFO",
                    );
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            let marshal_acknowledgement = if index == 0 {
                let (acknowledgement_height, acknowledgement) = first_acknowledgement
                    .take()
                    .expect("first Exact acknowledgement missing");
                assert_eq!(
                    acknowledgement_height, height,
                    "Exact acknowledgements must drain FIFO",
                );
                acknowledgement
            } else {
                let mut acknowledgement = loop {
                    if let Some(pending) = pending.lock().pop_front() {
                        break pending;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                };
                assert_eq!(
                    acknowledgement.height, height,
                    "Exact acknowledgements must drain FIFO"
                );
                select! {
                    result = &mut acknowledgement.stateful => {
                        result.expect("Stateful acknowledgement was cancelled");
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("Stateful did not acknowledge finalized height {height}");
                    },
                }
                acknowledgement.marshal
            };
            marshal_acknowledgement.acknowledge();

            loop {
                let processed = marshal
                    .get_processed_height()
                    .await
                    .expect("marshal has a processed genesis");
                assert!(
                    processed <= height,
                    "marshal skipped a held Exact acknowledgement: {processed} > {height}",
                );
                if processed == height {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            let expected_dispatched = (ACK_WINDOW + index + 1).min(FINALIZED_PREFIX);
            while dispatched.lock().len() < expected_dispatched {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                dispatched.lock().as_slice(),
                &finalized_heights[..expected_dispatched],
                "marshal did not roll its acknowledgement window forward in order",
            );
            assert!(
                pending.lock().len() <= ACK_WINDOW,
                "marshal exceeded its acknowledgement window while draining",
            );
            if index + 1 == ACK_WINDOW {
                select! {
                    started = &mut proposal_started => {
                        started.expect("queued proposal should reach the application");
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("queued proposal did not start at its FIFO position");
                    },
                }
                proposal_release
                    .take()
                    .expect("proposal release already consumed")
                    .send(())
                    .expect("proposal should remain active at its application gate");
                select! {
                    proposed = &mut proposal => {
                        assert_eq!(
                            proposed.expect("queued proposal should complete"),
                            descendant,
                        );
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("queued proposal did not complete");
                    },
                }
            }
        }
        assert!(proposal_release.is_none());
        assert!(first_acknowledgement.is_none());
        assert!(pending.lock().is_empty());
        assert_eq!(*finalized_hooks.lock(), finalized_heights);

        let _ = marshal_reporter.report(Activity::Finalization(fixtures::finalization(
            &fixture,
            descendant.height.get(),
            descendant.digest(),
        )));
        let (mut descendant_finalize_started, descendant_finalize_release) = finalization_controls
            .pop_front()
            .expect("descendant finalization gate missing");
        select! {
            result = &mut descendant_finalize_started => {
                result.expect("descendant finalization should reach its application gate");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("descendant finalization did not reach its application gate");
            },
        }
        {
            let mut pending = pending.lock();
            assert_eq!(
                pending.front().map(|pending| pending.height),
                Some(descendant.height),
            );
            for acknowledgement in pending.iter_mut() {
                assert!(
                    exact_is_pending(&mut acknowledgement.stateful),
                    "Stateful acknowledged the descendant before its finalized hook completed",
                );
            }
        }
        descendant_finalize_release
            .send(())
            .expect("descendant finalization should remain active at its application gate");
        loop {
            if finalized_hooks.lock().last() == Some(&descendant.height)
                && pending.lock().front().map(|pending| pending.height) == Some(descendant.height)
            {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        let mut acknowledgement = pending
            .lock()
            .pop_front()
            .expect("descendant Exact acknowledgement missing");
        assert_eq!(acknowledgement.height, descendant.height);
        select! {
            result = &mut acknowledgement.stateful => {
                result.expect("descendant Stateful acknowledgement was cancelled");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("Stateful did not acknowledge the finalized descendant");
            },
        }
        acknowledgement.marshal.acknowledge();
        while marshal.get_processed_height().await != Some(descendant.height) {
            context.sleep(Duration::from_millis(1)).await;
        }
        let all_heights = (1..=blocks.len() as u64)
            .map(Height::new)
            .collect::<Vec<_>>();
        assert_eq!(*dispatched.lock(), all_heights);
        assert_eq!(*finalized_hooks.lock(), all_heights);
        assert!(pending.lock().is_empty());
        assert!(finalization_controls.is_empty());
        assert_eq!(
            *apply_calls.lock(),
            replay_apply_calls,
            "finalization must not reconstruct or retry already supplied pending state",
        );
        assert_eq!(
            *verify_calls.lock(),
            expected_verify_calls,
            "finalization must not restart completed or retained verification work",
        );
        assert_eq!(
            *proposal_calls.lock(),
            1,
            "each proposal request should enter the application exactly once",
        );

        let committed = <MultiDatabaseSet<TestContext> as DatabaseSet<TestContext>>::committed_targets(
            &databases,
        )
        .await;
        let expected = <GatedMultiApp as Application<TestContext>>::sync_targets(
            blocks.last().expect("multi-QMDB chain is non-empty"),
        );
        assert_eq!(committed.0, expected.0, "full QMDB target diverged");
        assert_eq!(committed.1, expected.1, "compact QMDB target diverged");

        stateful_actor.abort();
        marshal_actor.abort();
        let _ = stateful_actor.await;
        let _ = marshal_actor.await;
    });
}

#[test]
fn pruning_quiesces_and_retries_verification_on_real_qmdbs() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (genesis, blocks) = build_multi_chain(&context, 5).await;
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(
            &mut signing_context,
            b"_COMMONWARE_GLUE_MULTI_QMDB_PRUNE_OVERLAP",
            1,
        );
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                "prune-overlap-multi-qmdb-marshal",
                "finalizations",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(
                "prune-overlap-multi-qmdb-marshal",
                "blocks",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, floor) =
            MarshalActor::<_, Standard<MultiBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal::Start::Genesis(genesis.clone()),
                    partition_prefix: "prune-overlap-multi-qmdb-marshal".to_string(),
                    mailbox_size: NZUsize!(8),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;
        let (resolver_receiver, _resolver_handler) =
            handler::init(context.child("marshal_resolver"), NZUsize!(8));
        let marshal_actor = marshal_actor.start_unbuffered(
            NoopMultiMarshalApplication,
            (resolver_receiver, fixtures::IgnoreResolver),
        );

        let verify_gates = Arc::new(Mutex::new(VecDeque::new()));
        let finalize_gates = Arc::new(Mutex::new(VecDeque::new()));
        let application = GatedMultiApp {
            inner: MultiApp::new(genesis),
            proposal_gate: Arc::new(Mutex::new(None)),
            proposal_calls: Arc::new(Mutex::new(0)),
            verify_gates: verify_gates.clone(),
            verify_height_gates: Arc::new(Mutex::new(BTreeMap::new())),
            apply_height_gates: Arc::new(Mutex::new(BTreeMap::new())),
            finalize_gates: finalize_gates.clone(),
            finalized_hooks: Arc::new(Mutex::new(Vec::new())),
            verify_calls: Arc::new(Mutex::new(BTreeMap::new())),
            apply_calls: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let plan = SyncPlan::init(&context, "prune-overlap-multi-qmdb-stateful".to_string()).await;
        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config: multi_qmdb_config("prune-overlap-multi-qmdb-stateful", page_cache),
                provider: (),
                marshal: (marshal.clone(), floor),
                mailbox_size: NZUsize!(1),
                plan,
                resolvers: (NoopQmdbResolver, NoopCompactQmdbResolver),
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
                // The first prune runs at block 4 and targets block 3's floor,
                // which crosses the full QMDB's first journal blob.
                prune_config: Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 2,
                    retained_qmdb_blocks: 0,
                }),
            },
        );
        let stateful_actor = stateful.start();
        let databases = stateful_mailbox.subscribe_databases().await;

        for block in &blocks {
            assert!(marshal.verified(block.context.round, block.clone()).await);
        }

        let mut deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox,
            marshal,
            FixedEpocher::new(EPOCH_LENGTH),
        );

        // Keep the first four batches available so block 5 reaches application
        // verification without owning ancestor replay.
        for block in &blocks[..4] {
            let certification = deferred.certify(block.context.round, block.digest()).await;
            assert!(
                certification
                    .await
                    .expect("priming certification result missing"),
            );
        }

        let finalized_tip = &blocks[3];
        let _ = deferred.report(marshal::Update::Tip(
            finalized_tip.context.round,
            finalized_tip.height,
            finalized_tip.digest(),
        ));
        let mut reporter = deferred;
        for block in &blocks[..3] {
            let (acknowledgement, waiter) = Exact::handle();
            let _ = reporter.report(marshal::Update::Block(
                Arc::new(block.clone()),
                acknowledgement,
            ));
            select! {
                result = waiter => result.expect("priming finalization should be durable"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("priming finalization did not become durable");
                },
            }
        }
        let expected_floor = *blocks[2].range_a.start();
        assert!(
            expected_floor > mmr::Location::new(0),
            "the prune target must discard real QMDB history",
        );

        let (first_gate, first_started, mut first_release) = application_gate();
        let (retry_gate, mut retry_started, retry_release) = application_gate();
        verify_gates.lock().extend([first_gate, retry_gate]);
        let (gate, finalize_started, finalize_release) = application_gate();
        finalize_gates.lock().push_back(gate);

        let block = &blocks[4];
        let mut certification = reporter.certify(block.context.round, block.digest()).await;
        first_started
            .await
            .expect("verification should start before pruning");
        assert!(
            futures::poll!(&mut certification).is_pending(),
            "verification completed before pruning",
        );

        let (acknowledgement, finalized) = Exact::handle();
        let _ = reporter.report(marshal::Update::Block(
            Arc::new(blocks[3].clone()),
            acknowledgement,
        ));
        finalize_started
            .await
            .expect("block 4 finalization should reach the application gate");
        assert!(
            !first_release.is_closed(),
            "same-branch finalization should retain verification",
        );

        // Hold the full QMDB reader after finalization applies block 4. Pruning
        // can quiesce verification, but cannot delete history or requeue it
        // until this guard is released.
        let full_database = databases.0.read().await;
        let before_prune = full_database.bounds();
        assert_eq!(
            before_prune.start,
            mmr::Location::new(0),
            "QMDB pruned before the configured retention window filled",
        );
        finalize_release
            .send(())
            .expect("block 4 finalization should remain active");

        select! {
            _ = first_release.closed() => {},
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("pruning did not quiesce the active verification");
            },
        }
        assert_eq!(
            full_database.bounds(),
            before_prune,
            "QMDB history changed while its reader was held",
        );
        assert!(
            futures::poll!(&mut certification).is_pending(),
            "quiesced verification completed before retry",
        );
        assert!(
            futures::poll!(&mut retry_started).is_pending(),
            "verification restarted before physical pruning completed",
        );
        drop(full_database);

        select! {
            result = &mut retry_started => {
                result.expect("verification should restart after pruning");
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("verification did not restart after pruning");
            },
        }

        let after_prune = databases.0.read().await.bounds();
        assert!(
            after_prune.start > before_prune.start,
            "verification restarted before the full QMDB discarded history",
        );
        assert!(
            after_prune.start <= expected_floor,
            "full QMDB pruned past the requested floor",
        );
        assert_eq!(
            after_prune.end, before_prune.end,
            "pruning changed the full QMDB tip",
        );
        retry_release
            .send(())
            .expect("retried verification should remain active");
        select! {
            result = certification => {
                assert!(result.expect("retried certification result missing"));
            },
            _ = context.sleep(Duration::from_secs(2)) => {
                panic!("retried verification did not complete");
            },
        }
        finalized
            .await
            .expect("block 4 finalization should become durable");

        let committed = <MultiDatabaseSet<deterministic::Context> as DatabaseSet<
            deterministic::Context,
        >>::committed_targets(&databases)
        .await;
        let expected =
            <GatedMultiApp as Application<deterministic::Context>>::sync_targets(&blocks[3]);
        assert_eq!(committed.0, expected.0, "full QMDB target diverged");
        assert_eq!(committed.1, expected.1, "compact QMDB target diverged");

        stateful_actor.abort();
        marshal_actor.abort();
        let _ = stateful_actor.await;
        let _ = marshal_actor.await;
    });
}
