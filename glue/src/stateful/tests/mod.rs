//! E2E tests for `stateful`

use crate::simulate::{
    action::{Action, Crash, Schedule},
    engine::EngineDefinition,
    exit::{ExitCondition, ProcessedHeightAtLeast},
    plan::PlanBuilder,
    processed::ProcessedHeight,
    property::Property,
};
use commonware_cryptography::{ed25519, PublicKey};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use commonware_runtime::deterministic;
use multi_db_app::MultiDbEngine;
use properties::{
    BlockAgreementAtHeight, CrashDuringStateSyncRecovery, LateJoinerStateSyncHandoff,
    MarshalPrunedBelow, QmdbPruned,
};
use single_db_app::SingleDbEngine;
use std::time::Duration;

mod common;
pub(crate) mod mocks;
mod multi_db_app;
mod properties;
mod single_db_app;

const NUM_VALIDATORS: u32 = 5;

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
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Delay { count: 1, after: 5 })
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
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
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
        .link(Link {
            latency: Duration::from_millis(100),
            jitter: Duration::from_millis(5),
            success_rate: 1.0,
        })
        .crash(Crash::Random {
            frequency: Duration::from_millis(5000),
            downtime: Duration::from_millis(500),
            count: total,
        })
        .exit_condition(ProcessedHeightAtLeast::new(2000))
        .property(BlockAgreementAtHeight::new(2000))
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
    let r1 = PlanBuilder::new(engine.clone())
        .seeds(seeds.clone())
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
    let r2 = PlanBuilder::new(engine)
        .seeds(seeds.clone())
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
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
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
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
    PlanBuilder::new(engine)
        .seeds(0..5)
        .crash(Crash::Delay {
            count: 1,
            after: 30,
        })
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
        .crash(Crash::Delay {
            count: 1,
            after: 80,
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
        .crash(Crash::Delay {
            count: 1,
            after: 20,
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
