//! E2E tests for `stateful`

use crate::simulate::{
    action::{Action, Crash, Schedule},
    engine::EngineDefinition,
    exit::{ExitCondition, ProcessedHeightAtLeast},
    plan::PlanBuilder,
    processed::ProcessedHeight,
    property::Property,
};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{PublicKey, ed25519};
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

mod certification_tests {
    use super::{
        common::*,
        single_db_app::{App, Block, Qmdb, SingleDatabaseSet, qmdb_config},
    };
    use crate::stateful::{
        Config as StatefulConfig, Stateful as StatefulActor, SyncPlan,
        db::{AttachableResolver, DatabaseSet, Merkleized as _, Shared, SyncEngineConfig},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        CertifiableAutomaton as _, Reporter,
        marshal::{
            self,
            core::Actor as MarshalActor,
            resolver::handler,
            standard::{Deferred, Standard},
        },
        simplex::{mocks::scheme as scheme_mocks, types::Context},
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digestible as _, Signer as _, certificate::ConstantProvider, ed25519, sha256,
    };
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_resolver::{Fetch, Resolver as MarshalResolver, TargetedResolver};
    use commonware_runtime::{
        Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        archive::prunable,
        mmr,
        qmdb::{
            any::unordered::fixed,
            sync::{FeedbackTx, Request, Response, Source as QmdbSource},
        },
    };
    use commonware_utils::{
        Acknowledgement as _, NZU64, NZUsize, non_empty_range, vec::NonEmptyVec,
    };
    use std::{convert::Infallible, future::Future, time::Duration};

    #[derive(Clone)]
    struct NoopQmdbResolver;

    impl QmdbSource for NoopQmdbResolver {
        type Family = mmr::Family;
        type Digest = sha256::Digest;
        type Op = fixed::Operation<mmr::Family, sha256::Digest, sha256::Digest>;
        type Error = Infallible;

        fn serve<'a>(
            &'a self,
            _request: Request<Self::Family>,
        ) -> impl Future<
            Output = Result<
                (Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx),
                Self::Error,
            >,
        > + Send
        + 'a {
            std::future::pending()
        }
    }

    impl AttachableResolver<Qmdb<deterministic::Context>> for NoopQmdbResolver {
        async fn attach_database(&self, _db: Shared<Qmdb<deterministic::Context>>) {}
    }

    #[derive(Clone)]
    struct NoopMarshalResolver;

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

    impl MarshalResolver for NoopMarshalResolver {
        type Key = handler::Key<sha256::Digest>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, _fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for NoopMarshalResolver {
        type PublicKey = ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
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
        let mut batches = databases.new_batches().await;
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
                (resolver_receiver, NoopMarshalResolver),
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
            let _databases = stateful_mailbox.subscribe_databases().await;

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
                    assert_eq!(results.len(), blocks.len());
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
}
