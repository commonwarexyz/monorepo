//! E2E tests for `stateful`

use crate::simulate::{
    engine::EngineDefinition,
    exit::{ExitCondition, ProcessedHeightAtLeast},
    fault::{Crash, Fault, Schedule},
    plan::PlanBuilder,
    processed::ProcessedHeight,
    property::Property,
};
use commonware_cryptography::ed25519;
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use multi_db_app::MultiDbEngine;
use properties::{BlockAgreementAtHeight, LateJoinerStateSyncHandoff};
use single_db_app::SingleDbEngine;
use std::time::Duration;

mod common;
mod multi_db_app;
mod properties;
mod single_db_app;

const NUM_VALIDATORS: u32 = 5;

#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    run_finalize(SingleDbEngine::new(NUM_VALIDATORS));
    run_finalize(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    run_determinism(SingleDbEngine::new(NUM_VALIDATORS));
    run_determinism(MultiDbEngine::new(NUM_VALIDATORS));
}

#[test_traced("DEBUG")]
fn crash_and_restart_one_validator() {
    run_crash_restart(SingleDbEngine::new(NUM_VALIDATORS));
    run_crash_restart(MultiDbEngine::new(NUM_VALIDATORS));
}

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

#[test_traced("DEBUG")]
fn random_crashes() {
    run_random_crashes(SingleDbEngine::new(NUM_VALIDATORS));
    run_random_crashes(MultiDbEngine::new(NUM_VALIDATORS));
}

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

fn run_finalize<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .exit_condition(ProcessedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight { height: 100 })
        .run()
        .unwrap();
}

fn run_determinism<D>(engine: D)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey> + Clone,
    D::State: ProcessedHeight + PartialEq,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    for seed in 0..5 {
        let r1 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        let r2 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .exit_condition(ProcessedHeightAtLeast::new(20))
            .property(BlockAgreementAtHeight { height: 20 })
            .run()
            .unwrap();
        assert_eq!(r1.state, r2.state, "seed {seed} produced different state");
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
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_millis(2500), Fault::Crash(validator.clone()))
                .at(Duration::from_millis(5000), Fault::Restart(validator)),
        ))
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
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
        .crash(Crash::Delay { count: 1, after: 5 })
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
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
    PlanBuilder::new(engine)
        .crash(Crash::Delay {
            count: 1,
            after: 400,
        })
        .exit_condition(ProcessedHeightAtLeast::new(500))
        .timeout(Duration::from_secs(300))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight { height: 500 })
        .run()
        .unwrap();
}

fn run_lossy<D>(engine: D, link: Link)
where
    D: EngineDefinition<PublicKey = ed25519::PublicKey>,
    D::State: ProcessedHeight,
    BlockAgreementAtHeight: Property<ed25519::PublicKey, D::State>,
    ProcessedHeightAtLeast: ExitCondition<ed25519::PublicKey, D::State>,
{
    PlanBuilder::new(engine)
        .link(link)
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
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
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_secs(1),
            count: 1,
        })
        .exit_condition(ProcessedHeightAtLeast::new(50))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 50 })
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
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(500),
            count: 3,
        })
        .exit_condition(ProcessedHeightAtLeast::new(20))
        .timeout(Duration::from_secs(300))
        .property(BlockAgreementAtHeight { height: 20 })
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
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(500),
            count: total,
        })
        .exit_condition(ProcessedHeightAtLeast::new(500))
        .timeout(Duration::from_secs(2400))
        .property(BlockAgreementAtHeight { height: 500 })
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
    for seed in 0..3 {
        let r1 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .crash(Crash::Delay {
                count: 1,
                after: 80,
            })
            .exit_condition(ProcessedHeightAtLeast::new(100))
            .timeout(Duration::from_secs(300))
            .property(LateJoinerStateSyncHandoff)
            .property(BlockAgreementAtHeight { height: 100 })
            .run()
            .unwrap();
        let r2 = PlanBuilder::new(engine.clone())
            .seed(seed)
            .crash(Crash::Delay {
                count: 1,
                after: 80,
            })
            .exit_condition(ProcessedHeightAtLeast::new(100))
            .timeout(Duration::from_secs(300))
            .property(LateJoinerStateSyncHandoff)
            .property(BlockAgreementAtHeight { height: 100 })
            .run()
            .unwrap();
        assert_eq!(r1.state, r2.state, "seed {seed} produced different state");
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
        .timeout(Duration::from_secs(300))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight { height: 150 })
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
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .link(link)
        .exit_condition(ProcessedHeightAtLeast::new(150))
        .timeout(Duration::from_secs(2400))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight { height: 150 })
        .run()
        .unwrap();
}
