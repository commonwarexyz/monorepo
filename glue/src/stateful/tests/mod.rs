//! E2E tests for `stateful`

use crate::simulate::{
    engine::EngineDefinition,
    fault::{Crash, Fault, Schedule},
    plan::PlanBuilder,
};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use mocks::app::ConsensusEngine;
use std::time::Duration;

pub(crate) mod mocks;

const NUM_VALIDATORS: u32 = 5;
const VOTE_CHANNEL: u64 = 0;
const BROADCAST_CHANNEL: u64 = 4;

fn assert_all_committed_states_agree(databases: &[mocks::app::MockDatabaseSet], context: &str) {
    let states: Vec<_> = databases
        .iter()
        .map(|db| db.try_read().unwrap().committed_state())
        .collect();
    for (i, state) in states.iter().enumerate() {
        assert!(
            !state.is_empty(),
            "validator {i} has empty committed state {context}"
        );
    }
    let first = &states[0];
    for (i, state) in states.iter().enumerate().skip(1) {
        assert_eq!(
            first, state,
            "validator {i} disagrees with validator 0 on committed state {context}"
        );
    }
}

fn stable_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 1.0,
    }
}

fn disconnected_link() -> Link {
    Link {
        latency: Duration::ZERO,
        jitter: Duration::ZERO,
        success_rate: 0.0,
    }
}

fn schedule_certificate_only_observer(
    mut schedule: Schedule<<ConsensusEngine as EngineDefinition>::PublicKey>,
    observer: &<ConsensusEngine as EngineDefinition>::PublicKey,
    participants: &[<ConsensusEngine as EngineDefinition>::PublicKey],
    at: Duration,
    link: Link,
) -> Schedule<<ConsensusEngine as EngineDefinition>::PublicKey> {
    for peer in participants {
        if peer == observer {
            continue;
        }
        for channel in [VOTE_CHANNEL, BROADCAST_CHANNEL] {
            schedule = schedule
                .at(
                    at,
                    Fault::UpdateChannelLink {
                        from: observer.clone(),
                        to: peer.clone(),
                        channel,
                        link: link.clone(),
                    },
                )
                .at(
                    at,
                    Fault::UpdateChannelLink {
                        from: peer.clone(),
                        to: observer.clone(),
                        channel,
                        link: link.clone(),
                    },
                );
        }
    }
    schedule
}

fn schedule_certificate_only_window(
    schedule: Schedule<<ConsensusEngine as EngineDefinition>::PublicKey>,
    observer: &<ConsensusEngine as EngineDefinition>::PublicKey,
    participants: &[<ConsensusEngine as EngineDefinition>::PublicKey],
    start: Duration,
    end: Duration,
) -> Schedule<<ConsensusEngine as EngineDefinition>::PublicKey> {
    let schedule = schedule_certificate_only_observer(
        schedule,
        observer,
        participants,
        start,
        disconnected_link(),
    );
    schedule_certificate_only_observer(schedule, observer, participants, end, stable_link())
}

#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let databases = engine.databases.clone();
    PlanBuilder::new(engine).run().unwrap();

    let mut states: Vec<_> = databases
        .iter()
        .map(|db| db.try_read().unwrap().committed_state())
        .collect();

    // All validators should have committed something
    for (i, state) in states.iter().enumerate() {
        assert!(!state.is_empty(), "validator {i} has empty committed state");
        assert!(
            state.contains_key(b"counter".as_slice()),
            "validator {i} is missing counter key"
        );
    }

    // All validators should agree on committed state
    let first = states.remove(0);
    for (i, state) in states.iter().enumerate() {
        assert_eq!(
            &first,
            state,
            "validator {} disagrees with validator 0 on committed state",
            i + 1
        );
    }
}

#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    for seed in 0..5 {
        let r1 = PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
            .seed(seed)
            .run()
            .unwrap();
        let r2 = PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
            .seed(seed)
            .run()
            .unwrap();
        assert_eq!(r1.state, r2.state, "seed {seed} produced different state");
    }
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn minority_crash() {
    PlanBuilder::new(ConsensusEngine::new(7))
        .crash(Crash::Random {
            frequency: Duration::from_millis(500),
            downtime: Duration::from_millis(200),
            count: 1,
        })
        .required_finalizations(20)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn many_crashes() {
    PlanBuilder::new(ConsensusEngine::new(7))
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(500),
            count: 2,
        })
        .required_finalizations(15)
        .timeout(Duration::from_secs(600))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn heavy_crashes() {
    // Crash 3 of 5 validators every second. This frequently drops below
    // quorum (requires 4/5), but the 200ms restarts allow windows of
    // progress.
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
        .crash(Crash::Random {
            frequency: Duration::from_secs(1),
            downtime: Duration::from_millis(200),
            count: 3,
        })
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn delayed_validator() {
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
        .crash(Crash::Delay { count: 1, after: 5 })
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn slow_and_lossy() {
    PlanBuilder::new(ConsensusEngine::new(NUM_VALIDATORS))
        .link(Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.7,
        })
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn partition_and_heal() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();
    let databases = engine.databases.clone();
    let minority = participants[..2].to_vec();
    let majority = participants[2..].to_vec();
    let link = stable_link();

    // Partition early (200ms), heal after 2s. The majority (3/5) can
    // still finalize during the partition, and the minority catches up
    // after healing.
    PlanBuilder::new(engine)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(200),
                    Fault::Partition {
                        a: minority,
                        b: majority,
                    },
                )
                .at(Duration::from_secs(2), Fault::Heal(link)),
        ))
        .required_finalizations(20)
        .run()
        .unwrap();

    // After healing, all validators must agree on committed state.
    let states: Vec<_> = databases
        .iter()
        .map(|db| db.try_read().unwrap().committed_state())
        .collect();
    let first = &states[0];
    for (i, state) in states.iter().enumerate().skip(1) {
        assert_eq!(
            first, state,
            "validator {i} disagrees with validator 0 after partition heal"
        );
    }
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn rolling_restart() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();

    // Crash and restart each validator sequentially with 500ms gaps.
    let mut schedule = Schedule::new();
    for (i, pk) in participants.iter().enumerate() {
        let crash_at = Duration::from_millis(200 + i as u64 * 500);
        let restart_at = crash_at + Duration::from_millis(200);
        schedule = schedule
            .at(crash_at, Fault::Crash(pk.clone()))
            .at(restart_at, Fault::Restart(pk.clone()));
    }

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(schedule))
        .required_finalizations(20)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn asymmetric_degradation() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();

    let degraded = Link {
        latency: Duration::from_millis(500),
        jitter: Duration::from_millis(200),
        success_rate: 0.5,
    };

    // Degrade links from validator 0 to all others at t=200ms.
    let mut schedule = Schedule::new();
    for pk in &participants[1..] {
        schedule = schedule.at(
            Duration::from_millis(200),
            Fault::UpdateLink {
                from: participants[0].clone(),
                to: pk.clone(),
                link: degraded.clone(),
            },
        );
    }

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(schedule))
        .timeout(Duration::from_secs(120))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn sync_then_participate() {
    // Validator 0 is totally offline while the other 4 finalize.
    // After 3 finalizations, the harness starts validator 0 with sync
    // enabled. Its simplex engine receives finalization certificates
    // from peers. Each finalization flows through the reporter,
    // driving sync target updates via forward_sync_target_update
    // (which fetches the block from marshal, which backfills from
    // peers). The mock sync resolver copies committed state from
    // another validator's database, then signals completion. After
    // sync, validator 0 catches up and joins consensus. All
    // validators must agree on committed state.
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let databases = engine.databases.clone();

    PlanBuilder::new(engine)
        .crash(Crash::Delay { count: 1, after: 5 })
        .required_finalizations(20)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after delayed sync");
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn certificate_only_observer_catches_up() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();
    let observer = participants[0].clone();
    let databases = engine.databases.clone();
    let schedule = schedule_certificate_only_window(
        Schedule::new(),
        &observer,
        &participants,
        Duration::ZERO,
        Duration::from_millis(200),
    );

    PlanBuilder::new(engine)
        .crash(Crash::Delay { count: 1, after: 5 })
        .crash(Crash::Schedule(schedule))
        .required_finalizations(25)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after certificate-only observer catch-up");
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn sync_then_participate_after_large_gap() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let databases = engine.databases.clone();

    PlanBuilder::new(engine)
        .crash(Crash::Delay {
            count: 1,
            after: 12,
        })
        .required_finalizations(30)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after large-gap delayed sync");
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn certificate_only_observer_catches_up_after_large_gap() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();
    let observer = participants[0].clone();
    let databases = engine.databases.clone();
    let schedule = schedule_certificate_only_window(
        Schedule::new(),
        &observer,
        &participants,
        Duration::ZERO,
        Duration::from_millis(300),
    );

    PlanBuilder::new(engine)
        .crash(Crash::Delay {
            count: 1,
            after: 12,
        })
        .crash(Crash::Schedule(schedule))
        .required_finalizations(50)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(
        &databases,
        "after large-gap certificate-only observer catch-up",
    );
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn restarted_validator_replays_finalizations_idempotently() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let databases = engine.databases.clone();
    let validator = engine.participants()[0].clone();

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_secs(1), Fault::Crash(validator.clone()))
                .at(Duration::from_millis(1200), Fault::Restart(validator)),
        ))
        .required_finalizations(20)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after validator restart replay");
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn restarted_certificate_only_observer_replays_cleanly() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();
    let observer = participants[0].clone();
    let databases = engine.databases.clone();

    let schedule = schedule_certificate_only_window(
        Schedule::new(),
        &observer,
        &participants,
        Duration::from_millis(50),
        Duration::from_millis(250),
    )
    .at(Duration::from_millis(120), Fault::Crash(observer.clone()))
    .at(Duration::from_millis(160), Fault::Restart(observer));

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(schedule))
        .required_finalizations(40)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after certificate-only observer restart replay");
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn partitioned_observer_heals_cleanly() {
    let engine = ConsensusEngine::new(NUM_VALIDATORS);
    let participants = engine.participants();
    let observer = participants[0].clone();
    let databases = engine.databases.clone();

    let schedule = schedule_certificate_only_window(
        Schedule::new(),
        &observer,
        &participants,
        Duration::from_millis(50),
        Duration::from_millis(200),
    );

    PlanBuilder::new(engine)
        .crash(Crash::Schedule(schedule))
        .required_finalizations(40)
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();

    assert_all_committed_states_agree(&databases, "after observer-only partition heal");
}
