mod harness;
mod properties;

use crate::simulate::action::{Action, Crash, Schedule};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use commonware_utils::probability;
use harness::{
    DkgEngine, good_link, run_activation_failure_completes_empty, run_closed_network_receiver,
    run_plan, run_restart_after_completion, run_restart_after_failure,
    run_restart_completion_state_is_fresh, run_restart_without_share, run_schedule,
    run_share_without_final_block,
};
use properties::ExpectedOutcome;
use std::time::Duration;

#[test]
fn dkg_e2e_completes_for_all_participants() {
    run_plan(
        DkgEngine::new(4),
        good_link(),
        vec![],
        ExpectedOutcome::Success,
        [0],
    );
}

#[test_group("slow")]
#[test_traced("INFO")]
fn dkg_e2e_lossy_network() {
    run_plan(
        DkgEngine::new(4),
        Link {
            latency: Duration::from_millis(60),
            jitter: Duration::from_millis(20),
            success_rate: probability!(0.75),
        },
        vec![],
        ExpectedOutcome::Success,
        [0],
    );
}

#[test_group("slow")]
#[test_traced("INFO")]
fn dkg_e2e_filtered_dkg_channel_fails() {
    run_plan(
        DkgEngine::new(4).with_filtered_dkg(),
        good_link(),
        vec![],
        ExpectedOutcome::Failure,
        [0],
    );
}

/// A participant that never receives consensus traffic completes by fetching
/// the final block's finalization through marshal.
#[test]
fn dkg_e2e_deaf_participant_completes() {
    run_plan(
        DkgEngine::new(4).with_deaf(0),
        good_link(),
        vec![],
        ExpectedOutcome::Success,
        [0],
    );
}

#[test]
fn dkg_e2e_closed_network_receiver_stops_engine() {
    run_closed_network_receiver();
}

#[test]
fn dkg_e2e_activation_failure_completes_empty() {
    run_activation_failure_completes_empty();
}

#[test]
fn dkg_e2e_restart_completion_state_is_fresh() {
    run_restart_completion_state_is_fresh();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn dkg_e2e_scheduled_restart() {
    let engine = DkgEngine::new(4);
    let restarted = engine.participant(0);
    run_plan(
        engine,
        good_link(),
        vec![Crash::Schedule(
            Schedule::new()
                .at(Duration::from_millis(80), Action::Crash(restarted.clone()))
                .at(Duration::from_millis(250), Action::Restart(restarted)),
        )],
        ExpectedOutcome::Success,
        [0],
    );
}

/// Random crashes can restart a participant that already persisted its
/// epoch-zero share, including one that completed. The dedicated restart tests
/// pin that path. This test runs over a seed range to try several crash
/// schedules.
#[test_group("slow")]
#[test_traced("INFO")]
fn dkg_e2e_random_crashes() {
    run_plan(
        DkgEngine::new(4),
        good_link(),
        vec![Crash::Random {
            frequency: Duration::from_millis(250),
            downtime: Duration::from_millis(50),
            count: 1,
        }],
        ExpectedOutcome::Success,
        0..16,
    );
}

/// A participant that falls behind catches up from a participant that
/// restarted after completing, and that restarted participant is the only
/// peer it can reach.
#[test_group("slow")]
#[test_traced("INFO")]
fn dkg_e2e_laggard_catches_up_from_restarted_participant() {
    let engine = DkgEngine::new(4);
    let restarted = engine.participant(0);
    let laggard = engine.participant(3);
    let cut = Link {
        success_rate: probability!(0.0),
        ..good_link()
    };

    // The laggard crashes mid-ceremony and loses its links to every peer but
    // the participant that will restart.
    let mut schedule =
        Schedule::new().at(Duration::from_millis(1500), Action::Crash(laggard.clone()));
    for peer in [engine.participant(1), engine.participant(2)] {
        schedule = schedule
            .at(
                Duration::from_millis(1500),
                Action::UpdateLink {
                    from: peer.clone(),
                    to: laggard.clone(),
                    link: cut.clone(),
                },
            )
            .at(
                Duration::from_millis(1500),
                Action::UpdateLink {
                    from: laggard.clone(),
                    to: peer,
                    link: cut.clone(),
                },
            );
    }

    // The other participants complete. One of them then restarts with its
    // share, and the laggard returns afterward.
    let schedule = schedule
        .at(
            Duration::from_millis(4500),
            Action::Crash(restarted.clone()),
        )
        .at(
            Duration::from_millis(4600),
            Action::Restart(restarted.clone()),
        )
        .at(
            Duration::from_millis(5000),
            Action::Restart(laggard.clone()),
        );
    run_schedule(&engine, schedule);

    // Guard the schedule: the restart held a share and the laggard never did.
    assert_eq!(engine.inits(&restarted), [false, true]);
    assert_eq!(engine.inits(&laggard), [false, false]);
}

/// A participant restarted after persisting its share, before marshal records
/// the final block as processed, reports the finalized artifact without running
/// the ceremony again, and keeps running.
#[test]
fn dkg_e2e_restart_after_completion() {
    run_restart_after_completion();
}

/// A participant without a share restarted after processing the final block
/// reports the finalized artifact and re-activates the peer set.
#[test]
fn dkg_e2e_restart_without_share() {
    run_restart_without_share();
}

/// A restart after a failed ceremony reports the failure.
#[test]
fn dkg_e2e_restart_after_failure() {
    run_restart_after_failure();
}

/// A persisted share without the stored final block means bootstrap storage
/// does not match the secret store.
#[test]
#[should_panic(expected = "bootstrap storage does not match the secret store")]
fn dkg_e2e_share_without_final_block_panics() {
    run_share_without_final_block();
}
