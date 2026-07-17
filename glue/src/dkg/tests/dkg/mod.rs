mod harness;
mod properties;

use crate::simulate::action::{Action, Crash, Schedule};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use harness::{
    DkgEngine, good_link, run_closed_network_receiver, run_plan,
    run_restart_completion_state_is_fresh,
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
            success_rate: 0.75,
        },
        vec![],
        ExpectedOutcome::Success,
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
    );
}

#[test]
fn dkg_e2e_closed_network_receiver_stops_engine() {
    run_closed_network_receiver();
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
    );
}

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
    );
}
