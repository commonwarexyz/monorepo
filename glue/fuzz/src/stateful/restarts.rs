//! The restart driver: four correct identities, no byzantine behaviour.
//!
//! Every identity runs one engine of the correct application, the network is
//! whole for the whole run, and the only fault is environmental: correct
//! identities are crashed and restarted on a schedule drawn from the tape. A
//! restart retains the node's storage, so the rebuilt engine reconciles its
//! database set against marshal's processed anchor and comes back with an empty
//! pending map, forcing lazy recovery on its next proposal or verification.
//!
//! Because every node here is correct, the invariants are checked over all four.

use super::{
    NUM_IDENTITIES, RUN_TIMEOUT,
    input::StatefulRestartsFuzzInput,
    invariants::EngineObservations,
    runner::{self, CorrectEngine, Outcome, RunReport},
    stack::round_robin,
};
use commonware_consensus::types::View;
use commonware_macros::select;
use commonware_runtime::{Clock, Runner as _, deterministic};
use commonware_utils::FuzzRng;
use futures::future::join_all;

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-restarts";

/// libFuzzer entry point.
pub fn fuzz_stateful_cert_mock_restarts(input: StatefulRestartsFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_restarts(input));
}

/// Run one restart schedule and return what it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_restarts(input: StatefulRestartsFuzzInput) -> RunReport {
    let entropy = input.raw_bytes.clone();
    let config = deterministic::Config::new().with_rng(FuzzRng::new(entropy.clone()));
    deterministic::Runner::new(config).start(|context| run(context, input, entropy))
}

async fn run(
    mut context: deterministic::Context,
    input: StatefulRestartsFuzzInput,
    entropy: Vec<u8>,
) -> RunReport {
    let cluster = runner::setup(&mut context).await;
    let elector = round_robin(input.term_length);

    let observations: Vec<EngineObservations> = (0..NUM_IDENTITIES as usize)
        .map(|_| EngineObservations::new())
        .collect();
    let mut correct = Vec::with_capacity(observations.len());
    for (index, node) in observations.iter().enumerate() {
        correct.push(
            CorrectEngine::start(&context, &cluster, index, elector.clone(), node.clone()).await,
        );
    }

    // The scheduler runs the events one at a time, so at most one correct
    // identity is ever down.
    let mut restart_rng = FuzzRng::new(entropy);
    let events = runner::restart_schedule(&mut restart_rng, input.restarts, correct.len());

    // Nothing is scripted per view here, so every applied height counts.
    let waiters = runner::waiters(
        &context,
        &correct,
        usize::from(input.required_heights),
        View::zero(),
    );
    let outcome = {
        let run = async {
            for (delay, victim) in events {
                context.sleep(delay).await;
                correct[victim]
                    .restart(&context, &cluster, runner::downtime())
                    .await;
            }
            join_all(waiters).await;
        };
        select! {
            _ = context.sleep(RUN_TIMEOUT) => Outcome::Timeout,
            _ = run => Outcome::Suffix,
        }
    };

    runner::measure(TARGET, outcome, &correct, &observations, &cluster.genesis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::TermLength;
    use commonware_utils::NZU32;

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        required_heights: u8,
        term_length: u32,
        restarts: u8,
        seed: u8,
    ) -> StatefulRestartsFuzzInput {
        StatefulRestartsFuzzInput {
            required_heights,
            term_length: TermLength::new(NZU32!(term_length)),
            restarts,
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input and asserts the checks were not vacuous.
    fn measured(input: StatefulRestartsFuzzInput) -> RunReport {
        let report = run_stateful_restarts(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        assert!(
            report.counts.restarts > 0,
            "restart schedule executed nothing: {report}"
        );
        report
    }

    /// All four identities are correct, so all four are compared.
    #[test]
    fn every_identity_is_checked() {
        assert_eq!(
            measured(input(2, 1, 1, 0)).counts.correct_nodes,
            NUM_IDENTITIES as usize
        );
    }

    #[test]
    fn repeated_restarts_hold_invariants() {
        measured(input(3, 1, 3, 5));
    }

    #[test]
    fn long_terms_hold_invariants() {
        measured(input(2, 4, 2, 9));
    }

    #[test]
    fn deeper_suffix_holds_invariants() {
        measured(input(6, 2, 2, 13));
    }

    /// I6: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let first = run_stateful_restarts(input(3, 2, 2, 21));
        let second = run_stateful_restarts(input(3, 2, 2, 21));
        assert_eq!(first, second, "replaying an input changed what it measured");
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(1, 1, 1, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
