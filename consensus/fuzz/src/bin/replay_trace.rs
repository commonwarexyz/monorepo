//! Replays a JSON trace file through isolated simplex engines and verifies
//! consensus invariants on the resulting observable state.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin replay_trace -- <trace.json> [expected_state.json]

use commonware_consensus_fuzz::{
    replayer::{self, compare},
    tracing::data::TraceData,
};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: replay_trace <trace.json> [expected_state.json]");
        process::exit(1);
    }

    let trace_path = &args[1];
    let json = fs::read_to_string(trace_path).unwrap_or_else(|e| {
        eprintln!("Error reading {trace_path}: {e}");
        process::exit(1);
    });

    let mut trace: TraceData = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("Error parsing {trace_path}: {e}");
        process::exit(1);
    });

    let faults_override: Option<usize> = env::var("REPLAY_FAULTS")
        .ok()
        .and_then(|s| s.parse().ok());
    if let Some(f) = faults_override {
        trace.faults = f;
    }

    println!(
        "Replaying trace: n={}, faults={}, epoch={}, entries={}, required_containers={}",
        trace.n,
        trace.faults,
        trace.epoch,
        trace.entries.len(),
        trace.required_containers
    );

    let states = replayer::replay_and_check(&trace, faults_override);

    println!("Extracted state for {} correct node(s):", states.len());
    for (i, state) in states.iter().enumerate() {
        let node_idx = i + trace.faults;
        println!(
            "  n{}: notarizations={:?}, nullifications={:?}, finalizations={:?}",
            node_idx,
            state.notarizations.keys().collect::<Vec<_>>(),
            state.nullifications.keys().collect::<Vec<_>>(),
            state.finalizations.keys().collect::<Vec<_>>(),
        );
        for (&view, signers) in &state.notarize_signers {
            println!("    notarize_votes[{view}]: {signers:?}");
        }
        for (&view, signers) in &state.nullify_signers {
            println!("    nullify_votes[{view}]: {signers:?}");
        }
        for (&view, signers) in &state.finalize_signers {
            println!("    finalize_votes[{view}]: {signers:?}");
        }
    }

    // If expected state is provided, compare
    if args.len() == 3 {
        let expected_path = &args[2];
        let expected_json = fs::read_to_string(expected_path).unwrap_or_else(|e| {
            eprintln!("Error reading {expected_path}: {e}");
            process::exit(1);
        });

        let expected: compare::ExpectedState =
            serde_json::from_str(&expected_json).unwrap_or_else(|e| {
                eprintln!("Error parsing {expected_path}: {e}");
                process::exit(1);
            });

        let mismatches = compare::compare(&expected, &states, trace.faults);
        if mismatches.is_empty() {
            println!("State comparison: MATCH");
        } else {
            println!("State comparison: {} mismatch(es):", mismatches.len());
            for m in &mismatches {
                println!("  - {m}");
            }
            process::exit(1);
        }
    }
}
