//! Reads a `Trace` JSON file, replays it through
//! [`commonware_consensus::simplex::replay::replay`], and compares the
//! resulting [`Snapshot`] against the trace's embedded
//! `expected` field. Exit code 0 on match, 1 on mismatch.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin replay_trace -- <trace.json>

use commonware_consensus::simplex::replay::{replay, Snapshot, Trace};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: replay_trace <trace.json>");
        process::exit(1);
    }
    let path = &args[1];
    let json = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("read {path}: {e}");
        process::exit(1)
    });
    let trace = Trace::from_json(&json).unwrap_or_else(|e| {
        eprintln!("parse {path}: {e}");
        process::exit(1)
    });

    println!(
        "Replaying trace: n={} faults={} epoch={} events={}",
        trace.topology.n,
        trace.topology.faults,
        trace.topology.epoch,
        trace.events.len(),
    );

    let expected = trace.expected.clone();
    let actual = replay(&trace);

    if actual == expected {
        println!("State comparison: MATCH");
        process::exit(0);
    } else {
        print_diff(&expected, &actual);
        process::exit(1);
    }
}

fn print_diff(expected: &Snapshot, actual: &Snapshot) {
    println!("State comparison: MISMATCH");
    for (p, exp) in &expected.nodes {
        let Some(act) = actual.nodes.get(p) else {
            println!("  node {p:?}: missing in actual");
            continue;
        };
        if exp.notarizations != act.notarizations {
            println!(
                "  node {p:?}: notarization views differ (exp={:?}, act={:?})",
                exp.notarizations.keys().collect::<Vec<_>>(),
                act.notarizations.keys().collect::<Vec<_>>()
            );
        }
        if exp.nullifications != act.nullifications {
            println!(
                "  node {p:?}: nullification views differ (exp={:?}, act={:?})",
                exp.nullifications.keys().collect::<Vec<_>>(),
                act.nullifications.keys().collect::<Vec<_>>()
            );
        }
        if exp.finalizations != act.finalizations {
            println!(
                "  node {p:?}: finalization views differ (exp={:?}, act={:?})",
                exp.finalizations.keys().collect::<Vec<_>>(),
                act.finalizations.keys().collect::<Vec<_>>()
            );
        }
        if exp.certified != act.certified {
            println!(
                "  node {p:?}: certified views differ (exp={:?}, act={:?})",
                exp.certified, act.certified
            );
        }
        if exp.last_finalized != act.last_finalized {
            println!(
                "  node {p:?}: last_finalized exp={:?} got={:?}",
                exp.last_finalized, act.last_finalized
            );
        }
        for (kind, e, a) in [
            ("notarize", &exp.notarize_signers, &act.notarize_signers),
            ("nullify", &exp.nullify_signers, &act.nullify_signers),
            ("finalize", &exp.finalize_signers, &act.finalize_signers),
        ] {
            if e != a {
                for view in e.keys().chain(a.keys()).collect::<std::collections::BTreeSet<_>>() {
                    let empty = std::collections::BTreeSet::new();
                    let es = e.get(view).unwrap_or(&empty);
                    let as_ = a.get(view).unwrap_or(&empty);
                    if es != as_ {
                        println!(
                            "  node {p:?} view {view:?} {kind}_signers: exp={:?} got={:?}",
                            es, as_
                        );
                    }
                }
            }
        }
    }
    for p in actual.nodes.keys() {
        if !expected.nodes.contains_key(p) {
            println!("  node {p:?}: unexpected in actual");
        }
    }
}
