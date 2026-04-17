//! Populates a canonical seed directory with freshly-recorded honest
//! traces for the canonical MBF pipeline.
//!
//! Each generated seed is produced by
//! [`commonware_consensus::simplex::replay::record_honest`], which runs
//! a 4-node honest simplex cluster on the simulated p2p network with
//! the canonical recorder wrappers attached. The resulting `Trace` is
//! written to disk as canonical JSON (hex-wrapped signed payloads,
//! `Participant` indices, no `val_bN` aliases).
//!
//! Variance across seeds comes from varying [`RecordConfig::namespace`]
//! — the ed25519 fixture is derived from the namespace, so each
//! distinct namespace yields distinct keys and therefore a distinct
//! leader schedule + signed-vote payloads. All other parameters
//! (`n`, `faults`, `required_containers`, `epoch`, `timing`) are shared
//! across generated seeds unless overridden via env.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin generate_canonical_seeds -- \
//!       <output_dir> [count]
//!
//! Defaults:
//!   * `count` = `SEED_COUNT` env var, or 10 if unset.
//!   * `n` = `SEED_N` env var, or 4.
//!   * `faults` = `SEED_FAULTS` env var, or 0.
//!   * `required_containers` = `SEED_CONTAINERS` env var, or 3.
//!   * `base_namespace` = `SEED_NAMESPACE` env var, or `"consensus_fuzz"`.
//!
//! The per-seed namespace is `"<base>_<i>"` so each seed has distinct keys.
//!
//! The binary is idempotent: it uses `fs::rename` atomic writes, and
//! skips files that already exist (by hash filename) so rerunning is
//! cheap.

use commonware_consensus::simplex::replay::{
    record_honest,
    trace::{Timing, Trace},
    RecordConfig,
};
use sha1::{Digest as _, Sha1};
use std::{env, fs, path::PathBuf, process};

fn usage() -> ! {
    eprintln!(
        "Usage: generate_canonical_seeds <output_dir> [count]\n\
         Env: SEED_COUNT, SEED_N, SEED_FAULTS, SEED_CONTAINERS, SEED_NAMESPACE"
    );
    process::exit(1)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        usage();
    }
    let out_dir = PathBuf::from(&args[1]);
    let count: usize = args
        .get(2)
        .map(|s| s.parse::<usize>().unwrap_or_else(|_| usage()))
        .or_else(|| env::var("SEED_COUNT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(10);

    let n: u32 = env::var("SEED_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let faults: u32 = env::var("SEED_FAULTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Default to 3 finalizations — with 2, the run sometimes stops
    // mid-flight with a leader's self-vote observed but not yet
    // propagated, which would not round-trip through replay cleanly.
    // Three finalizations reliably gives every node a settled final
    // state.
    let required_containers: u64 = env::var("SEED_CONTAINERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let base_namespace: String = env::var("SEED_NAMESPACE")
        .unwrap_or_else(|_| "consensus_fuzz".to_string());

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("failed to create {}: {e}", out_dir.display());
        process::exit(1);
    }

    eprintln!(
        "generate_canonical_seeds: out={} count={} n={} faults={} containers={} base_namespace={:?}",
        out_dir.display(),
        count,
        n,
        faults,
        required_containers,
        base_namespace
    );

    let mut written = 0usize;
    let mut skipped = 0usize;
    for i in 0..count {
        let namespace = format!("{base_namespace}_{i}").into_bytes();
        let cfg = RecordConfig {
            n,
            required_containers,
            namespace,
            epoch: 0,
            timing: Timing::default(),
        };
        let trace = record_honest(cfg);
        // `record_honest` is the honest pipeline — all nodes are correct.
        // Override `faults` if caller asked for a >0 value (seed will
        // still have all-correct events, but the `faults` field is
        // consistent with downstream filters that partition on it).
        let trace = override_faults(trace, faults);

        let json = match trace.to_json() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  seed {i}: encode error: {e}");
                continue;
            }
        };
        let name = trace_filename(&json);
        let path = out_dir.join(&name);
        if path.exists() {
            skipped += 1;
            eprintln!("  seed {i}: already exists {name}");
            continue;
        }
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = fs::write(&tmp, &json).and_then(|_| fs::rename(&tmp, &path)) {
            eprintln!("  seed {i}: write error {}: {e}", path.display());
            continue;
        }
        written += 1;
        eprintln!("  seed {i}: wrote {name} ({} events)", trace.events.len());
    }

    eprintln!(
        "generate_canonical_seeds: done — wrote {written}, skipped {skipped} existing"
    );
}

fn override_faults(mut trace: Trace, faults: u32) -> Trace {
    trace.topology.faults = faults;
    trace
}

fn trace_filename(json: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(json.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("canonical_{hex}.json")
}
