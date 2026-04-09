//! Trace fuzzer driven by the controlled TLC server.
//!
//! Faithful Rust port of the Go `modelfuzz` PoC under
//! `consensus/quint/modelfuzz/`. The high-level design mirrors
//! `modelfuzz.Fuzzer.Run` + `TLCStateGuider.Check`:
//!
//!   1. Load every JSON trace under
//!      `consensus/fuzz/src/tracing/tests/fixtures/` as the initial
//!      seed population.
//!   2. Maintain a `mutated_traces_queue: VecDeque<TraceData>` seeded
//!      from the initial population.
//!   3. Per iteration: pop a trace from the queue (or fall back to a
//!      random initial seed when the queue is empty), submit it to the
//!      controlled TLC server via [`TlcMapper`] / [`TlcClient`], and
//!      count fingerprints (`response.keys`) that are not in the
//!      cumulative `states_map`.
//!   4. If the trace produced new fingerprints, persist it under
//!      `consensus/fuzz/artifacts/mutated_traces/` and push
//!      `mut_per_trace * new_states` mutated descendants back onto the
//!      queue.
//!   5. Every `reseed_frequency` iterations, reset the queue and re-add
//!      the initial seed population (mirrors `Fuzzer.seed`).
//!
//! There is *no* validity gating: every fingerprint returned by TLC
//! contributes to coverage, exactly like `TLCStateGuider.Check`.
//!
//! Usage:
//!
//!   cargo run -p commonware-consensus-fuzz --bin trace_mutator
//!
//! Environment variables:
//!
//!   * `TLC_URL`               - oracle endpoint, default `http://localhost:2023/execute`
//!   * `MUTATOR_ITERATIONS`    - number of iterations, default `1000`
//!   * `MUTATOR_SEED`          - PRNG seed, default `0`
//!   * `MUTATOR_MUT_PER_TRACE` - mutations per new state, default `3`
//!   * `MUTATOR_RESEED_FREQ`   - iterations between queue reseeds, default `100`
//!   * `MUTATOR_FAULTS`        - override `faults` in persisted traces, default inherits from seed

use commonware_consensus_fuzz::{
    tlc::{TlcClient, TlcMapper, DEFAULT_TLC_URL},
    tracing::{
        data::TraceData,
        sniffer::{TraceEntry, TracedCert, TracedVote},
    },
};
use commonware_cryptography::{sha256::Sha256 as Sha256Hasher, Hasher};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process,
};

const DEFAULT_ITERATIONS: usize = 1000;
const DEFAULT_SEED: u64 = 0;
const DEFAULT_MUT_PER_TRACE: usize = 3;
const DEFAULT_RESEED_FREQ: usize = 100;
const DEFAULT_FAULTS: Option<usize> = None;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn seeds_dir() -> PathBuf {
    manifest_dir().join("src/tracing/tests/fixtures")
}

fn output_dir() -> PathBuf {
    manifest_dir().join("artifacts/mutated_traces")
}

/// Recursively walks `dir` and returns every `*.json` path under it.
fn find_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("warning: cannot read {}: {e}", dir.display());
            return out;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(find_json_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    out
}

/// Loads every JSON seed under `seeds_dir`. Files that fail to parse as
/// [`TraceData`] are skipped (with a warning) so a single bad fixture does
/// not abort the run.
fn load_seeds(dir: &Path) -> Vec<TraceData> {
    let mut seeds = Vec::new();
    for path in find_json_files(dir) {
        let json = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: skipping {}: read error: {e}", path.display());
                continue;
            }
        };
        match serde_json::from_str::<TraceData>(&json) {
            Ok(trace) if !trace.entries.is_empty() => seeds.push(trace),
            Ok(_) => {} // empty trace, nothing to mutate
            Err(e) => eprintln!("warning: skipping {}: parse error: {e}", path.display()),
        }
    }
    seeds
}

/// Mutation kinds applied to a trace.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// Swap two entries at random indices.
    Swap,
    /// Duplicate the entry at a random index, inserting the copy at
    /// another random index.
    Duplicate,
    /// Remove a single entry.
    Delete,
    /// Reverse a random sub-range of `entries`.
    ReverseRange,
    /// Bump (or decrement) the `view` field of a random vote/certificate
    /// by a random delta.
    BumpView,
}

const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::Swap,
    Mutation::Duplicate,
    Mutation::Delete,
    Mutation::ReverseRange,
    Mutation::BumpView,
];

/// Applies a single mutation to `trace.entries`. Returns `true` if the
/// mutation actually changed the trace; `false` if the trace was too small
/// for the chosen mutation (e.g. swap on a 1-element list).
fn apply_mutation(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let len = trace.entries.len();
    if len == 0 {
        return false;
    }
    let mutation = ALL_MUTATIONS[rng.gen_range(0..ALL_MUTATIONS.len())];
    match mutation {
        Mutation::Swap => {
            if len < 2 {
                return false;
            }
            let i = rng.gen_range(0..len);
            let mut j = rng.gen_range(0..len);
            while j == i {
                j = rng.gen_range(0..len);
            }
            trace.entries.swap(i, j);
            true
        }
        Mutation::Duplicate => {
            let src = rng.gen_range(0..len);
            let dst = rng.gen_range(0..=len);
            let copy = trace.entries[src].clone();
            trace.entries.insert(dst, copy);
            true
        }
        Mutation::Delete => {
            let idx = rng.gen_range(0..len);
            trace.entries.remove(idx);
            true
        }
        Mutation::ReverseRange => {
            if len < 2 {
                return false;
            }
            let a = rng.gen_range(0..len);
            let b = rng.gen_range(0..len);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            trace.entries[lo..=hi].reverse();
            true
        }
        Mutation::BumpView => {
            let idx = rng.gen_range(0..len);
            // Random signed delta in [-5, 5] excluding 0 so the view
            // actually changes.
            let mut delta: i64 = rng.gen_range(-5..=5);
            if delta == 0 {
                delta = 1;
            }
            mutate_view(&mut trace.entries[idx], delta)
        }
    }
}

/// Adds `delta` to the `view` of a vote or certificate, saturating at 0.
/// Returns `true` if the entry exposed a `view` field.
fn mutate_view(entry: &mut TraceEntry, delta: i64) -> bool {
    let bump = |view: &mut u64| {
        let new = (*view as i64).saturating_add(delta).max(0) as u64;
        *view = new;
    };
    match entry {
        TraceEntry::Vote { vote, .. } => match vote {
            TracedVote::Notarize { view, .. }
            | TracedVote::Nullify { view, .. }
            | TracedVote::Finalize { view, .. } => {
                bump(view);
                true
            }
        },
        TraceEntry::Certificate { cert, .. } => match cert {
            TracedCert::Notarization { view, .. }
            | TracedCert::Nullification { view, .. }
            | TracedCert::Finalization { view, .. } => {
                bump(view);
                true
            }
        },
    }
}

/// Returns a fresh trace produced by applying a single mutation to a copy
/// of `trace`. Returns `None` if the trace was too degenerate for any
/// mutation (mirrors `Mutator.Mutate -> (trace, ok)`).
fn mutate_once(trace: &TraceData, rng: &mut StdRng) -> Option<TraceData> {
    let mut copy = trace.clone();
    if apply_mutation(&mut copy, rng) {
        Some(copy)
    } else {
        None
    }
}

fn iterations_from_env() -> usize {
    env::var("MUTATOR_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn seed_from_env() -> u64 {
    env::var("MUTATOR_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

fn mut_per_trace_from_env() -> usize {
    env::var("MUTATOR_MUT_PER_TRACE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MUT_PER_TRACE)
}

fn reseed_freq_from_env() -> usize {
    env::var("MUTATOR_RESEED_FREQ")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RESEED_FREQ)
}

fn faults_from_env() -> Option<usize> {
    env::var("MUTATOR_FAULTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(DEFAULT_FAULTS)
}

/// Hex sha1 of the canonical-ish JSON encoding of a trace, used as the
/// on-disk file name. Two traces that serialize to the same bytes
/// collapse to the same file (idempotent).
fn trace_filename(json: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{hex}.json")
}

/// Hex sha256 of arbitrary bytes. Mirrors the `crypto/sha256` digests used
/// by `TLCStateGuider.Check` for trace and state-trace dedup.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256Hasher::hash(bytes);
    let mut hex = String::with_capacity(digest.0.len() * 2);
    for byte in digest.0 {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Pushes the initial seed population onto `queue`, mirroring
/// `Fuzzer.seed()`.
fn seed_queue(queue: &mut VecDeque<TraceData>, seeds: &[TraceData]) {
    queue.clear();
    for trace in seeds {
        queue.push_back(trace.clone());
    }
}

fn main() {
    let url = env::var("TLC_URL").unwrap_or_else(|_| DEFAULT_TLC_URL.to_string());
    let iterations = iterations_from_env();
    let seed = seed_from_env();
    let mut_per_trace = mut_per_trace_from_env();
    let reseed_freq = reseed_freq_from_env().max(1);
    let faults_override = faults_from_env();

    let seeds = load_seeds(&seeds_dir());
    if seeds.is_empty() {
        eprintln!("no usable seed traces under {}", seeds_dir().display());
        process::exit(1);
    }

    let out_dir = output_dir();
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("failed to create {}: {e}", out_dir.display());
        process::exit(1);
    }

    println!(
        "trace_mutator: seeds={} iterations={} seed={} mut_per_trace={} reseed_freq={} faults={} url={}",
        seeds.len(),
        iterations,
        seed,
        mut_per_trace,
        reseed_freq,
        faults_override.map_or("inherit".to_string(), |f| f.to_string()),
        url,
    );

    let client = TlcClient::new(&url);
    let mut rng = StdRng::seed_from_u64(seed);

    // Coverage signal: cumulative set of state fingerprints observed
    // across all `/execute` calls so far. Mirrors `TLCStateGuider.statesMap`.
    let mut states_map: HashSet<i64> = HashSet::new();
    // Trace dedup cache (sha256 of serialized TraceData), mirrors
    // `TLCStateGuider.tracesMap`.
    let mut traces_map: HashSet<String> = HashSet::new();
    // State-trace dedup cache (sha256 of serialized response.keys),
    // mirrors `TLCStateGuider.stateTracesMap`.
    let mut state_traces_map: HashSet<String> = HashSet::new();
    // BFS queue of mutated traces to evaluate next, mirrors
    // `Fuzzer.mutatedTracesQueue`.
    let mut queue: VecDeque<TraceData> = VecDeque::new();
    seed_queue(&mut queue, &seeds);

    let mut kept = 0usize;
    let mut empty_actions = 0usize;
    let mut errors = 0usize;
    let mut uninteresting = 0usize;
    let mut mutated_executions = 0usize;
    let mut random_executions = 0usize;

    for iter in 0..iterations {
        // Periodic reseed: refill the queue from the initial population
        // (mirrors `Fuzzer.Run`'s `if i % reseedFrequency == 0 { seed() }`).
        if iter > 0 && iter % reseed_freq == 0 {
            seed_queue(&mut queue, &seeds);
        }

        // Pop the next mutated trace; fall back to a random initial seed
        // if the queue ran dry between reseed cycles.
        let trace = match queue.pop_front() {
            Some(t) => {
                mutated_executions += 1;
                t
            }
            None => {
                random_executions += 1;
                seeds[rng.gen_range(0..seeds.len())].clone()
            }
        };

        // Track unique traces (cosmetic, like `tracesMap`).
        if let Ok(bytes) = serde_json::to_vec(&trace) {
            traces_map.insert(sha256_hex(&bytes));
        }

        let actions = TlcMapper::map_trace(&trace);
        if actions.is_empty() {
            empty_actions += 1;
            println!(
                "[iter {iter}] tlc=skip-empty (q={}, traces={}, states={})",
                queue.len(),
                traces_map.len(),
                states_map.len(),
            );
            continue;
        }

        let response = match client.execute_full(&actions) {
            Ok(r) => r,
            Err(e) => {
                errors += 1;
                println!(
                    "[iter {iter}] tlc=error (q={}, traces={}, states={}): {e}",
                    queue.len(),
                    traces_map.len(),
                    states_map.len(),
                );
                continue;
            }
        };

        // Mirror `TLCStateGuider.Check`: count every fingerprint that is
        // not yet in the cumulative `states_map` as a "new state". We
        // intentionally do NOT skip `keys[0]` — modelfuzz adds all keys.
        let mut num_new_states = 0usize;
        for key in &response.keys {
            if states_map.insert(*key) {
                num_new_states += 1;
            }
        }

        // Track unique state-traces (cosmetic). Mirrors modelfuzz which
        // hashes the full `[]State{Repr, Key}` list, not just the keys
        // — two traces with identical key vectors but different state
        // reprs must hash differently.
        let pairs: Vec<(&String, i64)> = response
            .states
            .iter()
            .zip(response.keys.iter().copied())
            .collect();
        if let Ok(bytes) = serde_json::to_vec(&pairs) {
            state_traces_map.insert(sha256_hex(&bytes));
        }

        if num_new_states == 0 {
            uninteresting += 1;
            println!(
                "[iter {iter}] tlc=ok-uninteresting (keys={}, q={}, traces={}, states={})",
                response.keys.len(),
                queue.len(),
                traces_map.len(),
                states_map.len(),
            );
            continue;
        }

        // Override faults in persisted traces if requested (e.g. the TLC
        // model validates all-correct behaviour so faults=0 is appropriate).
        let mut trace = trace;
        if let Some(f) = faults_override {
            trace.faults = f;
        }

        // Persist the keeper as pretty JSON named by sha1 of its bytes.
        // (Mirrors `TLCStateGuider.recordTrace`.)
        let json = match serde_json::to_string_pretty(&trace) {
            Ok(s) => s,
            Err(e) => {
                errors += 1;
                println!("[iter {iter}] tlc=ok-serialize-error: {e}");
                continue;
            }
        };
        let path = out_dir.join(trace_filename(&json));
        if let Err(e) = fs::write(&path, &json) {
            errors += 1;
            println!(
                "[iter {iter}] tlc=ok-write-error (path={}): {e}",
                path.display()
            );
            continue;
        }

        // Mirror the `numMutations := numNewStates * MutPerTrace` loop in
        // `Fuzzer.Run`: amplify successful traces by pushing several
        // mutated descendants back onto the queue.
        let num_mutations = num_new_states * mut_per_trace;
        let mut pushed = 0usize;
        for _ in 0..num_mutations {
            if let Some(child) = mutate_once(&trace, &mut rng) {
                queue.push_back(child);
                pushed += 1;
            }
        }

        kept += 1;
        println!(
            "[iter {iter}] tlc=ok-kept {} (keys={}, new={}, pushed={}, q={}, traces={}, states={})",
            path.file_name().unwrap().to_string_lossy(),
            response.keys.len(),
            num_new_states,
            pushed,
            queue.len(),
            traces_map.len(),
            states_map.len(),
        );
    }

    println!(
        "trace_mutator done: kept={kept} uninteresting={uninteresting} \
         empty_actions={empty_actions} errors={errors} \
         mutated_executions={mutated_executions} random_executions={random_executions} \
         traces={} state_traces={} states={}",
        traces_map.len(),
        state_traces_map.len(),
        states_map.len(),
    );
}
