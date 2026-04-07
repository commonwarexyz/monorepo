//! Trace fuzzer driven by the Quint model checker.
//!
//! High-level loop (mirrors `modelfuzz.Fuzzer.Run`):
//!
//!   1. Load every JSON trace under
//!      `consensus/fuzz/src/tracing/tests/fixtures/` as the initial
//!      seed population.
//!   2. Maintain a `mutated_traces_queue: VecDeque<TraceData>` seeded
//!      from the initial population.
//!   3. Per iteration: pop a trace from the queue (or fall back to a
//!      random initial seed when the queue is empty), encode it into a
//!      `.qnt` test module via [`encoder::encode`] (the same path used
//!      by `trace_to_quint` and the encoder roundtrip tests) and run
//!      `quint test ... --match=traceTest` against it. If quint exits
//!      non-zero, the mutation is rejected.
//!   4. If quint accepted the trace and we have not seen it before,
//!      persist it under `consensus/fuzz/artifacts/mutated_traces/` and
//!      push `mut_per_trace` mutated descendants back onto the queue.
//!   5. Every `reseed_frequency` iterations, reset the queue and re-add
//!      the initial seed population (mirrors `Fuzzer.seed`).
//!
//! Coverage signal: trace novelty (sha256 over the serialized
//! `TraceData`). There is no TLC fingerprint anymore - quint pass/fail
//! is the only validity gate.
//!
//! Usage:
//!
//!   cargo run -p commonware-consensus-fuzz --bin trace_mutator
//!
//! Environment variables:
//!
//!   * `MUTATOR_ITERATIONS`     - number of iterations, default `1000`
//!   * `MUTATOR_SEED`           - PRNG seed, default `0`
//!   * `MUTATOR_MUT_PER_TRACE`  - max mutations applied per child (1..=N
//!                                drawn uniformly), default `2`
//!   * `MUTATOR_RESEED_FREQ`    - iterations between queue reseeds, default `100`
//!   * `MUTATOR_DEBUG`          - print per-iteration log lines (set to `1`)
//!   * `MUTATED_TRACES_SEED_DIR` - seed-trace input directory, default
//!                                `<crate>/src/tracing/tests/fixtures`
//!   * `QUINT_BIN`              - quint executable, default `quint`

use commonware_consensus_fuzz::tracing::{
    data::TraceData,
    encoder::{self, EncoderConfig},
    sniffer::{TraceEntry, TracedCert, TracedVote},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::{self, Command},
};

const DEFAULT_ITERATIONS: usize = 1000;
const DEFAULT_SEED: u64 = 0;
/// Default max number of mutations applied per child (used when
/// `MUTATOR_MUT_PER_TRACE` is unset). The actual count per child is drawn
/// uniformly from `1..=max`.
const DEFAULT_MUT_PER_TRACE: usize = 2;
const DEFAULT_RESEED_FREQ: usize = 100;
/// Number of mutated descendants pushed onto the queue per accepted
/// parent. Mirrors the amplification factor in `Fuzzer.Run`.
const CHILDREN_PER_PARENT: usize = 3;
/// Default seed-trace input directory, relative to the crate manifest.
/// Overridable via `MUTATED_TRACES_SEED_DIR`.
const DEFAULT_MUTATED_TRACES_SEED_DIR: &str = "src/tracing/tests/fixtures";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Directory containing the JSON seed traces. Overridable via the
/// `MUTATED_TRACES_SEED_DIR` env var; falls back to
/// `DEFAULT_MUTATED_TRACES_SEED_DIR` resolved against the crate manifest.
fn seeds_dir() -> PathBuf {
    if let Ok(p) = env::var("MUTATED_TRACES_SEED_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    manifest_dir().join(DEFAULT_MUTATED_TRACES_SEED_DIR)
}

fn output_dir() -> PathBuf {
    manifest_dir().join("artifacts/mutated_traces")
}

/// Directory where transient `.qnt` test files are written for `quint test`.
/// Mirrors `tests/mod.rs::quint_traces_dir`.
fn quint_traces_dir() -> PathBuf {
    let dir = manifest_dir().parent().unwrap().join("quint/traces");
    fs::create_dir_all(&dir).ok();
    dir
}

fn quint_bin() -> String {
    env::var("QUINT_BIN").unwrap_or_else(|_| "quint".to_string())
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

impl Mutation {
    fn name(self) -> &'static str {
        match self {
            Mutation::Swap => "Swap",
            Mutation::Duplicate => "Duplicate",
            Mutation::Delete => "Delete",
            Mutation::ReverseRange => "ReverseRange",
            Mutation::BumpView => "BumpView",
        }
    }
}

const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::Swap,
    Mutation::Duplicate,
    Mutation::Delete,
    Mutation::ReverseRange,
    Mutation::BumpView,
];

/// A trace plus the lineage of mutation kinds applied to derive it from
/// its seed. Lives only in the mutator queue; never serialised into a
/// trace JSON file.
#[derive(Clone)]
struct Candidate {
    trace: TraceData,
    mutations: Vec<&'static str>,
}

impl Candidate {
    fn from_seed(trace: TraceData) -> Self {
        Self {
            trace,
            mutations: Vec::new(),
        }
    }
}

/// Applies a single mutation to `trace.entries`. Returns `Some(kind)` if
/// the mutation actually changed the trace; `None` if the trace was too
/// small for the chosen mutation (e.g. swap on a 1-element list).
fn apply_mutation(trace: &mut TraceData, rng: &mut StdRng) -> Option<Mutation> {
    let len = trace.entries.len();
    if len == 0 {
        return None;
    }
    let mutation = ALL_MUTATIONS[rng.gen_range(0..ALL_MUTATIONS.len())];
    let applied = match mutation {
        Mutation::Swap => {
            if len < 2 {
                return None;
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
                return None;
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
    };
    if applied {
        Some(mutation)
    } else {
        None
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

/// Returns a fresh candidate produced by applying `1..=max_mutations`
/// mutations to a copy of `parent`. The exact count is drawn uniformly
/// from that range. Each successfully applied mutation kind is appended
/// to the child's lineage. Returns `None` if no mutation could be applied
/// (mirrors `Mutator.Mutate -> (trace, ok)`).
fn mutate_once(parent: &Candidate, rng: &mut StdRng, max_mutations: usize) -> Option<Candidate> {
    let cap = max_mutations.max(1);
    let mut child = parent.clone();
    let count = rng.gen_range(1..=cap);
    let mut applied = 0usize;
    for _ in 0..count {
        if let Some(kind) = apply_mutation(&mut child.trace, rng) {
            child.mutations.push(kind.name());
            applied += 1;
        }
    }
    if applied == 0 {
        None
    } else {
        Some(child)
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

/// Returns true when `MUTATOR_DEBUG` is set to a truthy value. Controls
/// whether per-iteration log lines are emitted.
fn debug_from_env() -> bool {
    matches!(
        env::var("MUTATOR_DEBUG").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Hex sha1 of arbitrary bytes.
fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Pushes the initial seed population onto `queue`, mirroring
/// `Fuzzer.seed()`. Each seed enters the queue with an empty mutation
/// lineage.
fn seed_queue(queue: &mut VecDeque<Candidate>, seeds: &[TraceData]) {
    queue.clear();
    for trace in seeds {
        queue.push_back(Candidate::from_seed(trace.clone()));
    }
}

fn encoder_config_for(trace: &TraceData) -> EncoderConfig {
    EncoderConfig {
        n: trace.n,
        faults: trace.faults,
        epoch: trace.epoch,
        max_view: trace.max_view,
        required_containers: trace.required_containers,
    }
}

/// Result of running quint against an encoded trace.
struct QuintResult {
    accepted: bool,
    /// Combined stdout/stderr, only populated on rejection (for logging).
    detail: String,
}

/// Runs `quint test --match=traceTest` against `qnt_path` and returns
/// whether quint accepted the encoded trace.
fn run_quint(qnt_path: &Path) -> QuintResult {
    let output = Command::new(quint_bin())
        .args([
            "test",
            "--main=tests",
            "--backend=rust",
            "--max-samples=10",
            "--match=traceTest",
        ])
        .arg(qnt_path)
        .env("NODE_OPTIONS", "--max-old-space-size=8192")
        .output();

    match output {
        Ok(out) if out.status.success() => QuintResult {
            accepted: true,
            detail: String::new(),
        },
        Ok(out) => {
            let mut detail = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.is_empty() {
                if !detail.is_empty() {
                    detail.push('\n');
                }
                detail.push_str(&stderr);
            }
            QuintResult {
                accepted: false,
                detail,
            }
        }
        Err(e) => QuintResult {
            accepted: false,
            detail: format!("failed to spawn quint: {e}"),
        },
    }
}

/// Encodes `trace` to a temporary `.qnt` file and runs quint against it.
/// The file is removed before returning. Returns `None` if writing the
/// file failed.
fn validate_with_quint(trace: &TraceData, tag: &str) -> Option<QuintResult> {
    let cfg = encoder_config_for(trace);
    let qnt = encoder::encode(trace, &cfg);
    let qnt_path = quint_traces_dir().join(format!("trace_{tag}_mutator.qnt"));
    if let Err(e) = fs::write(&qnt_path, &qnt) {
        eprintln!("warning: failed to write {}: {e}", qnt_path.display());
        return None;
    }
    let result = run_quint(&qnt_path);
    let _ = fs::remove_file(&qnt_path);
    Some(result)
}

fn main() {
    let iterations = iterations_from_env();
    let seed = seed_from_env();
    let mut_per_trace = mut_per_trace_from_env();
    let reseed_freq = reseed_freq_from_env().max(1);
    let debug = debug_from_env();

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
        "trace_mutator: seeds={} iterations={} seed={} mut_per_trace={} children_per_parent={} reseed_freq={} debug={} seed_dir={} quint={}",
        seeds.len(),
        iterations,
        seed,
        mut_per_trace,
        CHILDREN_PER_PARENT,
        reseed_freq,
        debug,
        seeds_dir().display(),
        quint_bin(),
    );

    let mut rng = StdRng::seed_from_u64(seed);

    // Trace dedup cache (sha1 of serialized TraceData), mirrors
    // `TLCStateGuider.tracesMap`. Doubles as the novelty signal that
    // gates "interesting" traces.
    let mut traces_map: HashSet<String> = HashSet::new();
    // BFS queue of mutated trace candidates to evaluate next, mirrors
    // `Fuzzer.mutatedTracesQueue`. Each entry carries the lineage of
    // mutation kinds applied to derive it from its seed.
    let mut queue: VecDeque<Candidate> = VecDeque::new();
    seed_queue(&mut queue, &seeds);

    let mut kept = 0usize;
    let mut rejected = 0usize;
    let mut duplicates = 0usize;
    let mut empty_traces = 0usize;
    let mut mutated_executions = 0usize;
    let mut random_executions = 0usize;

    for iter in 0..iterations {
        // Periodic reseed: refill the queue from the initial population
        // (mirrors `Fuzzer.Run`'s `if i % reseedFrequency == 0 { seed() }`).
        if iter > 0 && iter % reseed_freq == 0 {
            seed_queue(&mut queue, &seeds);
        }

        // Pop the next mutated candidate; fall back to a random initial
        // seed if the queue ran dry between reseed cycles.
        let candidate = match queue.pop_front() {
            Some(c) => {
                mutated_executions += 1;
                c
            }
            None => {
                random_executions += 1;
                Candidate::from_seed(seeds[rng.gen_range(0..seeds.len())].clone())
            }
        };

        if candidate.trace.entries.is_empty() {
            empty_traces += 1;
            continue;
        }

        // Trace dedup: skip traces we have already evaluated.
        let trace_bytes = match serde_json::to_vec(&candidate.trace) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[iter {iter}] serialize error: {e}");
                continue;
            }
        };
        let trace_hash = sha1_hex(&trace_bytes);
        if !traces_map.insert(trace_hash.clone()) {
            duplicates += 1;
            if debug {
                println!(
                    "[iter {iter}] quint=skip-duplicate (q={}, traces={})",
                    queue.len(),
                    traces_map.len(),
                );
            }
            continue;
        }

        // Raw seeds (no mutations applied yet) are trusted inputs: skip
        // quint validation and persistence, but still expand them by
        // pushing mutated descendants onto the queue so the rest of the
        // run has real candidates to evaluate. We never write a seed to
        // the output artifact directory because it is an input, not a
        // mutation.
        if candidate.mutations.is_empty() {
            let mut pushed = 0usize;
            for _ in 0..CHILDREN_PER_PARENT {
                if let Some(child) = mutate_once(&candidate, &mut rng, mut_per_trace) {
                    queue.push_back(child);
                    pushed += 1;
                }
            }
            if debug {
                println!(
                    "[iter {iter}] seed-expanded pushed={pushed} q={} traces={}",
                    queue.len(),
                    traces_map.len(),
                );
            }
            continue;
        }

        let result = match validate_with_quint(&candidate.trace, &trace_hash[..12]) {
            Some(r) => r,
            None => continue,
        };

        if !result.accepted {
            rejected += 1;
            if debug {
                // Trim quint output so the per-iter line stays readable.
                let snippet: String = result
                    .detail
                    .lines()
                    .filter(|l| !l.is_empty())
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | ");
                println!(
                    "[iter {iter}] quint=reject mutations=[{}] (q={}, traces={}): {snippet}",
                    candidate.mutations.join(","),
                    queue.len(),
                    traces_map.len(),
                );
            }
            continue;
        }

        // Persist the keeper as pretty JSON named by sha1 of its bytes.
        // (Mirrors `TLCStateGuider.recordTrace`.)
        let json = match serde_json::to_string_pretty(&candidate.trace) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[iter {iter}] serialize error: {e}");
                continue;
            }
        };
        let path = out_dir.join(format!("{trace_hash}.json"));
        if let Err(e) = fs::write(&path, &json) {
            eprintln!("[iter {iter}] write error ({}): {e}", path.display());
            continue;
        }

        // Amplify successful traces by pushing several mutated descendants
        // back onto the queue (mirrors the `numMutations := numNewStates *
        // MutPerTrace` loop in `Fuzzer.Run`, with `numNewStates` collapsed
        // to 1 since quint only gives us pass/fail).
        let mut pushed = 0usize;
        for _ in 0..CHILDREN_PER_PARENT {
            if let Some(child) = mutate_once(&candidate, &mut rng, mut_per_trace) {
                queue.push_back(child);
                pushed += 1;
            }
        }

        kept += 1;
        if debug {
            println!(
                "[iter {iter}] quint=ok-kept {} mutations=[{}] (pushed={}, q={}, traces={})",
                path.file_name().unwrap().to_string_lossy(),
                candidate.mutations.join(","),
                pushed,
                queue.len(),
                traces_map.len(),
            );
        }
    }

    println!(
        "trace_mutator done: kept={kept} rejected={rejected} duplicates={duplicates} \
         empty_traces={empty_traces} mutated_executions={mutated_executions} \
         random_executions={random_executions} traces={}",
        traces_map.len(),
    );
}
