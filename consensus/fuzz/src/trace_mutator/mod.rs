//! Trace mutator used to mutate traces with feedback from the tlc-controlled server.
//!
//! Faithful Rust port of the Go `modelfuzz` PoC under
//! `consensus/quint/modelfuzz/`. The high-level design mirrors
//! `modelfuzz.Fuzzer.Run` + `TLCStateGuider.Check`:
//!
//! `tlc-controlled` must be installed from <https://github.com/burcuku/tlc-controlled>.
//!
//! It works like as follows:
//!
//!   1. Copy JSON fixtures from `consensus/fuzz/src/tracing/tests/fixtures/`
//!      into the seed folder (`MUTATION_SEEDS_FOLDER`, default
//!      `consensus/fuzz/corpus/tlc_mutator/`) and load all JSON traces
//!      from there as the initial seed population. Optionally, you can run a libfuzzer-based fuzzer
//!      that will add new implementation traces into `MUTATION_SEEDS_FOLDER`.
//!   2. Maintain a `mutated_traces_queue: VecDeque<TraceData>` seeded
//!      from the initial population.
//!   3. Per iteration: pop a trace from the queue (or fall back to a
//!      random initial seed when the queue is empty), submit it to the
//!      tlc-controlled server via [`TlcMapper`] / [`TlcClient`], and
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
//! All mutations reorder or duplicate entries but never modify message
//! contents (sender, receiver, vote/certificate fields). Because only the
//! delivery order changes, `reporter_states` inherited from the parent
//! trace may become stale: a different ordering can change which views
//! reach quorum first and therefore which blocks get notarized/finalized.
//! We keep the inherited `reporter_states` as-is because `replay_trace`
//! regenerates fresh state by replaying entries through actual engines.
//!
//! Environment variables:
//!
//!   * `TLC_URL`               - oracle endpoint, default `http://localhost:2023/execute`
//!   * `MUTATOR_ITERATIONS`    - number of iterations, default `10000`
//!   * `MUTATOR_SEED`          - PRNG seed, default random (stored in `MUTATION_SEEDS_FOLDER/.tlc_mutator_seed`)
//!   * `MUTATOR_MUT_PER_TRACE` - mutations per new state, default random in `[1, 4]`
//!   * `MUTATOR_RESEED_FREQ`   - iterations between queue reseeds, default `100`
//!   * `MUTATOR_FAULTS`        - override `faults` in persisted traces, default inherits from seed
//!   * `MUTATION_SEEDS_FOLDER` - seed corpus directory, default `corpus/tlc_mutator/`

use crate::{
    tlc::{TlcClient, TlcMapper, DEFAULT_TLC_URL},
    tracing::{data::TraceData, sniffer::TraceEntry},
};
use commonware_cryptography::{sha256::Sha256 as Sha256Hasher, Hasher};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process,
};

const DEFAULT_ITERATIONS: usize = 10000;
const DEFAULT_RESEED_FREQ: usize = 100;
const DEFAULT_FAULTS: Option<usize> = None;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures_dir() -> PathBuf {
    manifest_dir().join("src/tracing/tests/fixtures")
}

fn seed_dir() -> PathBuf {
    env::var("MUTATION_SEEDS_FOLDER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir().join("corpus/tlc_mutator"))
}

fn output_dir() -> PathBuf {
    manifest_dir().join("artifacts/mutated_traces")
}

/// Recursively walks `dir` and returns every `*.json` path under it,
/// sorted lexicographically for deterministic ordering across platforms.
pub fn find_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("warning: cannot read {}: {e}", dir.display());
            return out;
        }
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    children.sort();
    for path in children {
        if path.is_dir() {
            // Skip hidden directories (e.g. .seen marker dir)
            if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
                continue;
            }
            out.extend(find_json_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    out
}

/// Loads every JSON seed under `dir`. Files that fail to parse as
/// [`TraceData`] are skipped (with a warning) so a single bad fixture does
/// not abort the run.
pub fn load_seeds(dir: &Path) -> Vec<TraceData> {
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

/// Returns the receiver of a trace entry.
fn entry_receiver(entry: &TraceEntry) -> &str {
    match entry {
        TraceEntry::Vote { receiver, .. } | TraceEntry::Certificate { receiver, .. } => receiver,
    }
}

/// Mutation kinds applied to a trace.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// Swap two nearby entries at random indices.
    Swap,
    /// Duplicate the entry at a random index, inserting the copy after it.
    Duplicate,
    /// Reverse a random sub-range of `entries`.
    ReverseRange,
    /// Swap two entries with different recipients.
    SwapByRecipient,
    /// Shift a consecutive batch for one recipient later in the trace.
    DelayRecipient,
    /// Split a consecutive batch for one recipient by interleaving
    /// another recipient's entry between them.
    BatchSplit,
}

const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::Swap,
    Mutation::Duplicate,
    Mutation::ReverseRange,
    Mutation::SwapByRecipient,
    Mutation::DelayRecipient,
    Mutation::BatchSplit,
];

/// Applies a single mutation to `trace.entries`. Shuffles the mutation
/// list and tries each one until one succeeds. Returns `false` only if
/// no mutation is applicable (e.g. empty trace).
pub fn apply_mutation(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let len = trace.entries.len();
    if len == 0 {
        return false;
    }
    let mut candidates: Vec<Mutation> = ALL_MUTATIONS.to_vec();
    candidates.shuffle(rng);
    for mutation in candidates {
        if try_mutation(trace, rng, mutation) {
            return true;
        }
    }
    false
}

/// Tries to apply a single mutation kind. Returns `true` if the trace
/// was actually changed.
fn try_mutation(trace: &mut TraceData, rng: &mut StdRng, mutation: Mutation) -> bool {
    let len = trace.entries.len();
    match mutation {
        Mutation::Swap => {
            if len < 2 {
                return false;
            }
            let i = rng.gen_range(0..len);
            let diff = rng.gen_range(1..=5);
            let j = if rng.gen_bool(0.5) {
                i.saturating_add(diff).min(len - 1)
            } else {
                i.saturating_sub(diff)
            };
            if i == j {
                return false;
            }
            trace.entries.swap(i, j);
            true
        }
        Mutation::Duplicate => {
            let src = rng.gen_range(0..len);
            let dst = rng.gen_range(src..=len);
            let copy = trace.entries[src].clone();
            trace.entries.insert(dst, copy);
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
        Mutation::SwapByRecipient => {
            // Find two entries with different recipients and swap them.
            if len < 2 {
                return false;
            }
            let i = rng.gen_range(0..len);
            let recv_i = entry_receiver(&trace.entries[i]).to_string();
            // Collect indices with a different recipient.
            let others: Vec<usize> = (0..len)
                .filter(|&k| entry_receiver(&trace.entries[k]) != recv_i)
                .collect();
            if others.is_empty() {
                return false;
            }
            let j = others[rng.gen_range(0..others.len())];
            trace.entries.swap(i, j);
            true
        }
        Mutation::DelayRecipient => {
            // Find a consecutive batch for one recipient and shift it
            // later in the trace.
            if len < 2 {
                return false;
            }
            let start = rng.gen_range(0..len);
            let recv = entry_receiver(&trace.entries[start]).to_string();
            // Find the end of the consecutive batch for this recipient.
            let mut end = start;
            while end + 1 < len && entry_receiver(&trace.entries[end + 1]) == recv {
                end += 1;
            }
            let batch_len = end - start + 1;
            // Nothing after the batch to delay into.
            if end + 1 >= len {
                return false;
            }
            let shift = rng.gen_range(1..=(len - end - 1).min(10));
            // Remove the batch and reinsert it shifted later.
            let batch: Vec<_> = trace.entries.drain(start..=end).collect();
            let insert_at = (start + shift).min(trace.entries.len());
            for (offset, entry) in batch.into_iter().enumerate() {
                trace.entries.insert(insert_at + offset, entry);
            }
            // Only count as changed if we actually moved.
            insert_at != start || batch_len == 0
        }
        Mutation::BatchSplit => {
            // Find a consecutive run of 2+ entries for the same recipient
            // and interleave an entry from another recipient between them.
            if len < 3 {
                return false;
            }
            // Find a consecutive pair for the same recipient.
            let start = rng.gen_range(0..len - 1);
            let recv = entry_receiver(&trace.entries[start]).to_string();
            if entry_receiver(&trace.entries[start + 1]) != recv {
                return false;
            }
            // Find an entry from a different recipient to move between them.
            let others: Vec<usize> = (0..len)
                .filter(|&k| k != start && k != start + 1 && entry_receiver(&trace.entries[k]) != recv)
                .collect();
            if others.is_empty() {
                return false;
            }
            let donor = others[rng.gen_range(0..others.len())];
            let entry = trace.entries.remove(donor);
            // Insert between start and start+1 (adjust for removal shift).
            let insert_at = if donor < start + 1 { start } else { start + 1 };
            trace.entries.insert(insert_at, entry);
            true
        }
    }
}

/// Returns a fresh trace produced by applying a single mutation to a copy
/// of `trace`. Returns `None` if the trace was too degenerate for any
/// mutation (mirrors `Mutator.Mutate -> (trace, ok)`).
pub fn mutate_once(trace: &TraceData, rng: &mut StdRng) -> Option<TraceData> {
    let mut copy = trace.clone();
    if apply_mutation(&mut copy, rng) {
        Some(copy)
    } else {
        None
    }
}

fn resolve_iterations() -> usize {
    env::var("MUTATOR_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// Returns the PRNG seed. If `MUTATOR_SEED` is set, uses that value.
/// Otherwise generates a random seed and persists it to
/// `MUTATION_SEEDS_FOLDER/.tlc_mutator_seed` for reproducibility.
fn resolve_seed(seed_dir: &Path) -> u64 {
    if let Some(seed) = env::var("MUTATOR_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        return seed;
    }
    let seed: u64 = rand::random();
    let seed_file = seed_dir.join(".tlc_mutator_seed");
    fs::create_dir_all(seed_dir).ok();
    if let Err(e) = fs::write(&seed_file, seed.to_string()) {
        eprintln!("warning: failed to write seed to {}: {e}", seed_file.display());
    }
    seed
}

fn resolve_mut_per_trace(rng: &mut StdRng) -> usize {
    env::var("MUTATOR_MUT_PER_TRACE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| rng.gen_range(1..=4))
}

fn resolve_reseed_freq() -> usize {
    env::var("MUTATOR_RESEED_FREQ")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RESEED_FREQ)
}

fn resolve_faults() -> Option<usize> {
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

/// Mirrors JSON fixtures into the seed folder, preserving subdirectory
/// structure. A `.fixture_manifest` file tracks exactly which relative
/// paths were copied so stale copies are removed when fixtures are
/// deleted or renamed upstream, without touching user-added seeds.
fn copy_fixtures_to_seed_dir(seed_dir: &Path) {
    let fixtures = fixtures_dir();
    if !fixtures.is_dir() {
        return;
    }
    fs::create_dir_all(seed_dir).ok();

    let manifest_path = seed_dir.join(".fixture_manifest");

    // Load previous manifest.
    let prev: HashSet<PathBuf> = fs::read_to_string(&manifest_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();

    // Current fixture relative paths.
    let current: HashSet<PathBuf> = find_json_files(&fixtures)
        .iter()
        .filter_map(|p| p.strip_prefix(&fixtures).ok().map(PathBuf::from))
        .collect();

    // Remove stale copies: paths in the old manifest but not in current fixtures.
    for rel in prev.difference(&current) {
        let stale = seed_dir.join(rel);
        fs::remove_file(&stale).ok();
    }

    // Copy current fixtures.
    for rel in &current {
        let src = fixtures.join(rel);
        let dst = seed_dir.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).ok();
        }
        if let Err(e) = fs::copy(&src, &dst) {
            eprintln!(
                "warning: failed to copy {} -> {}: {e}",
                src.display(),
                dst.display()
            );
        }
    }

    // Write updated manifest.
    let mut manifest: Vec<&PathBuf> = current.iter().collect();
    manifest.sort();
    let content = manifest
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join("\n");
    if let Err(e) = fs::write(&manifest_path, content) {
        eprintln!("warning: failed to write fixture manifest: {e}");
    }
}

/// Pushes the initial seed population onto `queue`, mirroring
/// `Fuzzer.seed()`.
fn seed_queue(queue: &mut VecDeque<TraceData>, seeds: &[TraceData]) {
    queue.clear();
    for trace in seeds {
        queue.push_back(trace.clone());
    }
}

/// Main entry point for the trace mutator fuzzing loop.
pub fn run() {
    let url = env::var("TLC_URL").unwrap_or_else(|_| DEFAULT_TLC_URL.to_string());
    let iterations = resolve_iterations();
    let reseed_freq = resolve_reseed_freq().max(1);
    let faults_override = resolve_faults();

    let seed_dir = seed_dir();
    let seed = resolve_seed(&seed_dir);
    copy_fixtures_to_seed_dir(&seed_dir);

    let mut seeds = load_seeds(&seed_dir);
    if seeds.is_empty() {
        eprintln!("no usable seed traces under {}", seed_dir.display());
        process::exit(1);
    }

    let out_dir = output_dir();
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("failed to create {}: {e}", out_dir.display());
        process::exit(1);
    }

    let client = TlcClient::new(&url);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut_per_trace = resolve_mut_per_trace(&mut rng);

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
        // Periodic reseed: reload from disk (picks up new traces added by
        // mbf_live_trace_gen) and refill the queue.
        if iter > 0 && iter % reseed_freq == 0 {
            seeds = load_seeds(&seed_dir);
            println!(
                "[iter {iter}] reseed: loaded {} seeds from {}",
                seeds.len(),
                seed_dir.display(),
            );
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
                eprintln!(
                    "tlc oracle error at iter {iter}: {e}",
                );
                process::exit(1);
            }
        };

        // Mirror `TLCStateGuider.Check`: count every fingerprint that is
        // not yet in the cumulative `states_map` as a "new state". We
        // intentionally do NOT skip `keys[0]` -- modelfuzz adds all keys.
        let mut num_new_states = 0usize;
        for key in &response.keys {
            if states_map.insert(*key) {
                num_new_states += 1;
            }
        }

        // Track unique state-traces (cosmetic). Mirrors modelfuzz which
        // hashes the full `[]State{Repr, Key}` list, not just the keys
        // -- two traces with identical key vectors but different state
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
