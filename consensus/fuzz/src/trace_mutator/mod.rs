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
//!   5. Every `reseed_frequency` iterations, generate a fresh population
//!      of mutated traces from the base seeds using the current RNG
//!      state and refill the queue (mirrors `Fuzzer.seed`).
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
//!   * `MUTATOR_SEED_POPULATION_SIZE` - traces generated per reseed, default `100`
//!   * `MUTATOR_FAULTS`        - override `faults` in persisted traces, default inherits from seed
//!   * `MUTATION_SEEDS_FOLDER` - seed corpus directory, default `corpus/tlc_mutator/`

use crate::{
    tlc::{TlcClient, TlcMapper, DEFAULT_TLC_URL},
    tracing::{
        data::TraceData,
        sniffer::{TraceEntry, TracedCert, TracedVote},
    },
};
use commonware_cryptography::{sha256::Sha256 as Sha256Hasher, Hasher};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process,
};

const DEFAULT_ITERATIONS: usize = 10000;
const DEFAULT_RESEED_FREQ: usize = 100;
const DEFAULT_SEED_POPULATION_SIZE: usize = 100;
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
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
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

/// Returns the sender of a trace entry.
fn entry_sender(entry: &TraceEntry) -> &str {
    match entry {
        TraceEntry::Vote { sender, .. } | TraceEntry::Certificate { sender, .. } => sender,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EntryChannel {
    Vote,
    Certificate,
}

fn entry_channel(entry: &TraceEntry) -> EntryChannel {
    match entry {
        TraceEntry::Vote { .. } => EntryChannel::Vote,
        TraceEntry::Certificate { .. } => EntryChannel::Certificate,
    }
}

fn vote_identity(vote: &TracedVote) -> String {
    match vote {
        TracedVote::Notarize {
            view,
            parent,
            sig,
            block,
        } => format!("vote:notarize:{view}:{parent}:{sig}:{block}"),
        TracedVote::Nullify { view, sig } => format!("vote:nullify:{view}:{sig}"),
        TracedVote::Finalize {
            view,
            parent,
            sig,
            block,
        } => format!("vote:finalize:{view}:{parent}:{sig}:{block}"),
    }
}

fn cert_identity(cert: &TracedCert) -> String {
    match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => format!(
            "cert:notarization:{view}:{parent}:{block}:{}:{ghost_sender}",
            signers.join(",")
        ),
        TracedCert::Nullification {
            view,
            signers,
            ghost_sender,
        } => format!(
            "cert:nullification:{view}:{}:{ghost_sender}",
            signers.join(",")
        ),
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => format!(
            "cert:finalization:{view}:{parent}:{block}:{}:{ghost_sender}",
            signers.join(",")
        ),
    }
}

fn logical_cert_identity(cert: &TracedCert) -> String {
    match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ..
        } => format!(
            "logical:notarization:{view}:{parent}:{block}:{}",
            signers.join(",")
        ),
        TracedCert::Nullification { view, signers, .. } => {
            format!("logical:nullification:{view}:{}", signers.join(","))
        }
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ..
        } => format!(
            "logical:finalization:{view}:{parent}:{block}:{}",
            signers.join(",")
        ),
    }
}

fn broadcast_identity(entry: &TraceEntry) -> String {
    match entry {
        TraceEntry::Vote { vote, .. } => vote_identity(vote),
        TraceEntry::Certificate { cert, .. } => cert_identity(cert),
    }
}

fn trace_leader(trace: &TraceData, view: u64) -> String {
    format!("n{}", ((trace.epoch + view) as usize) % trace.n)
}

fn indices_form_contiguous_block(indices: &[usize]) -> bool {
    indices
        .windows(2)
        .all(|pair| pair[0].checked_add(1) == Some(pair[1]))
}

fn remove_indices(entries: &mut Vec<TraceEntry>, indices: &[usize]) -> Vec<TraceEntry> {
    let mut removed = Vec::with_capacity(indices.len());
    for &idx in indices.iter().rev() {
        removed.push(entries.remove(idx));
    }
    removed.reverse();
    removed
}

fn insert_entries(entries: &mut Vec<TraceEntry>, insert_at: usize, batch: Vec<TraceEntry>) {
    for (offset, entry) in batch.into_iter().enumerate() {
        entries.insert(insert_at + offset, entry);
    }
}

fn move_indices_later(
    entries: &mut Vec<TraceEntry>,
    indices: &[usize],
    rng: &mut StdRng,
    max_extra_gap: usize,
) -> bool {
    if indices.is_empty() {
        return false;
    }
    let len = entries.len();
    let max_idx = *indices.last().expect("indices not empty");
    let contiguous = indices_form_contiguous_block(indices);
    let min_target = max_idx + 1 + usize::from(contiguous);
    if min_target > len {
        return false;
    }
    let max_target = (min_target + max_extra_gap).min(len);
    let target_old = rng.gen_range(min_target..=max_target);
    let batch = remove_indices(entries, indices);
    let removed_before_target = indices.iter().filter(|&&idx| idx < target_old).count();
    let insert_at = target_old - removed_before_target;
    insert_entries(entries, insert_at, batch);
    true
}

fn move_indices_to_insert_at(
    entries: &mut Vec<TraceEntry>,
    indices: &[usize],
    insert_at: usize,
) -> bool {
    if indices.is_empty() || insert_at > entries.len() {
        return false;
    }
    let batch = remove_indices(entries, indices);
    let removed_before_target = indices.iter().filter(|&&idx| idx < insert_at).count();
    let adjusted_insert_at = insert_at.saturating_sub(removed_before_target);
    insert_entries(entries, adjusted_insert_at, batch);
    true
}

fn pick_ordered_batch(indices: &[usize], rng: &mut StdRng, max_take: usize) -> Vec<usize> {
    let start = rng.gen_range(0..indices.len());
    let remaining = indices.len() - start;
    let take = rng.gen_range(1..=remaining.min(max_take));
    indices[start..start + take].to_vec()
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
    /// Delay a single sender->receiver link while preserving link order.
    DelayLink,
    /// Delay a batch of messages from one sender.
    DelaySender,
    /// Delay part of one sender's broadcast fanout to selected receivers.
    FanoutSkew,
    /// Delay one receiver's vote or certificate channel independently.
    ChannelSkew,
    /// Hold several messages for one receiver and release them in a burst.
    BurstRelease,
    /// Weave messages for two receivers while preserving order within each receiver.
    InterleaveReceivers,
    /// Delay the leader's messages for a chosen view to a subset of receivers.
    TimeoutEdge,
    /// Make a different honest relay deliver the same certificate first.
    RelayPreference,
}

const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::Swap,
    Mutation::Duplicate,
    Mutation::ReverseRange,
    Mutation::SwapByRecipient,
    Mutation::DelayRecipient,
    Mutation::BatchSplit,
    Mutation::DelayLink,
    Mutation::DelaySender,
    Mutation::FanoutSkew,
    Mutation::ChannelSkew,
    Mutation::BurstRelease,
    Mutation::InterleaveReceivers,
    Mutation::TimeoutEdge,
    Mutation::RelayPreference,
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

fn mutate_delay_link(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry((
                entry_sender(entry).to_string(),
                entry_receiver(entry).to_string(),
            ))
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            indices
                .last()
                .is_some_and(|&idx| idx + 1 < trace.entries.len())
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let selected = pick_ordered_batch(group, rng, 4);
    move_indices_later(&mut trace.entries, &selected, rng, 8)
}

fn mutate_delay_sender(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry(entry_sender(entry).to_string())
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            indices
                .last()
                .is_some_and(|&idx| idx + 1 < trace.entries.len())
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let selected = pick_ordered_batch(group, rng, 6);
    move_indices_later(&mut trace.entries, &selected, rng, 10)
}

fn mutate_delay_recipient(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry(entry_receiver(entry).to_string())
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            indices.len() >= 2
                && indices
                    .last()
                    .is_some_and(|&idx| idx + 1 < trace.entries.len())
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let selected = pick_ordered_batch(group, rng, 6);
    move_indices_later(&mut trace.entries, &selected, rng, 10)
}

fn mutate_fanout_skew(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry((entry_sender(entry).to_string(), broadcast_identity(entry)))
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| indices.len() >= 2)
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let take = rng.gen_range(1..group.len());
    let mut positions: Vec<usize> = (0..group.len()).collect();
    positions.shuffle(rng);
    positions.truncate(take);
    positions.sort_unstable();
    let selected: Vec<usize> = positions.into_iter().map(|pos| group[pos]).collect();
    move_indices_later(&mut trace.entries, &selected, rng, 4)
}

fn mutate_channel_skew(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<(String, EntryChannel), Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry((entry_receiver(entry).to_string(), entry_channel(entry)))
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            indices.len() >= 2
                && indices
                    .last()
                    .is_some_and(|&idx| idx + 1 < trace.entries.len())
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let selected = pick_ordered_batch(group, rng, 5);
    move_indices_later(&mut trace.entries, &selected, rng, 8)
}

fn mutate_burst_release(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry(entry_receiver(entry).to_string())
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            indices.len() >= 2
                && indices.windows(2).any(|w| w[1] > w[0] + 1)
                && indices
                    .last()
                    .is_some_and(|&idx| idx + 1 < trace.entries.len())
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let start = rng.gen_range(0..group.len() - 1);
    let take = rng.gen_range(2..=(group.len() - start).min(4));
    let selected = group[start..start + take].to_vec();
    move_indices_later(&mut trace.entries, &selected, rng, 6)
}

fn mutate_interleave_receivers(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        groups
            .entry(entry_receiver(entry).to_string())
            .or_default()
            .push(idx);
    }
    let receivers: Vec<(String, Vec<usize>)> = groups
        .into_iter()
        .filter(|(_, indices)| !indices.is_empty())
        .collect();
    if receivers.len() < 2 {
        return false;
    }
    for _ in 0..16 {
        let a_idx = rng.gen_range(0..receivers.len());
        let mut b_idx = rng.gen_range(0..receivers.len());
        if a_idx == b_idx {
            b_idx = (b_idx + 1) % receivers.len();
        }
        let a = &receivers[a_idx].1;
        let b = &receivers[b_idx].1;
        let a_take = a.len().min(2);
        let b_take = b.len().min(2);
        if a_take == 0 || b_take == 0 {
            continue;
        }
        let selected_a = a[..a_take].to_vec();
        let selected_b = b[..b_take].to_vec();
        let mut selected = selected_a.clone();
        selected.extend(selected_b.clone());
        selected.sort_unstable();

        let replacement_a: Vec<_> = selected_a
            .iter()
            .map(|&idx| trace.entries[idx].clone())
            .collect();
        let replacement_b: Vec<_> = selected_b
            .iter()
            .map(|&idx| trace.entries[idx].clone())
            .collect();
        let mut replacement = Vec::with_capacity(selected.len());
        let mut ia = 0usize;
        let mut ib = 0usize;
        while ia < replacement_a.len() || ib < replacement_b.len() {
            if ia < replacement_a.len() {
                replacement.push(replacement_a[ia].clone());
                ia += 1;
            }
            if ib < replacement_b.len() {
                replacement.push(replacement_b[ib].clone());
                ib += 1;
            }
        }
        let original: Vec<String> = selected
            .iter()
            .map(|&idx| serde_json::to_string(&trace.entries[idx]).expect("entry serialization"))
            .collect();
        let replacement_keys: Vec<String> = replacement
            .iter()
            .map(|entry| serde_json::to_string(entry).expect("entry serialization"))
            .collect();
        if original == replacement_keys {
            continue;
        }

        let insert_at = selected[0];
        remove_indices(&mut trace.entries, &selected);
        insert_entries(&mut trace.entries, insert_at, replacement);
        return true;
    }
    false
}

fn mutate_timeout_edge(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut by_view: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        by_view.entry(entry.view()).or_default().push(idx);
    }
    let mut candidates = Vec::new();
    for (view, view_indices) in by_view {
        let leader = trace_leader(trace, view);
        let leader_indices: Vec<usize> = view_indices
            .iter()
            .copied()
            .filter(|&idx| entry_sender(&trace.entries[idx]) == leader)
            .collect();
        if leader_indices.len() >= 2 {
            candidates.push((view, leader_indices));
        }
    }
    if candidates.is_empty() {
        return false;
    }
    let (view, leader_indices) = &candidates[rng.gen_range(0..candidates.len())];
    let mut receiver_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for &idx in leader_indices {
        receiver_groups
            .entry(entry_receiver(&trace.entries[idx]).to_string())
            .or_default()
            .push(idx);
    }
    if receiver_groups.len() < 2 {
        return false;
    }
    let mut delayed_receivers: Vec<String> = receiver_groups.keys().cloned().collect();
    delayed_receivers.shuffle(rng);
    delayed_receivers.truncate(rng.gen_range(1..delayed_receivers.len()));
    let mut selected = Vec::new();
    for receiver in delayed_receivers {
        selected.extend(receiver_groups.get(&receiver).cloned().unwrap_or_default());
    }
    selected.sort_unstable();

    let target_old = trace
        .entries
        .iter()
        .enumerate()
        .rev()
        .find(|(_, entry)| entry.view() == *view)
        .map(|(idx, _)| idx + 1)
        .unwrap_or(trace.entries.len());
    move_indices_to_insert_at(&mut trace.entries, &selected, target_old)
}

fn mutate_relay_preference(trace: &mut TraceData, rng: &mut StdRng) -> bool {
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (idx, entry) in trace.entries.iter().enumerate() {
        let TraceEntry::Certificate { cert, .. } = entry else {
            continue;
        };
        groups
            .entry((
                entry_receiver(entry).to_string(),
                logical_cert_identity(cert),
            ))
            .or_default()
            .push(idx);
    }
    let candidates: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|indices| {
            let senders: HashSet<String> = indices
                .iter()
                .map(|&idx| entry_sender(&trace.entries[idx]).to_string())
                .collect();
            indices.len() >= 2 && senders.len() >= 2
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let group = &candidates[rng.gen_range(0..candidates.len())];
    let earliest = group[0];
    let mut alternates: Vec<usize> = group
        .iter()
        .copied()
        .filter(|&idx| entry_sender(&trace.entries[idx]) != entry_sender(&trace.entries[earliest]))
        .collect();
    if alternates.is_empty() {
        return false;
    }
    alternates.shuffle(rng);
    let chosen = alternates[0];
    let entry = trace.entries.remove(chosen);
    trace.entries.insert(earliest, entry);
    true
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
        Mutation::DelayRecipient => mutate_delay_recipient(trace, rng),
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
                .filter(|&k| {
                    k != start && k != start + 1 && entry_receiver(&trace.entries[k]) != recv
                })
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
        Mutation::DelayLink => mutate_delay_link(trace, rng),
        Mutation::DelaySender => mutate_delay_sender(trace, rng),
        Mutation::FanoutSkew => mutate_fanout_skew(trace, rng),
        Mutation::ChannelSkew => mutate_channel_skew(trace, rng),
        Mutation::BurstRelease => mutate_burst_release(trace, rng),
        Mutation::InterleaveReceivers => mutate_interleave_receivers(trace, rng),
        Mutation::TimeoutEdge => mutate_timeout_edge(trace, rng),
        Mutation::RelayPreference => mutate_relay_preference(trace, rng),
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
    if let Some(seed) = env::var("MUTATOR_SEED").ok().and_then(|s| s.parse().ok()) {
        return seed;
    }
    let seed: u64 = rand::random();
    let seed_file = seed_dir.join(".tlc_mutator_seed");
    fs::create_dir_all(seed_dir).ok();
    if let Err(e) = fs::write(&seed_file, seed.to_string()) {
        eprintln!(
            "warning: failed to write seed to {}: {e}",
            seed_file.display()
        );
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

/// Generates a fresh seed population by mutating randomly chosen base
/// seeds, then pushes them onto the queue. Mirrors Go's `Fuzzer.seed()`
/// which regenerates fresh traces each reseed rather than replaying the
/// same disk seeds.
fn seed_queue_generated(
    queue: &mut VecDeque<TraceData>,
    base_seeds: &[TraceData],
    rng: &mut StdRng,
    n: usize,
) {
    queue.clear();
    for _ in 0..n {
        let base = &base_seeds[rng.gen_range(0..base_seeds.len())];
        match mutate_once(base, rng) {
            Some(t) => queue.push_back(t),
            None => queue.push_back(base.clone()),
        }
    }
}

fn resolve_seed_population_size() -> usize {
    env::var("MUTATOR_SEED_POPULATION_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED_POPULATION_SIZE)
}

/// Main entry point for the trace mutator fuzzing loop.
pub fn run() {
    let url = env::var("TLC_URL").unwrap_or_else(|_| DEFAULT_TLC_URL.to_string());
    let iterations = resolve_iterations();
    let reseed_freq = resolve_reseed_freq().max(1);
    let seed_population_size = resolve_seed_population_size();
    let faults_override = resolve_faults();

    let seed_dir = seed_dir();
    let seed = resolve_seed(&seed_dir);
    copy_fixtures_to_seed_dir(&seed_dir);

    let mut base_seeds = load_seeds(&seed_dir);
    if base_seeds.is_empty() {
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
        "trace_mutator: base_seeds={} iterations={} seed={} mut_per_trace={} reseed_freq={} \
         seed_population={} faults={} url={}",
        base_seeds.len(),
        iterations,
        seed,
        mut_per_trace,
        reseed_freq,
        seed_population_size,
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
    seed_queue_generated(&mut queue, &base_seeds, &mut rng, seed_population_size);

    let mut kept = 0usize;
    let mut empty_actions = 0usize;
    let mut errors = 0usize;
    let mut uninteresting = 0usize;
    let mut mutated_executions = 0usize;
    let mut random_executions = 0usize;

    for iter in 0..iterations {
        // Periodic reseed: generate a fresh population from base seeds
        // using the current RNG state, matching Go's Fuzzer.seed() which
        // regenerates rather than replaying the same traces.
        if iter > 0 && iter % reseed_freq == 0 {
            let refreshed = load_seeds(&seed_dir);
            if !refreshed.is_empty() {
                base_seeds = refreshed;
            }
            seed_queue_generated(&mut queue, &base_seeds, &mut rng, seed_population_size);
            println!(
                "[iter {iter}] reseed: generated {} fresh traces from {} base seeds",
                seed_population_size,
                base_seeds.len(),
            );
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
                let base = &base_seeds[rng.gen_range(0..base_seeds.len())];
                mutate_once(base, &mut rng).unwrap_or_else(|| base.clone())
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
                eprintln!("tlc oracle error at iter {iter}: {e}",);
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

#[cfg(test)]
mod tests {
    use super::{try_mutation, Mutation};
    use crate::tracing::{
        data::TraceData,
        sniffer::{TraceEntry, TracedCert, TracedVote},
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::BTreeMap;

    fn vote(sender: &str, receiver: &str, vote: TracedVote) -> TraceEntry {
        TraceEntry::Vote {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            vote,
        }
    }

    fn cert(sender: &str, receiver: &str, cert: TracedCert) -> TraceEntry {
        TraceEntry::Certificate {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            cert,
        }
    }

    fn sample_trace() -> TraceData {
        TraceData {
            n: 4,
            faults: 0,
            epoch: 0,
            max_view: 2,
            required_containers: 1,
            reporter_states: Default::default(),
            entries: vec![
                vote(
                    "n1",
                    "n0",
                    TracedVote::Notarize {
                        view: 1,
                        parent: 0,
                        sig: "n1".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                vote(
                    "n2",
                    "n0",
                    TracedVote::Notarize {
                        view: 1,
                        parent: 0,
                        sig: "n2".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                vote(
                    "n1",
                    "n2",
                    TracedVote::Notarize {
                        view: 1,
                        parent: 0,
                        sig: "n1".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                vote(
                    "n3",
                    "n0",
                    TracedVote::Notarize {
                        view: 1,
                        parent: 0,
                        sig: "n3".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                vote(
                    "n1",
                    "n3",
                    TracedVote::Notarize {
                        view: 1,
                        parent: 0,
                        sig: "n1".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                cert(
                    "n1",
                    "n0",
                    TracedCert::Notarization {
                        view: 1,
                        parent: 0,
                        block: "b1".to_string(),
                        signers: vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
                        ghost_sender: "n1".to_string(),
                    },
                ),
                cert(
                    "n2",
                    "n0",
                    TracedCert::Notarization {
                        view: 1,
                        parent: 0,
                        block: "b1".to_string(),
                        signers: vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
                        ghost_sender: "n2".to_string(),
                    },
                ),
                vote(
                    "n0",
                    "n2",
                    TracedVote::Nullify {
                        view: 1,
                        sig: "n0".to_string(),
                    },
                ),
                cert(
                    "n1",
                    "n2",
                    TracedCert::Notarization {
                        view: 1,
                        parent: 0,
                        block: "b1".to_string(),
                        signers: vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
                        ghost_sender: "n1".to_string(),
                    },
                ),
                vote(
                    "n2",
                    "n1",
                    TracedVote::Finalize {
                        view: 1,
                        parent: 0,
                        sig: "n2".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                vote(
                    "n3",
                    "n1",
                    TracedVote::Finalize {
                        view: 1,
                        parent: 0,
                        sig: "n3".to_string(),
                        block: "b1".to_string(),
                    },
                ),
                cert(
                    "n1",
                    "n3",
                    TracedCert::Finalization {
                        view: 1,
                        parent: 0,
                        block: "b1".to_string(),
                        signers: vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
                        ghost_sender: "n1".to_string(),
                    },
                ),
                vote(
                    "n2",
                    "n3",
                    TracedVote::Nullify {
                        view: 2,
                        sig: "n2".to_string(),
                    },
                ),
                vote(
                    "n1",
                    "n0",
                    TracedVote::Notarize {
                        view: 2,
                        parent: 1,
                        sig: "n1".to_string(),
                        block: "b2".to_string(),
                    },
                ),
                vote(
                    "n1",
                    "n2",
                    TracedVote::Notarize {
                        view: 2,
                        parent: 1,
                        sig: "n1".to_string(),
                        block: "b2".to_string(),
                    },
                ),
                vote(
                    "n1",
                    "n3",
                    TracedVote::Notarize {
                        view: 2,
                        parent: 1,
                        sig: "n1".to_string(),
                        block: "b2".to_string(),
                    },
                ),
                cert(
                    "n2",
                    "n3",
                    TracedCert::Nullification {
                        view: 2,
                        signers: vec!["n0".to_string(), "n2".to_string(), "n3".to_string()],
                        ghost_sender: "n2".to_string(),
                    },
                ),
            ],
        }
    }

    fn multiset(trace: &TraceData) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for entry in &trace.entries {
            let key = serde_json::to_string(entry).expect("entry serialization");
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    fn assert_reordering_mutation_succeeds(mutation: Mutation) {
        let original = sample_trace();
        let original_multiset = multiset(&original);
        let original_json =
            serde_json::to_string(&original.entries).expect("trace entry serialization");

        for seed in 0..128u64 {
            let mut trace = original.clone();
            let mut rng = StdRng::seed_from_u64(seed);
            if try_mutation(&mut trace, &mut rng, mutation)
                && serde_json::to_string(&trace.entries).expect("trace entry serialization")
                    != original_json
            {
                assert_eq!(trace.entries.len(), original.entries.len());
                assert_eq!(multiset(&trace), original_multiset);
                return;
            }
        }

        panic!("mutation {mutation:?} never succeeded on sample trace");
    }

    #[test]
    fn delay_link_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::DelayLink);
    }

    #[test]
    fn delay_sender_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::DelaySender);
    }

    #[test]
    fn delay_recipient_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::DelayRecipient);
    }

    #[test]
    fn fanout_skew_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::FanoutSkew);
    }

    #[test]
    fn channel_skew_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::ChannelSkew);
    }

    #[test]
    fn burst_release_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::BurstRelease);
    }

    #[test]
    fn interleave_receivers_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::InterleaveReceivers);
    }

    #[test]
    fn timeout_edge_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::TimeoutEdge);
    }

    #[test]
    fn relay_preference_mutation_preserves_messages() {
        assert_reordering_mutation_succeeds(Mutation::RelayPreference);
    }
}
