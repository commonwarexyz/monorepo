use super::{
    data::{ReporterReplicaStateData, TraceData, TraceProposalData},
    sniffer::{ChannelKind, SniffingReceiver, TraceEntry, TraceLog, TracedCert, TracedVote},
};

/// `SniffingReceiver` pre-applied to the Ed25519 scheme. Every path in
/// this file except the generic `run_quint_honest_tracing_for` uses
/// Ed25519 concretely; this alias saves every call site from repeating
/// the full turbofish.
type Ed25519Sniffer<R> =
    SniffingReceiver<R, commonware_consensus::simplex::scheme::ed25519::Scheme>;
use crate::{
    disrupter::Disrupter,
    invariants, simplex,
    strategy::SmallScopeForTracing,
    types::ReplayedReplicaState,
    utils::{sometimes_certifier, Partition},
    ByzantineActor, FuzzInput, SimplexEd25519, EPOCH, N4F0C4, N4F1C3, PAGE_CACHE_SIZE, PAGE_SIZE,
};
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    simplex::{
        config::{self, ForwardingPolicy},
        elector::RoundRobin,
        mocks::{
            application, conflicter, equivocator, nuller, nullify_only, outdated, relay, reporter,
            twins::{self, Elector as TwinsElector, Framework, Mode},
        },
        types::{Certificate, Vote},
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::Scheme,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
};
use commonware_p2p::{
    simulated::{SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, IoBuf, Metrics, Runner, Spawner};
use commonware_utils::{channel::mpsc::Receiver, sync::Mutex, FuzzRng, NZUsize};
use futures::future::join_all;
use kdtree::{distance::squared_euclidean, KdTree};
use sha1::Digest;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::Duration,
};

const TRACE_SELECTION_STRATEGY_ENV: &str = "TRACE_SELECTION_STRATEGY";
const TRACE_SELECTION_LOG_FILE: &str = "fuzz.log";
const LOF_NEIGHBORS: usize = 5;
const LOF_OUTLIER_THRESHOLD: f64 = 1.5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceSelectionStrategyName {
    Current,
    SmallScope,
    Lof,
}

impl TraceSelectionStrategyName {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "current" | "default" => Ok(Self::Current),
            "smallscope" | "short" => Ok(Self::SmallScope),
            "lof" => Ok(Self::Lof),
            _ => Err(format!(
                "invalid {}={value}; expected one of: current, smallscope, lof",
                TRACE_SELECTION_STRATEGY_ENV
            )),
        }
    }

    fn from_env() -> Result<Self, String> {
        match std::env::var(TRACE_SELECTION_STRATEGY_ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::Current),
            Err(err) => Err(format!(
                "failed to read {}: {err}",
                TRACE_SELECTION_STRATEGY_ENV
            )),
        }
    }

    fn as_strategy(self) -> &'static dyn TraceSelectionStrategy {
        match self {
            Self::Current => &CURRENT_TRACE_SELECTION_STRATEGY,
            Self::SmallScope => &SMALLSCOPE_TRACE_SELECTION_STRATEGY,
            Self::Lof => &LOF_TRACE_SELECTION_STRATEGY,
        }
    }
}

trait TraceSelectionStrategy {
    fn name(&self) -> &'static str;

    fn is_interesting(&self, metrics: &TraceMetrics) -> bool;

    fn writes_logs_to_file(&self) -> bool {
        false
    }
}

struct CurrentTraceSelectionStrategy;

impl TraceSelectionStrategy for CurrentTraceSelectionStrategy {
    fn name(&self) -> &'static str {
        "current"
    }

    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        metrics.certificate_entries > 0 && metrics.unique_blocks > 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ViewTraceSignature {
    view: u64,
    vector: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TraceSessionSignature {
    view_signatures: Vec<ViewTraceSignature>,
}

fn session_signature_store() -> &'static StdMutex<HashSet<TraceSessionSignature>> {
    static STORE: OnceLock<StdMutex<HashSet<TraceSessionSignature>>> = OnceLock::new();
    STORE.get_or_init(|| StdMutex::new(HashSet::new()))
}

struct SmallScopeTraceSelectionStrategy;

impl TraceSelectionStrategy for SmallScopeTraceSelectionStrategy {
    fn name(&self) -> &'static str {
        "smallscope"
    }

    fn writes_logs_to_file(&self) -> bool {
        true
    }

    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        let signature = metrics.session_signature();
        let mut seen = session_signature_store()
            .lock()
            .unwrap_or_else(|err| err.into_inner());

        if seen.contains(&signature) {
            return false;
        }

        let signature_length = signature.view_signatures.len();
        let max_length = seen
            .iter()
            .map(|existing| existing.view_signatures.len())
            .max()
            .unwrap_or(0);

        let selected = signature_length >= max_length;

        if selected {
            seen.insert(signature);
        }

        selected
    }
}

#[derive(Default)]
struct LofSelectionStore {
    seen_signatures: HashSet<TraceSessionSignature>,
}

fn lof_signature_store() -> &'static StdMutex<LofSelectionStore> {
    static STORE: OnceLock<StdMutex<LofSelectionStore>> = OnceLock::new();
    STORE.get_or_init(|| StdMutex::new(LofSelectionStore::default()))
}

struct LofTraceSelectionStrategy;

impl TraceSelectionStrategy for LofTraceSelectionStrategy {
    fn name(&self) -> &'static str {
        "lof"
    }

    fn writes_logs_to_file(&self) -> bool {
        true
    }

    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        let signature = metrics.session_signature();
        let mut store = lof_signature_store()
            .lock()
            .unwrap_or_else(|err| err.into_inner());

        if !store.seen_signatures.insert(signature.clone()) {
            return false;
        }

        compute_lof_score(&store.seen_signatures, &signature)
            .is_some_and(|score| score > LOF_OUTLIER_THRESHOLD)
    }
}

static CURRENT_TRACE_SELECTION_STRATEGY: CurrentTraceSelectionStrategy =
    CurrentTraceSelectionStrategy;
static SMALLSCOPE_TRACE_SELECTION_STRATEGY: SmallScopeTraceSelectionStrategy =
    SmallScopeTraceSelectionStrategy;
static LOF_TRACE_SELECTION_STRATEGY: LofTraceSelectionStrategy = LofTraceSelectionStrategy;

fn configured_trace_selection_strategy() -> &'static dyn TraceSelectionStrategy {
    static SELECTED: OnceLock<TraceSelectionStrategyName> = OnceLock::new();
    SELECTED
        .get_or_init(|| {
            TraceSelectionStrategyName::from_env().unwrap_or_else(|msg| panic!("{msg}"))
        })
        .as_strategy()
}

#[derive(Debug, Clone)]
struct TraceMetrics {
    entry_count: usize,
    vote_entries: u64,
    certificate_entries: u64,
    unique_blocks: usize,
    last_finalized_view: u64,
    max_view: u64,
    view_signatures: Vec<ViewTraceSignature>,
}

impl TraceMetrics {
    fn from_entries(
        entries: &[TraceEntry],
        faults: usize,
        n: usize,
        max_view: u64,
        filter_n0: bool,
    ) -> Self {
        let mut vote_entries = 0;
        let mut certificate_entries = 0;
        let mut last_finalized_view = 0;
        let mut unique_blocks = HashSet::new();
        let correct_nodes = n.saturating_sub(faults);
        let vector_len = 6 * correct_nodes;
        let mut per_view_vectors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut seen_honest_votes = HashSet::new();

        for entry in entries {
            match entry {
                TraceEntry::Vote { vote, .. } => {
                    vote_entries += 1;
                    match vote {
                        TracedVote::Notarize {
                            view, sig, block, ..
                        } => {
                            if let Some(correct_idx) = correct_node_offset(sig, faults, n) {
                                let key = UniqueHonestVote::Notarize {
                                    view: *view,
                                    signer: correct_idx,
                                    block: block.clone(),
                                };
                                if seen_honest_votes.insert(key) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        0,
                                        correct_nodes,
                                    );
                                }
                            }
                            unique_blocks.insert(block.clone());
                        }
                        TracedVote::Nullify { view, sig } => {
                            if let Some(correct_idx) = correct_node_offset(sig, faults, n) {
                                let key = UniqueHonestVote::Nullify {
                                    view: *view,
                                    signer: correct_idx,
                                };
                                if seen_honest_votes.insert(key) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        1,
                                        correct_nodes,
                                    );
                                }
                            }
                        }
                        TracedVote::Finalize {
                            view, sig, block, ..
                        } => {
                            if let Some(correct_idx) = correct_node_offset(sig, faults, n) {
                                let key = UniqueHonestVote::Finalize {
                                    view: *view,
                                    signer: correct_idx,
                                    block: block.clone(),
                                };
                                if seen_honest_votes.insert(key) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        2,
                                        correct_nodes,
                                    );
                                }
                            }
                            unique_blocks.insert(block.clone());
                        }
                    }
                }
                TraceEntry::Certificate { sender, cert, .. } => {
                    certificate_entries += 1;
                    match cert {
                        TracedCert::Notarization { view, block, .. } => {
                            if !filter_n0 || sender != "n0" {
                                if let Some(correct_idx) = correct_node_offset(sender, faults, n) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        3,
                                        correct_nodes,
                                    );
                                }
                            }
                            unique_blocks.insert(block.clone());
                        }
                        TracedCert::Nullification { view, .. } => {
                            if !filter_n0 || sender != "n0" {
                                if let Some(correct_idx) = correct_node_offset(sender, faults, n) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        4,
                                        correct_nodes,
                                    );
                                }
                            }
                        }
                        TracedCert::Finalization { view, block, .. } => {
                            if !filter_n0 || sender != "n0" {
                                if let Some(correct_idx) = correct_node_offset(sender, faults, n) {
                                    increment_view_vector(
                                        &mut per_view_vectors,
                                        vector_len,
                                        *view,
                                        correct_idx,
                                        5,
                                        correct_nodes,
                                    );
                                }
                            }
                            unique_blocks.insert(block.clone());
                            last_finalized_view = last_finalized_view.max(*view);
                        }
                    }
                }
            }
        }

        let view_signatures = per_view_vectors
            .into_iter()
            .map(|(view, vector)| ViewTraceSignature { view, vector })
            .collect();

        Self {
            entry_count: entries.len(),
            vote_entries,
            certificate_entries,
            unique_blocks: unique_blocks.len(),
            last_finalized_view,
            max_view,
            view_signatures,
        }
    }

    fn session_signature(&self) -> TraceSessionSignature {
        TraceSessionSignature {
            view_signatures: self.view_signatures.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum UniqueHonestVote {
    Notarize {
        view: u64,
        signer: usize,
        block: String,
    },
    Nullify {
        view: u64,
        signer: usize,
    },
    Finalize {
        view: u64,
        signer: usize,
        block: String,
    },
}

fn correct_node_offset(sig: &str, faults: usize, n: usize) -> Option<usize> {
    let idx = sig.strip_prefix('n')?.parse::<usize>().ok()?;
    let offset = idx.checked_sub(faults)?;
    (idx < n).then_some(offset)
}

fn increment_view_vector(
    per_view_vectors: &mut BTreeMap<u64, Vec<u64>>,
    vector_len: usize,
    view: u64,
    correct_idx: usize,
    section: usize,
    correct_nodes: usize,
) {
    let vector = per_view_vectors
        .entry(view)
        .or_insert_with(|| vec![0; vector_len]);
    let idx = section * correct_nodes + correct_idx;
    vector[idx] += 1;
}

fn format_view_signatures(view_signatures: &[ViewTraceSignature]) -> String {
    view_signatures
        .iter()
        .map(|signature| format!("v{}:{:?}", signature.view, signature.vector))
        .collect::<Vec<_>>()
        .join(", ")
}

fn compute_lof_score(
    seen_signatures: &HashSet<TraceSessionSignature>,
    candidate: &TraceSessionSignature,
) -> Option<f64> {
    let signatures: Vec<_> = seen_signatures.iter().cloned().collect();
    let candidate_idx = signatures
        .iter()
        .position(|signature| signature == candidate)?;
    let points = flatten_signatures_for_lof(&signatures);
    let total_points = points.len();
    let k = LOF_NEIGHBORS.min(total_points.saturating_sub(1));
    if k < 2 {
        return None;
    }

    let mut tree = KdTree::new(points.first()?.len());
    for (idx, point) in points.iter().enumerate() {
        tree.add(point.clone(), idx).ok()?;
    }

    let neighbors: Vec<Vec<(f64, usize)>> = points
        .iter()
        .enumerate()
        .map(|(idx, point)| nearest_neighbors(&tree, point, idx, k))
        .collect::<Option<_>>()?;
    let k_distances: Vec<f64> = neighbors
        .iter()
        .map(|point_neighbors| {
            point_neighbors
                .last()
                .map(|(distance, _)| *distance)
                .unwrap_or(0.0)
        })
        .collect();
    let lrds: Vec<f64> = neighbors
        .iter()
        .map(|point_neighbors| local_reachability_density(point_neighbors, &k_distances))
        .collect();
    let candidate_lrd = *lrds.get(candidate_idx)?;
    let candidate_neighbors = neighbors.get(candidate_idx)?;
    if candidate_neighbors.is_empty() {
        return None;
    }

    let mut ratio_sum = 0.0;
    for (_, neighbor_idx) in candidate_neighbors {
        let neighbor_lrd = *lrds.get(*neighbor_idx)?;
        let ratio = if candidate_lrd.is_infinite() && neighbor_lrd.is_infinite() {
            1.0
        } else if candidate_lrd <= f64::EPSILON {
            f64::INFINITY
        } else {
            neighbor_lrd / candidate_lrd
        };
        ratio_sum += ratio;
    }

    Some(ratio_sum / candidate_neighbors.len() as f64)
}

fn flatten_signatures_for_lof(signatures: &[TraceSessionSignature]) -> Vec<Vec<f64>> {
    let max_views = signatures
        .iter()
        .map(|signature| signature.view_signatures.len())
        .max()
        .unwrap_or(0)
        .max(1);
    let max_vector_len = signatures
        .iter()
        .flat_map(|signature| {
            signature
                .view_signatures
                .iter()
                .map(|view_signature| view_signature.vector.len())
        })
        .max()
        .unwrap_or(0);

    signatures
        .iter()
        .map(|signature| flatten_signature(signature, max_views, max_vector_len))
        .collect()
}

fn flatten_signature(
    signature: &TraceSessionSignature,
    max_views: usize,
    max_vector_len: usize,
) -> Vec<f64> {
    let mut point = Vec::with_capacity(max_views * (1 + max_vector_len));
    for view_signature in &signature.view_signatures {
        point.push(view_signature.view as f64);
        point.extend(view_signature.vector.iter().map(|value| *value as f64));
        point.extend(std::iter::repeat_n(
            0.0,
            max_vector_len.saturating_sub(view_signature.vector.len()),
        ));
    }
    for _ in signature.view_signatures.len()..max_views {
        point.push(-1.0);
        point.extend(std::iter::repeat_n(0.0, max_vector_len));
    }
    if point.is_empty() {
        point.push(-1.0);
    }
    point
}

fn nearest_neighbors(
    tree: &KdTree<f64, usize, Vec<f64>>,
    point: &[f64],
    point_idx: usize,
    k: usize,
) -> Option<Vec<(f64, usize)>> {
    let mut neighbors = Vec::with_capacity(k);
    for (distance_squared, neighbor_idx) in tree.nearest(point, k + 1, &squared_euclidean).ok()? {
        let neighbor_idx = *neighbor_idx;
        if neighbor_idx == point_idx {
            continue;
        }
        neighbors.push((distance_squared.sqrt(), neighbor_idx));
        if neighbors.len() == k {
            break;
        }
    }
    Some(neighbors)
}

fn local_reachability_density(neighbors: &[(f64, usize)], k_distances: &[f64]) -> f64 {
    if neighbors.is_empty() {
        return 0.0;
    }
    let reachability_sum = neighbors
        .iter()
        .map(|(distance, neighbor_idx)| k_distances[*neighbor_idx].max(*distance))
        .sum::<f64>();
    if reachability_sum <= f64::EPSILON {
        f64::INFINITY
    } else {
        neighbors.len() as f64 / reachability_sum
    }
}

fn append_trace_log_line(path: &Path, line: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("failed to open trace log file");
    writeln!(file, "{line}").expect("failed to append trace log line");
}

fn emit_trace_log(strategy: &'static dyn TraceSelectionStrategy, artifacts_dir: &Path, line: &str) {
    if strategy.writes_logs_to_file() {
        append_trace_log_line(&artifacts_dir.join(TRACE_SELECTION_LOG_FILE), line);
    } else {
        println!("{line}");
    }
}

fn log_trace_selection(
    strategy: &'static dyn TraceSelectionStrategy,
    artifacts_dir: &Path,
    metrics: &TraceMetrics,
    selected: bool,
) {
    if strategy.writes_logs_to_file() && !selected {
        return;
    }
    let verdict = if selected { "selected" } else { "skipping" };
    let line = format!(
        "{verdict} trace (strategy={}, entries={}, votes={}, certs={}, unique_blocks={}, last_finalized_view={}, max_view={}, view_signature=[{}])",
        strategy.name(),
        metrics.entry_count,
        metrics.vote_entries,
        metrics.certificate_entries,
        metrics.unique_blocks,
        metrics.last_finalized_view,
        metrics.max_view,
        format_view_signatures(&metrics.view_signatures),
    );
    emit_trace_log(strategy, artifacts_dir, &line);
}

fn trace_artifacts_dir(base_dir: &str, strategy_name: &str) -> PathBuf {
    let dir_name = format!("{base_dir}_{strategy_name}");
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/traces")
        .join(dir_name)
}

fn persist_trace_if_selected(
    base_dir: &str,
    hash_hex: &str,
    trace_data: &TraceData,
    filter_n0: bool,
    corpus_bytes: &[u8],
) -> bool {
    let strategy = configured_trace_selection_strategy();
    let metrics = TraceMetrics::from_entries(
        &trace_data.entries,
        trace_data.faults,
        trace_data.n,
        trace_data.max_view,
        filter_n0,
    );
    let artifacts_dir = trace_artifacts_dir(base_dir, strategy.name());
    let selected = strategy.is_interesting(&metrics);
    if !selected {
        return false;
    }

    fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");
    log_trace_selection(strategy, &artifacts_dir, &metrics, selected);

    let bytes_path = artifacts_dir.join(format!("{hash_hex}.bytes"));
    fs::write(&bytes_path, corpus_bytes).expect("failed to write trace corpus bytes");

    let json = serde_json::to_string_pretty(trace_data).expect("failed to serialize trace");
    let json_path = artifacts_dir.join(format!("{hash_hex}.json"));
    fs::write(&json_path, &json).expect("failed to write trace JSON");
    let line = format!(
        "wrote {} trace entries to {} and corpus bytes to {}",
        trace_data.entries.len(),
        json_path.display(),
        bytes_path.display()
    );
    emit_trace_log(strategy, &artifacts_dir, &line);
    true
}

fn encode_reporter_states(
    replayed: Vec<ReplayedReplicaState>,
    faults: usize,
) -> BTreeMap<String, ReporterReplicaStateData> {
    replayed
        .into_iter()
        .enumerate()
        .map(|(idx, state)| {
            let node_id = format!("n{}", faults + idx);
            let max_finalized_view = state.finalizations.keys().copied().max().unwrap_or(0);
            let notarizations: BTreeMap<u64, TraceProposalData> = state
                .notarizations
                .iter()
                .map(|(view, cert)| {
                    (
                        *view,
                        TraceProposalData {
                            view: *view,
                            parent: 0,
                            payload: cert.payload.to_string(),
                        },
                    )
                })
                .collect();
            let notarization_signature_counts: BTreeMap<u64, Option<usize>> = state
                .notarizations
                .iter()
                .map(|(view, cert)| (*view, cert.signature_count))
                .collect();
            let nullifications: BTreeSet<u64> = state.nullifications.keys().copied().collect();
            let nullification_signature_counts: BTreeMap<u64, Option<usize>> = state
                .nullifications
                .iter()
                .map(|(view, cert)| (*view, cert.signature_count))
                .collect();
            let finalizations: BTreeMap<u64, TraceProposalData> = state
                .finalizations
                .iter()
                .map(|(view, cert)| {
                    (
                        *view,
                        TraceProposalData {
                            view: *view,
                            parent: 0,
                            payload: cert.payload.to_string(),
                        },
                    )
                })
                .collect();
            let finalization_signature_counts: BTreeMap<u64, Option<usize>> = state
                .finalizations
                .iter()
                .map(|(view, cert)| (*view, cert.signature_count))
                .collect();
            let data = ReporterReplicaStateData {
                notarizations,
                notarization_signature_counts,
                nullifications,
                nullification_signature_counts,
                finalizations,
                finalization_signature_counts,
                certified: state.certified.into_iter().collect(),
                successful_certifications: BTreeSet::new(),
                notarize_signers: state.notarize_signers.into_iter().collect(),
                nullify_signers: state.nullify_signers.into_iter().collect(),
                finalize_signers: state.finalize_signers.into_iter().collect(),
                max_finalized_view,
            };
            (node_id, data)
        })
        .collect()
}

/// Filter trace entries to only keep votes that the batcher actually processed
/// (i.e. that appear in the reporter state). The sniffer records every delivered
/// message, but the batcher drops votes for views it considers uninteresting
/// (already finalized or outside the activity window). Certificates are always kept.
fn filter_unprocessed(
    entries: &[TraceEntry],
    reporter_states: &BTreeMap<String, ReporterReplicaStateData>,
) -> Vec<TraceEntry> {
    entries
        .iter()
        .filter(|entry| {
            let TraceEntry::Vote { receiver, vote, .. } = entry else {
                return true; // keep all certificates
            };
            let Some(state) = reporter_states.get(receiver) else {
                return true; // no reporter for this receiver (fault node), keep
            };
            match vote {
                TracedVote::Notarize { view, sig, .. } => state
                    .notarize_signers
                    .get(view)
                    .is_some_and(|s| s.contains(sig)),
                TracedVote::Nullify { view, sig } => state
                    .nullify_signers
                    .get(view)
                    .is_some_and(|s| s.contains(sig)),
                TracedVote::Finalize { view, sig, .. } => state
                    .finalize_signers
                    .get(view)
                    .is_some_and(|s| s.contains(sig)),
            }
        })
        .cloned()
        .collect()
}

/// Drain all pending internal work (e.g. batcher-to-voter pipeline messages)
/// without advancing virtual time. This ensures all channel-driven cascades
/// complete while consensus timeouts are not triggered.
async fn drain_pipeline(context: &deterministic::Context) {
    context.quiesce().await;
}

/// Run consensus with a Byzantine twin and quint tracing, capturing messages as JSON.
pub fn run_quint_twins_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    let mut rng = FuzzRng::new(input.raw_bytes.clone());
    let case = twins::cases(
        &mut rng,
        Framework {
            participants: N4F1C3.n as usize,
            faults: N4F1C3.faults as usize,
            rounds: 1,
            mode: Mode::Sampled,
            max_cases: 1,
        },
    )
    .into_iter()
    .next()
    .expect("should generate at least one case");
    let scenario = case.scenario;

    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
            byzantine_actor: input.byzantine_actor,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;
        let participants_arc: Arc<[_]> = participants.clone().into();

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let config = tracing_input.configuration;
        let elector = TwinsElector::new(
            RoundRobin::<Sha256Hasher>::default(),
            &scenario,
            config.n as usize,
        );
        let mut reporters = Vec::new();

        {
            let idx = 0;
            let validator = participants[idx].clone();
            let twin_ctx = context.with_label(&format!("twin_{idx}"));
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let make_vote_forwarder = || {
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_resolver_forwarder = || {
                move |_: SplitOrigin, recipients: &Recipients<_>, _: &IoBuf| {
                    Some(recipients.clone())
                }
            };

            let make_vote_router = || {
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_router = || move |(_sender, _message): &(_, IoBuf)| SplitTarget::Both;

            let (vote_sender, vote_receiver) = vote_network;
            let (certificate_sender, certificate_receiver) = certificate_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(make_vote_forwarder());
            let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                twin_ctx.with_label(&format!("pending_split_{idx}")),
                make_vote_router(),
            );
            let (certificate_sender_primary, certificate_sender_secondary) =
                certificate_sender.split_with(make_certificate_forwarder());
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver.split_with(
                    twin_ctx.with_label(&format!("recovered_split_{idx}")),
                    make_certificate_router(),
                );
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(make_resolver_forwarder());
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(
                    twin_ctx.with_label(&format!("resolver_split_{idx}")),
                    make_resolver_router(),
                );

            let node_id = format!("n{}", idx);
            let sniffing_vote_primary = Ed25519Sniffer::new(
                vote_receiver_primary,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_primary = Ed25519Sniffer::new(
                certificate_receiver_primary,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let primary_label = format!("twin_{idx}_primary");
            let primary_context = twin_ctx.with_label(&primary_label);
            let primary_elector = elector.clone();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: primary_elector.clone(),
            };
            let reporter =
                reporter::Reporter::new(primary_context.with_label("reporter"), reporter_cfg);

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: sometimes_certifier(),
            };
            let (actor, application) =
                application::Application::new(primary_context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: scheme.clone(),
                elector: primary_elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: primary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(primary_context.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender_primary, sniffing_vote_primary),
                (certificate_sender_primary, sniffing_cert_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );

            let secondary_label = format!("twin_{idx}_secondary");
            let secondary_context = twin_ctx.with_label(&secondary_label);
            let secondary_elector = elector.clone();
            let secondary_reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: secondary_elector.clone(),
            };
            let secondary_reporter = reporter::Reporter::new(
                secondary_context.with_label("reporter"),
                secondary_reporter_cfg,
            );

            let secondary_app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: sometimes_certifier(),
            };
            let (secondary_actor, secondary_application) = application::Application::new(
                secondary_context.with_label("application"),
                secondary_app_cfg,
            );
            secondary_actor.start();

            let sniffing_vote_secondary = Ed25519Sniffer::new(
                vote_receiver_secondary,
                ChannelKind::Vote,
                format!("n{}", idx),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_secondary = Ed25519Sniffer::new(
                certificate_receiver_secondary,
                ChannelKind::Certificate,
                format!("n{}", idx),
                participants.clone(),
                trace.clone(),
            );

            let secondary_blocker = oracle.control(validator.clone());
            let secondary_engine_cfg = config::Config {
                blocker: secondary_blocker,
                scheme: scheme.clone(),
                elector: secondary_elector,
                automaton: secondary_application.clone(),
                relay: secondary_application.clone(),
                reporter: secondary_reporter.clone(),
                partition: secondary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&secondary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let secondary_engine =
                Engine::new(secondary_context.with_label("engine"), secondary_engine_cfg);
            secondary_engine.start(
                (vote_sender_secondary, sniffing_vote_secondary),
                (certificate_sender_secondary, sniffing_cert_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }

        for i in 1..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = Ed25519Sniffer::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = Ed25519Sniffer::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: sometimes_certifier(),
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;
        drain_pipeline(&context).await;

        let replayed = invariants::extract_replayed(&reporters, config.n as usize);
        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);
        invariants::check_vote_invariants(&replayed, config.faults as usize);
        let reporter_states = encode_reporter_states(replayed, config.faults as usize);

        let trace = trace.lock();
        let max_view = trace.structured.iter().map(|e| e.view()).max().unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: trace.structured.clone(),
            required_containers: tracing_input.required_containers,
            reporter_states,
        };

        persist_trace_if_selected(
            "simplex_ed25519_quint_twins",
            &hash_hex,
            &trace_data,
            false,
            corpus_bytes,
        );
    });
}

/// Run consensus with a Disrupter as node 0 and quint tracing, capturing messages as JSON.
pub fn run_quint_disrupter_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    run_quint_byzantine_tracing(ByzantineActor::Disrupter, input, corpus_bytes);
}

pub fn run_quint_byzantine_tracing(actor: ByzantineActor, input: FuzzInput, corpus_bytes: &[u8]) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
            byzantine_actor: input.byzantine_actor,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;

        {
            let validator = participants[0].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = "n0".to_string();

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = Ed25519Sniffer::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = Ed25519Sniffer::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            match actor {
                ByzantineActor::Equivocator => {
                    let cfg = equivocator::Config {
                        scheme: schemes[0].clone(),
                        elector: elector.clone(),
                        epoch: Epoch::new(EPOCH),
                        relay: relay.clone(),
                        hasher: Sha256Hasher::default(),
                    };
                    let equivocator =
                        equivocator::Equivocator::new(ctx.with_label("equivocator"), cfg);
                    equivocator.start((vote_sender, sniffing_vote), (cert_sender, sniffing_cert));
                }
                ByzantineActor::Conflicter => {
                    let cfg = conflicter::Config {
                        scheme: schemes[0].clone(),
                    };
                    let conflicter = conflicter::Conflicter::<_, _, Sha256Hasher>::new(
                        ctx.with_label("conflicter"),
                        cfg,
                    );
                    conflicter.start((vote_sender, sniffing_vote));
                }
                ByzantineActor::Nuller => {
                    let cfg = nuller::Config {
                        scheme: schemes[0].clone(),
                    };
                    let nuller =
                        nuller::Nuller::<_, _, Sha256Hasher>::new(ctx.with_label("nuller"), cfg);
                    nuller.start((vote_sender, sniffing_vote));
                }
                ByzantineActor::NullifyOnly => {
                    let cfg = nullify_only::Config {
                        scheme: schemes[0].clone(),
                    };
                    let nullify_only = nullify_only::NullifyOnly::<_, _, Sha256Hasher>::new(
                        ctx.with_label("nullify_only"),
                        cfg,
                    );
                    nullify_only.start((vote_sender, sniffing_vote));
                }
                ByzantineActor::Outdated => {
                    let cfg = outdated::Config {
                        scheme: schemes[0].clone(),
                        view_delta: Delta::new(5),
                    };
                    let outdated = outdated::Outdated::<_, _, Sha256Hasher>::new(
                        ctx.with_label("outdated"),
                        cfg,
                    );
                    outdated.start((vote_sender, sniffing_vote));
                }
                ByzantineActor::Disrupter => {
                    let disrupter = Disrupter::new(
                        ctx.with_label("disrupter"),
                        schemes[0].clone(),
                        SmallScopeForTracing::new(2, 5),
                    );
                    disrupter.start(
                        (vote_sender, sniffing_vote),
                        (cert_sender, sniffing_cert),
                        (resolver_sender, resolver_receiver),
                    );
                }
            }
        }

        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = Ed25519Sniffer::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = Ed25519Sniffer::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: sometimes_certifier(),
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;
        drain_pipeline(&context).await;

        let replayed = invariants::extract_replayed(&reporters, config.n as usize);
        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);
        invariants::check_vote_invariants(&replayed, config.faults as usize);
        let reporter_states = encode_reporter_states(replayed, config.faults as usize);

        let trace = trace.lock();
        let filtered = filter_unprocessed(&trace.structured, &reporter_states);
        let max_view = filtered.iter().map(|e| e.view()).max().unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: filtered,
            required_containers: tracing_input.required_containers,
            reporter_states,
        };

        persist_trace_if_selected(
            "simplex_ed25519_quint_byzantine",
            &hash_hex,
            &trace_data,
            matches!(actor, ByzantineActor::Disrupter),
            corpus_bytes,
        );
    });
}

/// Runs the deterministic 4-node honest consensus pipeline and returns the
/// resulting quint [`TraceData`].
///
/// Shared between [`run_quint_honest_tracing`] (which then persists the
/// trace as a fuzzing artifact) and the TLC-driven fuzz target (which then
/// feeds the trace into the controlled TLC server for coverage feedback).
pub(crate) fn run_honest_pipeline(input: FuzzInput) -> Option<TraceData> {
    let captured: Arc<StdMutex<Option<TraceData>>> = Arc::new(StdMutex::new(None));
    let captured_clone = captured.clone();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|context| async move {
        let trace_data = build_honest_trace_data(context, input).await;
        *captured_clone.lock().unwrap() = Some(trace_data);
    });

    let result = captured.lock().unwrap().take();
    result
}

/// Body of the honest tracing pipeline. Sets up the deterministic 4-node
/// network, runs consensus until every reporter has reached the required
/// container count, drains the pipeline, and returns the encoded
/// [`TraceData`].
async fn build_honest_trace_data(
    mut context: deterministic::Context,
    input: FuzzInput,
) -> TraceData {
    let tracing_input = FuzzInput {
        raw_bytes: input.raw_bytes.clone(),
        required_containers: input.required_containers,
        degraded_network: false,
        configuration: N4F0C4,
        partition: Partition::Connected,
        strategy: input.strategy,
        byzantine_actor: None,
    };

    let (oracle, participants, schemes, mut registrations) =
        crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;

    let trace = Arc::new(Mutex::new(TraceLog::default()));
    let relay = Arc::new(relay::Relay::new());
    let elector = RoundRobin::<Sha256Hasher>::default();
    let mut reporters = Vec::new();
    let config = tracing_input.configuration;

    for i in 0..(config.n as usize) {
        let validator = participants[i].clone();
        let (vote_network, cert_network, resolver_network) =
            registrations.remove(&validator).unwrap();
        let ctx = context.with_label(&format!("validator_{validator}"));
        let node_id = format!("n{}", i);

        let (vote_sender, vote_receiver) = vote_network;
        let (cert_sender, cert_receiver) = cert_network;
        let (resolver_sender, resolver_receiver) = resolver_network;

        let sniffing_vote = Ed25519Sniffer::new(
            vote_receiver,
            ChannelKind::Vote,
            node_id.clone(),
            participants.clone(),
            trace.clone(),
        );
        let sniffing_cert = Ed25519Sniffer::new(
            cert_receiver,
            ChannelKind::Certificate,
            node_id,
            participants.clone(),
            trace.clone(),
        );

        let reporter_cfg = reporter::Config {
            participants: participants
                .as_slice()
                .try_into()
                .expect("public keys are unique"),
            scheme: schemes[i].clone(),
            elector: elector.clone(),
        };
        let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
        reporters.push(reporter.clone());

        let app_cfg = application::Config {
            hasher: Sha256Hasher::default(),
            relay: relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: sometimes_certifier(),
        };
        let (actor, application) =
            application::Application::new(ctx.with_label("application"), app_cfg);
        actor.start();

        let blocker = oracle.control(validator.clone());
        let engine_cfg = config::Config {
            blocker,
            scheme: schemes[i].clone(),
            elector: elector.clone(),
            automaton: application.clone(),
            relay: application.clone(),
            reporter: reporter.clone(),
            partition: validator.to_string(),
            mailbox_size: 1024,
            epoch: Epoch::new(EPOCH),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: Delta::new(10),
            skip_timeout: Delta::new(5),
            fetch_concurrent: 1,
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forwarding: ForwardingPolicy::Disabled,
        };
        let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
        engine.start(
            (vote_sender, sniffing_vote),
            (cert_sender, sniffing_cert),
            (resolver_sender, resolver_receiver),
        );
    }

    let mut finalizers = Vec::new();
    for reporter in reporters.iter_mut() {
        let required_containers = tracing_input.required_containers;
        let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
        finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
            while latest.get() < required_containers {
                latest = monitor.recv().await.expect("event missing");
            }
        }));
    }
    join_all(finalizers).await;
    drain_pipeline(&context).await;

    let replayed = invariants::extract_replayed(&reporters, config.n as usize);
    let states = invariants::extract(&reporters, config.n as usize);
    invariants::check::<SimplexEd25519>(config.n, &states);
    invariants::check_vote_invariants(&replayed, config.faults as usize);
    let reporter_states = encode_reporter_states(replayed, config.faults as usize);

    let trace = trace.lock();
    let filtered = filter_unprocessed(&trace.structured, &reporter_states);
    let max_view = filtered.iter().map(|e| e.view()).max().unwrap_or(1);

    TraceData {
        n: config.n as usize,
        faults: config.faults as usize,
        epoch: EPOCH,
        max_view,
        entries: filtered,
        required_containers: tracing_input.required_containers,
        reporter_states,
    }
}

/// Run consensus with all honest nodes and quint tracing, using the
/// Ed25519 certificate scheme.
pub fn run_quint_honest_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    run_quint_honest_tracing_for::<SimplexEd25519>(
        "simplex_ed25519_quint_honest",
        input,
        corpus_bytes,
    );
}

/// Generic honest-only tracing entry point. `label` selects the per-target
/// artifact subdirectory under the trace root (e.g.
/// `simplex_mock_cert_quint_honest`) so parallel runs with different
/// certificate schemes don't clobber each other's traces or corpora.
pub fn run_quint_honest_tracing_for<P: simplex::Simplex>(
    label: &'static str,
    input: FuzzInput,
    corpus_bytes: &[u8],
) where
    P::Scheme: super::sniffer::TraceableScheme,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: input.strategy,
            byzantine_actor: None,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &tracing_input).await;

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;

        for i in 0..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::<_, P::Scheme>::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::<_, P::Scheme>::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Always,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;
        drain_pipeline(&context).await;

        let replayed = invariants::extract_replayed(&reporters, config.n as usize);
        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<P>(config.n, &states);
        invariants::check_vote_invariants(&replayed, config.faults as usize);
        let reporter_states = encode_reporter_states(replayed, config.faults as usize);

        let trace = trace.lock();
        let filtered = filter_unprocessed(&trace.structured, &reporter_states);
        let max_view = filtered.iter().map(|e| e.view()).max().unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: filtered,
            required_containers: tracing_input.required_containers,
            reporter_states,
        };

        persist_trace_if_selected(label, &hash_hex, &trace_data, false, corpus_bytes);
    });
}
