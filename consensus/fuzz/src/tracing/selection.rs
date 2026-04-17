//! Trace-selection strategies for the canonical fuzz recorder.
//!
//! Ported from the legacy sniffer-based runtime. Operates on
//! `simplex::replay::Trace` (canonical `Event`s) instead of the old
//! `TraceEntry` wire view. Three strategies are provided, selected via
//! the `TRACE_SELECTION_STRATEGY` env var:
//!
//! - `smallscope` (default): keeps only traces whose per-view action
//!   signature is new AND whose signature length is >= the longest seen
//!   so far. Prunes aggressively to short, novel-shape runs.
//! - `current`: keeps every trace that has at least one cert and more
//!   than one unique proposal payload.
//! - `lof`: Local Outlier Factor over per-view action vectors; keeps
//!   signatures whose LoF score exceeds a threshold, i.e. shapes that
//!   are far from previously-seen ones.
//!
//! The selected strategy is cached per-process in a OnceLock; all fuzz
//! iterations in one libfuzzer process share one decision pipeline so
//! novelty-based strategies accumulate state.

use commonware_consensus::{
    simplex::{
        replay::{Event, Trace, Wire},
        types::{Attributable, Certificate, Vote},
    },
    Viewable,
};
use commonware_utils::Participant;
use kdtree::{distance::squared_euclidean, KdTree};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex as StdMutex, OnceLock},
};

const TRACE_SELECTION_STRATEGY_ENV: &str = "TRACE_SELECTION_STRATEGY";
const TRACE_SELECTION_LOG_FILE: &str = "fuzz.log";
const LOF_NEIGHBORS: usize = 5;
const LOF_OUTLIER_THRESHOLD: f64 = 1.5;

// ---------------------------------------------------------------------------
// Strategy enum + dispatch
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrategyName {
    Current,
    SmallScope,
    Lof,
}

impl StrategyName {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "current" | "default" => Ok(Self::Current),
            "smallscope" | "short" => Ok(Self::SmallScope),
            "lof" => Ok(Self::Lof),
            _ => Err(format!(
                "invalid {TRACE_SELECTION_STRATEGY_ENV}={value}; expected one of: current, smallscope, lof"
            )),
        }
    }

    fn from_env() -> Result<Self, String> {
        match std::env::var(TRACE_SELECTION_STRATEGY_ENV) {
            Ok(value) => Self::parse(&value),
            // Default: smallscope. The canonical recorder's traces
            // without any strategy were all admitted, which blew up
            // the mbf seed pool with near-duplicates.
            Err(std::env::VarError::NotPresent) => Ok(Self::SmallScope),
            Err(err) => Err(format!("failed to read {TRACE_SELECTION_STRATEGY_ENV}: {err}")),
        }
    }

    fn as_strategy(self) -> &'static dyn TraceSelectionStrategy {
        match self {
            Self::Current => &CURRENT,
            Self::SmallScope => &SMALLSCOPE,
            Self::Lof => &LOF,
        }
    }
}

trait TraceSelectionStrategy: Sync {
    fn name(&self) -> &'static str;
    fn is_interesting(&self, metrics: &TraceMetrics) -> bool;
    fn writes_logs_to_file(&self) -> bool {
        false
    }
}

struct CurrentStrategy;
impl TraceSelectionStrategy for CurrentStrategy {
    fn name(&self) -> &'static str {
        "current"
    }
    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        metrics.certificate_entries > 0 && metrics.unique_blocks > 1
    }
}

struct SmallScopeStrategy;
impl TraceSelectionStrategy for SmallScopeStrategy {
    fn name(&self) -> &'static str {
        "smallscope"
    }
    fn writes_logs_to_file(&self) -> bool {
        true
    }
    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        let signature = metrics.session_signature();
        let mut seen = session_signature_store().lock().unwrap();
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

struct LofStrategy;
impl TraceSelectionStrategy for LofStrategy {
    fn name(&self) -> &'static str {
        "lof"
    }
    fn writes_logs_to_file(&self) -> bool {
        true
    }
    fn is_interesting(&self, metrics: &TraceMetrics) -> bool {
        let signature = metrics.session_signature();
        let mut store = lof_signature_store().lock().unwrap();
        if !store.seen_signatures.insert(signature.clone()) {
            return false;
        }
        compute_lof_score(&store.seen_signatures, &signature)
            .is_some_and(|score| score > LOF_OUTLIER_THRESHOLD)
    }
}

static CURRENT: CurrentStrategy = CurrentStrategy;
static SMALLSCOPE: SmallScopeStrategy = SmallScopeStrategy;
static LOF: LofStrategy = LofStrategy;

fn configured_strategy() -> &'static dyn TraceSelectionStrategy {
    static SELECTED: OnceLock<StrategyName> = OnceLock::new();
    SELECTED
        .get_or_init(|| StrategyName::from_env().unwrap_or_else(|msg| panic!("{msg}")))
        .as_strategy()
}

fn session_signature_store() -> &'static StdMutex<HashSet<TraceSessionSignature>> {
    static STORE: OnceLock<StdMutex<HashSet<TraceSessionSignature>>> = OnceLock::new();
    STORE.get_or_init(|| StdMutex::new(HashSet::new()))
}

#[derive(Default)]
struct LofStore {
    seen_signatures: HashSet<TraceSessionSignature>,
}

fn lof_signature_store() -> &'static StdMutex<LofStore> {
    static STORE: OnceLock<StdMutex<LofStore>> = OnceLock::new();
    STORE.get_or_init(|| StdMutex::new(LofStore::default()))
}

// ---------------------------------------------------------------------------
// Metrics + signatures (canonical Event-based)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ViewTraceSignature {
    view: u64,
    vector: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TraceSessionSignature {
    view_signatures: Vec<ViewTraceSignature>,
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
    /// Build metrics from a canonical Trace. Dimensions of
    /// `view_signatures[view].vector`:
    ///     6 * correct_nodes, laid out as
    ///     [ notarize_votes_by_correct | nullify_votes_by_correct
    ///     | finalize_votes_by_correct | notarization_cert_senders
    ///     | nullification_cert_senders | finalization_cert_senders ]
    ///
    /// Votes are counted from `Event::Construct` (each Construct is one
    /// unique broadcast; avoids double-counting network fanout).
    /// Certs are counted from `Event::Deliver { Wire::Cert(..) }`
    /// per-(ghost_sender, kind, view, payload) to match the old
    /// behaviour where certificate entries reflected network fanout.
    fn from_trace(trace: &Trace, filter_n0: bool) -> Self {
        let n = trace.topology.n as usize;
        let faults = trace.topology.faults as usize;
        let correct_nodes = n.saturating_sub(faults);
        let vector_len = 6 * correct_nodes;

        let mut vote_entries: u64 = 0;
        let mut certificate_entries: u64 = 0;
        let mut last_finalized_view: u64 = 0;
        let mut max_view: u64 = 0;
        let mut unique_blocks: HashSet<[u8; 32]> = HashSet::new();
        let mut per_view_vectors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

        let digest_bytes = |d: &commonware_cryptography::sha256::Digest| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(d.as_ref());
            out
        };

        for event in &trace.events {
            match event {
                Event::Construct { vote, .. } => {
                    vote_entries += 1;
                    match vote {
                        Vote::Notarize(n_) => {
                            let view = n_.proposal.view().get();
                            max_view = max_view.max(view);
                            unique_blocks.insert(digest_bytes(&n_.proposal.payload));
                            let signer = n_.signer();
                            if let Some(ci) = correct_offset(signer, faults, n) {
                                increment_slot(
                                    &mut per_view_vectors,
                                    vector_len,
                                    view,
                                    ci,
                                    0,
                                    correct_nodes,
                                );
                            }
                        }
                        Vote::Nullify(nu) => {
                            let view = nu.view().get();
                            max_view = max_view.max(view);
                            let signer = nu.signer();
                            if let Some(ci) = correct_offset(signer, faults, n) {
                                increment_slot(
                                    &mut per_view_vectors,
                                    vector_len,
                                    view,
                                    ci,
                                    1,
                                    correct_nodes,
                                );
                            }
                        }
                        Vote::Finalize(f) => {
                            let view = f.proposal.view().get();
                            max_view = max_view.max(view);
                            unique_blocks.insert(digest_bytes(&f.proposal.payload));
                            let signer = f.signer();
                            if let Some(ci) = correct_offset(signer, faults, n) {
                                increment_slot(
                                    &mut per_view_vectors,
                                    vector_len,
                                    view,
                                    ci,
                                    2,
                                    correct_nodes,
                                );
                            }
                        }
                    }
                }
                Event::Deliver { from, msg, .. } => match msg {
                    Wire::Cert(cert) => {
                        certificate_entries += 1;
                        if filter_n0 && from.get() == 0 {
                            // fall through: still count against entry_count
                        } else if let Some(ci) = correct_offset(*from, faults, n) {
                            match cert {
                                Certificate::Notarization(nc) => {
                                    let view = nc.proposal.view().get();
                                    max_view = max_view.max(view);
                                    unique_blocks.insert(digest_bytes(&nc.proposal.payload));
                                    increment_slot(
                                        &mut per_view_vectors,
                                        vector_len,
                                        view,
                                        ci,
                                        3,
                                        correct_nodes,
                                    );
                                }
                                Certificate::Nullification(nu) => {
                                    let view = nu.view().get();
                                    max_view = max_view.max(view);
                                    increment_slot(
                                        &mut per_view_vectors,
                                        vector_len,
                                        view,
                                        ci,
                                        4,
                                        correct_nodes,
                                    );
                                }
                                Certificate::Finalization(fc) => {
                                    let view = fc.proposal.view().get();
                                    max_view = max_view.max(view);
                                    unique_blocks.insert(digest_bytes(&fc.proposal.payload));
                                    last_finalized_view = last_finalized_view.max(view);
                                    increment_slot(
                                        &mut per_view_vectors,
                                        vector_len,
                                        view,
                                        ci,
                                        5,
                                        correct_nodes,
                                    );
                                }
                            }
                        }
                    }
                    Wire::Vote(_) => {
                        // Vote deliveries don't contribute to the vote
                        // signature (we count by Construct). They still
                        // bump `entry_count`.
                    }
                },
                Event::Propose { proposal, .. } => {
                    let view = proposal.view().get();
                    max_view = max_view.max(view);
                    unique_blocks.insert(digest_bytes(&proposal.payload));
                }
                Event::Timeout { view, .. } => {
                    max_view = max_view.max(view.get());
                }
            }
        }

        let view_signatures = per_view_vectors
            .into_iter()
            .map(|(view, vector)| ViewTraceSignature { view, vector })
            .collect();

        Self {
            entry_count: trace.events.len(),
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

fn correct_offset(p: Participant, faults: usize, n: usize) -> Option<usize> {
    let idx = p.get() as usize;
    if idx >= n {
        return None;
    }
    idx.checked_sub(faults)
}

fn increment_slot(
    per_view: &mut BTreeMap<u64, Vec<u64>>,
    vector_len: usize,
    view: u64,
    correct_idx: usize,
    section: usize,
    correct_nodes: usize,
) {
    let v = per_view.entry(view).or_insert_with(|| vec![0; vector_len]);
    let i = section * correct_nodes + correct_idx;
    if i < v.len() {
        v[i] += 1;
    }
}

// ---------------------------------------------------------------------------
// LoF
// ---------------------------------------------------------------------------

fn compute_lof_score(
    seen: &HashSet<TraceSessionSignature>,
    candidate: &TraceSessionSignature,
) -> Option<f64> {
    let signatures: Vec<_> = seen.iter().cloned().collect();
    let candidate_idx = signatures.iter().position(|s| s == candidate)?;
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
        .map(|nb| nb.last().map(|(d, _)| *d).unwrap_or(0.0))
        .collect();
    let lrds: Vec<f64> = neighbors
        .iter()
        .map(|nb| local_reachability_density(nb, &k_distances))
        .collect();
    let candidate_lrd = *lrds.get(candidate_idx)?;
    let candidate_nb = neighbors.get(candidate_idx)?;
    if candidate_nb.is_empty() {
        return None;
    }
    let mut ratio_sum = 0.0;
    for (_, nb_idx) in candidate_nb {
        let nb_lrd = *lrds.get(*nb_idx)?;
        let ratio = if candidate_lrd.is_infinite() && nb_lrd.is_infinite() {
            1.0
        } else if candidate_lrd <= f64::EPSILON {
            f64::INFINITY
        } else {
            nb_lrd / candidate_lrd
        };
        ratio_sum += ratio;
    }
    Some(ratio_sum / candidate_nb.len() as f64)
}

fn flatten_signatures_for_lof(signatures: &[TraceSessionSignature]) -> Vec<Vec<f64>> {
    let max_views = signatures
        .iter()
        .map(|s| s.view_signatures.len())
        .max()
        .unwrap_or(0)
        .max(1);
    let max_vector_len = signatures
        .iter()
        .flat_map(|s| s.view_signatures.iter().map(|v| v.vector.len()))
        .max()
        .unwrap_or(0);
    signatures
        .iter()
        .map(|s| flatten_signature(s, max_views, max_vector_len))
        .collect()
}

fn flatten_signature(
    signature: &TraceSessionSignature,
    max_views: usize,
    max_vector_len: usize,
) -> Vec<f64> {
    let mut point = Vec::with_capacity(max_views * (1 + max_vector_len));
    for vs in &signature.view_signatures {
        point.push(vs.view as f64);
        point.extend(vs.vector.iter().map(|v| *v as f64));
        point.extend(std::iter::repeat_n(
            0.0,
            max_vector_len.saturating_sub(vs.vector.len()),
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
    for (distance_squared, nb_idx) in tree.nearest(point, k + 1, &squared_euclidean).ok()? {
        let nb_idx = *nb_idx;
        if nb_idx == point_idx {
            continue;
        }
        neighbors.push((distance_squared.sqrt(), nb_idx));
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
    let reach_sum: f64 = neighbors
        .iter()
        .map(|(d, nb)| k_distances[*nb].max(*d))
        .sum();
    if reach_sum <= f64::EPSILON {
        f64::INFINITY
    } else {
        neighbors.len() as f64 / reach_sum
    }
}

// ---------------------------------------------------------------------------
// Logging + output directory
// ---------------------------------------------------------------------------

fn append_log_line(path: &Path, line: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("failed to open trace log file");
    writeln!(file, "{line}").expect("failed to append trace log line");
}

fn emit_log(strategy: &'static dyn TraceSelectionStrategy, artifacts_dir: &Path, line: &str) {
    if strategy.writes_logs_to_file() {
        append_log_line(&artifacts_dir.join(TRACE_SELECTION_LOG_FILE), line);
    } else {
        println!("{line}");
    }
}

fn format_view_signatures(view_signatures: &[ViewTraceSignature]) -> String {
    view_signatures
        .iter()
        .map(|s| format!("v{}:{:?}", s.view, s.vector))
        .collect::<Vec<_>>()
        .join(", ")
}

fn log_selection(
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
    emit_log(strategy, artifacts_dir, &line);
}

fn trace_artifacts_dir(base_dir: &str, strategy_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/traces")
        .join(format!("{base_dir}_{strategy_name}"))
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

/// Picks whether to keep a freshly-recorded canonical [`Trace`] based on
/// the configured strategy (default: `smallscope`, override via
/// `TRACE_SELECTION_STRATEGY`). Writes the trace JSON to
/// `artifacts/traces/<base_dir>_<strategy>/<hash_hex>.json` when
/// selected. Returns `true` iff the trace was persisted.
///
/// `filter_n0` matches the legacy disrupter behaviour: when true,
/// certificates whose wire sender is node 0 are excluded from the
/// per-view signer vector (still counted toward `certificate_entries`).
pub fn select_and_persist(
    base_dir: &str,
    hash_hex: &str,
    trace: &Trace,
    filter_n0: bool,
) -> bool {
    let strategy = configured_strategy();
    let metrics = TraceMetrics::from_trace(trace, filter_n0);
    let artifacts_dir = trace_artifacts_dir(base_dir, strategy.name());
    let selected = strategy.is_interesting(&metrics);
    if !selected {
        log_selection(strategy, &artifacts_dir, &metrics, false);
        return false;
    }
    fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");
    log_selection(strategy, &artifacts_dir, &metrics, true);
    let json = trace.to_json().expect("failed to serialize trace");
    let json_path = artifacts_dir.join(format!("{hash_hex}.json"));
    fs::write(&json_path, &json).expect("failed to write trace JSON");
    let line = format!(
        "wrote {} trace events to {}",
        trace.events.len(),
        json_path.display()
    );
    emit_log(strategy, &artifacts_dir, &line);
    true
}
