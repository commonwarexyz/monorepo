use super::{
    data::TraceData,
    sniffer::{ChannelKind, SniffingReceiver, TraceEntry, TraceLog, TracedCert, TracedVote},
};
use crate::{
    disrupter::Disrupter, invariants, simplex, strategy::SmallScopeForTracing, utils::Partition,
    FuzzInput, SimplexEd25519, EPOCH, N4F1C3, PAGE_CACHE_SIZE, PAGE_SIZE,
};
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    simplex::{
        config::{self, ForwardingPolicy},
        elector::RoundRobin,
        mocks::{application, relay, reporter, twins},
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
use sha1::Digest;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::Duration,
};

const TRACE_SELECTION_STRATEGY_ENV: &str = "COMMONWARE_TRACE_SELECTION_STRATEGY";
const TRACE_SELECTION_LOG_FILE: &str = "fuzz.log";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceSelectionStrategyName {
    Current,
    SmallScope,
}

impl TraceSelectionStrategyName {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "current" | "default" => Ok(Self::Current),
            "smallscope" | "short" => Ok(Self::SmallScope),
            _ => Err(format!(
                "invalid {}={value}; expected one of: current, smallscope",
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
        metrics.byzantine_distance > 3.0
            && metrics.byzantine_vote_types >= 2
            && metrics.certs_by_n0 > 0
            && metrics.notarize_by_n0 > 1
            && metrics.nullify_by_n0 > 1
            && metrics.finalize_by_n0 > 1
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

static CURRENT_TRACE_SELECTION_STRATEGY: CurrentTraceSelectionStrategy =
    CurrentTraceSelectionStrategy;
static SMALLSCOPE_TRACE_SELECTION_STRATEGY: SmallScopeTraceSelectionStrategy =
    SmallScopeTraceSelectionStrategy;

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
    notarization_certificates: u64,
    nullification_certificates: u64,
    finalization_certificates: u64,
    notarize_by_n0: u64,
    nullify_by_n0: u64,
    finalize_by_n0: u64,
    certs_by_n0: u64,
    byzantine_vote_types: u64,
    byzantine_distance: f64,
}

impl TraceMetrics {
    fn from_entries(entries: &[TraceEntry], faults: usize, n: usize, max_view: u64) -> Self {
        let mut vote_entries = 0;
        let mut certificate_entries = 0;
        let mut notarization_certificates = 0;
        let mut nullification_certificates = 0;
        let mut finalization_certificates = 0;
        let mut notarize_by_n0 = 0;
        let mut nullify_by_n0 = 0;
        let mut finalize_by_n0 = 0;
        let mut certs_by_n0 = 0;
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
                        TracedVote::Notarize { view, sig, block } => {
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
                            if sig == "n0" {
                                notarize_by_n0 += 1;
                            }
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
                            if sig == "n0" {
                                nullify_by_n0 += 1;
                            }
                        }
                        TracedVote::Finalize { view, sig, block } => {
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
                            if sig == "n0" {
                                finalize_by_n0 += 1;
                            }
                        }
                    }
                }
                TraceEntry::Certificate { sender, cert, .. } => {
                    certificate_entries += 1;
                    if sender == "n0" {
                        certs_by_n0 += 1;
                    }
                    match cert {
                        TracedCert::Notarization { view, block, .. } => {
                            if sender != "n0" {
                                notarization_certificates += 1;
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
                            if sender != "n0" {
                                nullification_certificates += 1;
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
                            if sender != "n0" {
                                finalization_certificates += 1;
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

        let byzantine_distance = [
            notarize_by_n0 as f64,
            nullify_by_n0 as f64,
            finalize_by_n0 as f64,
            certs_by_n0 as f64,
        ]
        .iter()
        .map(|x| x * x)
        .sum::<f64>()
        .sqrt();
        let byzantine_vote_types =
            (notarize_by_n0 > 0) as u64 + (nullify_by_n0 > 0) as u64 + (finalize_by_n0 > 0) as u64;
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
            notarization_certificates,
            nullification_certificates,
            finalization_certificates,
            notarize_by_n0,
            nullify_by_n0,
            finalize_by_n0,
            certs_by_n0,
            byzantine_vote_types,
            byzantine_distance,
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
        "{verdict} trace (strategy={}, entries={}, votes={}, certs={}, unique_blocks={}, last_finalized_view={}, max_view={}, view_signature=[{}], cert_signature=[nullification={}, notarization={}, finalization={}], distance={:.2}, vote_types={}, notarize_n0={}, nullify_n0={}, finalize_n0={}, certs_n0={})",
        strategy.name(),
        metrics.entry_count,
        metrics.vote_entries,
        metrics.certificate_entries,
        metrics.unique_blocks,
        metrics.last_finalized_view,
        metrics.max_view,
        format_view_signatures(&metrics.view_signatures),
        metrics.nullification_certificates,
        metrics.notarization_certificates,
        metrics.finalization_certificates,
        metrics.byzantine_distance,
        metrics.byzantine_vote_types,
        metrics.notarize_by_n0,
        metrics.nullify_by_n0,
        metrics.finalize_by_n0,
        metrics.certs_by_n0,
    );
    emit_trace_log(strategy, artifacts_dir, &line);
}

fn trace_artifacts_dir(base_dir: &str, strategy_name: &str) -> PathBuf {
    let dir_name = format!("{base_dir}_{strategy_name}");
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/traces")
        .join(dir_name)
}

fn persist_trace_if_selected(base_dir: &str, hash_hex: &str, trace_data: &TraceData) -> bool {
    let strategy = configured_trace_selection_strategy();
    let metrics = TraceMetrics::from_entries(
        &trace_data.entries,
        trace_data.faults,
        trace_data.n,
        trace_data.max_view,
    );
    let artifacts_dir = trace_artifacts_dir(base_dir, strategy.name());
    let selected = strategy.is_interesting(&metrics);
    if !selected {
        return false;
    }

    fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");
    log_trace_selection(strategy, &artifacts_dir, &metrics, selected);

    let json = serde_json::to_string_pretty(trace_data).expect("failed to serialize trace");
    let json_path = artifacts_dir.join(format!("{hash_hex}.json"));
    fs::write(&json_path, &json).expect("failed to write trace JSON");
    let line = format!(
        "wrote {} trace entries to {}",
        trace_data.entries.len(),
        json_path.display()
    );
    emit_trace_log(strategy, &artifacts_dir, &line);
    true
}

/// Run consensus with a Byzantine twin- and disruptor-node and quint tracing, capturing messages as JSON.
pub fn run_quint_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
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
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;
        let participants_arc: Arc<[_]> = participants.clone().into();

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;

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
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        twins::view_partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        twins::view_partitions(msg.view(), participants.as_ref());
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
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return SplitTarget::None;
                    };
                    twins::view_route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return SplitTarget::None;
                    };
                    twins::view_route(msg.view(), sender, participants.as_ref())
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
            let sniffing_vote_primary = SniffingReceiver::new(
                vote_receiver_primary,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_primary = SniffingReceiver::new(
                certificate_receiver_primary,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let primary_label = format!("twin_{idx}_primary");
            let primary_context = twin_ctx.with_label(&primary_label);
            let primary_elector = RoundRobin::<Sha256Hasher>::default();
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
                should_certify: application::Certifier::Sometimes,
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
            let secondary_elector = RoundRobin::<Sha256Hasher>::default();
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
                should_certify: application::Certifier::Sometimes,
            };
            let (secondary_actor, secondary_application) = application::Application::new(
                secondary_context.with_label("application"),
                secondary_app_cfg,
            );
            secondary_actor.start();

            let sniffing_vote_secondary = SniffingReceiver::new(
                vote_receiver_secondary,
                ChannelKind::Vote,
                format!("n{}", idx),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_secondary = SniffingReceiver::new(
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

        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
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
                should_certify: application::Certifier::Sometimes,
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

        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);

        let trace = trace.lock();
        let max_view = trace.structured.iter().map(|e| e.view()).max().unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: trace.structured.clone(),
            required_containers: tracing_input.required_containers,
        };

        persist_trace_if_selected("simplex_ed25519_quint", &hash_hex, &trace_data);
    });
}

/// Run consensus with a Disrupter as node 0 and quint tracing, capturing messages as JSON.
pub fn run_quint_disrupter_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
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

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

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

        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
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
                should_certify: application::Certifier::Sometimes,
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

        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);

        let trace = trace.lock();
        let max_view = trace.structured.iter().map(|e| e.view()).max().unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: trace.structured.clone(),
            required_containers: tracing_input.required_containers,
        };

        persist_trace_if_selected("simplex_ed25519_quint_disrupter", &hash_hex, &trace_data);
    });
}
