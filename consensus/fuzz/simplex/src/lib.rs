pub mod byzzfuzz;
pub(crate) mod chaos;
pub mod happens_before;
pub mod invariants;
pub(crate) mod mallory;
pub mod state_cov;

use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    Monitor, Viewable,
    simplex::{
        Engine, Floor, ForwardPolicy, SkipBudget, SkipPolicy, config,
        elector::Config as ElectorConfig,
        mocks::{application, reporter, twins},
        types::{Certificate, Vote},
    },
    types::{Delta, Epoch, TermLength, View},
};
pub use commonware_consensus_fuzz_core::FuzzInput;
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, CertCfgOf, CertifyChoice, EPOCH, FUZZ_LOG_ENV, MAX_SLEEP_DURATION, Mode,
    N4F0C4, N4F1C3, NetworkChannels, PAGE_CACHE_SIZE, PAGE_SIZE, PINNED_OPTIMISTIC_VIEWS,
    PublicKeyOf, ReporterWiring, TWINS_MAX_ROUNDS, TwinsBackend, TwinsCase, TwinsDisrupter,
    TwinsElector, TwinsReporter, TwinsSetup, TwinsTopology, block_relay,
    bounded_fuzz_runtime_config, default_link,
    network::{
        FinalizationOmissionChannel, FinalizationOmissionReceiver, NotarizeOmissionReceiver,
    },
    network_faults, print_fuzz_input, run_twins_with_backend, scheduled_partition, setup_network,
    simplex,
    simplex_audit::{self, RecordingReporter, summaries},
    spawn_filtered_honest_validator, spawn_filtered_validator_with_reporter,
    spawn_network_fault_scheduler, start_disrupter_with_epoch_and_relay, twins_prefix_views, types,
    utils::{Action, Partition, SetPartition, apply_partition, link_peers},
};
#[cfg(any(feature = "mocks", test))]
pub use commonware_consensus_fuzz_core::{
    SimplexCertificateMock, SimplexCertificateMockByzantineFirstLeader,
    SimplexCertificateMockCustomRoundRobin,
};
use commonware_cryptography::{Sha256, certificate::Verifier, sha256::Digest as Sha256Digest};
use commonware_p2p::simulated::{Link, Oracle, SplitTarget};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{
    Clock, IoBuf, Metrics, Runner, Spawner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic,
    telemetry::traces::collector::{CollectingLayer, TraceStorage},
};
use commonware_utils::{
    FuzzRng, NZUsize, channel::mpsc::Receiver, probability, sequence::U64, sync::Once,
};
use futures::future::join_all;
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    num::NonZeroUsize,
    panic,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tracing::{Dispatch, Level, dispatcher};
use tracing_subscriber::{Layer as _, filter::filter_fn, layer::SubscriberExt};

fn configure_block_filter<P: simplex::Simplex>(
    relay: &Arc<block_relay::Relay<PublicKeyOf<P>>>,
    participants: &[PublicKeyOf<P>],
    partition: &Partition,
    choice: BlockFilterChoice,
) {
    let drop_target = match choice {
        BlockFilterChoice::DropRecipient { view, target_idx } => participants
            .get(target_idx as usize)
            .cloned()
            .map(|target| (view, target)),
        BlockFilterChoice::None => None,
    };
    let static_partition = partition.set_partition().copied();
    let schedule = partition.schedule().map(<[_]>::to_vec).unwrap_or_default();
    if drop_target.is_none() && static_partition.is_none() && schedule.is_empty() {
        return;
    }

    let participants: Arc<[PublicKeyOf<P>]> = participants.to_vec().into();
    relay.set_filter(move |sender, _, recipient, _, _, contents| {
        let block_view = block_relay::mock_block_view(contents);
        if let Some((view, target)) = &drop_target
            && block_view == Some(*view)
            && recipient == target
        {
            return false;
        }

        let active_partition = static_partition
            .or_else(|| block_view.and_then(|view| scheduled_partition(&schedule, view.get())));
        let Some(active_partition) = active_partition else {
            return true;
        };
        let Some(sender_idx) = participants
            .iter()
            .position(|participant| participant == sender)
        else {
            return true;
        };
        let Some(recipient_idx) = participants
            .iter()
            .position(|participant| participant == recipient)
        else {
            return true;
        };
        active_partition.connected(sender_idx, recipient_idx)
    });
}

fn should_bound_standard_liveness(input: &FuzzInput) -> bool {
    input.partition.is_connected()
        && input.configuration.is_valid()
        && matches!(input.block_filter, BlockFilterChoice::None)
}

/// Happens-before sink for a [`SniffingReceiver`].
pub(crate) struct Sniff<P: simplex::Simplex> {
    /// Receiving node id events are attributed to.
    node: u32,
    /// Shared event log.
    log: happens_before::capture::EventLog,
    /// Participant set used to resolve wire senders to node ids.
    peers: Arc<[PublicKeyOf<P>]>,
    /// Participant indices whose identity is ambiguous (a twin pair runs two
    /// engines under one key): a receive from them resolves to no sender, so
    /// neither half's history can be merged.
    ambiguous: Arc<[u32]>,
}

pub(crate) type SniffSink<P> = Option<Sniff<P>>;

pub(crate) fn sniff_sink<P: simplex::Simplex>(
    hb_log: &Option<happens_before::capture::EventLog>,
    node: u32,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
) -> SniffSink<P> {
    hb_log.as_ref().map(|log| Sniff {
        node,
        log: log.clone(),
        peers: peers.clone(),
        ambiguous: ambiguous.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunAudit {
    auditor_state: String,
    reporter_states: BTreeMap<String, types::ReporterReplicaStateData>,
    happens_before: Option<happens_before::Summary>,
}

fn spawn_disrupter_with_relay<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    input: &FuzzInput,
    channels: NetworkChannels<PublicKeyOf<P>>,
    block_relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
) {
    let (vote_network, certificate_network, resolver_network) = channels;
    start_disrupter_with_epoch_and_relay::<P>(
        context.child("disrupter"),
        scheme,
        &input.strategy,
        input.required_containers,
        Epoch::new(EPOCH),
        vote_network,
        certificate_network,
        resolver_network,
        block_relay,
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_filtered_audited_validator<
    P,
    EC,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> RecordingReporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme> + Clone + Send + 'static,
    PendingSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    PendingReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    RecoveredSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    RecoveredReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ResolverSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    ResolverReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    spawn_filtered_validator_with_reporter::<
        P,
        EC,
        RecordingReporter<deterministic::Context, P::Scheme, EC, Sha256Digest>,
        _,
        _,
        _,
        _,
        _,
        _,
    >(
        context,
        oracle,
        participants,
        scheme,
        validator,
        elector,
        relay,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        forwarding,
        pending,
        recovered,
        resolver,
        certify,
        wiring,
    )
}

/// Look up the partition scheduled for view 1, the initial executing view.
/// The caller applies this synchronously before validators run so early view-1
/// traffic observes the scheduled topology.
fn initial_network_partition(partition: &Partition) -> Option<SetPartition> {
    partition
        .schedule()
        .and_then(|schedule| scheduled_partition(schedule, 1))
}

/// The trace-collection stack: a shared registry with a filtered
/// [CollectingLayer] over the given storage.
fn warn_trace_dispatch(trace_store: TraceStorage) -> Dispatch {
    let collecting_layer = CollectingLayer::new(trace_store).with_filter(filter_fn(|metadata| {
        (metadata.is_span()
            && metadata
                .target()
                .contains("commonware_consensus::simplex::actors::"))
            || (metadata.is_event() && *metadata.level() == Level::WARN)
            || (metadata.is_event()
                && *metadata.level() == Level::DEBUG
                && (metadata
                    .target()
                    .contains("commonware_consensus::simplex::actors::resolver")
                    || metadata
                        .target()
                        .contains("commonware_consensus::simplex::actors::voter")))
    }));
    Dispatch::new(tracing_subscriber::registry().with(collecting_layer))
}

/// Collect WARN events from the whole protocol run and feed bounded tokens into
/// state coverage.
///
/// Reporter-derived state is filtered to honest reporters in twins modes because
/// those tokens model protocol-state correctness. WARN events intentionally stay
/// whole-network: tracing events do not carry the emitting validator identity
/// without adding protocol instrumentation, and adversarial twin engines hitting
/// rejection paths is useful reachability feedback.
///
/// The collector dispatch is passed to `run` so paths that install per-node
/// subscribers (happens-before) can tee validator-task traces back into it.
fn run_with_warn_trace_collection<T>(run: impl FnOnce(&Dispatch) -> T) -> T {
    let trace_store = TraceStorage::default();
    let dispatch = warn_trace_dispatch(trace_store.clone());

    let output = dispatcher::with_default(&dispatch, || run(&dispatch));

    let events = trace_store.get_all();
    state_cov::observe_trace_events(&events);
    output
}

/// The consensus channel a [`SniffingReceiver`] decodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SniffChannel {
    Vote,
    Certificate,
    Resolver,
}

/// Decode a sniffed payload into its wire-arrival event (view, kind). Vote and
/// certificate channels carry the message directly; the resolver channel frames
/// it, with backfill responses delivering certificates (requests and errors
/// carry none and record nothing). `None` when the payload does not decode.
fn sniff_event<P: simplex::Simplex>(
    channel: SniffChannel,
    payload: &IoBuf,
    cert_cfg: &CertCfgOf<P>,
) -> Option<(u64, happens_before::EventKind)> {
    let cert_event = |cert: Certificate<P::Scheme, Sha256Digest>| {
        let kind = match &cert {
            Certificate::Notarization(_) => happens_before::EventKind::ReceiveNotarization,
            Certificate::Nullification(_) => happens_before::EventKind::ReceiveNullification,
            Certificate::Finalization(_) => happens_before::EventKind::ReceiveFinalization,
        };
        (cert.view().get(), kind)
    };
    match channel {
        SniffChannel::Vote => Vote::<P::Scheme, Sha256Digest>::decode(payload.clone())
            .ok()
            .map(|vote| {
                let kind = match &vote {
                    Vote::Notarize(_) => happens_before::EventKind::ReceiveNotarize,
                    Vote::Nullify(_) => happens_before::EventKind::ReceiveNullify,
                    Vote::Finalize(_) => happens_before::EventKind::ReceiveFinalize,
                };
                (vote.view().get(), kind)
            }),
        SniffChannel::Certificate => {
            Certificate::<P::Scheme, Sha256Digest>::decode_cfg(payload.clone(), cert_cfg)
                .ok()
                .map(cert_event)
        }
        SniffChannel::Resolver => match ResolverMessage::<U64>::decode(payload.clone())
            .ok()?
            .payload
        {
            ResolverPayload::Response(bytes) => {
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(bytes, cert_cfg)
                    .ok()
                    .map(cert_event)
            }
            ResolverPayload::Request(_) | ResolverPayload::Error => None,
        },
    }
}

/// p2p-boundary capture: wraps a validator's vote, certificate, or resolver
/// receiver, decodes each incoming message and records the wire RECEIVE into the
/// happens-before log, attributed to the receiving node and tagged with the
/// real sender's node id (resolved against the participant set, so the
/// send-before-receive merge uses that exact sender's history). This is the
/// arrival of a message, distinct from the node later PROCESSING it (a separate
/// tracing event): a message can arrive and be dropped without being processed.
/// Transparent (forwards the message unchanged); a `None` sink is a zero-decode
/// pass-through for runs without happens-before capture.
pub(crate) struct SniffingReceiver<P: simplex::Simplex, R> {
    inner: R,
    channel: SniffChannel,
    cert_cfg: CertCfgOf<P>,
    sink: SniffSink<P>,
    _p: std::marker::PhantomData<fn() -> P>,
}

impl<P: simplex::Simplex, R> SniffingReceiver<P, R> {
    pub(crate) fn new(
        inner: R,
        channel: SniffChannel,
        cert_cfg: CertCfgOf<P>,
        sink: SniffSink<P>,
    ) -> Self {
        Self {
            inner,
            channel,
            cert_cfg,
            sink,
            _p: std::marker::PhantomData,
        }
    }
}

impl<P: simplex::Simplex, R> fmt::Debug for SniffingReceiver<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniffingReceiver").finish()
    }
}

impl<P, R> commonware_p2p::Receiver for SniffingReceiver<P, R>
where
    P: simplex::Simplex,
    R: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    type Error = R::Error;
    type PublicKey = PublicKeyOf<P>;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let (sender, payload) = self.inner.recv().await?;
        if let Some(sniff) = &self.sink
            && let Some((view, kind)) = sniff_event::<P>(self.channel, &payload, &self.cert_cfg)
        {
            let from = sniff
                .peers
                .iter()
                .position(|p| p == &sender)
                .map(|i| i as u32)
                .filter(|i| !sniff.ambiguous.contains(i));
            sniff.log.record(happens_before::Event {
                node: sniff.node,
                view,
                kind,
                sender: from,
            });
        }
        Ok((sender, payload))
    }
}

fn run_standard_once<P: simplex::Simplex>(
    mut input: FuzzInput,
    state_coverage: bool,
    collect_audit: bool,
    happens_before: bool,
    warn_dispatch: Option<Dispatch>,
) -> Option<RunAudit> {
    let cfg = bounded_fuzz_runtime_config(&input.raw_bytes, input.required_containers, 0);
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before.then(happens_before::capture::EventLog::new);

    executor.start(move |mut context| async move {
        if matches!(input.partition, Partition::Adaptive(_)) {
            input.partition = Partition::Adaptive(network_faults(
                input.strategy,
                input.required_containers,
                &mut context,
            ));
        }

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let initial_partition = initial_network_partition(&input.partition);
        if initial_partition.is_some() {
            apply_partition(
                &oracle,
                &participants,
                initial_partition.as_ref(),
                &default_link(),
            )
            .await;
        }

        let relay = Arc::new(block_relay::Relay::new());
        // A withheld block should hold certification pending only for the
        // DropRecipient scenario (whose liveness is left unbounded); other
        // runs certify per the Certifier as the upstream mock does.
        relay.set_certify_requires_block(matches!(
            input.block_filter,
            BlockFilterChoice::DropRecipient { .. }
        ));
        configure_block_filter::<P>(&relay, &participants, &input.partition, input.block_filter);
        let mut reporters = Vec::new();
        let config = input.configuration;
        let term_length = P::effective_term_length(input.term_length);

        // Spawn Byzantine nodes (Disrupters only)
        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            spawn_disrupter_with_relay::<P>(
                ctx,
                schemes[i].clone(),
                &input,
                channels,
                Some(relay.clone()),
            );
        }

        // Spawn honest validators
        let peers: Arc<[PublicKeyOf<P>]> = participants.clone().into();
        let ambiguous: Arc<[u32]> = Vec::new().into();
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            // p2p-boundary sniffing: capture wire arrivals of votes,
            // certificates, and resolver backfill responses (distinct from the
            // node processing them, which the tracing source records).
            // Pass-through when not capturing.
            let pending = {
                let (vote_sender, vote_receiver) = pending;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    vote_sender,
                    SniffingReceiver::<P, _>::new(vote_receiver, SniffChannel::Vote, cfg, sink),
                )
            };
            let recovered = {
                let (cert_sender, cert_receiver) = recovered;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    cert_sender,
                    SniffingReceiver::<P, _>::new(
                        cert_receiver,
                        SniffChannel::Certificate,
                        cfg,
                        sink,
                    ),
                )
            };
            let resolver = {
                let (backfill_sender, backfill_receiver) = resolver;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    backfill_sender,
                    SniffingReceiver::<P, _>::new(
                        backfill_receiver,
                        SniffChannel::Resolver,
                        cfg,
                        sink,
                    ),
                )
            };
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let spawn = || {
                spawn_filtered_honest_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator.clone(),
                    P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    input.certify,
                    input.reporting,
                )
            };
            // Dispatch propagation: every task the engine spawns inherits this
            // per-node subscriber, so its tracing events are attributed to node
            // `i`. The subscriber shadows the whole-run trace collector for
            // those tasks, so tee it back in when one is installed.
            let reporter = match &hb_log {
                Some(log) => {
                    let mut subscriber =
                        happens_before::capture::NodeSubscriber::new(i as u32, log.clone());
                    if let Some(inner) = &warn_dispatch {
                        subscriber = subscriber.with_inner(inner.clone());
                    }
                    let dispatch = Dispatch::new(subscriber);
                    dispatcher::with_default(&dispatch, spawn)
                }
                None => spawn(),
            };
            reporters.push((validator, reporter));
        }

        spawn_network_fault_scheduler::<P, _>(
            &context,
            &oracle,
            &participants,
            &mut reporters,
            input.partition.clone(),
            input.required_containers,
            initial_partition,
        )
        .await;

        if should_bound_standard_liveness(&input) {
            let mut finalizers = Vec::new();
            for (validator, reporter) in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(
                    context
                        .child("finalizer")
                        .with_attribute("public_key", validator)
                        .spawn(move |_| async move {
                            while latest.get() < required_containers {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        }),
                );
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        if config.is_valid() {
            // Feedback stays behind the validity gate (like protocol-state
            // coverage): invalid configurations never reach the invariant
            // checks, so their interleavings must not be retained as novel.
            let hb_summary = hb_log.as_ref().map(|log| log.summary());
            if let Some(summary) = &hb_summary {
                let mut tokens = summary.tokens();
                if let Some(bucket) = summary.dispersion_bucket() {
                    tokens.insert(format!("hb:dispersion={bucket}"));
                }
                tokens.extend(summary.lsh_tokens());
                state_cov::observe_tokens(tokens);
            }
            let reporter_only: Vec<_> = reporters.iter().map(|(_, r)| r.clone()).collect();
            invariants::check_no_invalid_reports_if_no_faults(config.faults, &reporter_only);
            invariants::check_vote_invariants(
                config.faults as usize,
                P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
                Epoch::new(EPOCH),
                term_length,
                &reporter_only,
            );
            let reporter_states = (state_coverage || collect_audit)
                .then(|| state_cov::encode_reporter_states(&reporter_only, config.n as usize));
            if state_coverage {
                let metrics = context.encode();
                state_cov::observe_with_metrics(
                    reporter_states
                        .as_ref()
                        .expect("state coverage needs reporter states"),
                    &metrics,
                );
            }
            let audit = collect_audit.then(|| RunAudit {
                auditor_state: context.auditor().state(),
                reporter_states: reporter_states.unwrap_or_default(),
                happens_before: hb_summary,
            });
            let states = invariants::extract(reporter_only, config.n as usize);
            invariants::check::<P>(config, term_length, states);
            audit
        } else {
            None
        }
    })
}

/// Run the Standard harness with append-only Simplex activity and automaton
/// recording enabled.
///
/// This path exists only for the dedicated Standard audit fuzz targets. The
/// shared [`run_standard_once`] path continues to use the consensus mock
/// reporter and application automaton directly.
#[derive(Clone)]
struct NotarizeOmission {
    victim: usize,
    omitted_notarizes: Arc<AtomicUsize>,
    omitted_finalizations: Arc<AtomicUsize>,
}

impl NotarizeOmission {
    fn new(victim: usize) -> Self {
        Self {
            victim,
            omitted_notarizes: Arc::new(AtomicUsize::new(0)),
            omitted_finalizations: Arc::new(AtomicUsize::new(0)),
        }
    }
}

fn run_audited_standard_once<P: simplex::Simplex>(input: FuzzInput) -> (bool, bool) {
    run_audited_standard_once_with::<P>(input, None)
}

fn run_audited_standard_once_with<P: simplex::Simplex>(
    mut input: FuzzInput,
    notarize_omission: Option<NotarizeOmission>,
) -> (bool, bool) {
    let cfg = bounded_fuzz_runtime_config(&input.raw_bytes, input.required_containers, 0);
    let executor = deterministic::Runner::new(cfg);

    executor.start(move |mut context| async move {
        if matches!(input.partition, Partition::Adaptive(_)) {
            input.partition = Partition::Adaptive(network_faults(
                input.strategy,
                input.required_containers,
                &mut context,
            ));
        }

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let initial_partition = initial_network_partition(&input.partition);
        if initial_partition.is_some() {
            apply_partition(
                &oracle,
                &participants,
                initial_partition.as_ref(),
                &default_link(),
            )
            .await;
        }

        let relay = Arc::new(block_relay::Relay::new());
        // A withheld block should hold certification pending only for the
        // DropRecipient scenario (whose liveness is left unbounded); other
        // runs certify per the Certifier as the upstream mock does.
        relay.set_certify_requires_block(matches!(
            input.block_filter,
            BlockFilterChoice::DropRecipient { .. }
        ));
        configure_block_filter::<P>(&relay, &participants, &input.partition, input.block_filter);
        let mut reporters = Vec::new();
        let config = input.configuration;
        let term_length = P::effective_term_length(input.term_length);

        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            if matches!(input.certify, CertifyChoice::RejectView { .. }) {
                // A Byzantine participant may behave correctly. For the audit
                // rejection campaign, run its normal engine so the designated
                // Byzantine-led view reliably has a well-formed proposal. Its
                // application always certifies its own proposal, while all
                // correct applications consistently reject it. Its raw reporter
                // is intentionally excluded from the correct audit set below.
                let (pending, recovered, resolver) = channels;
                let _ = spawn_filtered_honest_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator,
                    P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    CertifyChoice::Always,
                    ReporterWiring::Solo,
                );
            } else {
                spawn_disrupter_with_relay::<P>(
                    ctx,
                    schemes[i].clone(),
                    &input,
                    channels,
                    Some(relay.clone()),
                );
            }
        }

        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let reporter = if let Some(omission) = &notarize_omission
                && omission.victim == i
            {
                let (sender, receiver) = pending;
                let receiver = NotarizeOmissionReceiver::<P::Scheme, Sha256Digest, _>::new(
                    receiver,
                    omission.omitted_notarizes.clone(),
                );
                let (certificate_sender, certificate_receiver) = recovered;
                let certificate_receiver =
                    FinalizationOmissionReceiver::<P::Scheme, Sha256Digest, _>::new(
                        certificate_receiver,
                        schemes[i].clone(),
                        FinalizationOmissionChannel::Certificate,
                        omission.omitted_finalizations.clone(),
                    );
                let (resolver_sender, resolver_receiver) = resolver;
                let resolver_receiver =
                    FinalizationOmissionReceiver::<P::Scheme, Sha256Digest, _>::new(
                        resolver_receiver,
                        schemes[i].clone(),
                        FinalizationOmissionChannel::Resolver,
                        omission.omitted_finalizations.clone(),
                    );
                spawn_filtered_audited_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator.clone(),
                    P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.forwarding,
                    (sender, receiver),
                    (certificate_sender, certificate_receiver),
                    (resolver_sender, resolver_receiver),
                    input.certify,
                    input.reporting,
                )
            } else {
                spawn_filtered_audited_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator.clone(),
                    P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    input.certify,
                    input.reporting,
                )
            };
            reporters.push((validator, reporter));
        }

        spawn_network_fault_scheduler::<P, _>(
            &context,
            &oracle,
            &participants,
            &mut reporters,
            input.partition.clone(),
            input.required_containers,
            initial_partition,
        )
        .await;

        if should_bound_standard_liveness(&input) {
            let mut finalizers = Vec::new();
            let omitted_validator = notarize_omission
                .as_ref()
                .map(|omission| &participants[omission.victim]);
            for (validator, reporter) in reporters.iter_mut() {
                if omitted_validator == Some(validator) {
                    continue;
                }
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(
                    context
                        .child("finalizer")
                        .with_attribute("public_key", validator)
                        .spawn(move |_| async move {
                            while latest.get() < required_containers {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        }),
                );
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        if !config.is_valid() {
            return (false, false);
        }

        let omitted_reporter = notarize_omission.as_ref().and_then(|omission| {
            let victim = &participants[omission.victim];
            reporters
                .iter()
                .position(|(validator, _)| validator == victim)
        });
        let reporter_only: Vec<_> = reporters
            .into_iter()
            .map(|(_, reporter)| reporter)
            .collect();
        let summary_reporters = summaries(&reporter_only);
        let rejected_certification_observed = reporter_only.iter().any(|reporter| {
            reporter.audit().events().iter().any(|recorded| {
                matches!(
                    &recorded.event,
                    simplex_audit::Event::Automaton(
                        simplex_audit::AutomatonEvent::CertifyCompleted {
                            outcome: simplex_audit::Completion::Returned(false),
                            ..
                        }
                    )
                )
            })
        });
        invariants::check_no_invalid_reports_if_no_faults(config.faults, &summary_reporters);
        let byzantine: HashSet<usize> = if matches!(input.certify, CertifyChoice::RejectView { .. })
        {
            HashSet::new()
        } else {
            (0..config.faults as usize).collect()
        };
        invariants::check_vote_invariants_with_byzantine(
            &byzantine,
            P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
            Epoch::new(EPOCH),
            term_length,
            &summary_reporters,
        );
        invariants::check::<P>(config, term_length, reporter_only.as_slice());
        if let Some(index) = omitted_reporter {
            // The finalizer wait excludes the victim, so a recovery whose
            // trigger is already in its log can still be in flight between
            // batcher and voter. Recovery is message-driven: one quiescing
            // sleep drains it, and only a recovery pending across both
            // snapshots is genuinely stuck.
            let earlier = invariants::unresolved_finalize_recoveries(&reporter_only[index]);
            if !earlier.is_empty() {
                context.sleep(MAX_SLEEP_DURATION).await;
                invariants::check_finalize_recoveries_drained(&reporter_only[index], &earlier);
            }
        }
        (true, rejected_certification_observed)
    })
}

fn run<P: simplex::Simplex>(input: FuzzInput, state_coverage: bool, happens_before: bool) {
    if state_coverage || happens_before {
        state_cov::reset();
    }
    if happens_before {
        if state_coverage {
            // Per-node subscribers shadow the collector for validator tasks, so
            // its dispatch is teed through them to keep trace-event tokens fed.
            let _ = run_with_warn_trace_collection(|dispatch| {
                run_standard_once::<P>(input, true, false, true, Some(dispatch.clone()))
            });
        } else {
            let _ = run_standard_once::<P>(input, false, false, true, None);
        }
    } else if state_coverage {
        let _ = run_with_warn_trace_collection(|_| {
            run_standard_once::<P>(input, true, false, false, None)
        });
    } else {
        let _ = run_standard_once::<P>(input, false, false, false, None);
    }
}

/// Role of the secondary half in a twin pair.
#[derive(Clone, Copy)]
enum TwinsRole {
    /// Secondary runs `Disrupter` over `input.strategy` (TwinsMutator mode).
    /// Liveness wait uses absolute view targets.
    Mutator,
    /// Secondary runs a full legitimate engine and contributes a reporter
    /// (TwinsCampaign mode). Liveness wait counts finalizations *after* the
    /// adversarial prefix.
    Campaign,
}

fn run_with_twins_mutator<P: simplex::Simplex>(
    input: FuzzInput,
    state_coverage: bool,
    happens_before: bool,
) {
    let _ = run_twins::<P>(
        input,
        TwinsRole::Mutator,
        state_coverage,
        happens_before,
        false,
    );
}

fn run_with_twins_campaign<P: simplex::Simplex>(
    input: FuzzInput,
    state_coverage: bool,
    happens_before: bool,
) {
    let _ = run_twins::<P>(
        input,
        TwinsRole::Campaign,
        state_coverage,
        happens_before,
        false,
    );
}

struct MockTwinsBackend<P: simplex::Simplex> {
    input: FuzzInput,
    role: TwinsRole,
    state_coverage: bool,
    record_audit: bool,
    hb_log: Option<happens_before::capture::EventLog>,
    warn_dispatch: Option<Dispatch>,
    _marker: std::marker::PhantomData<fn() -> P>,
}

struct MockTwinsState<P: simplex::Simplex> {
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    reporters: Vec<TwinsReporter<P>>,
    twin_observers: Vec<TwinsReporter<P>>,
    honest_start: usize,
}

impl<P: simplex::Simplex> MockTwinsBackend<P> {
    fn new(
        input: FuzzInput,
        role: TwinsRole,
        state_coverage: bool,
        record_audit: bool,
        hb_log: Option<happens_before::capture::EventLog>,
        warn_dispatch: Option<Dispatch>,
    ) -> Self {
        Self {
            input,
            role,
            state_coverage,
            record_audit,
            hb_log,
            warn_dispatch,
            _marker: std::marker::PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_twin_engine(
        &self,
        context: deterministic::Context,
        state: &MockTwinsState<P>,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, ()>,
        partition: String,
        relay_tag: u64,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) -> reporter::Reporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest> {
        let reporter_cfg = reporter::Config {
            participants: participants
                .as_ref()
                .try_into()
                .expect("public keys are unique"),
            scheme: scheme.clone(),
            elector: topology.elector.clone(),
        };
        let reporter = reporter::Reporter::new(context.child("reporter"), reporter_cfg);
        let app_cfg = block_relay::Config::<_> {
            relay: state.relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: application::Certifier::Always,
        };
        let (actor, application) = block_relay::Application::new_with_relay_tag(
            context.child("application"),
            app_cfg,
            relay_tag,
        );
        actor.start();
        let engine = Engine::new(
            context.child("engine"),
            config::Config {
                blocker: oracle.control(validator),
                scheme,
                elector: topology.elector.clone(),
                automaton: application.clone(),
                relay: application,
                reporter: reporter.clone(),
                partition,
                mailbox_size: self.input.mailbox_size,
                epoch: Epoch::new(EPOCH),
                floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(EPOCH))),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_millis(1_500),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                view_retention: Delta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(11),
                    budget: SkipBudget::Participants,
                },
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forward: self.input.forwarding,
                track_historical_votes: false,
            },
        );
        engine.start(vote, certificate, resolver);
        let _ = idx;
        reporter
    }
}

impl<P: simplex::Simplex> TwinsBackend<P> for MockTwinsBackend<P> {
    type State = MockTwinsState<P>;
    type Case = ();
    type Digest = Sha256Digest;

    async fn setup(&mut self, context: &mut deterministic::Context) -> TwinsSetup<P, Self::State> {
        let (mut oracle, participants, schemes, registrations) =
            setup_network::<P>(context, &self.input).await;
        link_peers(
            &mut oracle,
            &participants,
            Action::Update(Link {
                latency: Duration::from_millis(500),
                jitter: Duration::from_millis(500),
                success_rate: probability!(1.0),
            }),
            self.input.partition.set_partition(),
        )
        .await;
        TwinsSetup {
            oracle,
            participants,
            schemes,
            registrations,
            state: MockTwinsState {
                relay: Arc::new(block_relay::Relay::new()),
                reporters: Vec::new(),
                twin_observers: Vec::new(),
                honest_start: 0,
            },
        }
    }

    fn term_length(&self) -> TermLength {
        P::effective_term_length(self.input.term_length)
    }

    fn framework(&mut self, rng: &mut FuzzRng, participants: usize) -> twins::Framework {
        let mode = if rand::RngExt::random_bool(rng, 0.5) {
            twins::Mode::Sampled
        } else {
            twins::Mode::Sustained
        };
        twins::Framework {
            participants,
            faults: self.input.configuration.faults as usize,
            rounds: self.input.required_containers.clamp(1, TWINS_MAX_ROUNDS) as usize,
            mode,
            max_cases: 16,
        }
    }

    fn select_case(
        &mut self,
        rng: &mut FuzzRng,
        _participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>> {
        if cases.is_empty() {
            return None;
        }
        let case_idx = rand::RngExt::random_range(rng, 0..cases.len());
        let case = cases.into_iter().nth(case_idx)?;
        Some(TwinsCase {
            scenario: case.scenario,
            compromised: case.compromised,
            data: (),
        })
    }

    fn configure_topology(
        &mut self,
        state: &mut Self::State,
        topology: &TwinsTopology<P, Self::Case>,
        participants: &Arc<[PublicKeyOf<P>]>,
    ) {
        let scenario = topology.scenario.clone();
        let term_length = topology.term_length;
        let participants = participants.clone();
        state.relay.set_filter(
            move |sender, sender_tag, recipient, recipient_tag, _, contents| {
                let Some(view) = block_relay::mock_block_view(contents) else {
                    return true;
                };
                if !participants.iter().any(|participant| participant == sender) {
                    return true;
                }
                let (primary, secondary) =
                    scenario.partitions(view, term_length, participants.as_ref());
                let sender_permits_recipient = match sender_tag {
                    Some(block_relay::RELAY_TAG_TWIN_PRIMARY) => primary.contains(recipient),
                    Some(block_relay::RELAY_TAG_TWIN_SECONDARY) => secondary.contains(recipient),
                    _ => true,
                };
                if !sender_permits_recipient {
                    return false;
                }

                match recipient_tag {
                    block_relay::RELAY_TAG_TWIN_PRIMARY => matches!(
                        scenario.route(view, term_length, sender, participants.as_ref()),
                        SplitTarget::Primary | SplitTarget::Both
                    ),
                    block_relay::RELAY_TAG_TWIN_SECONDARY => matches!(
                        scenario.route(view, term_length, sender, participants.as_ref()),
                        SplitTarget::Secondary | SplitTarget::Both
                    ),
                    _ => true,
                }
            },
        );
    }

    fn spawn_primary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        let reporter = self.spawn_twin_engine(
            context,
            state,
            oracle,
            participants,
            scheme,
            validator,
            idx,
            topology,
            format!("twin_{idx}_primary"),
            block_relay::RELAY_TAG_TWIN_PRIMARY,
            vote,
            certificate,
            resolver,
        );
        match self.role {
            TwinsRole::Campaign => state.reporters.push(TwinsReporter::Summary(reporter)),
            TwinsRole::Mutator => state.twin_observers.push(TwinsReporter::Summary(reporter)),
        }
    }

    fn disrupter(&self) -> Option<TwinsDisrupter> {
        (matches!(self.role, TwinsRole::Mutator)).then_some(TwinsDisrupter {
            strategy: self.input.strategy,
            required_containers: self.input.required_containers,
            epoch: Epoch::new(EPOCH),
        })
    }

    fn disrupter_block_relay(
        &self,
        state: &Self::State,
    ) -> Option<Arc<block_relay::Relay<PublicKeyOf<P>>>> {
        Some(state.relay.clone())
    }

    fn disrupter_block_relay_tag(&self) -> Option<u64> {
        Some(block_relay::RELAY_TAG_TWIN_SECONDARY)
    }

    fn spawn_secondary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        assert!(
            matches!(self.role, TwinsRole::Campaign),
            "mock secondary engine is only used by TwinsCampaign"
        );
        let reporter = self.spawn_twin_engine(
            context,
            state,
            oracle,
            participants,
            scheme,
            validator,
            idx,
            topology,
            format!("twin_{idx}_secondary"),
            block_relay::RELAY_TAG_TWIN_SECONDARY,
            vote,
            certificate,
            resolver,
        );
        state.reporters.push(TwinsReporter::Summary(reporter));
    }

    fn finish_twins(&mut self, state: &mut Self::State, _topology: &TwinsTopology<P, Self::Case>) {
        state.honest_start = state.reporters.len();
    }

    fn spawn_honest(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        channels: NetworkChannels<PublicKeyOf<P>>,
    ) {
        let ambiguous: Arc<[u32]> = {
            let mut indices = topology
                .compromised
                .iter()
                .map(|&index| index as u32)
                .collect::<Vec<_>>();
            indices.sort_unstable();
            indices.into()
        };
        let (pending, recovered, resolver) = channels;
        let pending = {
            let (vote_sender, vote_receiver) = pending;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                vote_sender,
                SniffingReceiver::<P, _>::new(vote_receiver, SniffChannel::Vote, cfg, sink),
            )
        };
        let recovered = {
            let (cert_sender, cert_receiver) = recovered;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                cert_sender,
                SniffingReceiver::<P, _>::new(cert_receiver, SniffChannel::Certificate, cfg, sink),
            )
        };
        let resolver = {
            let (backfill_sender, backfill_receiver) = resolver;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                backfill_sender,
                SniffingReceiver::<P, _>::new(backfill_receiver, SniffChannel::Resolver, cfg, sink),
            )
        };
        let spawn = || {
            if self.record_audit {
                TwinsReporter::Recording(
                    spawn_filtered_audited_validator::<P, _, _, _, _, _, _, _>(
                        context,
                        oracle,
                        participants.as_ref(),
                        scheme,
                        validator,
                        topology.elector.clone(),
                        state.relay.clone(),
                        Duration::from_secs(1),
                        Duration::from_millis(1_500),
                        self.input.mailbox_size,
                        self.input.forwarding,
                        pending,
                        recovered,
                        resolver,
                        self.input.certify,
                        self.input.reporting,
                    ),
                )
            } else {
                TwinsReporter::Summary(spawn_filtered_honest_validator::<P, _, _, _, _, _, _, _>(
                    context,
                    oracle,
                    participants.as_ref(),
                    scheme,
                    validator,
                    topology.elector.clone(),
                    state.relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_millis(1_500),
                    self.input.mailbox_size,
                    self.input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    self.input.certify,
                    self.input.reporting,
                ))
            }
        };
        let reporter = match &self.hb_log {
            Some(log) => {
                let mut subscriber =
                    happens_before::capture::NodeSubscriber::new(idx as u32, log.clone());
                if let Some(inner) = &self.warn_dispatch {
                    subscriber = subscriber.with_inner(inner.clone());
                }
                let dispatch = Dispatch::new(subscriber);
                dispatcher::with_default(&dispatch, spawn)
            }
            None => spawn(),
        };
        state.reporters.push(reporter);
    }

    async fn observe_liveness(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        prefix_end: View,
    ) {
        if !self.input.configuration.is_valid() || matches!(self.role, TwinsRole::Mutator) {
            context.sleep(MAX_SLEEP_DURATION).await;
            return;
        }
        let mut finalizers = Vec::new();
        for (i, reporter) in state
            .reporters
            .iter_mut()
            .skip(state.honest_start)
            .enumerate()
        {
            let required = self.input.required_containers;
            match self.role {
                TwinsRole::Mutator => {
                    let (mut latest, mut monitor): (View, Receiver<View>) =
                        reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").with_attribute("index", i).spawn(
                        move |_| async move {
                            while latest.get() < required {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        },
                    ));
                }
                TwinsRole::Campaign => {
                    let (_latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").with_attribute("index", i).spawn(
                        move |_| async move {
                            let mut count = 0u64;
                            while count < required {
                                let view = monitor.recv().await.expect("event missing");
                                if view > prefix_end {
                                    count += 1;
                                }
                            }
                        },
                    ));
                }
            }
        }
        join_all(finalizers).await;
    }

    fn check_invariants(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        topology: &TwinsTopology<P, Self::Case>,
    ) {
        let config = self.input.configuration;
        if !config.is_valid() {
            return;
        }
        if let Some(log) = &self.hb_log {
            let summary = log.summary();
            let mut tokens = summary.tokens();
            if let Some(bucket) = summary.dispersion_bucket() {
                tokens.insert(format!("hb:dispersion={bucket}"));
            }
            tokens.extend(summary.lsh_tokens());
            state_cov::observe_tokens(tokens);
        }
        let honest_reporters = &state.reporters[state.honest_start..];
        let honest_summaries = honest_reporters
            .iter()
            .map(TwinsReporter::summary)
            .collect::<Vec<_>>();
        let observers = state
            .twin_observers
            .iter()
            .chain(state.reporters.iter())
            .map(TwinsReporter::summary)
            .collect::<Vec<_>>();
        invariants::check_vote_invariants_with_byzantine(
            &topology.compromised,
            topology.elector.clone(),
            Epoch::new(EPOCH),
            topology.term_length,
            &observers,
        );
        if self.state_coverage {
            let reporter_states =
                state_cov::encode_reporter_states(&honest_summaries, config.n as usize);
            state_cov::observe_with_metrics(&reporter_states, &context.encode());
        }
        if self.record_audit {
            let recordings = honest_reporters
                .iter()
                .filter_map(TwinsReporter::recording)
                .collect::<Vec<_>>();
            assert_eq!(
                recordings.len(),
                honest_reporters.len(),
                "every correct Twins reporter must record in audit mode"
            );
            invariants::check::<P>(config, topology.term_length, recordings.as_slice());
        } else {
            invariants::check::<P>(
                config,
                topology.term_length,
                invariants::extract(honest_summaries, config.n as usize),
            );
        }
    }
}

/// Unified twins driver. The two existing modes (TwinsMutator / TwinsCampaign)
/// share scenario sampling, forwarders/routers, twin-half splitting, the
/// primary engine, the honest validators, and the byzantine-aware invariants.
/// Only the secondary half (Disrupter vs full engine) and the liveness wait
/// shape (absolute view vs prefix-trailing count) differ; both are keyed on
/// `role`. Liveness and state extraction run over honest reporters only;
/// signer-filtered vote/fault checks also observe twin reporters (Campaign
/// halves and the retained Mutator primary).
///
/// Happens-before capture covers honest validators only: twin halves share
/// one identity across two engines, so neither tracing attribution nor
/// sender-resolved merges are sound for them; honest receives from a twin
/// resolve to no sender. When `record_audit` is true, only correct engines use
/// the append-only reporter and automaton wrappers. Returns the summary when
/// capture is enabled.
fn run_twins<P: simplex::Simplex>(
    mut input: FuzzInput,
    role: TwinsRole,
    state_coverage: bool,
    happens_before: bool,
    record_audit: bool,
) -> Option<happens_before::Summary> {
    if state_coverage || happens_before {
        state_cov::reset();
    }
    input.partition = Partition::Connected;
    input.configuration = N4F1C3;
    // Twins reuse the standard input; a certify variant sampled for an
    // all-honest configuration would stall this quorum-tight one.
    input.certify = CertifyChoice::Always;

    let cfg = bounded_fuzz_runtime_config(
        &input.raw_bytes,
        input.required_containers,
        twins_prefix_views(
            input.required_containers,
            P::effective_term_length(input.term_length),
        ),
    );
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before.then(happens_before::capture::EventLog::new);

    let hb_log_run = hb_log.clone();
    let execute = |warn_dispatch: Option<Dispatch>| {
        executor.start(|mut context| async move {
            let scenario_entropy = input.raw_bytes.clone();
            let mut backend = MockTwinsBackend::<P>::new(
                input,
                role,
                state_coverage,
                record_audit,
                hb_log_run,
                warn_dispatch,
            );
            run_twins_with_backend::<P, _>(&mut context, &mut backend, scenario_entropy).await;
        });
    };

    if happens_before {
        if state_coverage {
            // Per-node subscribers shadow the collector for validator tasks, so
            // its dispatch is teed through them to keep trace-event tokens fed.
            run_with_warn_trace_collection(|dispatch| execute(Some(dispatch.clone())));
        } else {
            execute(None);
        }
    } else if state_coverage {
        run_with_warn_trace_collection(|_| execute(None));
    } else {
        execute(None);
    }

    // Tokens are observed inside `execute` (before the invariant checks) so a
    // bug-finding panic still credits its interleaving. Here we only surface the
    // summary for the return value.
    hb_log.as_ref().map(|log| log.summary())
}

pub trait FuzzMode {
    const MODE: Mode;
}

/// Whether a harness run also emits protocol-state coverage feedback.
///
/// Orthogonal to [`FuzzMode`]: any honest-reporter mode (Standard, FaultyNet,
/// TwinsMutator, TwinsCampaign) can run with or without the [`state_cov`] signal.
pub trait Coverage {
    /// When `true`, the run projects its honest reporters through
    /// [`state_cov::observe_with_metrics`] so libFuzzer also tracks protocol-state novelty.
    const STATE: bool;
    /// When `true`, per-node subscribers capture a happens-before summary of the run
    /// (see [`happens_before`]) and fold its causal-pair tokens into the same table.
    const HAPPENS_BEFORE: bool = false;
}

/// Only libFuzzer's default code-edge coverage; no protocol-state feedback (the
/// baseline).
pub struct CodeCoverage;
impl Coverage for CodeCoverage {
    const STATE: bool = false;
}

/// Protocol-state coverage feedback enabled (see [`state_cov`]).
pub struct StateCoverage;
impl Coverage for StateCoverage {
    const STATE: bool = true;
}

/// Happens-before coverage only: per-node causal-interleaving novelty without the
/// protocol-state signal (see [`happens_before`]). The baseline HB target.
pub struct HappensBeforeCoverage;
impl Coverage for HappensBeforeCoverage {
    const STATE: bool = false;
    const HAPPENS_BEFORE: bool = true;
}

/// Happens-before coverage layered on top of the protocol-state signal: both feed
/// the same table so their contributions combine (see [`happens_before`] and
/// [`state_cov`]).
pub struct HappensBeforeStateCoverage;
impl Coverage for HappensBeforeStateCoverage {
    const STATE: bool = true;
    const HAPPENS_BEFORE: bool = true;
}

/// **Standard mode** - the baseline harness.
///
/// Configured byzantine validators run as `Disrupter` (mutating outgoing messages
/// per `input.strategy`); the remaining validators run honestly. Network
/// topology follows `input.partition` (`Connected`, a `Static` set partition,
/// or an `Adaptive` round-indexed schedule).
///
/// Use this for general protocol-level fuzzing of consensus under byzantine
/// message mutations and optional partition faults.
pub struct Standard;
impl FuzzMode for Standard {
    const MODE: Mode = Mode::Standard;
}

/// **TwinsMutator mode** - twin pairs with a `Disrupter` on the secondary half.
///
/// Each compromised participant (from a sampled `twins::cases` scenario) runs
/// two halves: a legitimate primary engine and a secondary `Disrupter` that
/// equivocates per `input.strategy`. The two halves see different network
/// views per the scenario's per-round partitions, and all engines use the
/// twins-aware elector for scripted leaders.
///
/// Use this to fuzz byzantine *content* mutations layered on top of twins-style
/// network splits.
pub struct TwinsMutator;
impl FuzzMode for TwinsMutator {
    const MODE: Mode = Mode::TwinsMutator;
}

/// **TwinsCampaign mode** - twin pairs where both halves are full engines.
///
/// Mirrors `consensus/src/simplex/mod.rs::twins_campaign`: no `Disrupter`,
/// both halves run as legitimate engines under the twins-aware elector and
/// see different network partitions per round. Liveness counts finalizations
/// only past the adversarial prefix; safety invariants run only over honest
/// reporters.
pub struct TwinsCampaign;
impl FuzzMode for TwinsCampaign {
    const MODE: Mode = Mode::TwinsCampaign;
}

/// **FaultyNet mode** - round-indexed set-partition faults at the network layer.
///
/// Coerces `input.partition` to `Adaptive(_)` so the per-view fault scheduler
/// activates a sampled `SetPartition` for each scheduled view, reverting to
/// fully connected outside scheduled views. Each strategy guarantees at least
/// one entry, so every run exercises an actual partition window.
pub struct FaultyNet;
impl FuzzMode for FaultyNet {
    const MODE: Mode = Mode::FaultyNet;
}

/// **Byzzfuzz mode** - sampled network and process faults checked against
/// safety *and* liveness on every run.
///
/// Runs four honest engines plus a per-message intercept layer. Faults are
/// sampled per iteration:
/// - **Network faults**: a schedule of `(view, partition)` entries. At a
///   scheduled view, traffic across partition blocks is dropped on every
///   channel (vote, certificate, resolver, even undecodable bytes); outside
///   scheduled views the topology is fully connected.
/// - **Process faults**: a fixed byzantine identity (always at index 0),
///   whose outgoing protocol messages are intercepted per a schedule of
///   `(view, receivers, action, message_scope)` entries. `message_scope`
///   optionally narrows a fault to a specific channel + message kind (e.g.
///   only Notarize votes); `Any` does not narrow the channel/kind. `action`
///   either omits targeted delivery or semantically mutates a vote and
///   re-signs it under the byzantine identity. Certificate and resolver
///   process faults are omit-only.
///
/// Round attribution uses each message sender's current protocol round
/// (the maximum view that sender has sent or received) for network faults.
/// Process faults use the decoded view carried by the byzantine message
/// itself. Retransmissions of an old view at a later sender round can be
/// filtered by that later round's network partition, but they do not inherit
/// process faults scheduled for the later round.
///
/// Network faults apply during a bounded fault phase. If all non-byzantine
/// reporters reach `required_containers` during that phase, the run skips GST
/// and proceeds to safety checks. Otherwise, the shared fault gate reaches GST:
/// partitions pass through, but the byzantine sender keeps mutating/omitting
/// its own messages under the same `(view, receivers, action, scope)` schedule
/// extended with a fresh post-GST view budget. Each non-byzantine reporter
/// below `required_containers` at GST must reach `required_containers`; each
/// reporter already at or above it must finalize above its baseline. Failure to
/// reach the post-GST target panics with a liveness violation. See
/// [`byzzfuzz::run`].
pub struct Byzzfuzz;
impl FuzzMode for Byzzfuzz {
    const MODE: Mode = Mode::Byzzfuzz;
}

/// **Mallory** - the dedicated adaptive-adversary runner over its own fault catalog,
/// bounded by a whole-episode CONTAINER (distinct-finalization) budget.
///
/// Each episode selects one adversary environment for the faultable identity
/// (node 0): honest, or one of six Byzantine profiles (Disrupter, Conflicter,
/// Nuller, Equivocator, Impersonator, Outdated). It then drives a reactive loop of
/// observe-orient-decide-act steps. Each step observes the honest happens-before
/// fingerprint (the Q-state) and protocol-state descriptor, then decodes the step's
/// fault from the input's action byte against a legal mask over the stable catalog
/// (`mallory::fault`); the Q-state feeds the update and the recorded trace, never a
/// runtime selection. The fault is a
/// network (isolation, partition), packet (delay/loss/corrupt/duplicate/reorder), or
/// lifecycle (crash-stop, durable restart, amnesia restart) fault. It applies the
/// fault, then reacts: the step ends on the first new honest finalization past its
/// baseline, or a deterministic per-action timeout if the fault suppressed progress.
/// The fault heals and (under the input chooser, which updates the campaign but
/// never selects from it) a temporal-difference update rewards
/// novel state and happens-before fingerprints (the pre-heal fault effect) via the
/// backend-agnostic Q-core in `mallory::policy`. The whole episode stops once it has
/// observed the input's `required_containers` distinct finalization boundaries (each
/// step counts at most one; view jumps and duplicate reports count once), or when it
/// hits the `max(MALLORY_EPISODE_STEPS, required_containers)` truncation cap. A
/// crash-stop is permanent but does NOT end the episode: the loop continues over the
/// surviving quorum. Mallory does not reuse the ByzzFuzz fault machinery: it builds
/// its own setup from the shared harness helpers and never samples ByzzFuzz
/// `(c, d, r)`.
///
/// The episode-end oracle checks liveness (each live correct node must finalize past
/// its pre-heal frontier) and the vote / state-extraction safety invariants. It runs
/// over the episode's honest reporter set, excluding an unmanaged Byzantine node 0, a
/// crash-stopped node from liveness, and an amnesiac node from the honest set. The
/// role and every step's fault are a prefix of `raw_bytes`, so an input replays
/// its episode exactly; the learned campaign only steers the target's custom
/// mutator ([`mallory_mutate`]). The name is kept as `MalloryContainer` to avoid
/// target / API churn. See `mallory::runner::run`.
pub struct MalloryContainer;

/// Announce the raw bytes of the Mallory input about to run, so the episode's
/// trace is recorded under the key [`mallory_mutate`] looks up for those bytes.
/// The Mallory fuzz target calls this before [`fuzz`].
pub fn mallory_observe_input(data: &[u8]) {
    mallory::mutator::set_current_input(data);
}

/// The Mallory custom libFuzzer mutator body (see `mallory::mutator`): rewrites the
/// parent's schedule prefix by the campaign's learned policy, or defers to
/// libFuzzer's default mutator. Wire it with `libfuzzer_sys::fuzz_mutator!`.
pub fn mallory_mutate(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    mallory::mutator::mutate(data, size, max_size, seed)
}
impl FuzzMode for MalloryContainer {
    const MODE: Mode = Mode::MalloryContainer;
}

/// **Chaos** - an all-honest committee under a fuzzer-driven crash/network
/// fault schedule, adapted from the zksync-os-server chaos rig.
///
/// Each episode runs four honest validators (N4F0C4, quorum three) and drives a
/// reactive loop: each step draws one action (kill, durable restart, bounded
/// reload, per-node disconnect, reconnect) from a pure quorum-aware schedule
/// seeded entirely by the fuzzer input. The schedule never takes the healthy
/// set below quorum except through a rare, deliberately sanctioned and bounded
/// outage window, and every fault is scheduled together with its own heal, so
/// it never permanently wedges the cluster. Chaos checks SAFETY only: the
/// `invariants` suite runs at EVERY step boundary with an EMPTY Byzantine set
/// (everyone is honest, so any conflicting finalization, equivocation, fault
/// evidence, or invalid report is a finding the moment it appears), plus a
/// step-level finalized-payload-uniqueness check over the reporters'
/// append-only finalize-vote maps. It asserts no liveness. Chaos keeps no
/// cross-input state, so replaying a saved input reproduces the run exactly.
/// See `chaos`.
pub struct Chaos;
impl FuzzMode for Chaos {
    const MODE: Mode = Mode::Chaos;
}

/// **ChaosTwins** - a real N4F1C3 cluster with one Byzantine twin leader and
/// three honest engines, one of which crash-stops and durably replays while the
/// twin equivocates. Checks SAFETY throughout (the twin excluded as the
/// Byzantine signer) and a bounded POST-RECOVERY LIVENESS target once the
/// scripted prefix ends and the node rejoins. Reuses the twins split model,
/// chaos's crash/restart, and byzzfuzz's liveness wait. Seeded solely from the
/// input, so a saved input replays exactly. See `chaos::twins`.
pub struct ChaosTwins;
impl FuzzMode for ChaosTwins {
    const MODE: Mode = Mode::ChaosTwins;
}

/// Install (once per process) a panic-hook chain that drains and prints the
/// ByzzFuzz decision log when the `CONSENSUS_FUZZ_LOG` environment variable is
/// set (any value). Off by default to keep the libfuzzer crash output
/// terse. The log is dumped *before* the previous hook runs: libfuzzer-sys
/// installs a panic hook that prints + `abort()`s the process, so anything
/// queued after it would never reach the terminal. With this ordering the
/// output reads: log -> default panic message -> libfuzzer stack trace /
/// `Failing input` / `Debug`.
fn install_byzzfuzz_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        // Sample the env var once at install time -- the hook itself runs
        // in panic context and shouldn't touch global env state.
        let dump = std::env::var_os(FUZZ_LOG_ENV).is_some();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if dump {
                let log = byzzfuzz::log::take();
                if !log.is_empty() {
                    eprintln!("---- ByzzFuzz decision log ({} entries) ----", log.len());
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("---- end of ByzzFuzz decision log ----");
                }
            }
            prev(info);
        }));
    });
}

/// Install (once per process) a panic-hook chain that drains and prints the
/// chaos decision log when `CONSENSUS_FUZZ_LOG` is set (any value). Mirrors
/// [`install_byzzfuzz_panic_hook`] over the separate chaos log; the same
/// ordering (log -> default message -> libfuzzer trace) applies.
fn install_chaos_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let dump = std::env::var_os(FUZZ_LOG_ENV).is_some();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if dump {
                let log = chaos::log::take();
                if !log.is_empty() {
                    eprintln!("---- Chaos decision log ({} entries) ----", log.len());
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("---- end of Chaos decision log ----");
                }
            }
            prev(info);
        }));
    });
}

/// Install (once per process) a panic-hook chain that drains and prints the
/// Mallory decision log when `CONSENSUS_FUZZ_LOG` is set (any value). Mirrors
/// [`install_byzzfuzz_panic_hook`] over the separate Mallory log; the same
/// ordering (log -> default message -> libfuzzer trace) applies.
fn install_mallory_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let dump = std::env::var_os(FUZZ_LOG_ENV).is_some();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if dump {
                let log = mallory::log::take();
                if !log.is_empty() {
                    eprintln!("---- Mallory decision log ({} entries) ----", log.len());
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("---- end of Mallory decision log ----");
                }
            }
            prev(info);
        }));
    });
}

pub fn fuzz<P: simplex::Simplex, M: FuzzMode, C: Coverage>(mut input: FuzzInput) {
    if matches!(M::MODE, Mode::Byzzfuzz) {
        install_byzzfuzz_panic_hook();
    } else if matches!(M::MODE, Mode::MalloryContainer) {
        install_mallory_panic_hook();
    } else if matches!(M::MODE, Mode::Chaos | Mode::ChaosTwins) {
        install_chaos_panic_hook();
    } else {
        if matches!(M::MODE, Mode::FaultyNet) {
            // We run only fuzzing with network faults, populated later by the
            // chosen strategy.
            input.partition = Partition::Adaptive(Vec::new());
        }
        print_fuzz_input::<P>(M::MODE, &input);
    }

    let raw_bytes = input.raw_bytes.clone();
    let run_result = match M::MODE {
        Mode::Standard => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::FaultyNet => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::TwinsMutator => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_mutator::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::TwinsCampaign => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_campaign::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::Byzzfuzz => {
            panic::catch_unwind(panic::AssertUnwindSafe(|| byzzfuzz::run::<P>(input)))
        }
        Mode::MalloryContainer => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            mallory::runner::run::<P>(input, mallory::runner::Chooser::Input)
        })),
        Mode::Chaos => {
            panic::catch_unwind(panic::AssertUnwindSafe(|| chaos::runner::run::<P>(input)))
        }
        Mode::ChaosTwins => {
            panic::catch_unwind(panic::AssertUnwindSafe(|| chaos::twins::run::<P>(input)))
        }
    };
    match run_result {
        Ok(()) => {
            // Drain the byzzfuzz log on success too so a *next* run (Byzzfuzz
            // or otherwise) starts clean. This is cheap when the log is empty.
            if matches!(M::MODE, Mode::Byzzfuzz) {
                let _ = byzzfuzz::log::take();
            }
            // Same for the separate Mallory log.
            if matches!(M::MODE, Mode::MalloryContainer) {
                let _ = mallory::log::take();
            }
            // And the separate chaos log (shared by chaos and chaos-twins).
            if matches!(M::MODE, Mode::Chaos | Mode::ChaosTwins) {
                let _ = chaos::log::take();
            }
        }
        Err(payload) => {
            println!("Panicked with raw_bytes: {:?}", raw_bytes);
            // The ByzzFuzz decision log is dumped by the panic hook
            // installed in `install_byzzfuzz_panic_hook` (fires during the
            // panic itself, before unwinding reaches here). No work needed
            // in this arm.
            panic::resume_unwind(payload);
        }
    }
}

/// Fuzz the Standard Simplex harness with the append-only recording reporter
/// and recording automaton.
///
/// Unlike [`fuzz`], this is an explicit opt-in used only by dedicated audit
/// targets. It runs the same basic and vote invariants as Standard mode, then
/// dispatches the additional audit invariants through [`invariants::check`].
pub fn fuzz_audit<P: simplex::Simplex>(mut input: FuzzInput) {
    // Rejected certification is sampled only for instantiations that expose a
    // statically known Byzantine-led view. General fuzz targets never receive
    // this override, so they cannot accidentally reject a correct proposer's
    // certifiable-by-construction payload. The known Byzantine-led view assumes
    // the rotating (term length one) leader schedule, so longer terms skip it.
    if input.certify == CertifyChoice::Always
        && input.term_length == TermLength::ONE
        && input.raw_bytes.first().is_some_and(|byte| byte % 4 == 0)
        && let Some(view) = P::audit_rejection_view(input.configuration)
        && input.required_containers >= view.get()
    {
        input.certify = CertifyChoice::RejectView { view };
    }
    print_fuzz_input::<P>(Mode::Standard, &input);

    let raw_bytes = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        run_audited_standard_once::<P>(input)
    }));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes);
        panic::resume_unwind(payload);
    }
}

/// Fuzz the audited Standard harness with four correct nodes while one selected
/// node omits every notarize vote and finalization certificate received from
/// the network.
///
/// The selected victim is derived from the first raw input byte. All
/// non-notarize votes remain connected, as do notarization and nullification
/// certificates on both the certificate and resolver channels.
pub fn fuzz_audit_notarize_omission<P: simplex::Simplex>(mut input: FuzzInput) {
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;
    input.required_containers = input.required_containers.max(4);
    input.term_length = TermLength::ONE;
    input.certify = CertifyChoice::Always;
    input.reporting = ReporterWiring::Solo;

    let victim = usize::from(input.raw_bytes.first().copied().unwrap_or_default())
        % usize::try_from(input.configuration.n).expect("node count exceeds usize");
    let omission = NotarizeOmission::new(victim);
    let omitted_notarizes = omission.omitted_notarizes.clone();
    let omitted_finalizations = omission.omitted_finalizations.clone();

    print_fuzz_input::<P>(Mode::Standard, &input);
    let raw_bytes = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        run_audited_standard_once_with::<P>(input, Some(omission))
    }));
    match run_result {
        Ok(_) => assert!(
            omitted_notarizes.load(Ordering::Relaxed) > 0
                && omitted_finalizations.load(Ordering::Relaxed) > 0,
            "omission model did not omit both notarize votes and finalization certificates"
        ),
        Err(payload) => {
            println!("Panicked with raw_bytes: {:?}", raw_bytes);
            panic::resume_unwind(payload);
        }
    }
}

/// Fuzz a Twins harness while recording append-only activity and automaton
/// history for correct engines. Compromised twin halves retain the ordinary
/// summary Reporter and participate only in signer-filtered vote checks.
pub fn fuzz_twins_audit<P: simplex::Simplex, M: FuzzMode>(input: FuzzInput) {
    let role = match M::MODE {
        Mode::TwinsMutator => TwinsRole::Mutator,
        Mode::TwinsCampaign => TwinsRole::Campaign,
        mode => panic!("fuzz_twins_audit requires a Twins mode, got {mode:?}"),
    };
    print_fuzz_input::<P>(M::MODE, &input);

    let raw_bytes = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_twins::<P>(input, role, false, false, true);
    }));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes);
        panic::resume_unwind(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::ViewDelta;
    use commonware_consensus_fuzz_core::{
        DEFAULT_MAILBOX_SIZE, FUZZ_RUNTIME_TIMEOUT_FLOOR, MAX_REQUIRED_CONTAINERS, MAX_TERM_LENGTH,
        MIN_REQUIRED_CONTAINERS, NAMESPACE, fuzz_runtime_timeout, strategy::StrategyChoice,
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_utils::{NZU32, non_empty};
    use proptest::prelude::*;

    const TEST_CONTAINERS: u64 = 1000;
    const PROPERTY_TEST_CONTAINERS: u64 = 30;
    const TERM_LENGTH_BOUNDARIES: [TermLength; 2] = [TermLength::ONE, TermLength::new(NZU32!(5))];
    const SEED: u64 = 0;

    /// The deadline must outlast the costliest workload the sampler can draw.
    /// A twins campaign under stable leaders was measured at ~12s of simulated
    /// time per demanded finalization, so widening any sampled bound without
    /// revisiting the per-unit budgets must fail here rather than in the fuzzer.
    #[test]
    fn fuzz_runtime_timeout_covers_worst_sampled_workload() {
        assert_eq!(
            fuzz_runtime_timeout(MIN_REQUIRED_CONTAINERS, 0),
            FUZZ_RUNTIME_TIMEOUT_FLOOR
        );

        let prefix_views = twins_prefix_views(
            MAX_REQUIRED_CONTAINERS,
            TermLength::new(NZU32!(MAX_TERM_LENGTH)),
        );
        let worst = fuzz_runtime_timeout(MAX_REQUIRED_CONTAINERS, prefix_views);
        assert!(
            worst > FUZZ_RUNTIME_TIMEOUT_FLOOR,
            "per-workload scaling never engages inside the sampled input space"
        );
        assert!(
            worst >= Duration::from_secs(12) * MAX_REQUIRED_CONTAINERS as u32,
            "{worst:?} is below the measured cost of {MAX_REQUIRED_CONTAINERS} finalizations"
        );
    }

    fn audit_input() -> FuzzInput {
        FuzzInput {
            raw_bytes: 0u64.to_be_bytes().to_vec(),
            required_containers: MIN_REQUIRED_CONTAINERS,
            term_length: TermLength::ONE,
            optimistic_views: ViewDelta::zero(),
            heterogeneous_optimism: false,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: StrategyChoice::AnyScope,
            mailbox_size: DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardPolicy::Disabled,
            certify: CertifyChoice::Always,
            block_filter: BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    #[test]
    fn warn_trace_collection_does_not_perturb_standard_run() {
        let input = audit_input();

        let unwrapped = run_standard_once::<simplex::SimplexCertificateMock>(
            input.clone(),
            false,
            true,
            false,
            None,
        )
        .expect("valid connected run should produce audit data");
        let wrapped = run_with_warn_trace_collection(|_| {
            run_standard_once::<simplex::SimplexCertificateMock>(input, false, true, false, None)
        })
        .expect("valid connected run should produce audit data");

        assert_eq!(unwrapped.auditor_state, wrapped.auditor_state);
        assert_eq!(unwrapped.reporter_states, wrapped.reporter_states);
    }

    #[cfg(feature = "mocks")]
    #[test]
    fn audited_standard_checks_certificate_mock() {
        assert!(run_audited_standard_once::<simplex::SimplexCertificateMock>(audit_input()).0);
    }

    #[test]
    fn audited_standard_progress_wait_accepts_normal_input() {
        assert!(run_audited_standard_once::<simplex::SimplexCertificateMock>(audit_input()).0);
    }

    #[test]
    fn audited_twins_checks_campaign_and_mutator() {
        for role in [TwinsRole::Campaign, TwinsRole::Mutator] {
            let _ = run_twins::<simplex::SimplexCertificateMock>(
                audit_input(),
                role,
                false,
                false,
                true,
            );
        }
    }

    #[test]
    fn audited_standard_observes_rejected_certification() {
        let mut input = audit_input();
        input.configuration = N4F1C3;
        input.required_containers = 4;
        // With epoch 333 and four round-robin participants, view 3 is led by
        // the compromised participant at index 0. Rejecting that proposal does
        // not violate any correct proposer's certifiable-by-construction duty.
        input.certify = CertifyChoice::RejectView { view: View::new(3) };
        let (valid, rejected) = run_audited_standard_once::<simplex::SimplexCertificateMock>(input);
        assert!(valid, "audit run was not checked");
        assert!(rejected, "audit run did not reach false certification");
    }

    #[test]
    fn certify_variants_preserve_liveness_with_full_honesty() {
        // With four honest validators, disabling one certifier leaves exactly
        // the finalize quorum. Both incomplete-result paths must retain
        // liveness.
        for certify in [
            CertifyChoice::SingleCancel { target_idx: 0 },
            CertifyChoice::SinglePending { target_idx: 0 },
        ] {
            let mut input = audit_input();
            input.certify = certify;
            let audit = run_standard_once::<simplex::SimplexCertificateMock>(
                input, false, true, false, None,
            );
            assert!(audit.is_some(), "run with {certify:?} produced no audit");
        }
    }

    #[test]
    fn rejected_byzantine_leader_view_preserves_liveness() {
        let mut input = audit_input();
        input.configuration = N4F1C3;
        input.required_containers = 4;
        input.certify = CertifyChoice::RejectView { view: View::new(3) };
        let (valid, rejected) = run_audited_standard_once::<simplex::SimplexCertificateMock>(input);
        assert!(valid, "rejecting one Byzantine-led view prevented recovery");
        assert!(rejected, "the Byzantine-led view was not rejected");
    }

    #[test]
    fn twins_happens_before_traces_honest_validators_only() {
        // N4F1C3 twins compromise one identity (two engines, one key): the
        // three honest validators are captured, twin halves contribute no
        // attributed events, and receives from the twin merge nothing.
        let summary = run_twins::<simplex::SimplexCertificateMock>(
            audit_input(),
            TwinsRole::Campaign,
            false,
            true,
            false,
        )
        .expect("happens-before summary");
        assert_eq!(summary.node_count(), 3, "only honest validators tracked");
        assert!(!summary.tokens().is_empty());
    }

    #[test]
    fn resolver_sniff_decodes_backfill_responses() {
        use commonware_codec::Encode;
        use commonware_consensus::{
            simplex::types::{Notarization, Notarize, Proposal},
            types::Round,
        };

        let executor = deterministic::Runner::seeded(7);
        executor.start(|mut context| async move {
            let (_, schemes) = <simplex::SimplexCertificateMock as simplex::Simplex>::setup(
                &mut context,
                NAMESPACE,
                4,
            );
            let proposal = Proposal::new(
                Round::new(Epoch::new(EPOCH), View::new(3)),
                View::new(2),
                Sha256Digest::from([7u8; 32]),
            );
            let votes: Vec<_> = schemes[..3]
                .iter()
                .map(|s| Notarize::sign(s, proposal.clone()).unwrap())
                .collect();
            let cert = Certificate::Notarization(
                Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential)
                    .unwrap(),
            );
            let response = ResolverMessage::<U64> {
                id: 9,
                payload: ResolverPayload::Response(cert.encode()),
            };
            assert_eq!(
                sniff_event::<simplex::SimplexCertificateMock>(
                    SniffChannel::Resolver,
                    &IoBuf::from(response.encode()),
                    &(),
                ),
                Some((3, happens_before::EventKind::ReceiveNotarization)),
            );

            // Requests deliver no certificate; nothing is recorded.
            let request = ResolverMessage::<U64> {
                id: 9,
                payload: ResolverPayload::Request(U64::from(3u64)),
            };
            assert_eq!(
                sniff_event::<simplex::SimplexCertificateMock>(
                    SniffChannel::Resolver,
                    &IoBuf::from(request.encode()),
                    &(),
                ),
                None,
            );
        });
    }

    #[test]
    fn happens_before_capture_is_node_attributed_and_deterministic() {
        let input = audit_input();

        let a = run_standard_once::<simplex::SimplexCertificateMock>(
            input.clone(),
            false,
            true,
            true,
            None,
        )
        .expect("valid connected run should produce audit data");
        let b =
            run_standard_once::<simplex::SimplexCertificateMock>(input, false, true, true, None)
                .expect("valid connected run should produce audit data");

        let summary = a.happens_before.as_ref().expect("hb capture requested");
        // Dispatch propagation attributed events to each honest validator, and each
        // recorded real causal history over a live run.
        assert!(
            summary.node_count() >= 2,
            "expected multiple attributed nodes, got {}",
            summary.node_count()
        );
        assert!(
            !summary.tokens().is_empty(),
            "expected non-empty happens-before token set"
        );
        // p2p-boundary sniffing captured wire arrivals of votes (which tracing
        // cannot observe): notarize votes are exchanged on the way to finalization.
        assert!(
            summary.tokens().iter().any(|t| t.contains("recv_notarize")),
            "expected p2p-sniffed vote-arrival tokens"
        );
        // Certificate arrival (p2p) and certificate processing (tracing) are
        // captured as distinct events.
        let toks = summary.tokens();
        assert!(
            toks.iter().any(|t| t.contains("recv_notarization")),
            "expected p2p-sniffed certificate-arrival tokens"
        );
        assert!(
            toks.iter().any(|t| t.contains("proc_")),
            "expected tracing certificate-processing tokens"
        );
        // Same seed and inputs must yield an identical summary.
        assert_eq!(a.happens_before, b.happens_before);
    }

    #[test]
    fn happens_before_tee_preserves_warn_trace_collection() {
        let input = audit_input();
        let collect = |happens_before: bool| {
            let store = TraceStorage::default();
            let dispatch = warn_trace_dispatch(store.clone());
            let warn_dispatch = happens_before.then(|| dispatch.clone());
            let audit = dispatcher::with_default(&dispatch, || {
                run_standard_once::<simplex::SimplexCertificateMock>(
                    input.clone(),
                    false,
                    true,
                    happens_before,
                    warn_dispatch,
                )
            })
            .expect("valid connected run should produce audit data");
            let events: Vec<_> = store.get_all().iter().map(|e| format!("{e:?}")).collect();
            (audit, events)
        };

        let (_, plain) = collect(false);
        let (audit, teed) = collect(true);
        // Both signals coexist: the per-node subscribers captured happens-before
        // events while the shadowed collector still received the identical
        // trace-event stream (spans included) through the tee.
        assert!(audit.happens_before.is_some());
        assert!(!plain.is_empty(), "expected collected trace events");
        assert_eq!(plain, teed);
    }

    fn test_input(seed: u64, containers: u64, term_length: TermLength) -> FuzzInput {
        FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            partition: Partition::Connected,
            configuration: N4F1C3,
            required_containers: containers,
            term_length,
            optimistic_views: ViewDelta::new(term_length.get()),
            heterogeneous_optimism: true,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
            mailbox_size: DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardPolicy::Disabled,
            certify: CertifyChoice::Always,
            block_filter: BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_certificate_mock_connected() {
        fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_certificate_mock_twin_connected() {
        fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_certificate_mock_stable_leader_connected() {
        // Multi-view terms exercise the stable-leader path, unlike the
        // TermLength::ONE tests above.
        fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::new(NZU32!(5)),
        ));
    }

    fn property_test_strategy() -> impl Strategy<Value = FuzzInput> {
        (
            any::<u64>(),
            prop::sample::select(TERM_LENGTH_BOUNDARIES.as_slice()),
        )
            .prop_map(move |(seed, term_length)| {
                test_input(seed, PROPERTY_TEST_CONTAINERS, term_length)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test_group("slow")]
        #[test]
        fn property_test_certificate_mock_connected(input in property_test_strategy()) {
            fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_certificate_mock_twins_mutator_connected(input in property_test_strategy()) {
            fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(input);
        }
    }
}
