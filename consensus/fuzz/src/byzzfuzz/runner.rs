//! Run a single ByzzFuzz iteration.
//!
//! [`run`] applies network faults during a bounded fault phase, reaches GST
//! when needed, and checks post-GST liveness targets. The full liveness model
//! is documented in `specs/decisions/005-post-gst-required-container-catch-up.md`.

use super::BYZANTINE_IDX;
use crate::{
    byzzfuzz::{
        fault::{NetworkFault, ProcessAction, ProcessFault},
        forwarder,
        injector::ByzzFuzzInjector,
        intercept::{self, FaultGate, SenderViewCell},
        log,
        mutator::ByzzFuzzMutator,
        observed::ObservedState,
        qlearn, sampling,
        scope::{self, MessageScope},
        ByzzFuzz,
    },
    happens_before, invariants,
    simplex::Simplex,
    sniff_sink, spawn_honest_validator, state_cov,
    utils::Partition,
    CertifyChoice, PublicKeyOf, SniffChannel, SniffingReceiver, EPOCH, FAULT_INJECTION_RATIO,
    FAULT_PHASE, N4F0C4, POST_GST_WINDOW,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::mocks::{relay, reporter::Reporter},
    types::{Epoch, View},
    Monitor as _,
};
use commonware_cryptography::{
    certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest, Hasher, Sha256,
};
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Runner, Spawner, Supervisor};
use commonware_utils::{channel::mpsc::Receiver as ViewReceiver, sync::Mutex, FuzzRng};
use futures::future::join_all;
use rand::RngExt as _;
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Write as _,
    sync::Arc,
    time::Duration,
};
use tracing::{dispatcher, Dispatch};

/// Number of policy decision steps in one Q-learning episode (Algorithm 1's
/// inner `repeat until S steps`).
const QLEARN_EPISODE_STEPS: usize = 12;
/// Per-step boundary: how long a step waits for the next finalization before
/// accepting a no-progress boundary (the fault suppressed progress). Bounds each
/// episode together with [`QLEARN_EPISODE_STEPS`].
const QLEARN_STEP_DEADLINE: Duration = Duration::from_secs(5);
/// Upper bound on the crash-action silence window, in views.
const QLEARN_CRASH_MAX_VIEWS: u64 = 5;

type ByzzReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// Sample a per-iteration [`CertifyChoice`] for ByzzFuzz. `SingleCancel` and
/// `SinglePending` always target [`BYZANTINE_IDX`]: ByzzFuzz keeps Byzantine
/// process faults active after GST, so disabling a *correct* certifier on top
/// of those faults would drop below the post-GST quorum of three. Targeting
/// the byzantine validator overlaps the disabled certifier with the existing
/// adversary instead of adding a new failure to the run.
fn sample_byzzfuzz_certify(context: &mut deterministic::Context) -> CertifyChoice {
    match context.random_range(0..10u32) {
        0..=5 => CertifyChoice::Always,
        6..=7 => CertifyChoice::SingleCancel {
            target_idx: BYZANTINE_IDX as u8,
        },
        _ => CertifyChoice::SinglePending {
            target_idx: BYZANTINE_IDX as u8,
        },
    }
}

struct EngineSetup<P: Simplex> {
    reporters: Vec<ByzzReporter<P>>,
    byzantine_view: SenderViewCell,
    /// Round cells of the honest senders, tracking each one's `rnd(m)` (max view
    /// sent or received). Their max is the honest execution frontier, which the
    /// Q-learner targets with network partitions -- the finalized frontier lags
    /// it whenever honest nodes advance through timeout/nullification.
    honest_views: Vec<SenderViewCell>,
    proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>>,
    net_schedule: Arc<Mutex<Vec<NetworkFault>>>,
    participants: Vec<PublicKeyOf<P>>,
    post_gst_fault_views: u64,
}

fn genesis_payload() -> Sha256Digest {
    let mut hasher = Sha256::default();
    hasher.update(&(Bytes::from_static(b"genesis"), Epoch::new(EPOCH)).encode());
    hasher.finalize()
}

/// Sample `(c, d, r)` from `context` and build the per-validator
/// forwarder/receiver/injector wiring used by [`run`] and [`run_qlearn`]. The
/// returned reporters are already running; `gate` lets the caller reach GST
/// after the fault phase. Byzantine process faults are not gated by GST.
///
/// When `hb_log` is `Some`, honest receivers are additionally wrapped in a
/// [`SniffingReceiver`] and each honest engine is spawned under a per-node
/// [`happens_before::capture::NodeSubscriber`], so the log accumulates an
/// honest-only happens-before history (the Byzantine identity at
/// [`BYZANTINE_IDX`] is excluded and marked ambiguous, since its mutated wire
/// output diverges from its tracing). `None` leaves capture off (the [`run`]
/// path) as a zero-decode pass-through.
async fn setup_engines<P: Simplex>(
    context: &mut deterministic::Context,
    input: &mut crate::FuzzInput,
    gate: FaultGate,
    log_label: &'static str,
    hb_log: Option<happens_before::capture::EventLog>,
) -> EngineSetup<P>
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Override the harness-wide `input.certify` with ByzzFuzz-specific
    // sampling. `FuzzInput::arbitrary` uses `Always` because Standard,
    // FaultyMessaging, and Twins on N4F1C3 cannot survive losing one of three
    // honest certifiers. ByzzFuzz forces N4F0C4 *and* keeps Byzantine process
    // faults active post-GST; `sample_byzzfuzz_certify` pins the single-target
    // variants to the byzantine index so the disabled certifier coincides with
    // the adversary rather than adding a new correct-validator failure.
    input.certify = sample_byzzfuzz_certify(context);

    // Sample `(c, d, r)` here rather than threading it through `FuzzInput` type.
    let use_required_bound = context.random_bool(0.5);
    let r_bound = if use_required_bound {
        input.required_containers
    } else {
        let multiplier = context.random_range(2..=100);
        input.required_containers.saturating_mul(multiplier)
    };

    let r_max = r_bound.max(input.required_containers);
    let r = context.random_range(1..=r_max);
    let max_per_fault_type = (r / FAULT_INJECTION_RATIO).max(1);
    let mut c = context.random_range(0..=max_per_fault_type);
    let mut d = context.random_range(0..=max_per_fault_type);
    // At least one fault type must be active; otherwise the run is a no-op.
    if c == 0 && d == 0 {
        if context.random_bool(0.5) {
            c = 1;
        } else {
            d = 1;
        }
    }
    let byzz = ByzzFuzz::new(c, d, r);

    let network_schedule_vec = byzz.network_faults(context);

    let (oracle, participants, schemes, mut registrations) =
        crate::setup_network::<P>(context, input).await;

    let proc_faults = byzz.process_faults(&participants, context);
    let r_post_gst = context.random_range(1..=r_max);

    log::push(format!(
        "{log_label} schedule: byzantine_idx={} required_containers={} (c,d,r)={:?} certify={:?} network_faults={:?} proc_faults={:?}",
        BYZANTINE_IDX,
        input.required_containers,
        byzz,
        input.certify,
        network_schedule_vec,
        proc_faults,
    ));

    let participants_arc: Arc<[PublicKeyOf<P>]> = Arc::from(participants.clone());
    // Live-mutable so the Q-learning policy can append `Partition` faults during
    // an episode; `run` never mutates it after setup.
    let network_schedule = Arc::new(Mutex::new(network_schedule_vec));
    let proc_schedule_arc = Arc::new(Mutex::new(proc_faults));
    let empty_proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>> =
        Arc::new(Mutex::new(Vec::new()));

    // Honest-only happens-before capture: the Byzantine identity is excluded
    // from sender resolution, so honest receives from it merge no history.
    let none_hb: Option<happens_before::capture::EventLog> = None;
    let ambiguous: Arc<[u32]> = vec![BYZANTINE_IDX as u32].into();

    // Intercept queue. Forwarders push (sync); injector consumes (async).
    let (intercept_tx, intercept_rx) = intercept::channel::<PublicKeyOf<P>>();

    // Observed-value pool shared by every extractor and by the
    // byzantine injector's vote mutator. Seed genesis so early mutations can
    // replay the genesis payload and parent view before any proposal is seen.
    let pool = ObservedState::new_with_genesis(genesis_payload());

    let relay = Arc::new(relay::Relay::new());
    let mut reporters = Vec::new();
    let config = input.configuration;
    let mut byzantine_view = None;
    let mut honest_views = Vec::new();

    // Cloned byzantine vote sender for the injector. Grabbed BEFORE
    // split_with so injector emissions bypass the forwarder. Cert and
    // resolver process faults are omit-only, so no clones needed for
    // those channels.
    let mut injector_vote_sender = None;

    for i in 0..config.n as usize {
        let validator = participants[i].clone();
        let (vote_chan, cert_chan, resolver_chan) = registrations.remove(&validator).unwrap();
        let (vote_sender, vote_receiver) = vote_chan;
        let (cert_sender, cert_receiver) = cert_chan;
        let (resolver_sender, resolver_receiver) = resolver_chan;

        if i == BYZANTINE_IDX {
            injector_vote_sender = Some(vote_sender.clone());
        }

        let sender_view = intercept::SenderViewCell::new();
        if i == BYZANTINE_IDX {
            byzantine_view = Some(sender_view.clone());
        } else {
            honest_views.push(sender_view.clone());
        }

        let proc_for_sender = if i == BYZANTINE_IDX {
            proc_schedule_arc.clone()
        } else {
            empty_proc_schedule.clone()
        };
        let intercept_for_sender = if i == BYZANTINE_IDX {
            Some(intercept_tx.clone())
        } else {
            None
        };

        let cert_codec = schemes[i].certificate_codec_config();

        let (vote_primary, _vote_secondary) =
            vote_sender.split_with(forwarder::make_vote::<P::Scheme>(
                participants_arc.clone(),
                i,
                network_schedule.clone(),
                proc_for_sender.clone(),
                sender_view.clone(),
                intercept_for_sender.clone(),
                pool.clone(),
                gate.clone(),
            ));
        let (cert_primary, _cert_secondary) =
            cert_sender.split_with(forwarder::make_certificate::<P::Scheme>(
                cert_codec.clone(),
                participants_arc.clone(),
                i,
                network_schedule.clone(),
                proc_for_sender.clone(),
                sender_view.clone(),
                intercept_for_sender.clone(),
                pool.clone(),
                gate.clone(),
            ));
        let (resolver_primary, _resolver_secondary) =
            resolver_sender.split_with(forwarder::make_resolver::<P::Scheme>(
                cert_codec.clone(),
                participants_arc.clone(),
                i,
                network_schedule.clone(),
                proc_for_sender,
                sender_view.clone(),
                intercept_for_sender,
                pool.clone(),
                gate.clone(),
            ));

        let vote_receiver = intercept::RoundTrackingReceiver::new(
            vote_receiver,
            sender_view.clone(),
            intercept::vote_view_extractor::<P::Scheme>(pool.clone()),
        );
        let cert_receiver = intercept::RoundTrackingReceiver::new(
            cert_receiver,
            sender_view.clone(),
            intercept::certificate_view_extractor::<P::Scheme>(cert_codec.clone(), pool.clone()),
        );
        let resolver_receiver = intercept::RoundTrackingReceiver::new(
            resolver_receiver,
            sender_view,
            intercept::resolver_view_extractor::<P::Scheme>(cert_codec.clone(), pool.clone()),
        );

        // Wrap each round-tracking receiver in a happens-before sniffer. Honest
        // nodes record wire arrivals; the Byzantine node (and the `None`-capture
        // `run` path) get a pass-through sink.
        let node_hb = if i == BYZANTINE_IDX {
            &none_hb
        } else {
            &hb_log
        };
        let vote_receiver = SniffingReceiver::<P, _>::new(
            vote_receiver,
            SniffChannel::Vote,
            cert_codec.clone(),
            sniff_sink::<P>(node_hb, i as u32, &participants_arc, &ambiguous),
        );
        let cert_receiver = SniffingReceiver::<P, _>::new(
            cert_receiver,
            SniffChannel::Certificate,
            cert_codec.clone(),
            sniff_sink::<P>(node_hb, i as u32, &participants_arc, &ambiguous),
        );
        let resolver_receiver = SniffingReceiver::<P, _>::new(
            resolver_receiver,
            SniffChannel::Resolver,
            cert_codec.clone(),
            sniff_sink::<P>(node_hb, i as u32, &participants_arc, &ambiguous),
        );

        let ctx = context
            .child("validator")
            .with_attribute("public_key", &validator);
        let spawn = || {
            spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                P::Elector::default(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.mailbox_size,
                input.fetch_concurrent,
                input.forwarding,
                (vote_primary, vote_receiver),
                (cert_primary, cert_receiver),
                (resolver_primary, resolver_receiver),
                input.certify,
                input.reporting,
            )
        };
        // Dispatch propagation: each honest engine's tracing is attributed to
        // node `i`. The Byzantine node and the `run` path (`hb_log == None`)
        // spawn under the ambient dispatch.
        let reporter = match node_hb {
            Some(log) => {
                let dispatch = Dispatch::new(happens_before::capture::NodeSubscriber::new(
                    i as u32,
                    log.clone(),
                ));
                dispatcher::with_default(&dispatch, spawn)
            }
            None => spawn(),
        };
        reporters.push(reporter);
    }

    // Closes the intercept queue once all forwarder-held clones drop.
    drop(intercept_tx);

    // Vote mutator: observed-value-first replay (seen payloads,
    // parent views, proposals, and nullify targets), local +/-1 or +/-2 edits
    // as fallback.
    // Cert/resolver process faults are omit-only so the injector
    // doesn't need their senders.
    let injector_ctx = context.child("byzzfuzz_injector");
    let injector = ByzzFuzzInjector::new(
        injector_ctx,
        schemes[BYZANTINE_IDX].clone(),
        ByzzFuzzMutator::new(pool.clone()),
    );
    injector.start(
        injector_vote_sender.expect("byzantine vote sender cloned"),
        intercept_rx,
    );

    EngineSetup {
        reporters,
        byzantine_view: byzantine_view.expect("byzantine sender view captured"),
        honest_views,
        proc_schedule: proc_schedule_arc,
        net_schedule: network_schedule,
        participants,
        post_gst_fault_views: r_post_gst,
    }
}

/// Reach GST and require post-GST honest liveness, shared by [`run`] (when the
/// fault phase did not already finish) and [`run_qlearn`] (unconditionally at
/// episode end). Prunes process faults past the byzantine's current round, then
/// appends a fresh post-GST omit/mutate budget so the byzantine stays
/// adversarial after the network heals. GST disables partition drops (network
/// faults), so any partition-wedged honest node recovers; process faults never
/// wedge the honest quorum (three honest nodes meet quorum without the
/// byzantine). Each non-byzantine reporter must reach its recorded target, or
/// this panics with a liveness violation.
#[allow(clippy::too_many_arguments)]
async fn reach_gst_and_check_liveness<P: Simplex>(
    context: &mut deterministic::Context,
    reporters: &mut [ByzzReporter<P>],
    non_byzantine: &[usize],
    required_containers: u64,
    byzantine_view: &SenderViewCell,
    proc_schedule: &Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>>,
    participants: &[PublicKeyOf<P>],
    post_gst_fault_views: u64,
    gate: &FaultGate,
) {
    // Phase 2 targets are recorded before GST for stable diagnostics.
    let mut watch_targets: Vec<(usize, u64, u64)> = Vec::with_capacity(non_byzantine.len());
    let mut watcher_inputs = Vec::with_capacity(non_byzantine.len());
    for &i in non_byzantine {
        let (latest, monitor): (View, ViewReceiver<View>) = reporters[i].subscribe().await;
        let baseline = latest.get();
        let target = if baseline < required_containers {
            required_containers
        } else {
            baseline
                .checked_add(1)
                .expect("finalized view reached u64::MAX")
        };
        watch_targets.push((i, baseline, target));
        watcher_inputs.push((i, target, latest, monitor));
    }

    // GST disables partition drops. Keep already-reachable process
    // faults, then append future faults so the byzantine sender
    // remains adversarial after GST.
    let byzantine_rnd = byzantine_view.get();
    let pruned_pre_gst_proc_faults = {
        let mut schedule = proc_schedule.lock();
        let before = schedule.len();
        schedule.retain(|f| f.view <= byzantine_rnd);
        before - schedule.len()
    };
    let first_post_gst_view = byzantine_rnd.saturating_add(1).max(1);
    let last_post_gst_view =
        first_post_gst_view.saturating_add(post_gst_fault_views.saturating_sub(1));
    let post_gst_faults = ByzzFuzz::post_gst_process_faults(
        first_post_gst_view..=last_post_gst_view,
        participants,
        context,
    );
    {
        let mut schedule = proc_schedule.lock();
        schedule.extend(post_gst_faults.clone());
    }
    log::push(format!(
        "byzzfuzz: gst_reached byzantine_rnd={byzantine_rnd} pruned_pre_gst_proc_faults={pruned_pre_gst_proc_faults} post_gst_fault_views={post_gst_fault_views} appended_post_gst_proc_faults={post_gst_faults:?}",
    ));
    gate.reach_gst();

    // Phase 2 watchers return true once their reporter reaches target.
    let mut watchers = Vec::new();
    for (i, target, mut latest, mut monitor) in watcher_inputs {
        watchers.push(
            context
                .child("byzzfuzz_post_gst_watcher")
                .with_attribute("index", i)
                .spawn(move |_| async move {
                    while latest.get() < target {
                        let Some(next) = monitor.recv().await else {
                            return false;
                        };
                        latest = next;
                    }
                    true
                }),
        );
    }

    let phase2_complete = select! {
        results = join_all(watchers) => {
            results.iter().all(|r| matches!(r, Ok(true)))
        },
        _ = context.sleep(POST_GST_WINDOW) => false,
    };

    if !phase2_complete {
        let mut diag = String::new();
        for &(i, baseline, target) in &watch_targets {
            let (latest, _): (View, ViewReceiver<View>) = reporters[i].subscribe().await;
            let current = latest.get();
            let _ = write!(
                diag,
                " node{i}={{baseline={baseline} target={target} current={current}}}"
            );
        }
        panic!(
            "byzzfuzz: no post-GST progress within {:?};{diag}",
            POST_GST_WINDOW,
        );
    }
}

/// Run a single ByzzFuzz iteration.
pub fn run<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let gate = FaultGate::new();
        let setup =
            setup_engines::<P>(&mut context, &mut input, gate.clone(), "byzzfuzz", None).await;
        crate::print_fuzz_input(crate::Mode::Byzzfuzz, &input);
        let mut reporters = setup.reporters;
        let byzantine_view = setup.byzantine_view;
        let proc_schedule = setup.proc_schedule;
        let participants = setup.participants;
        let post_gst_fault_views = setup.post_gst_fault_views;
        let config = input.configuration;
        let n = config.n as usize;
        let required_containers = input.required_containers;

        // Liveness is only meaningful for correct processes; the byzantine
        // identity at `BYZANTINE_IDX` is excluded.
        let non_byzantine: Vec<usize> = (0..n).filter(|i| *i != BYZANTINE_IDX).collect();

        // Phase 1: keep faults active until either all correct reporters
        // reach `required_containers` or the fault-phase timer expires.
        // Each finisher returns true iff its reporter actually reached
        // `required_containers`; a closed monitor is a stall (false), not a
        // success -- otherwise an unexpectedly dropped subscription would
        // skip Phase 2 entirely.
        let mut phase1_finishers = Vec::new();
        for &i in &non_byzantine {
            let (mut latest, mut monitor): (View, ViewReceiver<View>) =
                reporters[i].subscribe().await;
            let req = required_containers;
            phase1_finishers.push(context.child("byzzfuzz_phase1_finisher").spawn(
                move |_| async move {
                    while latest.get() < req {
                        let Some(next) = monitor.recv().await else {
                            return false;
                        };
                        latest = next;
                    }
                    true
                },
            ));
        }

        let phase1_early_complete = select! {
            results = join_all(phase1_finishers) => {
                results.iter().all(|r| matches!(r, Ok(true)))
            },
            _ = context.sleep(FAULT_PHASE) => false,
        };

        if !phase1_early_complete {
            reach_gst_and_check_liveness::<P>(
                &mut context,
                &mut reporters,
                &non_byzantine,
                required_containers,
                &byzantine_view,
                &proc_schedule,
                &participants,
                post_gst_fault_views,
                &gate,
            )
            .await;
        }

        let byzantine: HashSet<usize> = [BYZANTINE_IDX].into_iter().collect();
        invariants::check_vote_invariants_with_byzantine(&byzantine, &reporters);

        // State-extraction invariants assume each reporter is honest;
        // include only correct reporters here. Quorum thresholds still
        // derive from the full validator set, so `config.n` is unchanged.
        let correct_reporters = reporters
            .into_iter()
            .enumerate()
            .filter_map(|(i, reporter)| (!byzantine.contains(&i)).then_some(reporter))
            .collect();

        let states = invariants::extract(correct_reporters, config.n as usize);
        invariants::check::<P>(config.n, states);
    });
}

/// View-relative protocol-state descriptor of the honest reporters: a compact
/// fingerprint of their agreement state as offsets, spreads, and counts relative
/// to the finalization frontier -- never absolute view numbers. Unlike
/// [`state_cov::alpha`] (whose tokens embed absolute views and so almost never
/// recur across runs), this recurs, so its novelty is a genuine reward signal.
fn state_descriptor<P: Simplex>(honest: &[ByzzReporter<P>], max_participants: usize) -> u64 {
    let states = state_cov::encode_reporter_states(honest, max_participants);
    if states.is_empty() {
        return 0;
    }
    let max_fin = states.values().map(|r| r.last_finalized).max().unwrap_or(0);
    let min_fin = states.values().map(|r| r.last_finalized).min().unwrap_or(0);
    let max_notar = states.values().map(|r| r.last_notarized).max().unwrap_or(0);
    let max_null = states.values().map(|r| r.last_nullified).max().unwrap_or(0);

    let mut notarized = BTreeSet::new();
    let mut finalized = BTreeSet::new();
    let mut nullified = BTreeSet::new();
    let mut faulty = false;
    for r in states.values() {
        notarized.extend(r.notarizations.keys().copied());
        finalized.extend(r.finalizations.keys().copied());
        nullified.extend(r.nullifications.iter().copied());
        faulty |= !r.faults.is_empty();
    }
    let notar_unfinalized = notarized
        .iter()
        .filter(|v| !finalized.contains(v) && !nullified.contains(v))
        .count();
    let notar_and_nullified = notarized.intersection(&nullified).count();

    // Bucketed, view-relative features packed into one descriptor: notarization
    // depth over the finalized frontier, nullification depth over it, inter-
    // replica finalization spread, count of notarized-but-undecided views, count
    // of notarized-and-nullified (conflict) views, and any recorded equivocation.
    let fin_gap = max_notar.saturating_sub(max_fin).min(3);
    let null_gap = max_null.saturating_sub(max_fin).min(3);
    let fin_spread = max_fin.saturating_sub(min_fin).min(3);
    let unfinalized = (notar_unfinalized as u64).min(3);
    let conflicted = (notar_and_nullified as u64).min(2);

    let mut d = 0u64;
    d = (d << 2) | fin_gap;
    d = (d << 2) | null_gap;
    d = (d << 2) | fin_spread;
    d = (d << 2) | unfinalized;
    d = (d << 2) | conflicted;
    (d << 1) | u64::from(faulty)
}

/// Run one Q-learning ByzzFuzz episode (`Mode::ByzzfuzzQLearn`).
///
/// Reuses [`setup_engines`] (with honest-only happens-before capture), then
/// clears the i.i.d. fault schedule and lets a campaign-persistent Q-policy
/// produce the process- and network-fault schedule step by step. Every
/// stochastic choice -- softmax action sampling and the target/scope/receiver/
/// partition/crash-duration fill of a chosen action -- draws from the
/// deterministic runtime `context`, which is seeded from the fuzz input
/// (`FuzzRng`); the campaign Q-table is the only cross-input state. Because that
/// state persists, replaying identical bytes can yield a different schedule than
/// the first time (online RL over libFuzzer); each chosen action is pushed to
/// the ByzzFuzz decision log so a crashing episode is reproducible.
///
/// The safety + liveness oracle is identical to [`run`]: a single
/// [`reach_gst_and_check_liveness`] heal at episode end (process faults never
/// wedge the three-honest quorum; only partitions can, and GST disables them),
/// then the same invariant checks.
pub fn run_qlearn<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before::capture::EventLog::new();

    executor.start(|mut context| async move {
        use qlearn::FaultAction;

        let gate = FaultGate::new();
        let setup = setup_engines::<P>(
            &mut context,
            &mut input,
            gate.clone(),
            "byzzfuzz_qlearn",
            Some(hb_log.clone()),
        )
        .await;
        crate::print_fuzz_input(crate::Mode::ByzzfuzzQLearn, &input);

        let mut reporters = setup.reporters;
        let byzantine_view = setup.byzantine_view;
        let honest_views = setup.honest_views;
        let proc_schedule = setup.proc_schedule;
        let net_schedule = setup.net_schedule;
        let participants = setup.participants;
        let post_gst_fault_views = setup.post_gst_fault_views;
        let config = input.configuration;
        let n = config.n as usize;
        let required_containers = input.required_containers;

        // Replace ByzzFuzz's i.i.d. fault schedule with a purely policy-driven
        // one: the learner produces every process and network fault below.
        proc_schedule.lock().clear();
        net_schedule.lock().clear();

        let non_byzantine: Vec<usize> = (0..n).filter(|i| *i != BYZANTINE_IDX).collect();
        let candidates: Vec<PublicKeyOf<P>> = sampling::receiver_candidates(&participants);
        // Honest reporters cloned once; their Arc-backed maps reflect live state,
        // so re-encoding each step gives the current cumulative snapshot.
        let honest_reporters: Vec<ByzzReporter<P>> =
            non_byzantine.iter().map(|&i| reporters[i].clone()).collect();

        // Step clock: the first honest reporter's finalization monitor. Its
        // latest finalized view both schedules network partitions at the view the
        // honest quorum is actually executing (a byzantine-lagged view would never
        // match a honest sender's round) and gates each step on genuine progress
        // past the pre-action frontier (draining stale queued notifications).
        let clock_idx = non_byzantine[0];
        let (latest, mut monitor): (View, ViewReceiver<View>) =
            reporters[clock_idx].subscribe().await;
        let mut honest_finalized = latest.get();

        let campaign = qlearn::campaign();
        let mut state: u64 = 0;
        for step in 0..QLEARN_EPISODE_STEPS {
            // Drain every already-queued finalization to the current frontier
            // before deciding, so this step's progress baseline is the max
            // pre-action finalized view. Otherwise a finalization queued before
            // this step's action ran could immediately satisfy the next step and
            // credit its action for progress it did not cause.
            while let Ok(v) = monitor.try_recv() {
                honest_finalized = honest_finalized.max(v.get());
            }

            let byz_view = byzantine_view.get();
            let action = campaign.lock().policy.select(state, &mut context);

            // Resolve the chosen action into concrete faults on the live schedule,
            // recording the fully-sampled fault so the decision log reproduces the
            // exact schedule (not just the action type).
            let enacted = match action {
                FaultAction::NoFault => "no_fault".to_string(),
                FaultAction::Process(proc_action) => {
                    if candidates.is_empty() {
                        "process_skipped_no_candidates".to_string()
                    } else {
                        let receivers = sampling::sample_receivers(&candidates, &mut context);
                        // MutateVote only executes on the vote channel, so it must
                        // not draw a certificate-only scope (a guaranteed no-op).
                        let scope = match proc_action {
                            ProcessAction::MutateVote => scope::sample_vote(&mut context),
                            ProcessAction::Omit => scope::sample(&mut context),
                        };
                        let fault_view = byz_view.saturating_add(1);
                        let targets: Vec<usize> = receivers
                            .iter()
                            .filter_map(|r| participants.iter().position(|p| p == r))
                            .collect();
                        proc_schedule.lock().push(ProcessFault {
                            view: fault_view,
                            receivers,
                            action: proc_action,
                            scope,
                        });
                        format!("process action={proc_action:?} view={fault_view} targets={targets:?} scope={scope:?}")
                    }
                }
                FaultAction::Partition => {
                    // Target the honest execution frontier: the max honest
                    // sender round `rnd(m)`, which network faults match by exact
                    // equality. This tracks nodes that advanced through
                    // timeout/nullification without finalizing, which the
                    // finalized frontier (and the byzantine's lagging round) miss.
                    let honest_rnd = honest_views
                        .iter()
                        .map(|c| c.get())
                        .max()
                        .unwrap_or(honest_finalized);
                    let fault_view = honest_rnd.saturating_add(1);
                    let partition = sampling::sample_partition(&mut context);
                    net_schedule.lock().push(NetworkFault {
                        view: View::new(fault_view),
                        partition,
                    });
                    format!("partition view={fault_view} partition={partition:?}")
                }
                FaultAction::Crash => {
                    if candidates.is_empty() {
                        "crash_skipped_no_candidates".to_string()
                    } else {
                        // Byzantine silent from its current view onward for a small
                        // span. NOTE: process faults match a message's carried view,
                        // so old-view rebroadcasts within the span still escape and
                        // the engine stays alive -- this is multi-view outbound
                        // omission, not a true crash-stop.
                        let span = context.random_range(2..=QLEARN_CRASH_MAX_VIEWS);
                        let first = byz_view;
                        let last = byz_view.saturating_add(span.saturating_sub(1));
                        let mut schedule = proc_schedule.lock();
                        for v in first..=last {
                            schedule.push(ProcessFault {
                                view: v,
                                receivers: candidates.clone(),
                                action: ProcessAction::Omit,
                                scope: MessageScope::Any,
                            });
                        }
                        format!("crash views={first}..={last}")
                    }
                }
            };
            log::push(format!(
                "byzzfuzz_qlearn: step={step} byzantine_view={byz_view} honest_finalized={honest_finalized} action={action:?} enacted=[{enacted}] state={state:#018x}"
            ));

            // Wait for a finalization strictly past the pre-action frontier,
            // draining stale queued notifications, or a bounded deadline; a
            // timeout is a valid boundary (the fault suppressed progress).
            let baseline = honest_finalized;
            loop {
                select! {
                    msg = monitor.recv() => {
                        match msg {
                            Some(v) => {
                                let v = v.get();
                                if v > baseline {
                                    honest_finalized = v;
                                    break;
                                }
                            }
                            None => break,
                        }
                    },
                    _ = context.sleep(QLEARN_STEP_DEADLINE) => break,
                }
            }

            // Q-state and HB novelty key on the view-relative happens-before
            // pair-set (its tokens are relative to each node's current view, so
            // the same interleaving at different absolute views shares a Q-row),
            // stored in the policy's fixed-size table. The protocol-state term
            // uses the view-relative descriptor for the same reason.
            let hb_fp = hb_log.summary().fingerprint();
            let state_fp = state_descriptor::<P>(&honest_reporters, n);
            let terminal = step + 1 == QLEARN_EPISODE_STEPS;
            {
                let mut c = campaign.lock();
                let reward = c.reward(state_fp, hb_fp);
                if terminal {
                    c.policy.learn_terminal(state, action, reward);
                } else {
                    c.policy.learn(state, action, reward, hb_fp);
                }
            }
            state = hb_fp;
        }

        // Single GST heal + post-GST liveness, shared with `run`.
        reach_gst_and_check_liveness::<P>(
            &mut context,
            &mut reporters,
            &non_byzantine,
            required_containers,
            &byzantine_view,
            &proc_schedule,
            &participants,
            post_gst_fault_views,
            &gate,
        )
        .await;

        // Same safety + liveness oracle as `run`.
        let byzantine: HashSet<usize> = [BYZANTINE_IDX].into_iter().collect();
        invariants::check_vote_invariants_with_byzantine(&byzantine, &reporters);
        let correct_reporters = reporters
            .into_iter()
            .enumerate()
            .filter_map(|(i, reporter)| (!byzantine.contains(&i)).then_some(reporter))
            .collect();
        let states = invariants::extract(correct_reporters, n);
        invariants::check::<P>(config.n, states);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::SimplexId, strategy::StrategyChoice, utils::Partition, CertifyChoice, FuzzInput,
        ReporterWiring, N4F0C4,
    };
    use commonware_consensus::simplex::ForwardingPolicy;
    use std::num::NonZeroUsize;

    fn qlearn_input(seed: u64) -> FuzzInput {
        let mut raw_bytes = seed.to_le_bytes().to_vec();
        raw_bytes.extend_from_slice(&[0x5au8; 96]);
        FuzzInput {
            raw_bytes,
            required_containers: 2,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: StrategyChoice::AnyScope,
            messaging_faults: Vec::new(),
            mailbox_size: NonZeroUsize::new(1024).unwrap(),
            fetch_concurrent: NonZeroUsize::new(1).unwrap(),
            forwarding: ForwardingPolicy::Disabled,
            certify: CertifyChoice::Always,
            reporting: ReporterWiring::Solo,
        }
    }

    // Full deterministic episodes (runtime + GST + invariants); ignored so the
    // default `just test` stays fast. Run with `--ignored` to validate wiring.
    #[test]
    #[ignore]
    fn run_qlearn_smoke_completes_and_learns() {
        qlearn::reset_campaign();
        for seed in [1u64, 2, 3] {
            run_qlearn::<SimplexId>(qlearn_input(seed));
        }
        assert!(
            !qlearn::campaign().lock().policy.is_empty(),
            "episodes must populate the campaign Q-table"
        );
    }
}
