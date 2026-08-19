//! Run a single ByzzFuzz iteration.
//!
//! [`run`] applies network faults during a bounded fault phase, reaches GST
//! when needed, and checks post-GST liveness targets. The full liveness model
//! is documented in `specs/decisions/005-post-gst-required-container-catch-up.md`.

use super::BYZANTINE_IDX;
use crate::{
    CertifyChoice, EPOCH, FAULT_INJECTION_RATIO, FAULT_PHASE, N4F0C4, PublicKeyOf, SniffChannel,
    SniffingReceiver, block_relay,
    byzzfuzz::{
        ByzzFuzz,
        fault::{NetworkFault, ProcessFault},
        forwarder,
        injector::ByzzFuzzInjector,
        intercept::{self, FaultGate, SenderViewCell},
        log,
        mutator::ByzzFuzzMutator,
        observed::ObservedState,
    },
    happens_before, invariants,
    simplex::Simplex,
    sniff_sink, spawn_filtered_honest_validator,
    utils::Partition,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::{
    Monitor as _,
    simplex::mocks::reporter::Reporter,
    types::{Epoch, View},
};
use commonware_cryptography::{
    Hasher, Sha256, certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_runtime::{Clock, Runner, Spawner, Supervisor, deterministic};
use commonware_utils::{FuzzRng, channel::mpsc::Receiver as ViewReceiver, sync::Mutex};
use futures::future::join_all;
use rand::RngExt as _;
use std::{collections::HashSet, fmt::Write as _, sync::Arc, time::Duration};
use tracing::{Dispatch, dispatcher};

type ByzzReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// ByzzFuzz's post-GST recovery budget on the ordinary simulated links.
const BYZZFUZZ_LIVENESS_WINDOW: Duration = Duration::from_secs(360);

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
    proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>>,
    participants: Vec<PublicKeyOf<P>>,
    post_gst_fault_views: u64,
}

fn genesis_payload() -> Sha256Digest {
    Sha256::hash(&[&(Bytes::from_static(b"genesis"), Epoch::new(EPOCH)).encode()])
}

fn block_partition_allows<P: commonware_cryptography::PublicKey>(
    participants: &[P],
    sender_idx: usize,
    recipient: &P,
    schedule: &[NetworkFault],
    view: u64,
) -> bool {
    let mut active = schedule
        .iter()
        .filter(|fault| fault.view.get() == view)
        .map(|fault| fault.partition);
    let Some(recipient_idx) = participants.iter().position(|p| p == recipient) else {
        return true;
    };
    active.all(|partition| partition.connected(sender_idx, recipient_idx))
}

/// Sample `(c, d, r)` from `context` and build the per-validator
/// forwarder/receiver/injector wiring used by [`run`]. The
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
    // Shared (read-only after setup) by every forwarder, which consults the
    // sampled network-fault schedule per message.
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

    let relay = Arc::new(block_relay::Relay::new());
    let mut reporters = Vec::new();
    let config = input.configuration;
    let mut byzantine_view = None;
    let sender_views: Arc<[SenderViewCell]> = (0..config.n as usize)
        .map(|_| SenderViewCell::new())
        .collect::<Vec<_>>()
        .into();
    {
        let gate = gate.clone();
        let network_schedule = network_schedule.clone();
        let participants = participants_arc.clone();
        let sender_views = sender_views.clone();
        relay.set_filter(move |sender, _, recipient, _, _, contents| {
            let Some(sender_idx) = participants.iter().position(|p| p == sender) else {
                return true;
            };
            if let Some(view) = block_relay::mock_block_view(contents) {
                sender_views[sender_idx].update(view.get());
            }
            if gate.gst_reached() {
                return true;
            }
            let view = sender_views[sender_idx].get();
            let schedule = network_schedule.lock();
            let allowed =
                block_partition_allows(participants.as_ref(), sender_idx, recipient, &schedule, view);
            if !allowed {
                let recipient_idx = participants
                    .iter()
                    .position(|participant| participant == recipient);
                log::push(format!(
                    "byzzfuzz: drop channel=Block view={view} sender={sender_idx} recipient={recipient_idx:?} reason=partition",
                ));
            }
            allowed
        });
    }

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

        let sender_view = sender_views[i].clone();
        if i == BYZANTINE_IDX {
            byzantine_view = Some(sender_view.clone());
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
            spawn_filtered_honest_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                P::elector(
                    P::effective_term_length(input.term_length),
                    crate::PINNED_OPTIMISTIC_VIEWS,
                ),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.mailbox_size,
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
        proc_schedule: proc_schedule_arc,
        participants,
        post_gst_fault_views: r_post_gst,
    }
}

/// Reach GST and require post-GST honest liveness, used by [`run`] when the
/// fault phase did not already finish. Prunes process faults past the byzantine's current round, then
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
        _ = context.sleep(BYZZFUZZ_LIVENESS_WINDOW) => false,
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
            BYZZFUZZ_LIVENESS_WINDOW,
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
        crate::print_fuzz_input::<P>(crate::Mode::Byzzfuzz, &input);
        let mut reporters = setup.reporters;
        let byzantine_view = setup.byzantine_view;
        let proc_schedule = setup.proc_schedule;
        let participants = setup.participants;
        let post_gst_fault_views = setup.post_gst_fault_views;
        let config = input.configuration;
        let n = config.n as usize;
        let required_containers = input.required_containers;
        let term_length = P::effective_term_length(input.term_length);

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
        invariants::check_vote_invariants_with_byzantine(
            &byzantine,
            P::elector(term_length, crate::PINNED_OPTIMISTIC_VIEWS),
            Epoch::new(EPOCH),
            term_length,
            &reporters,
        );

        // State-extraction invariants assume each reporter is honest;
        // include only correct reporters here. Quorum thresholds still
        // derive from the full validator set, so `config.n` is unchanged.
        let correct_reporters: Vec<_> = reporters
            .into_iter()
            .enumerate()
            .filter_map(|(i, reporter)| (!byzantine.contains(&i)).then_some(reporter))
            .collect();

        let states = invariants::extract(correct_reporters, config.n as usize);
        invariants::check::<P>(config, term_length, states);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockFilterChoice, CertifyChoice, FuzzInput, N4F0C4, ReporterWiring, simplex::SimplexId,
        strategy::StrategyChoice, utils::Partition,
    };
    use commonware_consensus::{simplex::ForwardingPolicy, types::TermLength};
    use std::num::NonZeroUsize;

    fn baseline_input(seed: u64) -> FuzzInput {
        let mut raw_bytes = seed.to_le_bytes().to_vec();
        raw_bytes.extend_from_slice(&[0x5au8; 96]);
        FuzzInput {
            raw_bytes,
            required_containers: 2,
            term_length: TermLength::ONE,
            optimistic_views: commonware_consensus::types::ViewDelta::zero(),
            heterogeneous_optimism: false,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: StrategyChoice::AnyScope,
            messaging_faults: Vec::new(),
            mailbox_size: NonZeroUsize::new(1024).unwrap(),
            forwarding: ForwardingPolicy::Disabled,
            certify: CertifyChoice::Always,
            block_filter: BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    /// Run the plain ByzzFuzz baseline and drain its decision log, tolerating a
    /// panic so a same-seed liveness violation is still captured identically.
    fn baseline_trace(input: FuzzInput) -> (bool, Vec<String>) {
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run::<SimplexId>(input);
        }))
        .is_ok();
        (ok, log::take())
    }

    // Same-seed determinism regression: the i.i.d. baseline draws only from the
    // input-seeded `FuzzRng`, so two runs of one fixed input must produce a
    // byte-identical decision log (the full sampled process/network schedule)
    // and the same completion outcome. This fixed input finalizes in the fault
    // phase, so it stays within the fast-test budget.
    #[test]
    fn run_baseline_is_deterministic_for_fixed_input() {
        let (ok_first, first) = baseline_trace(baseline_input(7));
        let (ok_second, second) = baseline_trace(baseline_input(7));
        assert_eq!(
            ok_first, ok_second,
            "same seed must reach the same completion outcome"
        );
        assert_eq!(
            first, second,
            "same seed must produce a byte-identical ByzzFuzz schedule"
        );
        assert!(
            !first.is_empty(),
            "the decision log must record the schedule"
        );
    }
}
