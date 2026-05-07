//! Run a single ByzzFuzz iteration.
//!
//! Two entry points:
//! - [`run`]: safety mode. Apply faults for the whole run, wait for
//!   finalization (with a fixed virtual-time fallback), check invariants.
//!   Timeouts are not failures.
//! - [`run_liveness`]: liveness mode. Apply network faults during a bounded
//!   *fault phase*, then reach GST on a shared `FaultGate`, then require
//!   each non-byzantine reporter to advance at least one finalized view
//!   inside a fixed *post-GST window*. Failure to advance panics; Byzantine
//!   process faults are explicitly scheduled for a second sampled view budget.

use super::BYZANTINE_IDX;
use crate::{
    byzzfuzz::{
        fault::ProcessFault,
        forwarder,
        injector::ByzzFuzzInjector,
        intercept::{self, FaultGate, SenderViewCell},
        log,
        mutator::ByzzFuzzMutator,
        observed::ObservedState,
        ByzzFuzz,
    },
    invariants,
    simplex::Simplex,
    spawn_honest_validator,
    utils::Partition,
    PublicKeyOf, EPOCH, FAULT_INJECTION_RATIO, MAX_SLEEP_DURATION, N4F0C4,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::mocks::{relay, reporter::Reporter},
    types::{Epoch, View},
    Monitor as _,
};
use commonware_cryptography::{
    certificate::Scheme as CertificateScheme, sha256::Digest as Sha256Digest, Hasher, Sha256,
};
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{channel::mpsc::Receiver as ViewReceiver, sync::Mutex, FuzzRng};
use futures::future::join_all;
use rand::Rng;
use std::{collections::HashSet, fmt::Write as _, sync::Arc, time::Duration};

/// Liveness-mode fault phase length. The fuzzer applies network partition
/// faults during this virtual-time window; after it elapses (or all
/// non-byzantine reporters reach `required_containers`, whichever comes
/// first) the [`FaultGate`] reaches GST. Kept close to [`MAX_SLEEP_DURATION`]
/// so each libFuzzer iteration stays cheap; tune up from corpus signal.
const BYZZFUZZ_FAULT_PHASE: Duration = MAX_SLEEP_DURATION;

/// Liveness-mode post-GST window. After GST, each non-byzantine reporter
/// must finalize at least one new view within this virtual-time window;
/// otherwise `run_liveness` panics with a liveness violation.
///
/// Intentionally generous to avoid false liveness failures while the target
/// is still being calibrated. This should dominate honest retry/recovery
/// timers after GST.
const BYZZFUZZ_POST_GST_WINDOW: Duration = Duration::from_secs(360);

type ByzzReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

struct EngineSetup<P: Simplex> {
    reporters: Vec<ByzzReporter<P>>,
    byzantine_view: SenderViewCell,
    proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>>,
    participants: Vec<PublicKeyOf<P>>,
    post_gst_fault_views: Option<u64>,
}

enum RunMode {
    Safety,
    Liveness,
}

fn genesis_payload() -> Sha256Digest {
    let mut hasher = Sha256::default();
    hasher.update(&(Bytes::from_static(b"genesis"), Epoch::new(EPOCH)).encode());
    hasher.finalize()
}

/// Sample `(c, d, r)` from `context` and build the per-validator
/// forwarder/receiver/injector wiring shared by [`run`] (safety) and
/// [`run_liveness`] (liveness). The returned reporters are already running;
/// `gate` controls whether forwarders apply network partition faults (safety
/// mode constructs a gate that never reaches GST; liveness mode reaches GST
/// after the fault phase). Byzantine process faults are not gated by GST.
async fn setup_engines<P: Simplex>(
    context: &mut deterministic::Context,
    input: &mut crate::FuzzInput,
    gate: FaultGate,
    log_label: &'static str,
    mode: RunMode,
) -> EngineSetup<P>
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Sample `(c, d, r)` here rather than threading it through `FuzzInput` type.
    let use_required_bound = context.gen_bool(0.5);
    let r_bound = if use_required_bound {
        input.required_containers
    } else {
        let multiplier = context.gen_range(2..=100);
        input.required_containers.saturating_mul(multiplier)
    };

    let r_max = r_bound.max(input.required_containers);
    let r = context.gen_range(1..=r_max);
    let max_per_fault_type = (r / FAULT_INJECTION_RATIO).max(1);
    let mut c = context.gen_range(0..=max_per_fault_type);
    let mut d = context.gen_range(0..=max_per_fault_type);
    // At least one fault type must be active; otherwise the run is a no-op.
    if c == 0 && d == 0 {
        if context.gen_bool(0.5) {
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
    let r_post_gst = match mode {
        RunMode::Safety => None,
        RunMode::Liveness => Some(context.gen_range(1..=r_max)),
    };

    log::push(format!(
        "{log_label} schedule: byzantine_idx={} required_containers={} (c,d,r)={:?} network_faults={:?} proc_faults={:?}",
        BYZANTINE_IDX,
        input.required_containers,
        byzz,
        network_schedule_vec,
        proc_faults,
    ));

    let participants_arc: Arc<[PublicKeyOf<P>]> = Arc::from(participants.clone());
    let network_schedule = Arc::new(network_schedule_vec);
    let proc_schedule_arc = Arc::new(Mutex::new(proc_faults));
    let empty_proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>> =
        Arc::new(Mutex::new(Vec::new()));

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
            intercept::resolver_view_extractor::<P::Scheme>(cert_codec, pool.clone()),
        );

        let ctx = context.with_label(&format!("validator_{validator}"));
        let reporter = spawn_honest_validator::<P, _, _, _, _, _, _, _>(
            ctx,
            &oracle,
            &participants,
            schemes[i].clone(),
            validator,
            P::Elector::default(),
            relay.clone(),
            Duration::from_secs(1),
            Duration::from_secs(2),
            (vote_primary, vote_receiver),
            (cert_primary, cert_receiver),
            (resolver_primary, resolver_receiver),
        );
        reporters.push(reporter);
    }

    // Closes the intercept queue once all forwarder-held clones drop.
    drop(intercept_tx);

    // Vote mutator: observed-value-first replay (seen payloads,
    // parent views, proposals, and nullify targets), local +/-1 or +/-2 edits
    // as fallback.
    // Cert/resolver process faults are omit-only so the injector
    // doesn't need their senders.
    let injector_ctx = context.with_label("byzzfuzz_injector");
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

/// Run the ByzzFuzz fuzzing method on `input` to check whether safety holds.
/// 4 honest engines plus a per-message strict-replace interception layer.
/// Faults apply for the whole run; finalization timeout is not a failure.
///
/// See [`crate::byzzfuzz`] module docs for the architectural overview.
pub fn run<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Per-channel forwarders own all network-fault behavior in this mode;
    // disable oracle-driven topology and do not use `Disrupter` actor.
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        // Safety mode: gate is constructed but never reaches GST, so
        // partition faults remain active for the entire run.
        let gate = FaultGate::new();
        let setup =
            setup_engines::<P>(&mut context, &mut input, gate, "byzzfuzz", RunMode::Safety).await;
        let mut reporters = setup.reporters;
        let config = input.configuration;

        // Wait only on correct reporters: BYZANTINE_IDX is intentionally
        // adversarial in this harness and may stall, which would otherwise
        // burn the full MAX_SLEEP_DURATION before invariants run.
        let mut finalizers = Vec::new();
        for (i, reporter) in reporters.iter_mut().enumerate() {
            if i == BYZANTINE_IDX {
                continue;
            }
            let required_containers = input.required_containers;
            let (mut latest, mut monitor): (View, ViewReceiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    let Some(next) = monitor.recv().await else {
                        return;
                    };
                    latest = next;
                }
            }));
        }

        select! {
          _ = join_all(finalizers) => {},
          _ = context.sleep(MAX_SLEEP_DURATION) => {},
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

/// Run the ByzzFuzz fuzzing method on `input` to check whether liveness holds.
/// Network partition faults apply during Phase 1, then the shared fault gate
/// reaches GST and Phase 2 requires each non-byzantine reporter to advance at
/// least one finalized view inside the post-GST window. Failure to advance is
/// a liveness violation (panics). Byzantine process faults may still apply
/// after GST: correct senders cannot omit messages, and the network cannot
/// drop messages, but the Byzantine sender can still omit or mutate its own
/// messages to correct recipients. `setup_engines` samples a second
/// post-GST view budget, and at GST the runner appends explicit process
/// faults for that many future Byzantine sender views so this path is not
/// accidentally exhausted by Phase 1 progress.
/// The byzantine identity (always at index 0) is excluded; only correct
/// process liveness is checked.
///
/// **Post-GST fault budget.** The initial process-fault schedule samples
/// views from `[1, r]` at setup, before any view advances. By the time GST
/// is reached, the Byzantine sender's `rnd(m)` has typically progressed past
/// most of those views, so the matching predicate `f.view == sender.rnd(m)`
/// stops firing and the Byzantine becomes silently well-behaved. To keep
/// the model claim honest, at GST the runner records the Byzantine's
/// current `rnd(m)` and appends one process fault per view in
/// `[byzantine_rnd + 1, byzantine_rnd + r_post_gst]`. `r_post_gst` is sampled
/// from the same range as the initial `r`. The schedule lives behind a
/// `Mutex<Vec<_>>` so the runtime extension is visible to the Byzantine's
/// outgoing forwarders.
///
/// ```text
/// time
///   |------ Phase 1: fault phase -------|---- Phase 2: post-GST window -----|
///   | network partitions may drop msgs  | all network links deliver msgs    |
///   | Byzantine process faults may run  | Byzantine process faults may run  |
///   |                                   |                                   |
///   | phase timer or early completion   | each correct reporter must        |
///   |                                   | finalize above its baseline       |
///   |                                   |                                   |
///   +-----------------------------------+-----------------------------------+
///                                       |
///                                       +-- record finalization baselines,
///                                           then reach GST
/// ```
///
/// The finalization baseline is each correct reporter's latest finalized
/// view immediately before GST. The post-GST check requires every
/// correct reporter to finalize a strictly newer view.
///
/// If all non-byzantine reporters reach `required_containers` during the
/// fault phase, the run skips the post-GST check and proceeds directly to
/// safety invariants.
pub fn run_liveness<P: Simplex>(mut input: crate::FuzzInput)
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
            setup_engines::<P>(
                &mut context,
                &mut input,
                gate.clone(),
                "byzzfuzz_liveness",
                RunMode::Liveness,
            )
            .await;
        let mut reporters = setup.reporters;
        let byzantine_view = setup.byzantine_view;
        let proc_schedule = setup.proc_schedule;
        let participants = setup.participants;
        let post_gst_fault_views = setup
            .post_gst_fault_views
            .expect("liveness mode samples post-GST fault views");
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
            phase1_finishers.push(context.with_label("byzzfuzz_phase1_finisher").spawn(
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
            _ = context.sleep(BYZZFUZZ_FAULT_PHASE) => false,
        };

        if !phase1_early_complete {
            // Phase 2: record each correct reporter's finalization baseline,
            // reach GST, then require a strictly newer finalization.
            // Keep `baselines` separate so timeout diagnostics can
            // re-subscribe and report each node's current view.
            let mut baselines: Vec<(usize, u64)> = Vec::with_capacity(non_byzantine.len());
            let mut watcher_inputs = Vec::with_capacity(non_byzantine.len());
            for &i in &non_byzantine {
                let (latest, monitor): (View, ViewReceiver<View>) = reporters[i].subscribe().await;
                let baseline = latest.get();
                baselines.push((i, baseline));
                watcher_inputs.push((i, baseline, latest, monitor));
            }

            // GST: disable partition drops. Append post-GST Byzantine
            // process faults starting after the sender's current rnd(m) so
            // Byzantine behavior does not disappear when the initial schedule
            // was exhausted during Phase 1.
            let byzantine_rnd = byzantine_view.get();
            let highest_pre_gst_proc_fault = proc_schedule
                .lock()
                .iter()
                .map(|f| f.view)
                .max()
                .unwrap_or(0);
            let first_post_gst_view = byzantine_rnd.saturating_add(1).max(1);
            let last_post_gst_view = first_post_gst_view
                .saturating_add(post_gst_fault_views.saturating_sub(1));
            let post_gst_faults = ByzzFuzz::post_gst_process_faults(
                first_post_gst_view..=last_post_gst_view,
                &participants,
                &mut context,
            );
            {
                let mut schedule = proc_schedule.lock();
                schedule.extend(post_gst_faults.clone());
            }
            log::push(format!(
                "byzzfuzz_liveness: gst_reached byzantine_rnd={byzantine_rnd} highest_pre_gst_proc_fault={highest_pre_gst_proc_fault} post_gst_fault_views={post_gst_fault_views} appended_post_gst_proc_faults={post_gst_faults:?}",
            ));
            gate.reach_gst();

            // Phase 2 watchers: true means the reporter advanced strictly
            // past its finalization baseline before the post-GST window closed.
            let mut watchers = Vec::new();
            for (i, baseline, mut latest, mut monitor) in watcher_inputs {
                watchers.push(
                    context
                        .with_label(&format!("byzzfuzz_post_gst_watcher_{i}"))
                        .spawn(move |_| async move {
                            while latest.get() <= baseline {
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
                _ = context.sleep(BYZZFUZZ_POST_GST_WINDOW) => false,
            };

            if !phase2_complete {
                let mut diag = String::new();
                for &(i, baseline) in &baselines {
                    let (latest, _): (View, ViewReceiver<View>) = reporters[i].subscribe().await;
                    let current = latest.get();
                    let _ = write!(diag, " node{i}={{baseline={baseline} current={current}}}");
                }
                panic!(
                    "byzzfuzz_liveness: no post-GST progress within {:?};{diag}",
                    BYZZFUZZ_POST_GST_WINDOW,
                );
            }
        }
g
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
