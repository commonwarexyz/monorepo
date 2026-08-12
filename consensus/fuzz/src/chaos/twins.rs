//! Chaos-twins: a real N4F1C3 cluster (one Byzantine twin leader + three honest
//! engines) in which an honest node crash-stops and durably replays while the
//! twin equivocates, then a post-recovery liveness check confirms the healed
//! cluster resumes finalizing.
//!
//! This corner is unreached by every other campaign. Chaos (N4F0C4) is
//! all-honest; the twins targets never crash a managed node; byzzfuzz has no
//! process crashes; mallory pins its single faultable identity to one node and
//! masks lifecycle faults whenever a Byzantine role is live. Only here do THREE
//! real honest engines run beside a real Byzantine twin while one of the honest
//! engines crashes and replays its journal.
//!
//! Safety math (N4F1C3, quorum 3): two conflicting finalizations need two nodes
//! signing both. The twin is ONE such identity; a crash-stopped honest node
//! signs nothing, so it can never be the second. So a Byzantine twin plus a
//! crashed honest node cannot forge a conflict UNLESS the recovered node replays
//! badly and becomes the second equivocator, the exact bug this hunts. The crash
//! costs liveness (two honest < quorum during the outage), never safety.
//!
//! Recovery is checked by an actual oracle, not "did not panic on restart".
//! After the node restarts, the oracle requires every honest reporter to
//! OBSERVE a finalization strictly above the cluster's tip at recovery (the
//! byzzfuzz liveness-checker shape). The target sits above the cluster max, so
//! it cannot be met by merely backfilling to an existing view; it demands one
//! genuinely new container that every honest node sees. Each wait is reactive
//! (returns on the first finalization; the step timeout is only the no-progress
//! fallback) and the oracle stops once every honest node reaches the target. A
//! restart that rejoins but never catches up, or any honest node that wedges,
//! is a finding. This is the only liveness assertion chaos-twins makes.
//!
//! Wiring reuses the twins split model (one registered identity driven as two
//! partition-scoped engines via `split_with`), the twins-aware elector with
//! scripted leaders, chaos's `crash_stop` / durable restart, and byzzfuzz's
//! bounded post-recovery liveness wait.
//!
//! The Byzantine index is not pinned to a constant: the canonical twins
//! generator elects the LAST index of a symmetry cell, so a low index (0) only
//! leads a scenario long enough to have been isolated first, and never leads a
//! single-round prefix. Chaos-twins instead DERIVES the Byzantine index from an
//! actual scripted leader, and derives the crash target as a distinct honest
//! index. The Byzantine term is fixed to the SECOND scripted term (via `Sampled`
//! per-round leaders), so exactly one honest-led warm-up term precedes it. The
//! crash fires only once the crash node's OWN reporter shows it finalized in the
//! warm-up (journaled real vote / certificate / view state) AND observed `byz`
//! leading the Byzantine term, so the node is always down while the Byzantine
//! node is the active leader and its restart exercises durable journal replay
//! rather than a cold startup, the corner this target exists to reach. An input
//! that never reaches that gate within a bounded cap is skipped, never crashed
//! in the wrong term.

use super::{log, runner::all_nodes_reached};
use crate::{
    ManagedValidator, N4F1C3, PublicKeyOf, build_validator_with_reporter, invariants,
    mallory::{
        lifecycle,
        runner::{FinalizationClock, wait_for_step_boundary},
    },
    simplex::Simplex,
    simplex_audit::{RecordingReporter, summaries},
    utils::Partition,
};
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    Monitor as _, Viewable as _,
    simplex::{
        Engine, Floor, config,
        mocks::{application, relay, reporter, twins},
        types::{Certificate, Vote},
    },
    types::{Delta, Epoch, TermLength, View},
};
use commonware_cryptography::{
    Sha256, certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_p2p::{
    Recipients,
    simulated::{Oracle, SplitOrigin, SplitTarget},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, IoBuf, Runner, Supervisor, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{FuzzRng, NZUsize, channel::mpsc::Receiver as ViewReceiver};
use rand::RngExt as _;
use std::{cmp::Ordering, collections::HashSet, sync::Arc, time::Duration};

/// Bound on scenario resamples while searching for a case whose compromised
/// participant is also a scripted leader. Generous; the search almost always
/// succeeds on the first try, and a leader-derived fallback covers the rest.
const SCENARIO_SAMPLE_TRIES: usize = 64;

/// The scripted round the Byzantine twin must lead: exactly the SECOND term, so
/// round 0 is a single honest-led warm-up term and the crash lands one term in.
/// Fixing it to 1 keeps the crash view small (`term_length`, at most 5), so the
/// pre-crash phase never truncates against its step cap before the term entry.
const CHAOS_TWINS_BYZ_ROUND: u64 = 1;

/// Bound on the pre-crash phase: paced steps advancing the cluster to the
/// Byzantine leader's term before crashing. A cap in case finalization stalls
/// below the target view (the crash still lands inside the scripted prefix).
const CHAOS_TWINS_MAX_PRE_CRASH_STEPS: usize = 24;
/// Down-window length in paced steps: how long the crashed honest node stays
/// down (spanning the Byzantine leader's term) before the durable restart.
const CHAOS_TWINS_DOWN_STEPS: u64 = 4;
/// Per-step reactive boundary timeout: a step ends on the first finalization
/// past its baseline over the live honest set, or after this deterministic
/// timeout if progress was suppressed (normal during the sub-quorum outage).
const CHAOS_TWINS_STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound of the RNG-drawn jitter before each step, roughly one view.
const CHAOS_TWINS_JITTER_MS: u64 = 2_000;
/// Bounded wait for post-recovery liveness, mirroring byzzfuzz's post-GST
/// window: once the prefix has ended and the node has recovered, three honest
/// engines must all observe a fresh finalization within this horizon.
const CHAOS_TWINS_LIVENESS_WINDOW: Duration = Duration::from_secs(120);

/// The honest managed reporter type: the recording reporter over the twins
/// elector (honest nodes share the scripted leader schedule).
type TwinsElector<P> = twins::Elector<<P as Simplex>::Elector>;
type HonestReporter<P> = RecordingReporter<
    deterministic::Context,
    <P as Simplex>::Scheme,
    TwinsElector<P>,
    Sha256Digest,
>;
type HonestSummary<P> = reporter::Reporter<
    deterministic::Context,
    <P as Simplex>::Scheme,
    TwinsElector<P>,
    Sha256Digest,
>;
type HonestValidator<P> = ManagedValidator<P, HonestReporter<P>>;

/// Choose the Byzantine twin: an index that leads scripted round
/// [`CHAOS_TWINS_BYZ_ROUND`] (the second term) but NOT round 0, so round 0 is a
/// clean honest-led warm-up term the crash target finalizes and journals before
/// it is crashed inside the Byzantine term. Uses `Sampled` mode (independent
/// per-round leaders); `Sustained` repeats one leader every round, which would
/// force the Byzantine term to round 0 and crash at genesis.
///
/// Prefers a case whose compromised participant is that leader (canonical
/// partition masks built around its identity); otherwise derives the Byzantine
/// index from the round's scripted leader when it differs from round 0's. Every
/// scripted round sharing one leader (no warm-up term possible) returns `None`,
/// so the caller skips the input rather than crash at genesis. `faults = 1`.
fn choose_byz(
    context: &mut deterministic::Context,
    n: usize,
    rounds: usize,
) -> Option<(twins::Scenario, usize)> {
    let framework = twins::Framework {
        participants: n,
        faults: 1,
        rounds,
        mode: twins::Mode::Sampled,
        max_cases: 16,
    };
    let r_byz = CHAOS_TWINS_BYZ_ROUND as usize;
    let leads_byz_term = |rounds: &[twins::RoundScenario], byz: usize| {
        rounds.len() > r_byz && rounds[0].leader() != byz && rounds[r_byz].leader() == byz
    };
    // Prefer the case's compromised participant as the Byzantine-term leader.
    for _ in 0..SCENARIO_SAMPLE_TRIES {
        for case in twins::cases(context, framework) {
            if let Some(&byz) = case.compromised.first()
                && leads_byz_term(case.scenario.rounds(), byz)
            {
                return Some((case.scenario, byz));
            }
        }
    }
    // Fallback: take the Byzantine-term leader directly when it differs from
    // round 0's, so an honest warm-up term still precedes it.
    for _ in 0..SCENARIO_SAMPLE_TRIES {
        for case in twins::cases(context, framework) {
            let rounds = case.scenario.rounds();
            if rounds.len() > r_byz && rounds[r_byz].leader() != rounds[0].leader() {
                let byz = rounds[r_byz].leader();
                return Some((case.scenario, byz));
            }
        }
    }
    None
}

/// Spawn the Byzantine twin pair on `validator`: two full legitimate engines
/// (primary and secondary) sharing one registered identity, their traffic split
/// by the scenario's per-round partition masks. Returns both halves' summary
/// reporters so the vote/fault oracle can observe evidence they alone may hold.
#[allow(clippy::too_many_arguments)]
fn spawn_twin_pair<P: Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &Arc<[PublicKeyOf<P>]>,
    idx: usize,
    scheme: P::Scheme,
    elector: TwinsElector<P>,
    scenario: &twins::Scenario,
    term_length: TermLength,
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    channels: crate::NetworkChannels<PublicKeyOf<P>>,
    input: &crate::FuzzInput,
) -> [HonestSummary<P>; 2]
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    let validator = participants[idx].clone();
    let context = context.child("twin").with_attribute("index", idx);
    let (vote_network, certificate_network, resolver_network) = channels;

    let make_vote_forwarder = || {
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
            let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                return None;
            };
            let (primary, secondary) =
                scenario.partitions(msg.view(), term_length, participants.as_ref());
            match origin {
                SplitOrigin::Primary => Some(Recipients::Some(primary)),
                SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
            }
        }
    };
    let make_certificate_forwarder = || {
        let codec = scheme.certificate_codec_config();
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
            let Ok(msg) =
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut message.as_ref(), &codec)
            else {
                return None;
            };
            let (primary, secondary) =
                scenario.partitions(msg.view(), term_length, participants.as_ref());
            match origin {
                SplitOrigin::Primary => Some(Recipients::Some(primary)),
                SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
            }
        }
    };
    let make_vote_router = || {
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |(sender, message): &(_, IoBuf)| {
            let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                return SplitTarget::None;
            };
            scenario.route(msg.view(), term_length, sender, participants.as_ref())
        }
    };
    let make_certificate_router = || {
        let codec = scheme.certificate_codec_config();
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |(sender, message): &(_, IoBuf)| {
            let Ok(msg) =
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut message.as_ref(), &codec)
            else {
                return SplitTarget::None;
            };
            scenario.route(msg.view(), term_length, sender, participants.as_ref())
        }
    };
    let make_resolver_forwarder = || {
        let codec = scheme.certificate_codec_config();
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
            let view = crate::twins_resolver_view::<P, Sha256Digest>(message, &codec)?;
            let (primary, secondary) =
                scenario.partitions(view, term_length, participants.as_ref());
            match origin {
                SplitOrigin::Primary => Some(Recipients::Some(primary)),
                SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
            }
        }
    };
    let make_resolver_router = || {
        let codec = scheme.certificate_codec_config();
        let participants = participants.clone();
        let scenario = scenario.clone();
        move |(sender, message): &(_, IoBuf)| {
            let Some(view) = crate::twins_resolver_view::<P, Sha256Digest>(message, &codec) else {
                return SplitTarget::None;
            };
            scenario.route(view, term_length, sender, participants.as_ref())
        }
    };

    let (vote_sender, vote_receiver) = vote_network;
    let (certificate_sender, certificate_receiver) = certificate_network;
    let (resolver_sender, resolver_receiver) = resolver_network;

    let (vote_sender_primary, vote_sender_secondary) =
        vote_sender.split_with(make_vote_forwarder());
    let (vote_receiver_primary, vote_receiver_secondary) =
        vote_receiver.split_with(context.child("pending_split"), make_vote_router());
    let (certificate_sender_primary, certificate_sender_secondary) =
        certificate_sender.split_with(make_certificate_forwarder());
    let (certificate_receiver_primary, certificate_receiver_secondary) = certificate_receiver
        .split_with(context.child("recovered_split"), make_certificate_router());
    let (resolver_sender_primary, resolver_sender_secondary) =
        resolver_sender.split_with(make_resolver_forwarder());
    let (resolver_receiver_primary, resolver_receiver_secondary) =
        resolver_receiver.split_with(context.child("resolver_split"), make_resolver_router());

    let primary = {
        let reporter_cfg = reporter::Config {
            participants: participants
                .as_ref()
                .try_into()
                .expect("public keys are unique"),
            scheme: scheme.clone(),
            elector: elector.clone(),
        };
        let primary_context = context.child("primary");
        let reporter = reporter::Reporter::new(primary_context.child("reporter"), reporter_cfg);
        let app_cfg = application::Config::<Sha256, _> {
            relay: relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: application::Certifier::Always,
        };
        let (actor, application) =
            application::Application::new(primary_context.child("application"), app_cfg);
        actor.start();
        let engine_cfg = config::Config {
            blocker: oracle.control(validator.clone()),
            scheme: scheme.clone(),
            elector: elector.clone(),
            automaton: application.clone(),
            relay: application.clone(),
            reporter: reporter.clone(),
            partition: format!("twin_{idx}_primary"),
            mailbox_size: input.mailbox_size,
            epoch: Epoch::new(crate::EPOCH),
            floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(crate::EPOCH))),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_millis(1_500),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip_timeout: Duration::from_secs(11),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(
                &primary_context,
                crate::PAGE_SIZE,
                crate::PAGE_CACHE_SIZE,
            ),
            strategy: Sequential,
            forwarding: input.forwarding,
            track_historical_votes: false,
        };
        Engine::new(primary_context.child("engine"), engine_cfg).start(
            (vote_sender_primary, vote_receiver_primary),
            (certificate_sender_primary, certificate_receiver_primary),
            (resolver_sender_primary, resolver_receiver_primary),
        );
        reporter
    };

    let secondary = {
        let reporter_cfg = reporter::Config {
            participants: participants
                .as_ref()
                .try_into()
                .expect("public keys are unique"),
            scheme: scheme.clone(),
            elector: elector.clone(),
        };
        let secondary_context = context.child("secondary");
        let reporter = reporter::Reporter::new(secondary_context.child("reporter"), reporter_cfg);
        let app_cfg = application::Config::<Sha256, _> {
            relay: relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: application::Certifier::Always,
        };
        let (actor, application) =
            application::Application::new(secondary_context.child("application"), app_cfg);
        actor.start();
        let engine_cfg = config::Config {
            blocker: oracle.control(validator.clone()),
            scheme: scheme.clone(),
            elector,
            automaton: application.clone(),
            relay: application.clone(),
            reporter: reporter.clone(),
            partition: format!("twin_{idx}_secondary"),
            mailbox_size: input.mailbox_size,
            epoch: Epoch::new(crate::EPOCH),
            floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(crate::EPOCH))),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_millis(1_500),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip_timeout: Duration::from_secs(11),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(
                &secondary_context,
                crate::PAGE_SIZE,
                crate::PAGE_CACHE_SIZE,
            ),
            strategy: Sequential,
            forwarding: input.forwarding,
            track_historical_votes: false,
        };
        Engine::new(secondary_context.child("engine"), engine_cfg).start(
            (vote_sender_secondary, vote_receiver_secondary),
            (certificate_sender_secondary, certificate_receiver_secondary),
            (resolver_sender_secondary, resolver_receiver_secondary),
        );
        reporter
    };

    [primary, secondary]
}

/// Build one honest managed validator (recording reporter, twins elector) on the
/// given partition. `existing` reuses a retained reporter for a durable restart.
#[allow(clippy::too_many_arguments)]
fn build_honest<P: Simplex>(
    existing: Option<HonestReporter<P>>,
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: TwinsElector<P>,
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    partition: String,
    channels: crate::NetworkChannels<PublicKeyOf<P>>,
    input: &crate::FuzzInput,
) -> HonestValidator<P>
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    let (pending, recovered, resolver) = channels;
    build_validator_with_reporter::<P, TwinsElector<P>, HonestReporter<P>, _, _, _, _, _, _>(
        existing,
        context,
        oracle,
        participants,
        scheme,
        validator,
        elector,
        relay.clone(),
        Duration::from_secs(1),
        Duration::from_millis(1_500),
        input.mailbox_size,
        input.forwarding,
        partition,
        pending,
        recovered,
        resolver,
        input.certify,
        input.reporting,
    )
}

/// Durable restart of `mv` on its existing partition with the twins elector, so
/// the recovered engine replays its journal and rejoins the scripted schedule.
#[allow(clippy::too_many_arguments)]
async fn restart_honest<P: Simplex>(
    mv: &mut HonestValidator<P>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    elector: TwinsElector<P>,
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    input: &crate::FuzzInput,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    lifecycle::abort_tasks(mv).await;
    let validator = mv.validator().clone();
    let mut fresh = crate::utils::register(oracle, std::slice::from_ref(&validator)).await;
    let channels = fresh
        .remove(&validator)
        .expect("chaos-twins: re-registration returned no channels");
    let ctx = context
        .child("honest")
        .with_attribute("public_key", &validator);
    let rebuilt = build_honest::<P>(
        Some(mv.reporter()),
        ctx,
        oracle,
        participants,
        mv.scheme().clone(),
        validator,
        elector,
        relay,
        mv.partition().to_string(),
        channels,
        input,
    );
    mv.adopt(rebuilt);
    mv.reporter().set_generation(mv.generation());
}

/// Full safety suite over the honest managed reporters, with the Byzantine twin
/// index `byz` excluded as the Byzantine signer. The twin's two summary
/// reporters are observers only (a twin half may solely hold evidence against a
/// correct signer); they are never fed to the honest-only audit suite, which the
/// twin legitimately violates for its own identity.
fn check_safety<P: Simplex>(
    honest: &[HonestReporter<P>],
    twin_summaries: &[HonestSummary<P>],
    byz: usize,
    elector: TwinsElector<P>,
    term_length: TermLength,
) {
    // Full audit-history suite over the RECORDING reporters: the append-only,
    // full-proposal (parent-aware) conflict checks (`finalization_history` /
    // `notarization_history` keep every certificate per round and compare the
    // whole signed proposal, unlike the overwrite-per-view summary certificate
    // maps and the payload-keyed vote maps) PLUS the certificate-graph basic
    // suite. The retained audit log stamps each durable incarnation, so
    // replay-order-sensitive checks remain incarnation-local while
    // order-independent safety and healing evidence survives journal pruning.
    invariants::check::<P>(term_length, honest);

    let honest_summaries = summaries(honest);
    let mut observers = honest_summaries.clone();
    observers.extend(twin_summaries.iter().cloned());
    invariants::check_no_invalid_reports(&honest_summaries);
    invariants::check_vote_invariants_with_byzantine(
        &HashSet::from([byz]),
        elector,
        Epoch::new(crate::EPOCH),
        term_length,
        &observers,
    );
}

/// The live honest set for the step boundary: honest managed nodes still
/// `Running` (the crashed node is excluded until it recovers).
fn live_honest<P: Simplex>(managed: &[HonestValidator<P>]) -> HashSet<usize> {
    managed
        .iter()
        .filter(|mv| matches!(mv.lifecycle(), crate::ValidatorLifecycle::Running))
        .map(|mv| mv.idx())
        .collect()
}

/// One paced observation step: jitter, then wait for the first finalization past
/// the live-honest baseline (or the deterministic no-progress fallback), then
/// run the safety suite. Shared by the pre-crash, down-window, and settle
/// phases so every phase safety-checks on the same reactive boundary.
#[allow(clippy::too_many_arguments)]
async fn paced_step<P: Simplex>(
    context: &mut deterministic::Context,
    clock: &mut FinalizationClock,
    managed: &[HonestValidator<P>],
    honest: &[HonestReporter<P>],
    twin_summaries: &[HonestSummary<P>],
    byz: usize,
    elector: &TwinsElector<P>,
    term_length: TermLength,
) {
    let jitter = Duration::from_millis(context.random_range(0..=CHAOS_TWINS_JITTER_MS));
    context.sleep(jitter).await;

    clock.drain();
    let live = live_honest::<P>(managed);
    let baseline = clock.baseline(&live);
    let deadline = context.current() + CHAOS_TWINS_STEP_TIMEOUT;
    wait_for_step_boundary(context, clock, &live, baseline, deadline).await;
    check_safety::<P>(honest, twin_summaries, byz, elector.clone(), term_length);
}

/// Run one chaos-twins episode. Seeded solely from `FuzzRng::new(raw_bytes)`;
/// no cross-input state, so a saved input replays exactly.
pub(crate) fn run<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    input.configuration = N4F1C3;
    input.partition = Partition::Connected;
    input.degraded_network = false;
    input.certify = crate::CertifyChoice::Always;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (mut oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;
        crate::print_fuzz_input::<P>(crate::Mode::ChaosTwins, &input);
        let participants: Arc<[PublicKeyOf<P>]> = participants.into();

        let n = input.configuration.n as usize;
        let required_containers = input.required_containers;
        let term_length = P::effective_term_length(input.term_length);
        let relay = Arc::new(relay::Relay::new());

        // At least two scripted rounds so an honest-led warm-up term (round 0)
        // precedes the Byzantine-led term the crash lands in.
        let rounds = (required_containers as usize).clamp(2, 8);
        let Some((scenario, byz)) = choose_byz(&mut context, n, rounds) else {
            log::push(
                "chaos-twins: no honest-warm-up twins scenario sampled; skipping input".into(),
            );
            return;
        };
        // `crash` is a distinct honest index. `target_view` is the first view of
        // the Byzantine term; Phase A crashes `crash` only once its OWN reporter
        // shows `byz` leading `target_view` (entry into the Byzantine term).
        let crash = (0..n).find(|&idx| idx != byz).expect("an honest index exists");
        let target_view = View::new(CHAOS_TWINS_BYZ_ROUND * term_length.get() + 1);
        let elector = twins::Elector::new(P::elector(term_length), &scenario, n);

        // Byzantine twin on `byz` (never crashed).
        let twin_channels = registrations
            .remove(&participants[byz])
            .expect("twin validator should be registered");
        let twin_summaries = spawn_twin_pair::<P>(
            &context,
            &oracle,
            &participants,
            byz,
            schemes[byz].clone(),
            elector.clone(),
            &scenario,
            term_length,
            &relay,
            twin_channels,
            &input,
        );

        // Honest managed validators (every index != `byz`).
        let mut managed: Vec<HonestValidator<P>> = Vec::with_capacity(n - 1);
        for idx in 0..n {
            if idx == byz {
                continue;
            }
            let validator = participants[idx].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("honest")
                .with_attribute("public_key", &validator);
            let partition = validator.to_string();
            managed.push(build_honest::<P>(
                None,
                ctx,
                &oracle,
                participants.as_ref(),
                schemes[idx].clone(),
                validator,
                elector.clone(),
                &relay,
                partition,
                channels,
                &input,
            ));
        }

        // Persistent finalization clock over the honest managed reporters.
        // `latest` is indexed by NODE id (the twin's slot is unused), so it is
        // sized to `n`, not the honest count.
        let honest: Vec<HonestReporter<P>> = managed.iter().map(|mv| mv.reporter()).collect();
        let mut clock = FinalizationClock {
            latest: vec![0u64; n],
            monitors: Vec::with_capacity(managed.len()),
        };
        for mv in &managed {
            let (latest, monitor): (View, ViewReceiver<View>) = mv.reporter().subscribe().await;
            clock.latest[mv.idx()] = latest.get();
            clock.monitors.push((mv.idx(), monitor));
        }

        let crash_slot = managed.iter().position(|mv| mv.idx() == crash).unwrap();
        let down_steps = context.random_range(1..=CHAOS_TWINS_DOWN_STEPS);

        // Phase A: run the honest warm-up term, then crash the honest node
        // exactly as it ENTERS the Byzantine term. Wait specifically for the
        // CRASH NODE to finalize the last warm-up view (`warmup_tip`); that
        // boundary is emitted while it processes the certificate that unlocks the
        // next (Byzantine) view, so crashing immediately after, with no further
        // paced step, lets the engine enter the Byzantine term but never run
        // through and finalize it. The tip must land EXACTLY on `warmup_tip`:
        // an overshoot means the warm-up term was nullified/skipped and a
        // Byzantine-term view already finalized, so the intended crash boundary
        // was missed, SKIP rather than crash late. `warmup_tip > 0` also proves
        // the crash node itself finalized and journaled durable warm-up state.
        let warmup_tip = target_view.get() - 1;
        let only_crash: HashSet<usize> = std::iter::once(crash).collect();
        let mut pre = 0usize;
        let reached = loop {
            clock.drain();
            match clock.latest[crash].cmp(&warmup_tip) {
                Ordering::Equal => break true,
                Ordering::Greater => break false,
                Ordering::Less => {}
            }
            if pre >= CHAOS_TWINS_MAX_PRE_CRASH_STEPS {
                break false;
            }
            pre += 1;
            log::push(format!(
                "pre-crash step={pre} byz={byz} crash={crash} warmup_tip={warmup_tip} crash_tip={}",
                clock.latest[crash],
            ));
            // Wait for the CRASH NODE's own next finalization (baseline = its
            // current tip), so the loop stops the moment it reaches the warm-up
            // tip rather than on any node's progress.
            let baseline = clock.latest[crash];
            let step_deadline = context.current() + CHAOS_TWINS_STEP_TIMEOUT;
            wait_for_step_boundary(&mut context, &mut clock, &only_crash, baseline, step_deadline)
                .await;
            check_safety::<P>(&honest, &twin_summaries, byz, elector.clone(), term_length);
        };
        // Confirm from the crash node's own leader map that the next term is
        // Byzantine-led before crashing; skip if not yet derived (never crash in
        // the wrong term).
        let byz_leads_next = honest[crash_slot]
            .inner()
            .leaders
            .lock()
            .get(&target_view)
            .is_some_and(|leader| leader == &participants[byz]);
        if !reached || !byz_leads_next {
            log::push(format!(
                "chaos-twins: skipping input (reached={reached} byz_leads_next={byz_leads_next} byz={byz} crash={crash} warmup_tip={warmup_tip} crash_tip={})",
                clock.latest[crash],
            ));
            return;
        }
        lifecycle::crash_stop(&mut managed[crash_slot]).await;
        log::push(format!("crash byz={byz} crash={crash} down_steps={down_steps}"));

        // Phase B: hold the outage across the Byzantine leader's term.
        for _ in 0..down_steps {
            paced_step::<P>(
                &mut context,
                &mut clock,
                &managed,
                &honest,
                &twin_summaries,
                byz,
                &elector,
                term_length,
            )
            .await;
        }

        // Phase C: durable restart (journal replay). Capture the recovery target
        // IMMEDIATELY, before any settle step, so it is exactly ONE container
        // above the cluster's tip at recovery (a settle step here would inflate
        // the baseline and demand an extra finalization).
        restart_honest::<P>(
            &mut managed[crash_slot],
            &context,
            &mut oracle,
            participants.as_ref(),
            elector.clone(),
            &relay,
            &input,
        )
        .await;
        log::push(format!("recover crash={crash}"));

        // Recovery oracle (byzzfuzz liveness-checker shape). The crashed node has
        // restarted; the target is one finalization above the cluster's tip at
        // recovery. The baseline is the cluster MAX, so the target cannot be met
        // by merely backfilling to an existing view: it demands one NEW container
        // that every honest node observes. A restarted node that never catches
        // up, a cluster wedge, or a different honest node wedged by its final
        // trigger all remain below the target and are findings. Each wait is
        // reactive, and the loop stops once every honest node reaches the target.
        // This is the only place chaos-twins asserts liveness.
        let live = live_honest::<P>(&managed);
        assert_eq!(
            live.len(),
            n - 1,
            "chaos-twins: honest node did not recover before the liveness oracle",
        );
        clock.drain();
        let target = clock.baseline(&live) + 1;
        let deadline = context.current() + CHAOS_TWINS_LIVENESS_WINDOW;
        loop {
            clock.drain();
            if all_nodes_reached(&clock.latest, &live, target) {
                break;
            }
            assert!(
                context.current() < deadline,
                "chaos-twins: not every honest node finalized a new container after recovery: target {target}, honest tips {:?}, recovered node {crash}, window {:?}",
                {
                    let mut tips: Vec<_> = live
                        .iter()
                        .map(|node| (*node, clock.latest[*node]))
                        .collect();
                    tips.sort_unstable();
                    tips
                },
                CHAOS_TWINS_LIVENESS_WINDOW,
            );
            paced_step::<P>(
                &mut context,
                &mut clock,
                &managed,
                &honest,
                &twin_summaries,
                byz,
                &elector,
                term_length,
            )
            .await;
        }

        check_safety::<P>(&honest, &twin_summaries, byz, elector.clone(), term_length);
    });
}
