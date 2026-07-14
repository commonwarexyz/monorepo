//! The `Mode::Mallory` OODA episode loop and its two action choosers.
//!
//! Mallory runs four honest Simplex validators and drives a fixed-length episode
//! of observe-orient-decide-act steps, perturbing only the network (never node
//! behavior). Each step observes the honest happens-before fingerprint (the
//! Q-state) and protocol-state descriptor, decides on an [`action`] under a legal
//! mask, enacts its [`action::FaultPlan`] against the network, runs one fixed
//! deterministic-time window, then heals the fault and (for the learned chooser)
//! applies a temporal-difference update rewarding novel state / happens-before
//! fingerprints.
//!
//! Both [`Chooser`]s share ALL of this infrastructure -- setup, catalog,
//! parameter sampling, episode length, observation window, healing, state and
//! reward extraction, and the episode-end oracle. Only action selection differs:
//! [`Chooser::Learned`] samples a masked softmax over the campaign Q-row and
//! learns; [`Chooser::Random`] samples a uniform legal action from the runtime
//! RNG and never touches the campaign, so it neither learns nor pollutes the
//! shared novelty registries. With real faults (node isolation, network
//! partition) in the catalog the two genuinely diverge; the split exists so that
//! divergence measures the policy against a uniform baseline over the same wiring.

use super::{action, adversary, lifecycle, log, network, policy, state};
use crate::{
    build_validator, build_validator_with_reporter, happens_before, invariants,
    simplex::Simplex, sniff_sink, CertCfgOf, CertifyChoice, ManagedValidator, PublicKeyOf,
    SniffChannel, SniffingReceiver, ValidatorLifecycle, BYZANTINE_IDX, N4F0C4, POST_GST_WINDOW,
};
use commonware_consensus::{
    simplex::mocks::{relay, reporter::Reporter},
    types::View,
    Monitor as _,
};
use commonware_cryptography::{
    certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Oracle, Receiver as SimReceiver};
use commonware_runtime::{deterministic, Clock, Runner, Spawner, Supervisor};
use commonware_utils::{
    channel::{
        mpsc::{self, Receiver as ViewReceiver},
        oneshot,
    },
    FuzzRng,
};
use futures::future::join_all;
use rand::{Rng, RngExt as _};
use std::{collections::HashSet, fmt::Write as _, sync::Arc, time::Duration};
use tracing::{dispatcher, Dispatch};

/// Number of policy decision steps in one Mallory episode.
const MALLORY_EPISODE_STEPS: usize = 12;
/// The single fixed deterministic-time observation window each step runs for.
/// A FIXED window (not "next finalization or deadline") keeps the step reward
/// from being biased toward progress-preserving actions: a step that suppresses
/// progress is observed over the same span as one that does not.
const MALLORY_WINDOW: Duration = Duration::from_secs(5);
/// Brief deterministic settle run after a packet fault heals: the F3 quiescence
/// barrier flushes the pump, then this lets the engine consume the just-flushed
/// packets so the next-state fingerprint reflects THIS step's fault rather than
/// bleeding into the next step. Fixed (no RNG) so a same-seed replay is identical.
const MALLORY_SETTLE: Duration = Duration::from_millis(500);

/// Env-tag bit folded into the Q-state / novelty fingerprints once node 0 has become
/// amnesiac (Running but empty-storage, so Byzantine). A distinct nonzero constant,
/// well-separated from every [`adversary::AdversaryRole::tag`], so post-amnesia states
/// key distinct Q-rows and novelty slots from the pre-amnesia Honest states they would
/// otherwise alias despite a different legality and fault model.
const AMNESIA_TAG: u64 = 0xa3f1_9c2d_7b64_e850;

/// The honest reporter type the runner clones for state extraction and liveness.
type MalloryReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// Whether a step's sampled action actually perturbed the run. Logging / observability
/// ONLY (the decision log's `applied` field); it never gates learning -- a `NoEffect`
/// action still receives its TD credit, which is the correct RL treatment of a no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enactment {
    /// The action perturbed the run: a lifecycle or topology fault (which always take
    /// effect), or a packet fault the pump actually matched a packet on.
    Applied,
    /// The action installed but changed nothing: [`action::Action::NoFault`], or a
    /// packet fault whose pump matched no packet this window.
    NoEffect,
}

/// The per-step environment tag folded into the Q-state and novelty fingerprints:
/// the episode [`adversary::AdversaryRole`] tag XOR [`AMNESIA_TAG`] once node 0 is
/// amnesiac. Under the Honest role with no amnesia this is `0` (an identity mix, so
/// the warm campaign's honest rows are unchanged).
fn env_tag(role: adversary::AdversaryRole, node0_amnesiac: bool) -> u64 {
    role.tag() ^ if node0_amnesiac { AMNESIA_TAG } else { 0 }
}

/// The remaining observation sleep so a step spans exactly [`MALLORY_WINDOW`] from its
/// start regardless of any deterministic downtime already slept during enact (a
/// restart's [`lifecycle::MALLORY_RESTART_DOWNTIME`]). Saturates to zero if enact
/// already exceeded the window, so a restart observes `window - downtime` and totals
/// exactly one window, matching every non-restart step (F6).
fn observe_remaining(window: Duration, elapsed: Duration) -> Duration {
    window.saturating_sub(elapsed)
}

/// The post-heal liveness target every live correct node must reach: one view past the
/// highest pre-heal frontier `max_baseline`, proving each caught up after the last
/// fault/heal/restart, but never below the absolute `required_containers`. On overflow
/// of `max_baseline + 1` the absolute target is kept (F2).
fn liveness_target(required_containers: u64, max_baseline: u64) -> u64 {
    match max_baseline.checked_add(1) {
        Some(next) => required_containers.max(next),
        None => required_containers,
    }
}

/// The decision-log effect of enacting `plan`, given whether its packet pump matched a
/// packet. Logging only (see [`Enactment`]): a lifecycle or topology fault always takes
/// effect; a packet fault takes effect iff the pump matched; [`action::FaultPlan::None`]
/// never does. `matched` is ignored for the non-packet arms.
fn enactment_of(plan: &action::FaultPlan, matched: bool) -> Enactment {
    match plan {
        action::FaultPlan::None => Enactment::NoEffect,
        action::FaultPlan::PacketDelay { .. }
        | action::FaultPlan::PacketLoss { .. }
        | action::FaultPlan::PacketCorrupt { .. }
        | action::FaultPlan::PacketDuplicate { .. }
        | action::FaultPlan::PacketReorder { .. } => {
            if matched {
                Enactment::Applied
            } else {
                Enactment::NoEffect
            }
        }
        action::FaultPlan::IsolateByzantine
        | action::FaultPlan::Partition(_)
        | action::FaultPlan::CrashStop
        | action::FaultPlan::CrashRestartDurable
        | action::FaultPlan::AmnesiaRestart => Enactment::Applied,
    }
}

/// Which action-selection policy an episode uses.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Chooser {
    /// Masked softmax over the campaign-persistent Q-row, with a temporal-
    /// difference update per step.
    Learned,
    /// Uniform over the legal actions from the runtime RNG; never consults or
    /// updates the campaign. The A/B baseline: exercised by the runner's A/B
    /// test and given its own fuzz target in a later PR, so the library build
    /// (which dispatches only [`Chooser::Learned`]) never constructs it.
    #[allow(dead_code)]
    Random,
    /// Force a fixed action id every step, bypassing the campaign. A test-only
    /// seam used to drive a specific fault (isolation, partition) deterministically
    /// rather than relying on RNG luck; like [`Chooser::Random`] it never learns.
    #[cfg(test)]
    Fixed(policy::ActionId),
    /// Force a fixed action id on the FIRST step and [`action::Action::NoFault`] on
    /// every subsequent step. A test-only seam for a one-shot lifecycle transition
    /// that masks itself afterward (an amnesia restart), so the forced id stays legal
    /// on step 0 while the episode still runs to full length -- letting a test
    /// observe the non-terminal property (unlike a crash-stop).
    #[cfg(test)]
    FixedFirst(policy::ActionId),
}

/// Uniformly sample a LEGAL action id from the runtime RNG. The [`Chooser::Random`]
/// selection: it never consults the campaign, so it neither learns nor pollutes
/// the shared novelty registries. At least one action must be legal.
fn select_uniform_legal(legal: &[bool], rng: &mut impl Rng) -> policy::ActionId {
    let legal_ids: Vec<policy::ActionId> = legal
        .iter()
        .enumerate()
        .filter_map(|(i, &ok)| ok.then_some(i))
        .collect();
    assert!(
        !legal_ids.is_empty(),
        "select requires at least one legal action"
    );
    legal_ids[rng.random_range(0..legal_ids.len())]
}

/// Insert the packet-fault layer below the sniffer for one honest node's one
/// channel: spawn a [`network::pump`] that owns `sim_rx` and relays it into an
/// unbounded internal FIFO, and return the [`network::PacketFaultReceiver`] that
/// drains that FIFO (the sniffer wraps it) plus the flush sender that signals the
/// pump to drain its held reorder buffer in order. The pump is idle -- a
/// transparent relay -- until the shared `cell` carries a fault matching
/// `(node, channel)`, and it draws no randomness, so it never perturbs a same-seed
/// replay.
fn spawn_packet_pump<P: Simplex>(
    context: &deterministic::Context,
    sim_rx: commonware_p2p::simulated::Receiver<PublicKeyOf<P>>,
    cell: network::PacketFaultCell,
    node: usize,
    channel: SniffChannel,
) -> (
    network::PacketFaultReceiver<PublicKeyOf<P>>,
    mpsc::UnboundedSender<network::FlushAck>,
) {
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (flush_tx, flush_rx) = mpsc::unbounded_channel();
    context
        .child("packet_pump")
        .spawn(move |ctx| network::pump(ctx, sim_rx, internal_tx, flush_rx, cell, node, channel));
    (network::PacketFaultReceiver::new(internal_rx), flush_tx)
}

/// Signal the pump for `(node, channel)` to drain its held reorder buffer in arrival
/// order and finish any in-flight per-packet delay, and WAIT for its ack (the F3
/// quiescence barrier): once this returns, that pump holds no fault-injected packet, so
/// the runner may clear the fault without step N's effects leaking into step N+1. Only
/// the single active pump ever buffers (one fault at a time), so every other pump acks
/// immediately. A dropped receiver or a failed send (the pump stopped) is ignored --
/// there is nothing to drain from a stopped pump.
async fn flush_pump_and_wait(
    senders: &[(usize, SniffChannel, mpsc::UnboundedSender<network::FlushAck>)],
    node: usize,
    channel: SniffChannel,
) {
    if let Some((_, _, tx)) = senders
        .iter()
        .find(|(n, c, _)| *n == node && *c == channel)
    {
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx.send(ack_tx).is_ok() {
            let _ = ack_rx.await;
        }
    }
}

/// The engine-facing receive stack [`wrap_receive`] builds for one channel: the
/// original simulated sender paired with the sniffer-over-pump receiver, plus the
/// pump's heal-time flush sender.
type WrappedReceive<P, S> = (
    (S, SniffingReceiver<P, network::PacketFaultReceiver<PublicKeyOf<P>>>),
    mpsc::UnboundedSender<network::FlushAck>,
);

/// Wrap one honest node's one raw simulated channel into Mallory's receive stack:
/// a fresh [`network::pump`] (applying the shared packet fault) beneath a
/// [`SniffingReceiver`] (recording happens-before arrivals). Returns the engine-
/// facing `(sender, receiver)` pair plus the pump's heal-time flush sender. Both
/// the initial setup and a durable restart go through this, so a restarted node's
/// receive stack is byte-for-byte identical to its first incarnation's.
#[allow(clippy::too_many_arguments)]
fn wrap_receive<P: Simplex, S>(
    context: &deterministic::Context,
    raw: (S, SimReceiver<PublicKeyOf<P>>),
    packet_cell: &network::PacketFaultCell,
    hb_capture: &Option<happens_before::capture::EventLog>,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
    cert_cfg: CertCfgOf<P>,
    node: usize,
    channel: SniffChannel,
) -> WrappedReceive<P, S> {
    let (sender, receiver) = raw;
    let (faulted, flush) =
        spawn_packet_pump::<P>(context, receiver, packet_cell.clone(), node, channel);
    let sink = sniff_sink(hb_capture, node as u32, peers, ambiguous);
    (
        (
            sender,
            SniffingReceiver::<P, _>::new(faulted, channel, cert_cfg, sink),
        ),
        flush,
    )
}

/// Restart the crashed faultable identity in place (`Mode::Mallory`), either
/// DURABLY on its existing storage or with AMNESIA on a fresh (empty) storage
/// partition. Shared body for [`restart_durable`] and [`restart_amnesia`]; the
/// `amnesia` flag selects the two differences (see below).
///
/// Ordering matters: abort+await BOTH old handles FIRST so no second incarnation
/// ever coexists with the first, then wait a fixed deterministic downtime, then
/// re-register the three channels (which overwrites the node's mailboxes and
/// disconnects the OLD incarnation's receivers, so it can no longer be delivered
/// to), re-wrap the fresh channels exactly as setup, and rebuild engine +
/// application under the node's dispatch. Not terminal in either mode.
///
/// The `amnesia` flag selects two things:
/// - `false` (durable): rebuild on the SAME storage partition while REUSING the
///   reporter, so the node replays its journal (durable state) and its pre-crash
///   safety history survives; it returns to [`Running`](crate::ValidatorLifecycle::Running).
/// - `true` (amnesia): rebuild on a FRESH (empty) partition derived from the bumped
///   generation ([`lifecycle::amnesia_partition`]) with a CLEAN-SLATE reporter
///   (`None`), so the node finds empty journaled storage -- it has forgotten its
///   durable state including signed votes and may equivocate. It becomes
///   [`Amnesiac`](crate::ValidatorLifecycle::Amnesiac), treated as Byzantine for the
///   rest of the episode.
///
/// A durably restarted node catches up to the quorum via resolver backfill.
#[allow(clippy::too_many_arguments)]
async fn restart<P: Simplex>(
    mv: &mut ManagedValidator<P>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    hb_log: &happens_before::capture::EventLog,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
    packet_cell: &network::PacketFaultCell,
    flush_senders: &mut Vec<(usize, SniffChannel, mpsc::UnboundedSender<network::FlushAck>)>,
    input: &crate::FuzzInput,
    amnesia: bool,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // (1) Abort+await both old handles FIRST: no double-incarnation sender.
    lifecycle::abort_tasks(mv).await;

    // (2) Fixed deterministic downtime (never the node's own stalled view).
    context.sleep(lifecycle::MALLORY_RESTART_DOWNTIME).await;

    let node = mv.idx();
    let validator = mv.validator().clone();

    // (3) Re-register the three channels: overwrites this node's mailboxes, which
    //     disconnects the OLD receivers the crashed incarnation's pumps still hold
    //     (they then stop), and hands back fresh raw channels.
    let mut fresh = crate::utils::register(oracle, std::slice::from_ref(&validator)).await;
    let (pending_raw, recovered_raw, resolver_raw) = fresh.remove(&validator).unwrap();

    // (4) Re-wrap the fresh channels EXACTLY as setup does. The old pumps are gone,
    //     so replace this node's stale flush senders with the fresh ones (keeping
    //     `flush_pump`'s first-match lookup pointing at the live pumps).
    let hb_capture = Some(hb_log.clone());
    flush_senders.retain(|(n, _, _)| *n != node);
    let (pending, pending_flush) = wrap_receive::<P, _>(
        context,
        pending_raw,
        packet_cell,
        &hb_capture,
        peers,
        ambiguous,
        mv.scheme().certificate_codec_config(),
        node,
        SniffChannel::Vote,
    );
    flush_senders.push((node, SniffChannel::Vote, pending_flush));
    let (recovered, recovered_flush) = wrap_receive::<P, _>(
        context,
        recovered_raw,
        packet_cell,
        &hb_capture,
        peers,
        ambiguous,
        mv.scheme().certificate_codec_config(),
        node,
        SniffChannel::Certificate,
    );
    flush_senders.push((node, SniffChannel::Certificate, recovered_flush));
    let (resolver, resolver_flush) = wrap_receive::<P, _>(
        context,
        resolver_raw,
        packet_cell,
        &hb_capture,
        peers,
        ambiguous,
        mv.scheme().certificate_codec_config(),
        node,
        SniffChannel::Resolver,
    );
    flush_senders.push((node, SniffChannel::Resolver, resolver_flush));

    // (5) Rebuild engine+app under the node's NodeSubscriber dispatch so its events
    //     stay attributed to node 0. Durable reuses the SAME partition and reporter
    //     (journal replay + retained safety history); amnesia rebuilds on a FRESH
    //     partition derived from the bumped generation with a CLEAN-SLATE reporter
    //     (`None`), so the engine finds empty storage and forgets its signed votes.
    let ctx = context
        .child("validator")
        .with_attribute("public_key", &validator);
    let existing = if amnesia { None } else { Some(mv.reporter()) };
    let scheme = mv.scheme().clone();
    let partition = if amnesia {
        lifecycle::amnesia_partition(&validator, mv.generation().wrapping_add(1))
    } else {
        mv.partition().to_string()
    };
    let dispatch = Dispatch::new(happens_before::capture::NodeSubscriber::new(
        node as u32,
        hb_log.clone(),
    ));
    let oracle_ref: &Oracle<PublicKeyOf<P>, deterministic::Context> = oracle;
    let rebuilt = dispatcher::with_default(&dispatch, || {
        build_validator_with_reporter::<P, P::Elector, _, _, _, _, _, _>(
            existing,
            ctx,
            oracle_ref,
            participants,
            scheme,
            validator,
            P::Elector::default(),
            relay.clone(),
            Duration::from_secs(1),
            Duration::from_secs(2),
            input.mailbox_size,
            input.fetch_concurrent,
            input.forwarding,
            partition,
            pending,
            recovered,
            resolver,
            input.certify,
            input.reporting,
        )
    });

    // (6) Adopt the new incarnation: take over its handles and bump generation.
    //     Durable returns to Running (same partition => durable storage replays);
    //     amnesia becomes Amnesiac and takes over the fresh partition and reporter.
    if amnesia {
        mv.adopt_amnesiac(rebuilt);
    } else {
        mv.adopt(rebuilt);
    }
}

/// Durably restart the crashed faultable identity in place
/// ([`action::FaultPlan::CrashRestartDurable`]): rebuild on its EXISTING storage
/// partition, reusing the reporter, and return to `Running`. See [`restart`].
#[allow(clippy::too_many_arguments)]
async fn restart_durable<P: Simplex>(
    mv: &mut ManagedValidator<P>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    hb_log: &happens_before::capture::EventLog,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
    packet_cell: &network::PacketFaultCell,
    flush_senders: &mut Vec<(usize, SniffChannel, mpsc::UnboundedSender<network::FlushAck>)>,
    input: &crate::FuzzInput,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    restart::<P>(
        mv,
        context,
        oracle,
        participants,
        relay,
        hb_log,
        peers,
        ambiguous,
        packet_cell,
        flush_senders,
        input,
        false,
    )
    .await;
}

/// Amnesia-restart the crashed faultable identity
/// ([`action::FaultPlan::AmnesiaRestart`]): rebuild on a FRESH (empty) storage
/// partition with a clean-slate reporter, so it forgets its durable state and
/// becomes `Amnesiac` (Byzantine for the rest of the episode). See [`restart`].
#[allow(clippy::too_many_arguments)]
async fn restart_amnesia<P: Simplex>(
    mv: &mut ManagedValidator<P>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    hb_log: &happens_before::capture::EventLog,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
    packet_cell: &network::PacketFaultCell,
    flush_senders: &mut Vec<(usize, SniffChannel, mpsc::UnboundedSender<network::FlushAck>)>,
    input: &crate::FuzzInput,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    restart::<P>(
        mv,
        context,
        oracle,
        participants,
        relay,
        hb_log,
        peers,
        ambiguous,
        packet_cell,
        flush_senders,
        input,
        true,
    )
    .await;
}

/// Run one Mallory episode (`Mode::Mallory`).
///
/// Builds its OWN setup by reusing the shared harness helpers directly
/// ([`crate::setup_network`], [`build_validator`], the [`SniffingReceiver`]
/// / [`sniff_sink`] happens-before capture): it does NOT call the ByzzFuzz
/// `setup_engines`, does NOT sample ByzzFuzz `(c, d, r)`, and consumes no
/// irrelevant `FuzzRng` bytes.
///
/// An [`adversary::AdversaryRole`] is sampled ONCE at setup from the runtime RNG
/// and held for the whole episode. Under the Honest role all four nodes are honest
/// processes (Mallory perturbs only the network), all four are happens-before
/// captured (empty ambiguous set), and all four are checked by the episode-end
/// oracle. Under a Byzantine role node 0 ([`BYZANTINE_IDX`]) is replaced by a raw,
/// unmanaged adversary (no pump / sniffer / reporter / [`ManagedValidator`]); the
/// three honest nodes form the N4F0C4 quorum of three, are happens-before captured
/// (node 0 marked ambiguous), and safety excludes node 0's equivocation via
/// [`invariants::check_vote_invariants_with_byzantine`].
///
/// The deterministic runtime is seeded from `FuzzRng::new(input.raw_bytes)` --
/// Mallory's only entropy. For [`Chooser::Learned`] the campaign Q-table is the
/// only cross-input state; because it persists, replaying identical bytes can
/// yield a different schedule than the first time (online RL over libFuzzer). A
/// Disrupter role additionally draws from the shared RNG while running, coupling
/// the stream to its timing -- still deterministic under the single-threaded
/// scheduler since the role is fixed for the episode.
pub fn run<P: Simplex>(input: crate::FuzzInput, chooser: Chooser)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    run_with::<P>(input, chooser, MALLORY_EPISODE_STEPS);
}

/// [`run`] with an explicit episode length, sampling the adversary role from the
/// runtime RNG. Production runs [`MALLORY_EPISODE_STEPS`]; the ignored integration
/// tests pass a short count so a full deterministic episode (runtime + window +
/// liveness + invariants) finishes in seconds while exercising the same code paths.
fn run_with<P: Simplex>(input: crate::FuzzInput, chooser: Chooser, steps: usize)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    run_inner::<P>(input, chooser, steps, None);
}

/// [`run_with`] with an optional forced adversary role. `forced_role` is
/// `Some(role)` only from the role-specific ignored tests, which pin the episode
/// environment; production and the A/B / smoke tests pass `None` and sample the
/// role from the runtime RNG. When forced, the role is NOT drawn from the RNG, so
/// an Honest-forced episode's schedule is byte-identical to the no-role baseline.
fn run_inner<P: Simplex>(
    mut input: crate::FuzzInput,
    chooser: Chooser,
    steps: usize,
    forced_role: Option<adversary::AdversaryRole>,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Four honest validators, fully connected at setup. N4F0C4 with every node
    // certifying is the config that keeps four honest nodes live (a quorum of
    // three is always met); the per-step transient partitions are installed by
    // the topology controller, not by the initial input config.
    input.configuration = N4F0C4;
    input.partition = crate::utils::Partition::Connected;
    input.degraded_network = false;
    input.certify = CertifyChoice::Always;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before::capture::EventLog::new();

    executor.start(|mut context| async move {
        // `oracle` and `participants` are retained (not moved into the topology
        // controller) because a durable restart re-registers channels through the
        // oracle and rebuilds an engine over the participant set.
        let (mut oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;
        crate::print_fuzz_input(crate::Mode::Mallory, &input);

        let config = input.configuration;
        let n = config.n as usize;
        let required_containers = input.required_containers;
        let relay = Arc::new(relay::Relay::new());
        let peers: Arc<[PublicKeyOf<P>]> = participants.clone().into();

        // Sample the episode's adversary role ONCE, before the per-node loop, from
        // the runtime RNG (so a replay reproduces it). A forced role skips the draw,
        // keeping an Honest-forced episode byte-identical to the no-role baseline.
        let role = match forced_role {
            Some(r) => r,
            None => adversary::AdversaryRole::sample(&mut context),
        };
        let byz = role.is_byzantine();
        // Under a byzantine role, node 0's forged messages create no honest causal
        // edges, so it is excluded from happens-before sender attribution; the honest
        // nodes 1-3 stay captured. Under the Honest role no node is ambiguous. This is
        // fixed at setup (the sniffers are built once), so a LATER amnesia restart
        // does not retroactively mark node 0 ambiguous: its post-amnesia messages
        // stay in the honest HB attribution. That is acceptable -- the HB log feeds
        // only the reward/novelty fingerprint, never the safety oracle, which
        // excludes an amnesiac node 0 via the `node0_byzantine` flag at episode end.
        let ambiguous: Arc<[u32]> = if byz {
            vec![BYZANTINE_IDX as u32].into()
        } else {
            Vec::new().into()
        };
        let hb_capture = Some(hb_log.clone());

        // The sole packet-fault authority, shared by every pump and set/cleared
        // by the step loop. Idle here, so every pump starts as a transparent
        // relay; the receive stack becomes
        //   sim receiver -> pump -> PacketFaultReceiver -> SniffingReceiver -> engine
        // so the sniffer records exactly what the engine receives.
        let packet_cell = network::PacketFaultCell::new();
        // Per-pump heal-time flush senders, keyed by (node, channel). Held for the
        // whole episode so no pump ever sees a dropped flush sender mid-run; the
        // runner signals the one matching pump when a reorder fault heals.
        let mut flush_senders: Vec<(usize, SniffChannel, mpsc::UnboundedSender<network::FlushAck>)> =
            Vec::with_capacity(n * 3);

        // Each honest node's task handles are RETAINED in a `ManagedValidator` so
        // the faultable identity (node 0, Honest role) can be crash-stopped or
        // durably restarted at runtime; the reporter is Arc-backed, so a crashed
        // node's safety history survives its abort. Under a byzantine role node 0 is
        // NOT managed (it is the unmanaged adversary), so `managed` holds nodes 1-3
        // and `honest_indices[k]` recovers the node index of `managed[k]`.
        let mut managed: Vec<ManagedValidator<P>> = Vec::with_capacity(n);
        for i in 0..n {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();

            // Byzantine role at node 0: spawn the adversary with its RAW channels
            // (no pump, no SniffingReceiver, no reporter, no ManagedValidator). Single
            // owner of those single-consumer mailboxes; nothing is pushed to `managed`.
            if byz && i == BYZANTINE_IDX {
                let ctx = context
                    .child("validator")
                    .with_attribute("public_key", &validator);
                // The Equivocator shares the honest nodes' relay and leader
                // schedule (`P::Elector::default()`, the same config the honest
                // validators build with) so it equivocates as the elected leader;
                // the other roles ignore both.
                adversary::spawn_adversary::<P>(
                    role,
                    ctx,
                    schemes[i].clone(),
                    required_containers,
                    relay.clone(),
                    P::Elector::default(),
                    channels,
                );
                continue;
            }

            let (pending_raw, recovered_raw, resolver_raw) = channels;
            // p2p-boundary sniffing below a fresh packet pump per channel: record
            // wire arrivals of votes, certificates, and resolver backfill responses
            // into the honest-only HB log. `wrap_receive` is shared with the durable
            // restart path so a restarted node's receive stack is identical.
            let (pending, pending_flush) = wrap_receive::<P, _>(
                &context,
                pending_raw,
                &packet_cell,
                &hb_capture,
                &peers,
                &ambiguous,
                schemes[i].certificate_codec_config(),
                i,
                SniffChannel::Vote,
            );
            flush_senders.push((i, SniffChannel::Vote, pending_flush));
            let (recovered, recovered_flush) = wrap_receive::<P, _>(
                &context,
                recovered_raw,
                &packet_cell,
                &hb_capture,
                &peers,
                &ambiguous,
                schemes[i].certificate_codec_config(),
                i,
                SniffChannel::Certificate,
            );
            flush_senders.push((i, SniffChannel::Certificate, recovered_flush));
            let (resolver, resolver_flush) = wrap_receive::<P, _>(
                &context,
                resolver_raw,
                &packet_cell,
                &hb_capture,
                &peers,
                &ambiguous,
                schemes[i].certificate_codec_config(),
                i,
                SniffChannel::Resolver,
            );
            flush_senders.push((i, SniffChannel::Resolver, resolver_flush));

            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let scheme = schemes[i].clone();
            let build = || {
                build_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    scheme,
                    validator,
                    P::Elector::default(),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.fetch_concurrent,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    input.certify,
                    input.reporting,
                )
            };
            // Dispatch propagation: every task this honest engine spawns inherits
            // a per-node subscriber, so its tracing events are attributed to node
            // `i`.
            let dispatch = Dispatch::new(happens_before::capture::NodeSubscriber::new(
                i as u32,
                hb_log.clone(),
            ));
            managed.push(dispatcher::with_default(&dispatch, build));
        }

        // Mallory's sole topology authority: every network fault (and every heal)
        // goes through this controller's `apply_partition`; there is no forwarder
        // or message filter. Given a CLONE of the setup oracle and participants (the
        // runner keeps the originals for durable-restart re-registration).
        let topology =
            network::Topology::new(oracle.clone(), participants.clone(), crate::default_link());

        // The honest managed validators are safety-checked by the episode-end
        // oracle. `reporters` is position-aligned with `managed` (and with
        // `honest_indices`); under a byzantine role node 0 has no reporter, so this
        // IS the honest reporter set. Reporters are cloned once from the managed
        // validators; their Arc-backed maps reflect live state (and a durable restart
        // reuses the same reporter instance), so re-encoding each step gives the
        // current cumulative snapshot.
        let honest_indices: Vec<usize> = if byz { (1..n).collect() } else { (0..n).collect() };
        let mut reporters: Vec<MalloryReporter<P>> =
            managed.iter().map(|m| m.reporter()).collect();

        // Drain clock: the first honest reporter's finalization monitor. Used to
        // keep a current finalized frontier for the decision log and to keep the
        // monitor from backing up across steps.
        let (latest, mut monitor): (View, ViewReceiver<View>) = reporters[0].subscribe().await;
        let mut finalized = latest.get();

        // A crash-stop ends the episode; this flips true when node 0 is crashed so
        // the loop finishes after that step's TD update.
        let mut episode_terminal = false;
        // Observe before the first decision: the initial (empty-history) HB
        // fingerprint is the step-0 Q-state, so there is no `state = 0` sentinel.
        // The env tag (role plus an amnesia bit) is folded in so Honest, each
        // byzantine role, and a post-amnesia node 0 key distinct Q-rows / novelty (a
        // campaign never merges incompatible environments). Node 0 cannot be amnesiac
        // yet, so this reduces to the role tag.
        let mut state = hb_log.summary().fingerprint() ^ env_tag(role, false);
        for step in 0..steps {
            // (a) Drain queued finalizations to the current frontier.
            while let Ok(v) = monitor.try_recv() {
                finalized = finalized.max(v.get());
            }

            // The per-step legal mask. Under the Honest role, while node 0 runs
            // every action is legal; once it is crash-stopped only NoFault is (a
            // crash is terminal, so this is reached only defensively), and a durable
            // restart re-opens the full mask. Once node 0 is amnesiac it is the
            // single Byzantine identity (Running but empty-storage), so the three
            // lifecycle faults are masked out. Under a byzantine role node 0 is the
            // unmanaged adversary (never "crashed"), and the lifecycle faults are
            // likewise masked -- there is no ManagedValidator at node 0 to crash.
            let node0_crashed =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Crashed);
            let node0_amnesiac =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Amnesiac);
            let legal = action::legal_mask(node0_crashed, byz, node0_amnesiac);

            // (b)/(c)/(d) Current abstract state is `state`; select under the
            // legal mask. Learned consults the campaign; Random does not.
            let action_id = match chooser {
                Chooser::Learned => policy::campaign(action::N_ACTIONS)
                    .lock()
                    .policy
                    .select(state, &legal, &mut context),
                Chooser::Random => select_uniform_legal(&legal, &mut context),
                #[cfg(test)]
                Chooser::Fixed(id) => {
                    assert!(legal[id], "forced action must be legal");
                    id
                }
                #[cfg(test)]
                Chooser::FixedFirst(id) => {
                    let want = if step == 0 {
                        id
                    } else {
                        action::Action::NoFault.id()
                    };
                    assert!(legal[want], "forced action must be legal");
                    want
                }
            };
            let action = action::Action::from_id(action_id);
            // The stable-order contract: the resolved action must project back to
            // the selected column, so a broken catalog mapping is caught here
            // rather than mislabeling a Q-table update.
            debug_assert_eq!(action.id(), action_id, "catalog id round-trip");

            // (e)/(f) Sample concrete params and enact. A topology fault goes
            // through the sole topology authority (`apply_partition` panics on an
            // oracle error, so reaching the observation window is itself the
            // enactment acknowledgement); a packet fault is installed into the
            // shared cell every pump reads. Exactly one fault is applied per step
            // and healed before the next decision, so packet and topology faults
            // never stack (v1 contract).
            //
            // The step's clock starts HERE so the observation window is measured from
            // the action's start: a restart sleeps its downtime inside enact, and
            // folding that into the window keeps every step exactly one window long
            // (F6) rather than a restart observing downtime + window.
            let step_start = context.current();
            let plan = action.sample(&mut context, byz);
            let params = plan.describe();
            match &plan {
                action::FaultPlan::None => {}
                action::FaultPlan::IsolateByzantine => topology.isolate_byzantine().await,
                action::FaultPlan::Partition(sp) => topology.partition(sp).await,
                action::FaultPlan::PacketDelay {
                    node,
                    channel,
                    per_packet,
                } => packet_cell.set(network::PacketFault {
                    node: *node,
                    channel: *channel,
                    kind: network::PacketFaultKind::Delay {
                        per_packet: *per_packet,
                    },
                }),
                action::FaultPlan::PacketLoss {
                    node,
                    channel,
                    drop_count,
                } => packet_cell.set(network::PacketFault {
                    node: *node,
                    channel: *channel,
                    kind: network::PacketFaultKind::Loss {
                        drop_count: *drop_count,
                    },
                }),
                action::FaultPlan::PacketCorrupt {
                    node,
                    channel,
                    count,
                    offset,
                    mask,
                } => packet_cell.set(network::PacketFault {
                    node: *node,
                    channel: *channel,
                    kind: network::PacketFaultKind::Corrupt {
                        count: *count,
                        offset: *offset,
                        mask: *mask,
                    },
                }),
                action::FaultPlan::PacketDuplicate {
                    node,
                    channel,
                    extra,
                } => packet_cell.set(network::PacketFault {
                    node: *node,
                    channel: *channel,
                    kind: network::PacketFaultKind::Duplicate { extra: *extra },
                }),
                action::FaultPlan::PacketReorder {
                    node,
                    channel,
                    buffer,
                } => packet_cell.set(network::PacketFault {
                    node: *node,
                    channel: *channel,
                    kind: network::PacketFaultKind::Reorder { buffer: *buffer },
                }),
                action::FaultPlan::CrashStop => {
                    // Crash-stop the faultable identity and END the episode after
                    // this step's TD update: abort+await both handles so the old
                    // engine/application tasks can never send again. Enacted against
                    // the managed validator, so the topology/packet layers are
                    // untouched (no heal below).
                    lifecycle::crash_stop(&mut managed[0]).await;
                    episode_terminal = true;
                }
                action::FaultPlan::CrashRestartDurable => {
                    // Crash then durably restart the faultable identity in place on
                    // its existing partition. Not terminal: the node replays its
                    // journal and catches up via resolver backfill, and the episode
                    // continues.
                    restart_durable::<P>(
                        &mut managed[0],
                        &context,
                        &mut oracle,
                        &participants,
                        &relay,
                        &hb_log,
                        &peers,
                        &ambiguous,
                        &packet_cell,
                        &mut flush_senders,
                        &input,
                    )
                    .await;
                }
                action::FaultPlan::AmnesiaRestart => {
                    // Crash then restart the faultable identity on a FRESH (empty)
                    // partition with a clean-slate reporter: it forgets its durable
                    // state (including signed votes) and becomes Amnesiac -- Byzantine
                    // for the rest of the episode. Not terminal: the amnesiac node
                    // runs (and may equivocate) while the 3 honest nodes finalize.
                    restart_amnesia::<P>(
                        &mut managed[0],
                        &context,
                        &mut oracle,
                        &participants,
                        &relay,
                        &hb_log,
                        &peers,
                        &ambiguous,
                        &packet_cell,
                        &mut flush_senders,
                        &input,
                    )
                    .await;
                }
            }

            // (g) Run the single fixed observation window, measured from the action's
            // start so a restart's in-enact downtime counts toward it (F6). A step
            // whose enact already exceeded the window observes for zero more time.
            let elapsed = context
                .current()
                .duration_since(step_start)
                .unwrap_or_default();
            context
                .sleep(observe_remaining(MALLORY_WINDOW, elapsed))
                .await;

            // (h) Settle ready work queued during the window.
            while let Ok(v) = monitor.try_recv() {
                finalized = finalized.max(v.get());
            }

            // (i) Heal the transient fault before the next decision, so at most one
            // fault is ever active (v1 contract). A topology fault heals via the
            // topology authority. A packet fault heals behind the F3 QUIESCENCE
            // BARRIER: request-reply flush the target pump and WAIT for its ack, which
            // (single-threaded pump) implies its reorder buffer is drained and any
            // in-flight per-packet delay finished, so no fault-injected packet is left
            // buffered; then clear the cell and run a brief deterministic settle so the
            // engine consumes the just-flushed packets before next-state -- keeping
            // this step's fault effect out of the next step. `matched` is read before
            // the clear resets it. `enactment` is logging-only (F8): a packet fault
            // that matched nothing is `NoEffect`, a lifecycle/topology fault is always
            // `Applied`. NoFault installs nothing, so there is nothing to heal.
            let (healed, matched_log, enactment) = match &plan {
                action::FaultPlan::None => ("none", "n/a".to_string(), Enactment::NoEffect),
                action::FaultPlan::IsolateByzantine | action::FaultPlan::Partition(_) => {
                    topology.heal().await;
                    ("mesh", "n/a".to_string(), Enactment::Applied)
                }
                action::FaultPlan::PacketDelay { node, channel, .. }
                | action::FaultPlan::PacketLoss { node, channel, .. }
                | action::FaultPlan::PacketCorrupt { node, channel, .. }
                | action::FaultPlan::PacketDuplicate { node, channel, .. }
                | action::FaultPlan::PacketReorder { node, channel, .. } => {
                    let matched = packet_cell.matched();
                    flush_pump_and_wait(&flush_senders, *node, *channel).await;
                    packet_cell.clear();
                    context.sleep(MALLORY_SETTLE).await;
                    (
                        "packet_flush",
                        matched.to_string(),
                        enactment_of(&plan, matched),
                    )
                }
                action::FaultPlan::CrashStop
                | action::FaultPlan::CrashRestartDurable
                | action::FaultPlan::AmnesiaRestart => {
                    // A lifecycle fault is enacted against the managed validator,
                    // not the network: there is no topology or packet fault to heal
                    // (re-meshing links does not un-crash a node). The episode-end
                    // heal still runs so a restarted node can catch up.
                    ("lifecycle", "n/a".to_string(), Enactment::Applied)
                }
            };

            // The packet-fault settle above may have produced new finalizations;
            // fold them into the frontier before next-state.
            while let Ok(v) = monitor.try_recv() {
                finalized = finalized.max(v.get());
            }

            // Node 0's POST-enact lifecycle: an amnesia restart THIS step flips it to
            // Amnesiac (Byzantine), which changes both the environment tag folded into
            // the next fingerprints (F5a) and the legal bootstrap mask (F4). Under a
            // byzantine role node 0 is unmanaged, so both stay false (short-circuit).
            let node0_crashed_next =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Crashed);
            let node0_amnesiac_next =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Amnesiac);
            let next_tag = env_tag(role, node0_amnesiac_next);

            // (j) Next abstract state and the reward's protocol-state descriptor, each
            // folded with the env tag so `select`, `reward`, and `learn` all key the
            // environment-specific Q-row / novelty (see the initial `state`). The reward
            // descriptor is over the CURRENT correct reporters only (F5b): a crash-
            // stopped node (no live engine) and an amnesiac node 0 (now Byzantine, and
            // whose setup-clone reporter is stale after `adopt_amnesiac`) are excluded,
            // so the reward reflects honest protocol state. The setup `reporters` clone
            // is retained unchanged for the episode-end safety oracle.
            let hb_fp = (hb_log.summary().fingerprint()) ^ next_tag;
            let reward_reporters: Vec<MalloryReporter<P>> = (0..managed.len())
                .filter(|&k| matches!(managed[k].lifecycle(), ValidatorLifecycle::Running))
                .map(|k| reporters[k].clone())
                .collect();
            let state_fp = state::state_descriptor::<P>(&reward_reporters, n) ^ next_tag;
            // Terminal on the last step or when a crash-stop ended the episode.
            let terminal = step + 1 == steps || episode_terminal;

            // (k) TD update (Learned only). Terminal on the last step (no bootstrap);
            // otherwise the bootstrap max is over the actions legal at NEXT --
            // recomputed from node 0's POST-enact lifecycle so an amnesia restart, which
            // flips the lifecycle faults illegal, does not bootstrap over now-illegal
            // columns (F4). `select` above still used the pre-enact `legal`.
            let reward_log = if matches!(chooser, Chooser::Learned) {
                let legal_next = action::legal_mask(node0_crashed_next, byz, node0_amnesiac_next);
                let campaign = policy::campaign(action::N_ACTIONS);
                let mut c = campaign.lock();
                let reward = c.reward(state_fp, hb_fp);
                if terminal {
                    c.policy.learn_terminal(state, action_id, reward);
                } else {
                    c.policy.learn(state, action_id, reward, hb_fp, &legal_next);
                }
                format!("{reward}")
            } else {
                "n/a".to_string()
            };

            // (l) Log the full transition. The role is recorded on every decision
            // line (so a replay reproduces the sampled environment). `generation` is
            // node 0's incarnation counter and `lifecycle0` its lifecycle state, both
            // meaningful only for the Honest faultable identity; under a byzantine
            // role node 0 is an unmanaged adversary (generation 0, "unmanaged").
            // `lifecycle0` makes the mid-episode honest->Amnesiac flip observable.
            let generation = if byz { 0 } else { managed[0].generation() };
            let lifecycle0 = if byz {
                "unmanaged".to_string()
            } else {
                format!("{:?}", managed[0].lifecycle())
            };
            log::push(format!(
                "mallory: chooser={chooser:?} role={} step={step} action_id={action_id} action={action:?} legal={legal:?} params=[{params}] applied={enactment:?} generation={generation} lifecycle0={lifecycle0} prev_state={state:#018x} finalized={finalized} next_state={hb_fp:#018x} state_desc={state_fp:#018x} reward={reward_log} window={MALLORY_WINDOW:?} heal={healed} matched={matched_log}",
                role.label()
            ));
            state = hb_fp;

            // A crash-stop is terminal: end the episode after its TD update.
            if episode_terminal {
                break;
            }
        }

        // Episode end: reach the synchronous phase. Heal unconditionally so any
        // last-step fault is cleared and every node -- including an isolated
        // node 0 -- can reconnect and catch up before the liveness check below.
        // Clear the packet cell too, so every pump is a transparent relay during
        // catch-up.
        topology.heal().await;
        packet_cell.clear();
        // Belt-and-suspenders reorder drain: every step-end heal already flushed
        // the step's reorder buffer, so every pump's buffer is empty here. Signal
        // them all anyway so any residual held packet is drained in order rather
        // than stranded; anything not drained is discarded when the pump tasks are
        // dropped at teardown (stale pre-catch-up packets). No wait needed here: the
        // ack is DISCARDED (drop the receiver) -- held packets drain during the
        // liveness catch-up below.
        for (_, _, tx) in &flush_senders {
            let (ack_tx, _ack_rx) = oneshot::channel();
            let _ = tx.send(ack_tx);
        }

        // Unified "node 0 is Byzantine" flag, read HERE (episode end) so a late
        // amnesia restart correctly flips the excluded set: node 0 is Byzantine iff
        // the episode role owns it as an unmanaged adversary OR it became amnesiac
        // (Running but empty-storage, so it may equivocate). This single flag drives
        // both the safety byzantine set and the liveness exclusion below. Under the
        // Honest role with no amnesia it is false, so all four nodes are honest.
        let node0_amnesiac =
            !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Amnesiac);
        let node0_byzantine = byz || node0_amnesiac;

        // Liveness argument (relied on below): the honest nodes always form the
        // N4F0C4 quorum of three. IsolateNodeWindow removes only node 0, so the
        // other three keep finalizing while node 0 stalls and then catches up
        // post-heal via resolver backfill; PartitionWindow (2-2) leaves neither
        // side a quorum, so all progress stalls during the window and resumes once
        // healed. Under the Honest role a crash-stop permanently removes node 0
        // (excluded from the liveness watch below) and a durable restart brings it
        // back to catch up like the others. An amnesia restart leaves node 0 Running
        // but Byzantine, so it is excluded from the watch (it may equivocate) while
        // the three honest nodes tolerate it (f = 1). Under a byzantine role node 0
        // is the unmanaged adversary, never a watch target, and the three honest
        // nodes tolerate it too. Because Mallory heals after every window and again at
        // episode end, no live honest node permanently wedges -- every one reaches
        // `required_containers`.

        // Post-heal liveness over the LIVE honest managed validators (by position).
        // Keep only nodes still `Running`: a crash-stopped node (no engine) and an
        // amnesiac node (Running but Byzantine, excluded because it may equivocate)
        // are both filtered out -- `Crashed` and `Amnesiac` are distinct from
        // `Running`, so both are excluded here. Under a byzantine role node 0 is not
        // managed, so it never joins this watch. Together the excluded set is at most
        // {node 0}. A crash-stopped node stays in the safety set below via its
        // retained reporter; an amnesiac node is Byzantine and excluded from safety.
        let live_positions: Vec<usize> = (0..managed.len())
            .filter(|&k| matches!(managed[k].lifecycle(), ValidatorLifecycle::Running))
            .collect();
        let mut watch_targets: Vec<(usize, usize, u64)> = Vec::with_capacity(live_positions.len());
        let mut watcher_inputs = Vec::with_capacity(live_positions.len());
        for &k in &live_positions {
            let node = honest_indices[k];
            let (latest, monitor): (View, ViewReceiver<View>) = reporters[k].subscribe().await;
            watch_targets.push((k, node, latest.get()));
            watcher_inputs.push((node, latest, monitor));
        }
        // Require post-heal PROGRESS, not just the absolute frontier (F2): after a
        // full episode the honest nodes are already well past `required_containers`,
        // so a node wedged by the LAST fault/heal/restart would pass instantly against
        // it. Instead every live correct node must reach one view past the HIGHEST
        // pre-heal frontier, proving it caught up. The target never drops below
        // `required_containers` (a very short episode) and stays there on overflow.
        let max_baseline = watch_targets
            .iter()
            .map(|&(_, _, baseline)| baseline)
            .max()
            .unwrap_or(0);
        let target = liveness_target(required_containers, max_baseline);
        let mut watchers = Vec::with_capacity(watcher_inputs.len());
        for (node, mut latest, mut monitor) in watcher_inputs {
            watchers.push(
                context
                    .child("mallory_liveness_watcher")
                    .with_attribute("index", node)
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
        let live = select! {
            results = join_all(watchers) => {
                results.iter().all(|r| matches!(r, Ok(true)))
            },
            _ = context.sleep(POST_GST_WINDOW) => false,
        };
        if !live {
            let mut diag = String::new();
            for &(k, node, baseline) in &watch_targets {
                let (latest, _): (View, ViewReceiver<View>) = reporters[k].subscribe().await;
                let _ = write!(
                    diag,
                    " node{node}={{baseline={baseline} current={}}}",
                    latest.get()
                );
            }
            panic!(
                "mallory: no post-episode liveness within {POST_GST_WINDOW:?} (target={target} required_containers={required_containers} max_baseline={max_baseline});{diag}"
            );
        }

        // Safety invariants over the honest reporters. Node 0's equivocation is
        // excluded from the vote-equivocation check exactly when it is Byzantine
        // (`node0_byzantine`): under a byzantine role its forged votes are recorded
        // in the honest reporters' vote maps, and post-amnesia its empty-storage
        // double-votes are too -- `check_vote_invariants_with_byzantine(&{0}, ...)`
        // excludes both by sender identity across all reporters (the byzzfuzz
        // treatment). When node 0 is honest (Honest role, no amnesia) the set is
        // empty and a crash-stopped node's retained reporter is safety-checked like
        // any other -- a crashed node is NOT Byzantine (it never equivocated), so it
        // is excluded from liveness but not from the safety set. This is the same
        // unified flag used by the liveness exclusion, so a mid-episode amnesia flip
        // consistently drops node 0 from BOTH sets.
        let byzantine: HashSet<usize> = if node0_byzantine {
            std::iter::once(BYZANTINE_IDX).collect()
        } else {
            HashSet::new()
        };
        invariants::check_vote_invariants_with_byzantine(&byzantine, &reporters);
        let states = invariants::extract(reporters, n);
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

    /// Episode length the ignored integration tests run. Short (versus the
    /// production [`MALLORY_EPISODE_STEPS`]) so a full deterministic episode --
    /// runtime, window, healing, liveness, and invariants -- finishes in seconds
    /// while still exercising isolation catch-up, partition stall, and packet
    /// drop/delay. Paired with `required_containers = 2` in [`mallory_input`].
    const TEST_STEPS: usize = 3;

    fn mallory_input(seed: u64) -> FuzzInput {
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

    /// Run a short episode with the role SAMPLED from the RNG, tolerating a panic so
    /// a same-seed outcome is captured identically, and drain the decision log.
    fn mallory_trace(input: FuzzInput, chooser: Chooser) -> (bool, Vec<String>) {
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_with::<SimplexId>(input, chooser, TEST_STEPS);
        }))
        .is_ok();
        (ok, log::take())
    }

    /// [`mallory_trace`] with a forced adversary role. Pins the episode environment
    /// so a test can drive a specific role (Honest for the lifecycle tests, a
    /// byzantine profile for the per-role tests).
    fn mallory_trace_role(
        input: FuzzInput,
        chooser: Chooser,
        role: adversary::AdversaryRole,
    ) -> (bool, Vec<String>) {
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_inner::<SimplexId>(input, chooser, TEST_STEPS, Some(role));
        }))
        .is_ok();
        (ok, log::take())
    }

    /// Run a forced-action episode in the Honest environment (node 0 managed) --
    /// the world the action tests target. Pins the role so a sampled byzantine
    /// profile never masks a lifecycle action or drops node 0 from the watch, and
    /// keeps the schedule byte-identical to the pre-role baseline (a forced role
    /// skips the RNG draw).
    fn run_honest(input: FuzzInput, chooser: Chooser) {
        run_inner::<SimplexId>(input, chooser, TEST_STEPS, Some(adversary::AdversaryRole::Honest));
    }

    #[test]
    fn select_helpers_only_return_legal_ids() {
        // Both selection paths must respect the legal mask. The masked-softmax
        // path is exercised over a seeded Q-row; the uniform path over the same
        // mask. Pure (no runtime), so this stays in the fast suite.
        let legal = action::legal_mask(false, false, false);
        let mut policy = policy::QPolicy::new(action::N_ACTIONS);
        policy.learn_terminal(0, 0, 5.0);
        let mut rng = FuzzRng::new(vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15]);
        for _ in 0..64 {
            let learned = policy.select(0, &legal, &mut rng);
            assert!(legal[learned], "softmax select must return a legal id");
            let random = select_uniform_legal(&legal, &mut rng);
            assert!(legal[random], "uniform select must return a legal id");
        }
    }

    #[test]
    fn observe_remaining_folds_downtime_into_the_window() {
        // F6: a restart sleeps its downtime during enact, so the remaining
        // observation is `window - downtime`; a plain step observes the full window;
        // an over-budget enact observes nothing (saturating). Every step totals one
        // window.
        assert_eq!(
            observe_remaining(MALLORY_WINDOW, Duration::ZERO),
            MALLORY_WINDOW,
            "a plain step observes the full window"
        );
        assert_eq!(
            observe_remaining(MALLORY_WINDOW, lifecycle::MALLORY_RESTART_DOWNTIME),
            MALLORY_WINDOW - lifecycle::MALLORY_RESTART_DOWNTIME,
            "a restart observes the window minus its downtime"
        );
        assert_eq!(
            observe_remaining(MALLORY_WINDOW, MALLORY_WINDOW * 2),
            Duration::ZERO,
            "an over-budget enact observes nothing"
        );
    }

    #[test]
    fn restart_and_plain_steps_span_the_same_window() {
        // F6 in the deterministic runtime: a step that sleeps the restart downtime
        // during enact then observes `observe_remaining` spans exactly one
        // MALLORY_WINDOW from its start -- identical to a plain step with no downtime.
        let executor = deterministic::Runner::seeded(1);
        executor.start(|context| async move {
            let start = context.current();
            context.sleep(lifecycle::MALLORY_RESTART_DOWNTIME).await;
            let elapsed = context.current().duration_since(start).unwrap();
            context
                .sleep(observe_remaining(MALLORY_WINDOW, elapsed))
                .await;
            let restart_span = context.current().duration_since(start).unwrap();

            let plain_start = context.current();
            let plain_elapsed = context.current().duration_since(plain_start).unwrap();
            context
                .sleep(observe_remaining(MALLORY_WINDOW, plain_elapsed))
                .await;
            let plain_span = context.current().duration_since(plain_start).unwrap();

            assert_eq!(restart_span, MALLORY_WINDOW, "a restart step spans one window");
            assert_eq!(plain_span, MALLORY_WINDOW, "a plain step spans one window");
            assert_eq!(
                restart_span, plain_span,
                "a restart step and a plain step span the same total window"
            );
        });
    }

    #[test]
    fn liveness_target_requires_progress_past_the_frontier() {
        // F2: the post-heal target is one view past the HIGHEST pre-heal frontier, so
        // a node wedged by the last fault/heal/restart cannot pass by sitting at the
        // frontier; it never drops below required_containers, and stays there on
        // overflow.
        assert_eq!(liveness_target(2, 10), 11, "one view past the frontier");
        assert_eq!(liveness_target(20, 10), 20, "never below required_containers");
        assert_eq!(
            liveness_target(2, u64::MAX),
            2,
            "overflow keeps required_containers"
        );
        assert_eq!(
            liveness_target(0, 0),
            1,
            "an empty frontier still demands one view of progress"
        );
    }

    #[test]
    fn env_tag_separates_post_amnesia_from_every_other_environment() {
        // F5a: the amnesia bit keys a distinct Q-state / novelty slot, so post-amnesia
        // node 0 no longer aliases the pre-amnesia Honest environment (nor any role).
        assert_ne!(AMNESIA_TAG, 0, "the amnesia tag must be nonzero");
        assert_eq!(
            env_tag(adversary::AdversaryRole::Honest, false),
            adversary::AdversaryRole::Honest.tag(),
            "no amnesia reduces to the role tag"
        );
        assert_ne!(
            env_tag(adversary::AdversaryRole::Honest, true),
            env_tag(adversary::AdversaryRole::Honest, false),
            "post-amnesia must differ from Honest"
        );
        for role in [
            adversary::AdversaryRole::Honest,
            adversary::AdversaryRole::Disrupter,
            adversary::AdversaryRole::Conflicter,
            adversary::AdversaryRole::Nuller,
            adversary::AdversaryRole::Equivocator,
            adversary::AdversaryRole::Impersonator,
            adversary::AdversaryRole::Outdated,
        ] {
            assert_ne!(
                env_tag(adversary::AdversaryRole::Honest, true),
                env_tag(role, false),
                "post-amnesia must not alias {role:?}"
            );
            // Equivalently, every role tag is distinct from AMNESIA_TAG, so no role
            // environment collides with the post-amnesia environment as a Q-state key.
            assert_ne!(role.tag(), AMNESIA_TAG, "{role:?} tag must differ from AMNESIA_TAG");
        }
    }

    #[test]
    fn enactment_accounts_lifecycle_applied_and_ineffective_packet_noeffect() {
        // F8 (logging only): a lifecycle fault always logs Applied (the old
        // is_active()-driven field logged applied=false for it); a packet fault that
        // matched no packet logs NoEffect (the old field logged applied=true);
        // NoFault is NoEffect.
        let loss = action::FaultPlan::PacketLoss {
            node: 1,
            channel: crate::SniffChannel::Vote,
            drop_count: 3,
        };
        assert_eq!(
            enactment_of(&loss, true),
            Enactment::Applied,
            "a packet fault that matched is Applied"
        );
        assert_eq!(
            enactment_of(&loss, false),
            Enactment::NoEffect,
            "a packet fault that matched nothing is NoEffect"
        );
        for plan in [
            action::FaultPlan::CrashStop,
            action::FaultPlan::CrashRestartDurable,
            action::FaultPlan::AmnesiaRestart,
            action::FaultPlan::IsolateByzantine,
        ] {
            assert_eq!(
                enactment_of(&plan, false),
                Enactment::Applied,
                "{plan:?} always takes effect"
            );
        }
        assert_eq!(
            enactment_of(&action::FaultPlan::None, false),
            Enactment::NoEffect,
            "NoFault is NoEffect"
        );
    }

    #[test]
    fn amnesia_bootstrap_mask_excludes_lifecycle_columns() {
        // F4: the runner recomputes the NEXT-state legal mask from node 0's POST-enact
        // lifecycle and passes THAT as the TD bootstrap mask. After an amnesia restart
        // that mask must exclude the three lifecycle columns the pre-enact running mask
        // includes, so the bootstrap max cannot span a now-illegal lifecycle action.
        // (The policy's exclusion of illegal columns from the bootstrap max is proven
        // in `policy::tests::legal_mask_excludes_illegal_from_select_and_bootstrap`.)
        let running = action::legal_mask(false, false, false);
        let amnesiac = action::legal_mask(false, false, true);
        for id in [
            action::Action::CrashStop.id(),
            action::Action::CrashRestartDurable.id(),
            action::Action::AmnesiaRestart.id(),
        ] {
            assert!(running[id], "lifecycle columns are legal pre-enact (running)");
            assert!(
                !amnesiac[id],
                "lifecycle columns must be excluded from the post-amnesia bootstrap mask"
            );
        }
        // The two masks differ EXACTLY on the lifecycle columns, so the fix changes
        // the bootstrap only for amnesia and leaves every other step untouched.
        for id in 0..action::N_ACTIONS {
            let is_lifecycle = matches!(
                action::Action::from_id(id),
                action::Action::CrashStop
                    | action::Action::CrashRestartDurable
                    | action::Action::AmnesiaRestart
            );
            assert_eq!(
                running[id] != amnesiac[id],
                is_lifecycle,
                "masks differ exactly on lifecycle columns (id {id})"
            );
        }
    }

    // Full deterministic episodes (runtime + window + liveness + invariants);
    // ignored so the default `just test` stays fast. Run with `--ignored`.

    /// A/B baseline: both choosers share the setup, catalog, window, healing, and
    /// oracle. Each must complete (which means its safety and liveness invariants
    /// held). Random never touches the campaign, so a fixed seed must produce a
    /// byte-identical decision log; that same-seed determinism is the property
    /// Mallory relies on to attribute any learned-vs-random divergence to the
    /// policy. It must survive the packet-fault pumps: the pumps draw no
    /// randomness and apply a deterministic, param-driven transform, so the two
    /// same-seed Random runs stay byte-identical with the pump inserted.
    #[test]
    #[ignore]
    fn learned_random_ab_baseline() {
        policy::reset_campaign(action::N_ACTIONS);
        for seed in [1u64, 2, 3] {
            let (learned_ok, learned_log) = mallory_trace(mallory_input(seed), Chooser::Learned);
            assert!(
                learned_ok,
                "learned chooser must complete and hold invariants (seed {seed})"
            );
            assert!(
                !learned_log.is_empty(),
                "the decision log must record the learned episode (seed {seed})"
            );

            let (random_ok_a, random_log_a) = mallory_trace(mallory_input(seed), Chooser::Random);
            let (random_ok_b, random_log_b) = mallory_trace(mallory_input(seed), Chooser::Random);
            assert!(
                random_ok_a && random_ok_b,
                "random chooser must complete and hold invariants (seed {seed})"
            );
            assert_eq!(
                random_log_a, random_log_b,
                "random chooser: a fixed seed must produce a byte-identical decision log (seed {seed})"
            );
        }
    }

    /// Smoke: learned episodes complete (liveness + safety oracle pass) and the
    /// campaign Q-table gains a row.
    #[test]
    #[ignore]
    fn run_mallory_smoke_completes_and_learns() {
        policy::reset_campaign(action::N_ACTIONS);
        for seed in [1u64, 2, 3] {
            run_with::<SimplexId>(mallory_input(seed), Chooser::Learned, TEST_STEPS);
        }
        assert!(
            !policy::campaign(action::N_ACTIONS)
                .lock()
                .policy
                .is_empty(),
            "learned episodes must populate the campaign Q-table"
        );
    }

    /// Force [`action::Action::IsolateNodeWindow`] every step: node 0
    /// (BYZANTINE_IDX) is isolated for each window while the other three keep a
    /// quorum. The episode must still complete -- node 0 catches up via resolver
    /// backfill after the topology heals -- so all four reach `required_containers`
    /// and the safety invariants hold. Completion (no panic) is the assertion.
    #[test]
    #[ignore]
    fn forced_isolation_still_completes_and_catches_up() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::IsolateNodeWindow.id()),
            );
        }
    }

    /// Force [`action::Action::PartitionWindow`] every step: a balanced 2-2 split
    /// stalls all progress during each window. The episode must still complete --
    /// every node catches up once the topology heals after the window and at
    /// episode end -- so all four reach `required_containers` and the safety
    /// invariants hold.
    #[test]
    #[ignore]
    fn forced_partition_still_completes_and_catches_up() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PartitionWindow.id()),
            );
        }
    }

    /// Force [`action::Action::PacketLoss`] every step: a bounded number of
    /// packets on a sampled `(node, channel)` are dropped below the sniffer for
    /// each window, so they never reach the engine or the happens-before log. A
    /// bounded loss does not kill liveness -- Simplex backfills the gap after the
    /// fault heals -- so all four nodes still reach `required_containers` and the
    /// safety invariants hold. Completion is the assertion here; the pump unit
    /// tests in [`network`] assert the drop / absence property directly.
    #[test]
    #[ignore]
    fn forced_packet_loss_still_completes() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PacketLoss.id()),
            );
        }
    }

    /// Force [`action::Action::PacketDelay`] every step: a sampled `(node,
    /// channel)` is slowed by a per-packet delay for each window. Delay is an
    /// in-order FIFO slowdown -- never a drop or reorder -- so every delayed
    /// packet is still delivered and observed by the engine; the episode
    /// completes once the fault heals. The pump unit tests in [`network`] assert
    /// the in-order property directly.
    #[test]
    #[ignore]
    fn forced_packet_delay_still_completes() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PacketDelay.id()),
            );
        }
    }

    /// Force [`action::Action::PacketCorrupt`] every step: a bounded number of
    /// packets on a sampled `(node, channel)` are byte-mutated (without
    /// re-signing) for each window, so each corrupted message fails to decode and
    /// is rejected by the engine -- an effective loss. A bounded corrupt does not
    /// kill liveness -- Simplex backfills the gap after the fault heals -- so all
    /// four nodes still reach `required_containers` and the safety invariants hold.
    /// The pump unit tests in [`network`] assert the byte-mutation property.
    #[test]
    #[ignore]
    fn forced_packet_corrupt_still_completes() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PacketCorrupt.id()),
            );
        }
    }

    /// Force [`action::Action::PacketDuplicate`] every step: each packet on a
    /// sampled `(node, channel)` is delivered with a bounded number of extra
    /// identical copies for each window. The engine's idempotent vote handling
    /// tolerates the duplicates, so all four nodes still reach `required_containers`
    /// and the safety invariants hold. The pump unit tests in [`network`] assert
    /// the extra-copies property directly.
    #[test]
    #[ignore]
    fn forced_packet_duplicate_still_completes() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PacketDuplicate.id()),
            );
        }
    }

    /// Force [`action::Action::PacketReorder`] every step: a sampled `(node,
    /// channel)` is reordered through a bounded per-pump buffer for each window,
    /// and the buffer is flushed in order when the fault heals so no packet is
    /// lost. The engine tolerates reordering, so all four nodes still reach
    /// `required_containers` and the safety invariants hold. The pump unit tests in
    /// [`network`] assert the reorder / bound / flush properties directly.
    #[test]
    #[ignore]
    fn forced_packet_reorder_still_completes() {
        for seed in [1u64, 2, 3] {
            run_honest(
                mallory_input(seed),
                Chooser::Fixed(action::Action::PacketReorder.id()),
            );
        }
    }

    /// Force [`action::Action::CrashStop`] on the first step: node 0 (the single
    /// faultable identity) is crash-stopped -- both its engine and application
    /// tasks are aborted and awaited to termination, so the old incarnation can
    /// never send again -- and the episode ENDS (crash-stop is terminal). The
    /// other three nodes form the N4F0C4 quorum of three and reach
    /// `required_containers`, and the safety invariants hold over ALL four
    /// reporters (node 0's retained pre-crash reporter included). Completion is the
    /// liveness+safety oracle; the single logged step is the behavioral proof that
    /// the crash ended the episode after one step, with no node-0 engine left to
    /// act.
    #[test]
    #[ignore]
    fn forced_crash_stop_ends_episode_and_others_progress() {
        for seed in [1u64, 2, 3] {
            // Force the Honest role: a crash-stop targets node 0's ManagedValidator,
            // which only the Honest environment provides (a byzantine role masks it).
            let (ok, logv) = mallory_trace_role(
                mallory_input(seed),
                Chooser::Fixed(action::Action::CrashStop.id()),
                adversary::AdversaryRole::Honest,
            );
            assert!(
                ok,
                "crash-stop episode must complete: the 3 live nodes reach \
                 required_containers and safety holds over all 4 (seed {seed})"
            );
            assert_eq!(
                logv.len(),
                1,
                "crash-stop is terminal: the episode ends after the crash step (seed {seed})"
            );
            assert!(
                logv[0].contains("action=CrashStop"),
                "the sole logged step must be the crash-stop (seed {seed}): {:?}",
                logv[0]
            );
        }
    }

    /// Force [`action::Action::CrashRestartDurable`] every step: node 0 is crashed
    /// and durably restarted in place on its EXISTING partition each step, losing
    /// volatile state and replaying its journal. A durable restart is not terminal,
    /// so the episode runs to full length; node 0 returns to running each time (its
    /// generation increments per restart) and catches up via resolver backfill, so
    /// ALL four nodes reach `required_containers` and the safety invariants hold.
    /// Re-registration disconnects each prior incarnation's receivers, so a
    /// restarted node never hears from its old self.
    #[test]
    #[ignore]
    fn forced_crash_restart_durable_recovers_and_all_progress() {
        for seed in [1u64, 2, 3] {
            // Force the Honest role: a durable restart targets node 0's
            // ManagedValidator, which only the Honest environment provides.
            let (ok, logv) = mallory_trace_role(
                mallory_input(seed),
                Chooser::Fixed(action::Action::CrashRestartDurable.id()),
                adversary::AdversaryRole::Honest,
            );
            assert!(
                ok,
                "durable-restart episode must complete: all 4 nodes (node 0 \
                 restarted) reach required_containers and safety holds (seed {seed})"
            );
            assert_eq!(
                logv.len(),
                TEST_STEPS,
                "a durable restart is not terminal: the episode runs full length (seed {seed})"
            );
            assert!(
                logv.last()
                    .unwrap()
                    .contains(&format!("generation={TEST_STEPS}")),
                "node 0 must return to running and restart every step, so its \
                 generation reaches {TEST_STEPS} (seed {seed}): {:?}",
                logv.last().unwrap()
            );
        }
    }

    /// Force [`action::Action::AmnesiaRestart`] on the FIRST step (then NoFault, as
    /// amnesia masks itself): node 0 is crashed and restarted on a FRESH (empty)
    /// storage partition, so it forgets its durable state (including signed votes)
    /// and becomes Byzantine (`Amnesiac`) for the rest of the episode. Unlike a
    /// crash-stop this is NOT terminal: the episode runs to full length. The three
    /// honest nodes form the N4F0C4 quorum of three and reach `required_containers`,
    /// and the safety oracle holds over the honest-only set -- node 0's post-amnesia
    /// equivocation is excluded via the unified `node0_byzantine` flag. Its
    /// generation bumps (evidence of the fresh partition, which
    /// [`lifecycle::amnesia_partition`]'s unit test proves differs from the durable
    /// one), and node 0 ends `Amnesiac`.
    #[test]
    #[ignore]
    fn forced_amnesia_restart_flips_node0_byzantine_and_others_progress() {
        for seed in [1u64, 2, 3] {
            // Force the Honest role: an amnesia restart targets node 0's
            // ManagedValidator, which only the Honest environment provides. FixedFirst
            // fires amnesia once (it masks itself afterward) then runs NoFault, so the
            // episode reaches full length and the non-terminal property is observable.
            let (ok, logv) = mallory_trace_role(
                mallory_input(seed),
                Chooser::FixedFirst(action::Action::AmnesiaRestart.id()),
                adversary::AdversaryRole::Honest,
            );
            assert!(
                ok,
                "amnesia-restart episode must complete: the 3 honest nodes reach \
                 required_containers and safety holds over the honest-only set with \
                 node 0 excluded (seed {seed})"
            );
            assert_eq!(
                logv.len(),
                TEST_STEPS,
                "an amnesia restart is NOT terminal (unlike a crash-stop): the \
                 episode runs full length (seed {seed}): {logv:?}"
            );
            assert!(
                logv[0].contains("action=AmnesiaRestart"),
                "step 0 must be the amnesia restart (seed {seed}): {:?}",
                logv[0]
            );
            // The restart bumped the incarnation counter from 0 to 1: the fresh
            // partition is derived from that new generation, so a bumped generation is
            // the evidence the fresh partition differs from the durable one.
            assert!(
                logv[0].contains("generation=1"),
                "the amnesia restart must bump node 0's generation to 1, from which \
                 its fresh partition is derived (seed {seed}): {:?}",
                logv[0]
            );
            // Node 0 flipped honest->Amnesiac mid-episode and STAYS amnesiac: every
            // step from the restart on records lifecycle0=Amnesiac.
            assert!(
                logv.iter().all(|l| l.contains("lifecycle0=Amnesiac")),
                "node 0 must end Amnesiac and stay so after the restart (seed {seed}): {logv:?}"
            );
        }
    }

    /// Drive one byzantine role at node 0 (with `NoFault` every step, so the only
    /// perturbation is the adversary): the three honest nodes must still reach
    /// `required_containers` and the safety oracle must hold with node 0's
    /// equivocation excluded via `check_vote_invariants_with_byzantine(&{0}, ...)`.
    /// Every decision line records the role, and the crash actions are masked out.
    fn assert_byzantine_role_completes(role: adversary::AdversaryRole, label: &str) {
        for seed in [1u64, 2, 3] {
            let (ok, logv) = mallory_trace_role(
                mallory_input(seed),
                Chooser::Fixed(action::Action::NoFault.id()),
                role,
            );
            assert!(
                ok,
                "{label} episode must complete: the 3 honest nodes reach \
                 required_containers and safety holds over the honest-only set \
                 (seed {seed})"
            );
            assert_eq!(
                logv.len(),
                TEST_STEPS,
                "a byzantine role is not terminal: the episode runs full length (seed {seed})"
            );
            assert!(
                logv.iter().all(|l| l.contains(&format!("role={label}"))),
                "every decision line records the {label} role (seed {seed}): {logv:?}"
            );
            assert!(
                logv.iter().all(|l| l.contains("legal=[true, true, true, true, true, true, true, true, false, false, false]")),
                "the three lifecycle actions are masked under a byzantine role (seed {seed}): {:?}",
                logv.first()
            );
        }
    }

    /// A [`adversary::AdversaryRole::Disrupter`] at node 0 (full byzantine engine on
    /// all three channels) is tolerated: the three honest nodes reach
    /// `required_containers` and safety holds over the honest-only set.
    #[test]
    #[ignore]
    fn disrupter_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Disrupter, "disrupter");
    }

    /// A [`adversary::AdversaryRole::Conflicter`] at node 0 (conflicting
    /// notarize/finalize on the vote channel) is tolerated: the three honest nodes
    /// reach `required_containers` and safety holds -- node 0's equivocation is
    /// excluded from the vote-equivocation check.
    #[test]
    #[ignore]
    fn conflicter_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Conflicter, "conflicter");
    }

    /// A [`adversary::AdversaryRole::Nuller`] at node 0 (nullify+finalize for the
    /// same view on the vote channel) is tolerated: the three honest nodes reach
    /// `required_containers` and safety holds over the honest-only set.
    #[test]
    #[ignore]
    fn nuller_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Nuller, "nuller");
    }

    /// A [`adversary::AdversaryRole::Equivocator`] at node 0 (different proposals to
    /// different nodes, consuming the vote and certificate channels) is tolerated:
    /// the three honest nodes reach `required_containers` and safety holds over the
    /// honest-only set -- node 0's equivocation is excluded from the vote check.
    #[test]
    #[ignore]
    fn equivocator_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Equivocator, "equivocator");
    }

    /// An [`adversary::AdversaryRole::Impersonator`] at node 0 (votes re-signed under
    /// a swapped signer index on the vote channel) is tolerated: the three honest
    /// nodes reach `required_containers` and safety holds over the honest-only set.
    #[test]
    #[ignore]
    fn impersonator_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Impersonator, "impersonator");
    }

    /// An [`adversary::AdversaryRole::Outdated`] at node 0 (re-notarizing/finalizing
    /// a stale earlier-view proposal on the vote channel) is tolerated: the three
    /// honest nodes reach `required_containers` and safety holds over the honest-only
    /// set.
    #[test]
    #[ignore]
    fn outdated_role_completes_and_safety_holds() {
        assert_byzantine_role_completes(adversary::AdversaryRole::Outdated, "outdated");
    }
}
