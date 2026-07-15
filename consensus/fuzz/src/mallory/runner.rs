//! The Mallory OODA episode loop and its action choosers.
//!
//! Each episode first picks one adversary ENVIRONMENT for the faultable identity
//! ([`BYZANTINE_IDX`], node 0): honest, or one of six Byzantine profiles
//! ([`adversary::AdversaryRole`] -- Disrupter, Conflicter, Nuller, Equivocator,
//! Impersonator, Outdated). It then drives a reactive observe-orient-decide-act
//! loop: each step observes the honest happens-before fingerprint (the Q-state,
//! keyed by the environment) and a protocol-state descriptor, selects an
//! [`action`] under a legal mask, and enacts its [`action::FaultPlan`]. The action
//! is a network (isolation, partition), packet (delay/loss/corrupt/duplicate/reorder),
//! or lifecycle (crash-stop, durable restart, amnesia restart) fault. It then waits
//! for the first new honest finalization or a per-action timeout, heals the fault,
//! and (for the learned chooser) applies a temporal-difference update rewarding novel
//! state / happens-before fingerprints. The episode stops once it has observed
//! `required_containers` distinct finalizations, or on the step cap. A crash-stop is
//! permanent but not terminal: the loop continues over the surviving quorum.
//!
//! Reporter membership and the episode-end oracle follow the environment. Under
//! `Honest` all four validators are honest [`ManagedValidator`]s. Under a
//! Byzantine role, node 0 is an unmanaged adversary excluded from the honest set
//! ([`invariants::check_vote_invariants_with_byzantine`]). A crash-stopped node
//! is dropped from liveness but kept in safety via its retained reporter; an
//! amnesiac node (durable restart with fresh storage) is treated as Byzantine.
//!
//! Both [`Chooser`]s share ALL of the wiring -- setup, catalog, parameter
//! sampling, the reactive step boundary, the container budget, healing, state and
//! reward extraction, and the episode-end oracle. Only selection differs:
//! [`Chooser::Learned`] uses the campaign-persistent Q-policy (and an adaptive
//! bandit for the episode's role) and learns; [`Chooser::Random`] samples
//! uniformly from the runtime RNG and never touches the campaign, so it neither
//! learns nor pollutes the shared novelty registries -- the controlled baseline.

use super::{action, adversary, lifecycle, log, multiplexer, network, policy, state};
use crate::{
    build_validator, build_validator_with_reporter, happens_before, invariants, simplex::Simplex,
    sniff_sink, CertCfgOf, CertifyChoice, ManagedValidator, PublicKeyOf, SniffChannel,
    SniffingReceiver, ValidatorLifecycle, BYZANTINE_IDX, N4F0C4, POST_GST_WINDOW,
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
use futures::future::{join_all, select_all};
use rand::{Rng, RngExt as _};
use std::{
    collections::HashSet,
    fmt::Write as _,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{dispatcher, Dispatch};

/// Base episode step count and the container-mode step floor: container mode allows
/// `max(MALLORY_EPISODE_STEPS, required_containers)` steps so it can attempt the
/// requested finalization budget.
const MALLORY_EPISODE_STEPS: usize = 12;
/// Per-action reactive boundary timeout: a step ends on the first honest finalization
/// past its baseline, or -- if the fault suppressed progress -- after this
/// deterministic timeout. Just when Mallory reacts, not a whole observation span.
const MALLORY_STEP_TIMEOUT: Duration = Duration::from_secs(5);
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

/// Env-tag bit folded in once node 0 is permanently crash-stopped: the episode
/// continues over the surviving quorum, but under a DIFFERENT legality (lifecycle /
/// isolate-node-0 masked) and fault model (a bare quorum of three, no faultable
/// identity left), so it must key distinct Q-rows / novelty slots from both the
/// pre-crash Honest and the amnesiac environments.
const CRASHED_TAG: u64 = 0x5c8b_2e71_d4a0_936f;

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
/// amnesiac XOR [`CRASHED_TAG`] once node 0 is permanently crash-stopped (the two
/// lifecycle states are mutually exclusive). Under the Honest role with neither this
/// is `0` (an identity mix, so the warm campaign's honest rows are unchanged).
fn env_tag(role: adversary::AdversaryRole, node0_amnesiac: bool, node0_crashed: bool) -> u64 {
    role.tag()
        ^ if node0_amnesiac { AMNESIA_TAG } else { 0 }
        ^ if node0_crashed { CRASHED_TAG } else { 0 }
}

/// Coarse remaining-container horizon tag folded into the Q-STATE ONLY (never the
/// novelty fingerprints), so transitions with a materially different remaining budget
/// key distinct Q-rows without an identical protocol state being scored novel merely
/// because the horizon changed. `remaining_bucket` is a small clamped index.
fn horizon_tag(remaining_bucket: u64) -> u64 {
    0xfdb9_7531_eca8_6420u64.wrapping_add(remaining_bucket.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

/// Number of coarse remaining-budget buckets fed to [`horizon_tag`].
const HORIZON_BUCKETS: u64 = 4;

/// The coarse remaining-container bucket in `0..HORIZON_BUCKETS`: the finalizations
/// still owed toward `required_containers`, clamped.
fn remaining_bucket(finalization_budget: usize, observed: usize) -> u64 {
    (finalization_budget.saturating_sub(observed) as u64).min(HORIZON_BUCKETS - 1)
}

/// Node-attributed finalization frontier read STRAIGHT from each initially-honest
/// reporter's own subscription monitor (subscribed ONCE at setup because
/// [`Reporter::subscribe`](commonware_consensus::Monitor::subscribe) never prunes its
/// senders). The runner OWNS the monitors and drains them synchronously, so the cut
/// is authoritative -- there is no intermediate forwarder task whose async copy could
/// let a pre-cut finalization arrive after the next fault is enacted. `latest[node]`
/// is the highest finalized view drained from `node` (0 for never-honest indices).
struct FinalizationClock {
    latest: Vec<u64>,
    monitors: Vec<(usize, ViewReceiver<View>)>,
}

impl FinalizationClock {
    /// Fold every event already queued in every SOURCE monitor into `latest`, without
    /// blocking. This is the authoritative synchronous frontier snapshot.
    fn drain(&mut self) {
        for (node, monitor) in &mut self.monitors {
            while let Ok(view) = monitor.try_recv() {
                self.latest[*node] = self.latest[*node].max(view.get());
            }
        }
    }

    /// The step baseline: the highest finalized view across the given live-correct
    /// set. Call [`drain`](Self::drain) first. `0` if the set is empty.
    fn baseline(&self, live_correct: &HashSet<usize>) -> u64 {
        live_correct
            .iter()
            .map(|node| self.latest[*node])
            .max()
            .unwrap_or(0)
    }
}

/// How a reactive step ended: a genuinely new honest finalization (a live-correct
/// node reached a view past the step baseline), or the deterministic step timeout
/// (the fault suppressed progress).
#[derive(Clone, Copy, Debug)]
enum StepBoundary {
    Finalized { node: usize, view: u64 },
    Timeout,
}

/// Wait until any node in `live_correct` finalizes a view strictly past `baseline`,
/// or `deadline` expires. The boundary is "the first qualifying finalization the
/// runner OBSERVES when it regains control" -- NOT an exact global emission order.
/// Each iteration first takes an authoritative synchronous drain of every SOURCE
/// monitor (finalization priority: an already-queued crossing wins even at the
/// deadline); events from other nodes and views `<= baseline` fold into
/// `clock.latest` but do not close the step. If nothing is queued, it races the
/// monitors EVENT-DRIVEN against the deadline via [`select_all`], waking at the
/// instant a monitor emits. When several finalizations accumulate while an awaited
/// action was being enacted (e.g. a restart's downtime), or several monitors are
/// ready at once, the choice among the ALREADY-QUEUED crossings is by monitor
/// (vector) order, not exact emission order. This is an accepted approximation: every
/// honest node finalizes the SAME views in Simplex, so the boundary VIEW (which the
/// container budget counts and the reward keys on) is still the first new view; only
/// the diagnostic `trigger_node` may name a later reporter. `live_correct` is the
/// POST-enact set, so a crashed / amnesiac node's stale events never close the step.
/// Waiting for EVERY honest node is exclusively an episode-end liveness
/// responsibility; here one live-correct node closes the step.
async fn wait_for_step_boundary(
    context: &mut deterministic::Context,
    clock: &mut FinalizationClock,
    live_correct: &HashSet<usize>,
    baseline: u64,
    deadline: SystemTime,
) -> StepBoundary {
    loop {
        for (node, monitor) in &mut clock.monitors {
            while let Ok(view) = monitor.try_recv() {
                let view = view.get();
                clock.latest[*node] = clock.latest[*node].max(view);
                if live_correct.contains(node) && view > baseline {
                    return StepBoundary::Finalized { node: *node, view };
                }
            }
        }
        let Ok(remaining) = deadline.duration_since(context.current()) else {
            return StepBoundary::Timeout;
        };
        if remaining.is_zero() {
            return StepBoundary::Timeout;
        }
        // Race every source monitor against the deadline. The `select_all` future
        // borrows the monitors, so the arm only extracts the woken `(node, view)` (a
        // Copy value); the fold + crossing check run AFTER the borrow ends. A closed
        // monitor (never expected mid-episode -- reporter `Arc`s are held) reads as a
        // timeout rather than spinning.
        let recvs: Vec<_> = clock
            .monitors
            .iter_mut()
            .map(|(node, monitor)| {
                let node = *node;
                Box::pin(async move { (node, monitor.recv().await) })
            })
            .collect();
        let woken: (usize, u64) = select! {
            (fired, _, _) = select_all(recvs) => match fired {
                (node, Some(view)) => (node, view.get()),
                (_, None) => return StepBoundary::Timeout,
            },
            _ = context.sleep(remaining) => return StepBoundary::Timeout,
        };
        clock.latest[woken.0] = clock.latest[woken.0].max(woken.1);
        if live_correct.contains(&woken.0) && woken.1 > baseline {
            return StepBoundary::Finalized {
                node: woken.0,
                view: woken.1,
            };
        }
    }
}

/// The real node indices currently live-correct: `managed` positions with
/// `lifecycle() == Running`, mapped to node indices via `honest_indices`. Excludes a
/// crash-stopped or amnesiac node 0 (and a byzantine-role node 0 is never in
/// `managed`); a durably-restarted node 0 is `Running` and included. The step
/// baseline and the reactive step boundary observe exactly this set, refreshed each
/// step so a lifecycle change is reflected immediately.
fn live_correct_nodes<P: Simplex>(
    managed: &[ManagedValidator<P>],
    honest_indices: &[usize],
) -> HashSet<usize> {
    (0..managed.len())
        .filter(|&k| matches!(managed[k].lifecycle(), ValidatorLifecycle::Running))
        .map(|k| honest_indices[k])
        .collect()
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
        | action::FaultPlan::AmnesiaRestart
        | action::FaultPlan::SetRole(_) => Enactment::Applied,
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
    senders: &[(
        usize,
        SniffChannel,
        mpsc::UnboundedSender<network::FlushAck>,
    )],
    node: usize,
    channel: SniffChannel,
) {
    if let Some((_, _, tx)) = senders.iter().find(|(n, c, _)| *n == node && *c == channel) {
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
    (
        S,
        SniffingReceiver<P, network::PacketFaultReceiver<PublicKeyOf<P>>>,
    ),
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

/// Restart the crashed faultable identity in place (Mallory), either
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
    flush_senders: &mut Vec<(
        usize,
        SniffChannel,
        mpsc::UnboundedSender<network::FlushAck>,
    )>,
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
    flush_senders: &mut Vec<(
        usize,
        SniffChannel,
        mpsc::UnboundedSender<network::FlushAck>,
    )>,
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
    flush_senders: &mut Vec<(
        usize,
        SniffChannel,
        mpsc::UnboundedSender<network::FlushAck>,
    )>,
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

/// Run one Mallory episode.
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
    // The hard step cap (truncation guard): allow at least the requested finalization
    // budget so the episode can attempt its full container budget.
    let steps = MALLORY_EPISODE_STEPS.max(input.required_containers as usize);
    run_with::<P>(input, chooser, steps);
}

/// [`run`] with an explicit hard step cap, sampling the adversary role from the
/// runtime RNG. Production derives the cap from `required_containers` (see [`run`]);
/// the ignored integration tests pass a short count so a full deterministic episode
/// (runtime + reactive steps + liveness + invariants) finishes in seconds while
/// exercising the same code paths. The episode still stops at its finalization budget
/// before the cap.
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
        crate::print_fuzz_input(crate::Mode::MalloryContainer, &input);

        let config = input.configuration;
        let n = config.n as usize;
        let required_containers = input.required_containers;
        let relay = Arc::new(relay::Relay::new());
        let peers: Arc<[PublicKeyOf<P>]> = participants.clone().into();

        // Select the episode's adversary role ONCE, before the per-node loop. The
        // learned chooser draws it from the campaign-persistent role bandit, so the
        // campaign concentrates episodes on the more productive Byzantine profiles;
        // every other chooser keeps the campaign-independent uniform sample, which
        // preserves the Random A/B determinism (the bandit never drives that path).
        // A forced role overrides both and skips the draw, keeping an Honest-forced
        // episode byte-identical to the no-role baseline. Both draw from the runtime
        // RNG, so a replay reproduces the role.
        let role = forced_role.unwrap_or_else(|| match chooser {
            Chooser::Learned => adversary::role_bandit().lock().select(&mut context),
            _ => adversary::AdversaryRole::sample(&mut context),
        });
        let byz = role.is_byzantine();
        // The MUTABLE per-step environment role. It starts at the sampled `role` and,
        // in a byzantine episode, a `SetRole` step swaps it (via the multiplexer) to
        // another Byzantine profile. It keys the role region of the Q-state every step
        // (`env_tag(current_role, ..)`), so a switch connects the role regions of the
        // MDP. `byz`, `ambiguous`, and the role bandit's credit stay pinned to the
        // INITIAL `role` (all six profiles are Byzantine, so `byz` never changes, and
        // the bandit learns the role it selected).
        let mut current_role = role;
        // The byzantine node cannot send messages under another node's identity, so its messages are
        // always correctly attributed to node 0 -- but a byzantine node (node with BYZANTINE_IDX)
        // can attach a causal history that matches no honest execution, which is not sound to merge
        // into an honest node's fingerprint. So it is excluded from happens-before
        // sender attribution while byzantine; the honest nodes 1-3 stay captured. Under
        // the Honest role no node is ambiguous. This is fixed at setup (the sniffers are
        // built once), so a LATER amnesia restart does not retroactively mark node 0
        // ambiguous: its post-amnesia messages stay in the honest HB attribution. That
        // is acceptable -- the HB log feeds only the reward/novelty fingerprint, never
        // the safety oracle, which excludes an amnesiac node 0 via the `node0_byzantine`
        // flag at episode end.
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
        // Under a byzantine role node 0 is owned by the adversary multiplexer, which
        // spawns the current profile's raw actor and swaps it on a `SetRole` step.
        // `None` under the Honest environment. Only the byzantine branch sets it.
        let mut multiplexer: Option<multiplexer::RoleMultiplexer<P>> = None;
        for i in 0..n {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();

            // Byzantine role at node 0: hand its RAW channels to the multiplexer (no
            // pump, no SniffingReceiver, no reporter, no ManagedValidator). The
            // multiplexer is the single owner of those single-consumer mailboxes and
            // spawns the INITIAL profile's actor; nothing is pushed to `managed`. The
            // Equivocator shares the honest nodes' relay and leader schedule (built
            // internally as `P::Elector::default()`, the same config the honest
            // validators build with); the other roles ignore both.
            if byz && i == BYZANTINE_IDX {
                multiplexer = Some(multiplexer::RoleMultiplexer::new(
                    &context,
                    validator,
                    schemes[i].clone(),
                    oracle.clone(),
                    relay.clone(),
                    required_containers,
                    role,
                    channels,
                ));
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

        // Persistent finalization clock: subscribe ONCE to every initially-honest
        // reporter and KEEP the monitors in the runner so each step drains them
        // synchronously (an authoritative cut, no intermediate forwarder). Subscribing
        // once (not per step) is required -- `Reporter::subscribe` never prunes its
        // senders. A durable restart REUSES its reporter, so its monitor keeps
        // delivering; an amnesia restart SWAPS node 0's reporter, so its monitor stops
        // advancing, which is correct because node 0 is then Byzantine and excluded.
        let mut clock = FinalizationClock {
            latest: vec![0u64; n],
            monitors: Vec::with_capacity(managed.len()),
        };
        for k in 0..managed.len() {
            let node = honest_indices[k];
            let (latest0, monitor): (View, ViewReceiver<View>) =
                managed[k].reporter().subscribe().await;
            clock.latest[node] = latest0.get();
            clock.monitors.push((node, monitor));
        }

        // Episode budget, captured ONCE: the episode stops once it has observed
        // `required_containers` distinct finalization boundaries. The step count
        // (`steps`) is a truncation guard.
        let finalization_budget = required_containers as usize;
        let mut observed_finalizations: HashSet<u64> = HashSet::new();

        // Observe before the first decision: the initial (empty-history) HB
        // fingerprint XOR the env tag (role plus amnesia / crashed bits) XOR the
        // horizon tag is the step-0 Q-state. The env tag keeps Honest, each byzantine
        // role, a post-amnesia node 0, and a post-crash node 0 in distinct Q-rows; the
        // horizon tag keeps a different remaining container budget distinct (folded
        // into the Q-STATE only, never novelty). Node 0 cannot be amnesiac or crashed
        // yet, so the env tag reduces to the role.
        let mut state = hb_log.summary().fingerprint()
            ^ env_tag(current_role, false, false)
            ^ horizon_tag(remaining_bucket(finalization_budget, 0));
        // Summed per-step novelty reward and the executed-step count. The role
        // bandit's signal (Learned only) is their ratio -- the per-step AVERAGE, which
        // is length-independent, so roles are ranked by novelty density rather than
        // episode length (a short early-crash episode must not out-rank a long
        // productive one).
        let mut episode_reward = 0.0;
        let mut executed_steps = 0usize;

        // Budget-driven reactive loop. `steps` is the hard step cap (truncation
        // guard); the episode also stops at its time or finalization budget. The end
        // reason is recorded per step in the decision log (`episode_end=`).
        let mut step = 0usize;
        loop {
            executed_steps += 1;
            // (a) Authoritative PRE-enact cut: drain the source monitors synchronously
            // (select and sample below never await, so no finalization is processed
            // between here and enactment). `clock.latest` now holds the causal baseline
            // frontier; it is NOT re-drained until the boundary wait, so the baseline
            // computed AFTER enactment still reflects this pre-enact cut. The eligible
            // live-correct set is (re)computed after enactment (see below), so a crash /
            // amnesia THIS step is reflected in both membership and baseline.
            clock.drain();

            // The per-step legal mask. Under the Honest role, while node 0 runs
            // every action is legal; once it is crash-stopped only NoFault is (a
            // crash is terminal, so this is reached only defensively), and a durable
            // restart re-opens the full mask. Once node 0 is amnesiac it is the
            // single Byzantine identity (Running but empty-storage), so the three
            // lifecycle faults are masked out. Under a byzantine role node 0 is the
            // unmanaged adversary (never "crashed"), and the lifecycle faults are
            // likewise masked -- there is no ManagedValidator at node 0 to crash. A
            // `SetRole` swap is legal only under a byzantine role and only until the
            // multiplexer's per-episode switch cap is reached.
            let node0_crashed =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Crashed);
            let node0_amnesiac =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Amnesiac);
            let role_switches_exhausted = multiplexer
                .as_ref()
                .is_some_and(|m| m.switches() >= action::MALLORY_MAX_ROLE_SWITCHES);
            let legal =
                action::legal_mask(node0_crashed, byz, node0_amnesiac, role_switches_exhausted);

            // (b)/(c)/(d) Current abstract state is `state`; select under the
            // legal mask. Learned consults the campaign; Random does not.
            let action_id = match chooser {
                Chooser::Learned => policy::campaign(action::N_ACTIONS)
                    .lock()
                    .policy
                    .select(state, &legal, &mut context),
                Chooser::Random => select_uniform_legal(&legal, &mut context),
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
            // Exclude node 0 as a packet target when it has no live pump / sniffer:
            // a byzantine role owns it (raw channels) or it is crash-stopped.
            let plan = action.sample(&mut context, byz || node0_crashed);
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
                    // Crash-stop the faultable identity PERMANENTLY (but NOT terminal):
                    // abort+await both handles so the old engine/application tasks can
                    // never send again. Node 0 stays `Crashed` for the rest of the
                    // episode, dropped from the reactive finalization / liveness sets
                    // and every subsequent step's legal mask (lifecycle and
                    // isolate-node-0 masked), while Mallory keeps perturbing the
                    // surviving quorum. Its retained reporter (pre-crash history) stays
                    // in the safety set. Enacted against the managed validator, so the
                    // topology / packet layers are untouched (no heal below).
                    lifecycle::crash_stop(&mut managed[0]).await;
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
                action::FaultPlan::SetRole(new_role) => {
                    // Swap node 0's active Byzantine profile via the multiplexer:
                    // abort+await the live actor, re-register node 0's channels, and
                    // spawn the new profile. `current_role` then keys the role region
                    // of the Q-state for the rest of the episode (see `next_tag`), so
                    // this step is the transition that connects the MDP's role regions.
                    // Only reachable in a byzantine episode (SetRole is masked
                    // otherwise), so the multiplexer is always present.
                    let mux = multiplexer
                        .as_mut()
                        .expect("SetRole is only legal in a byzantine episode");
                    mux.set_role(*new_role, &mut context).await;
                    current_role = mux.current_role();
                }
            }

            // (f2) POST-enact observation set + baseline. The live-correct set is
            // recomputed HERE (not pre-enact) so a crash-stop / amnesia this step drops
            // node 0 immediately -- its stale events can never close the step. The
            // baseline is the pre-enact cut (`clock.latest`, not re-drained since (a))
            // restricted to that eligible set: new progress is a finalization past the
            // frontier that existed just before the fault, from a node still eligible.
            let live_correct = live_correct_nodes(&managed, &honest_indices);
            let baseline = clock.baseline(&live_correct);

            // (g) Reactive step boundary: wait for the first genuinely new honest
            // finalization (a live-correct node past `baseline`) or the deterministic
            // per-action step timeout (the fault suppressed progress).
            let step_deadline = step_start + MALLORY_STEP_TIMEOUT;
            let boundary = wait_for_step_boundary(
                &mut context,
                &mut clock,
                &live_correct,
                baseline,
                step_deadline,
            )
            .await;
            let (boundary_label, trigger_node, trigger_view) = match boundary {
                StepBoundary::Finalized { node, view } => {
                    // Count this finalization boundary ONCE (container budget): a view
                    // jump V->V+N, and duplicate reports of one view, each count once.
                    observed_finalizations.insert(view);
                    ("finalization", Some(node), Some(view))
                }
                StepBoundary::Timeout => ("timeout", None, None),
            };

            // Node 0's POST-enact lifecycle (an amnesia restart THIS step already
            // flipped it to Amnesiac/Byzantine; a crash to Crashed). Stable from enact
            // through heal, so one env tag serves the effect AND the next state. Under a
            // byzantine role node 0 is unmanaged, so both flags stay false.
            let node0_crashed_now =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Crashed);
            let node0_amnesiac_now =
                !byz && matches!(managed[0].lifecycle(), ValidatorLifecycle::Amnesiac);
            // The env tag uses the POST-enact `current_role`: a `SetRole` this step has
            // already swapped it, so the effect / next fingerprints key the NEW role
            // region -- the transition that connects the role regions of the MDP. A
            // crash this step also keys the post-crash region for every later step.
            let tag = env_tag(current_role, node0_amnesiac_now, node0_crashed_now);

            // (h) FAULT-EFFECT fingerprints, captured BEFORE healing so recovery /
            // settle work is not credited to the fault. The reward and its novelty use
            // these. The protocol-state descriptor is over the CURRENT running reporters
            // only (a crashed / amnesiac node excluded); the setup `reporters` clone is
            // retained unchanged for the episode-end safety oracle.
            let effect_hb = hb_log.summary().fingerprint() ^ tag;
            let effect_reporters: Vec<MalloryReporter<P>> = (0..managed.len())
                .filter(|&k| matches!(managed[k].lifecycle(), ValidatorLifecycle::Running))
                .map(|k| reporters[k].clone())
                .collect();
            let effect_state = state::state_descriptor::<P>(&effect_reporters, n) ^ tag;
            let reward = if matches!(chooser, Chooser::Learned) {
                let campaign = policy::campaign(action::N_ACTIONS);
                let mut c = campaign.lock();
                let r = c.reward(effect_state, effect_hb);
                episode_reward += r;
                Some(r)
            } else {
                None
            };

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
                action::FaultPlan::SetRole(_) => {
                    // A role switch is enacted against the multiplexer and PERSISTS:
                    // there is no transient fault to heal (the new profile keeps
                    // running into the next step).
                    ("role_switch", "n/a".to_string(), Enactment::Applied)
                }
            };

            // (i2) Episode budget check (item 13): does the episode end after this
            // step, and why? Only the hard step cap or the distinct-finalization budget
            // end it. A crash-stop is NOT terminal (the episode continues over the
            // surviving quorum). `step` is this step's 0-based index; `step + 1` is the
            // count.
            let ended: Option<&'static str> = if step + 1 >= steps {
                Some("step_cap")
            } else {
                (observed_finalizations.len() >= finalization_budget).then_some("budget")
            };

            // (j) NEXT-decision Q-state, captured POST-heal + settle: the environment in
            // which the next action is selected. The horizon tag folds in the remaining
            // container budget AFTER this step (never into the effect novelty above).
            let remaining_next =
                remaining_bucket(finalization_budget, observed_finalizations.len());
            let next_state = (hb_log.summary().fingerprint() ^ tag) ^ horizon_tag(remaining_next);

            // (k) TD update (Learned only, `reward` already computed pre-heal). Terminal
            // when the episode ends here (no bootstrap); otherwise bootstrap over the
            // actions legal at NEXT, recomputed from node 0's POST-enact lifecycle and
            // switch count (so an amnesia restart or a switch-cap hit does not bootstrap
            // over now-illegal columns). `select` above used the pre-enact `legal`.
            let reward_log = match reward {
                Some(r) => {
                    let role_switches_exhausted_next = multiplexer
                        .as_ref()
                        .is_some_and(|m| m.switches() >= action::MALLORY_MAX_ROLE_SWITCHES);
                    let legal_next = action::legal_mask(
                        node0_crashed_now,
                        byz,
                        node0_amnesiac_now,
                        role_switches_exhausted_next,
                    );
                    let campaign = policy::campaign(action::N_ACTIONS);
                    let mut c = campaign.lock();
                    if ended.is_some() {
                        c.policy.learn_terminal(state, action_id, r);
                    } else {
                        c.policy.learn(state, action_id, r, next_state, &legal_next);
                    }
                    format!("{r}")
                }
                None => "n/a".to_string(),
            };

            // (l) Log the full transition. `boundary`/`trigger_*` say why the step
            // ended; `baseline` is the pre-action honest frontier; `episode_remaining`
            // and `episode_end` expose the budget. `state_desc` is the pre-heal fault
            // effect; `next_state` the post-heal bootstrap state. `generation` /
            // `lifecycle0` track node 0's incarnation and lifecycle ("unmanaged" under a
            // byzantine role), making the mid-episode Honest->Amnesiac flip observable.
            let generation = if byz { 0 } else { managed[0].generation() };
            let lifecycle0 = if byz {
                "unmanaged".to_string()
            } else {
                format!("{:?}", managed[0].lifecycle())
            };
            let trigger_node_log = trigger_node.map_or_else(|| "none".to_string(), |x| x.to_string());
            let trigger_view_log = trigger_view.map_or_else(|| "none".to_string(), |x| x.to_string());
            let containers_remaining =
                finalization_budget.saturating_sub(observed_finalizations.len());
            log::push(format!(
                "mallory: chooser={chooser:?} role={} step={step} action_id={action_id} action={action:?} legal={legal:?} params=[{params}] applied={enactment:?} generation={generation} lifecycle0={lifecycle0} prev_state={state:#018x} next_state={next_state:#018x} state_desc={effect_state:#018x} reward={reward_log} boundary={boundary_label} trigger_node={trigger_node_log} trigger_view={trigger_view_log} baseline={baseline} containers_remaining={containers_remaining} episode_end={} heal={healed} matched={matched_log}",
                current_role.label(),
                ended.unwrap_or("false"),
            ));
            state = next_state;

            // (m) End or continue (item 14).
            if ended.is_some() {
                break;
            }
            step += 1;
        }

        // Episode end: fold this episode's accumulated novelty into the campaign-
        // persistent role bandit so the campaign concentrates on the roles that keep
        // producing novelty. Learned only -- Random / Fixed never touch the bandit,
        // keeping the A/B baseline campaign-independent. Done before the oracle so a
        // productive-but-panicking episode still credits its role.
        if matches!(chooser, Chooser::Learned) {
            let role_reward = episode_reward / executed_steps.max(1) as f64;
            adversary::role_bandit().lock().learn(role, role_reward);
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

    #[test]
    fn select_helpers_only_return_legal_ids() {
        // Both selection paths must respect the legal mask. The masked-softmax
        // path is exercised over a seeded Q-row; the uniform path over the same
        // mask. Pure (no runtime), so this stays in the fast suite.
        let legal = action::legal_mask(false, false, false, false);
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
    fn liveness_target_requires_progress_past_the_frontier() {
        // The post-heal target is one view past the HIGHEST pre-heal frontier, so
        // a node wedged by the last fault/heal/restart cannot pass by sitting at the
        // frontier; it never drops below required_containers, and stays there on
        // overflow.
        assert_eq!(liveness_target(2, 10), 11, "one view past the frontier");
        assert_eq!(
            liveness_target(20, 10),
            20,
            "never below required_containers"
        );
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
    fn env_tag_separates_post_amnesia_and_post_crash_from_every_other_environment() {
        use adversary::AdversaryRole::Honest;
        // The amnesia and crashed bits each key a distinct Q-state / novelty slot, so a
        // post-amnesia or post-crash node 0 no longer aliases the pre-fault Honest
        // environment, each other, or any role.
        assert_ne!(AMNESIA_TAG, 0, "the amnesia tag must be nonzero");
        assert_ne!(CRASHED_TAG, 0, "the crashed tag must be nonzero");
        assert_ne!(AMNESIA_TAG, CRASHED_TAG, "amnesia and crashed must differ");
        assert_eq!(
            env_tag(Honest, false, false),
            Honest.tag(),
            "neither bit reduces to the role tag"
        );
        let amnesiac = env_tag(Honest, true, false);
        let crashed = env_tag(Honest, false, true);
        assert_ne!(
            amnesiac,
            env_tag(Honest, false, false),
            "amnesia differs from Honest"
        );
        assert_ne!(
            crashed,
            env_tag(Honest, false, false),
            "crashed differs from Honest"
        );
        assert_ne!(amnesiac, crashed, "amnesia and crashed key different rows");
        for role in [
            Honest,
            adversary::AdversaryRole::Disrupter,
            adversary::AdversaryRole::Conflicter,
            adversary::AdversaryRole::Nuller,
            adversary::AdversaryRole::Equivocator,
            adversary::AdversaryRole::Impersonator,
            adversary::AdversaryRole::Outdated,
        ] {
            assert_ne!(
                amnesiac,
                env_tag(role, false, false),
                "post-amnesia must not alias {role:?}"
            );
            assert_ne!(
                crashed,
                env_tag(role, false, false),
                "post-crash must not alias {role:?}"
            );
            assert_ne!(
                role.tag(),
                AMNESIA_TAG,
                "{role:?} tag must differ from AMNESIA_TAG"
            );
            assert_ne!(
                role.tag(),
                CRASHED_TAG,
                "{role:?} tag must differ from CRASHED_TAG"
            );
        }
    }

    #[test]
    fn enactment_accounts_lifecycle_applied_and_ineffective_packet_noeffect() {
        // A lifecycle fault always logs Applied; a packet fault that matched no packet
        // logs NoEffect; NoFault is NoEffect.
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
        // The runner recomputes the NEXT-state legal mask from node 0's POST-enact
        // lifecycle and passes THAT as the TD bootstrap mask. After an amnesia restart
        // that mask must exclude the three lifecycle columns the pre-enact running mask
        // includes, so the bootstrap max cannot span a now-illegal lifecycle action.
        let running = action::legal_mask(false, false, false, false);
        let amnesiac = action::legal_mask(false, false, true, false);
        for id in [
            action::Action::CrashStop.id(),
            action::Action::CrashRestartDurable.id(),
            action::Action::AmnesiaRestart.id(),
        ] {
            assert!(
                running[id],
                "lifecycle columns are legal pre-enact (running)"
            );
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
        adversary::reset_role_bandit();
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

    /// The reactive container flow completes and holds the SAME liveness/safety oracle,
    /// and every step records a reactive boundary (finalization or timeout). Uses the
    /// campaign-independent [`Chooser::Random`] so the test is hermetic (no Q-table
    /// mutation) and isolates the episode flow from the chooser.
    #[test]
    #[ignore]
    fn container_flow_completes_and_holds_the_oracle() {
        for seed in [1u64, 2, 3] {
            let (ok, logv) = mallory_trace(mallory_input(seed), Chooser::Random);
            assert!(
                ok,
                "the episode must complete and hold the oracle (seed {seed})"
            );
            assert!(
                !logv.is_empty()
                    && logv
                        .iter()
                        .all(|l| l.contains("boundary=finalization")
                            || l.contains("boundary=timeout")),
                "every step must record a reactive boundary (seed {seed}): {logv:?}"
            );
        }
    }

    /// Smoke: learned episodes complete (liveness + safety oracle pass), the campaign
    /// Q-table gains a row, and the episode-level role bandit learns a nonzero arm.
    /// A nonzero Q-table implies some step scored a non-novel (negative) reward, whose
    /// episode therefore accumulated a nonzero productivity total for its role -- so a
    /// learning campaign moves the bandit off its uniform start.
    #[test]
    #[ignore]
    fn run_mallory_smoke_completes_and_learns() {
        policy::reset_campaign(action::N_ACTIONS);
        adversary::reset_role_bandit();
        for seed in [1u64, 2, 3] {
            run_with::<SimplexId>(mallory_input(seed), Chooser::Learned, TEST_STEPS);
        }
        assert!(
            !policy::campaign(action::N_ACTIONS).lock().policy.is_empty(),
            "learned episodes must populate the campaign Q-table"
        );
        assert!(
            !adversary::role_bandit().lock().is_empty(),
            "learned episodes must move the role bandit off its uniform start"
        );
    }

    /// Acceptance criterion 3 (structural): the role is a MUTABLE Q-state component.
    /// The runner folds `env_tag(current_role, ..)` into every Q-state / novelty
    /// fingerprint, and each of the six Byzantine roles has a distinct tag, so a
    /// SetRole swap changes the role component of the key -- the post-switch steps key
    /// a distinct role region of the MDP.
    #[test]
    fn set_role_changes_the_q_state_role_component() {
        let byz = [
            adversary::AdversaryRole::Disrupter,
            adversary::AdversaryRole::Conflicter,
            adversary::AdversaryRole::Nuller,
            adversary::AdversaryRole::Equivocator,
            adversary::AdversaryRole::Impersonator,
            adversary::AdversaryRole::Outdated,
        ];
        for (i, a) in byz.iter().enumerate() {
            for b in &byz[i + 1..] {
                assert_ne!(
                    env_tag(*a, false, false),
                    env_tag(*b, false, false),
                    "a {a:?}<->{b:?} switch must change the Q-state role component"
                );
            }
        }
    }

    /// Acceptance criterion 3 (learned): a learned campaign that runs byzantine
    /// episodes moves the `SetRole` Q-column off zero, i.e. it learns a NON-ZERO
    /// Q-value for some `(state, SetRole)` entry. Reuses the smoke seam (run learned
    /// episodes, then inspect the campaign): with node 0 pinned to a Byzantine role
    /// SetRole is legal every step, so the softmax selects and learns it, and by the
    /// later episodes the recurring view-relative fingerprints are non-novel, giving a
    /// nonzero reward that moves the column.
    #[test]
    #[ignore]
    fn learned_set_role_learns_a_nonzero_qvalue() {
        policy::reset_campaign(action::N_ACTIONS);
        adversary::reset_role_bandit();
        for seed in 1u64..=8 {
            run_inner::<SimplexId>(
                mallory_input(seed),
                Chooser::Learned,
                MALLORY_EPISODE_STEPS,
                Some(adversary::AdversaryRole::Disrupter),
            );
        }
        assert!(
            !policy::campaign(action::N_ACTIONS)
                .lock()
                .policy
                .action_column_is_empty(action::Action::SetRole.id()),
            "a learned byzantine campaign must learn a nonzero (state, SetRole) Q-value"
        );
    }
}
