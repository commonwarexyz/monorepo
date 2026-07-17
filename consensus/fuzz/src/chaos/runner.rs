//! The chaos episode loop: an all-honest committee under a fuzzer-driven
//! crash/network fault schedule, watched online.
//!
//! Each episode builds four honest [`ManagedValidator`]s over the simulated
//! network and drives a reactive loop. Each step first observes the cluster
//! under the PREVIOUS step's expectations (so a heal can never retroactively
//! excuse a violation that preceded it), then draws one [`Action`] from the
//! pure [`Schedule`], publishes the schedule's updated beliefs (faults publish
//! before landing; heals land before publishing), enacts it after a small
//! RNG-drawn jitter (so faults are not phase-locked to finalization
//! boundaries), and waits for the next finalization past the step baseline or
//! a deterministic timeout. The episode stops once it has observed the input's
//! `required_containers` distinct finalization boundaries, or at the step cap.
//!
//! Enactment maps the schedule vocabulary onto existing harness primitives:
//! Kill is `mallory::lifecycle::crash_stop`, Start and Reload are a durable
//! restart (re-register, rebuild on the same storage partition with the
//! retained reporter, journal replay), and Disconnect/Reconnect are surgical
//! per-edge link changes (only edges adjacent to the changed node are touched,
//! so in-flight traffic between healthy quorum members is never dropped by the
//! harness itself).
//!
//! The episode-end oracle heals everything, requires every node to finalize
//! past the highest pre-heal frontier within [`POST_GST_WINDOW`], and then runs
//! the safety invariants over all four reporters with an EMPTY Byzantine set:
//! the committee is honest, so any equivocation, fault evidence, or invalid
//! report is a finding.
//!
//! A failed harness operation (a link change or rebuild that cannot succeed)
//! panics immediately with wording distinct from the `chaos:` oracle findings:
//! in a deterministic in-process rig a failed injection means the harness's
//! state model is wrong, and the scene is exactly reproducible from the input.

use super::{
    log,
    schedule::{Action, Condition, Schedule},
    watch,
    watch::Checker,
};
use crate::{
    CertifyChoice, ManagedValidator, N4F0C4, POST_GST_WINDOW, PublicKeyOf, bounds,
    build_validator, build_validator_with_reporter, invariants,
    mallory::{
        lifecycle,
        runner::{FinalizationClock, StepBoundary, liveness_target, wait_for_step_boundary},
    },
    simplex::Simplex,
    utils::Partition,
};
use commonware_consensus::{
    Monitor as _,
    simplex::mocks::{relay, reporter::Reporter},
    types::View,
};
use commonware_cryptography::{
    PublicKey, certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock, Runner, Spawner, Supervisor, deterministic};
use commonware_utils::{FuzzRng, channel::mpsc::Receiver as ViewReceiver};
use futures::future::join_all;
use rand::RngExt as _;
use std::{
    collections::HashSet,
    fmt::Write as _,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Base episode step count; the hard cap is `max(CHAOS_EPISODE_STEPS,
/// required_containers)` so the episode can attempt its finalization budget.
const CHAOS_EPISODE_STEPS: usize = 12;
/// Per-step reactive boundary timeout: a step ends on the first finalization
/// past its baseline, or after this deterministic timeout if the schedule
/// suppressed progress. Exceeds the reload downtime so a restart never eats the
/// whole window.
const CHAOS_STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// Fixed deterministic downtime inside a [`Action::Reload`], between abort and
/// rebuild.
const CHAOS_RESTART_DOWNTIME: Duration = Duration::from_secs(2);
/// How long after losing the liveness expectation in-flight finalizations may
/// still land before the tip freezes. At least one full step, not a
/// link-latency estimate: pre-loss votes drain through whole steps.
const CHAOS_SETTLE_MARGIN: Duration = Duration::from_secs(10);
/// How long the tip may stand still while the committee is expected live.
/// Sized from protocol constants, generously: `timeout_retry` is 10s, a
/// dead-leader view costs a few seconds, and a restarted quorum member needs
/// seconds of catch-up; deterministic time is cheap and a false positive
/// poisons the corpus.
const CHAOS_LIVENESS_WINDOW: Duration = Duration::from_secs(60);
/// Upper bound of the RNG-drawn jitter before each enactment, roughly one view
/// time: the fuzzer controls the protocol phase a fault lands in.
const CHAOS_JITTER_MS: u64 = 2_000;

/// The reporter type the runner snapshots for the checker and the episode-end
/// oracle.
type ChaosReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// Surgical connectivity controller: tracks the disconnected set and touches
/// only the edges adjacent to the node whose state changes. Edges between
/// connected peers are never removed and re-added, so the harness never drops
/// in-flight traffic between healthy quorum members (a full-topology reset
/// would, and lost votes are only rebroadcast on the engines' 10s retry).
struct Connectivity<P: PublicKey> {
    oracle: Oracle<P, deterministic::Context>,
    participants: Vec<P>,
    link: Link,
    disconnected: Vec<bool>,
}

impl<P: PublicKey> Connectivity<P> {
    fn new(oracle: Oracle<P, deterministic::Context>, participants: Vec<P>, link: Link) -> Self {
        let disconnected = vec![false; participants.len()];
        Self {
            oracle,
            participants,
            link,
            disconnected,
        }
    }

    /// Remove every edge adjacent to `node`. Idempotent.
    async fn disconnect(&mut self, node: usize) {
        if self.disconnected[node] {
            return;
        }
        self.disconnected[node] = true;
        for peer in 0..self.participants.len() {
            if peer == node {
                continue;
            }
            let a = self.participants[node].clone();
            let b = self.participants[peer].clone();
            self.oracle.remove_link(a.clone(), b.clone()).await.ok();
            self.oracle.remove_link(b, a).await.ok();
        }
    }

    /// Restore `node`'s edges to every peer that is itself connected.
    /// Idempotent (each edge is removed before it is re-added).
    async fn reconnect(&mut self, node: usize) {
        if !self.disconnected[node] {
            return;
        }
        self.disconnected[node] = false;
        for peer in 0..self.participants.len() {
            if peer == node || self.disconnected[peer] {
                continue;
            }
            let a = self.participants[node].clone();
            let b = self.participants[peer].clone();
            self.oracle.remove_link(a.clone(), b.clone()).await.ok();
            self.oracle
                .add_link(a.clone(), b.clone(), self.link.clone())
                .await
                .expect("chaos harness: add_link failed on reconnect");
            self.oracle.remove_link(b.clone(), a.clone()).await.ok();
            self.oracle
                .add_link(b, a, self.link.clone())
                .await
                .expect("chaos harness: add_link failed on reconnect");
        }
    }
}

/// Durable restart of one managed validator: abort both handles (a no-op if a
/// crash already took them), wait `downtime`, re-register its three channels
/// (which overwrites the node's mailboxes and disconnects the dead
/// incarnation's receivers), and rebuild engine + application on the SAME
/// storage partition with the RETAINED reporter, so the engine replays its
/// journal and catches up via resolver backfill. This is
/// `mallory::runner::restart` minus the packet-pump / sniffer / dispatch
/// re-wrap, which chaos does not install.
#[allow(clippy::too_many_arguments)]
async fn restart_durable<P: Simplex>(
    mv: &mut ManagedValidator<P>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    input: &crate::FuzzInput,
    downtime: Duration,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    lifecycle::abort_tasks(mv).await;
    if !downtime.is_zero() {
        context.sleep(downtime).await;
    }

    let validator = mv.validator().clone();
    let mut fresh = crate::utils::register(oracle, std::slice::from_ref(&validator)).await;
    let (pending, recovered, resolver) = fresh
        .remove(&validator)
        .expect("chaos harness: re-registration returned no channels");

    let ctx = context
        .child("validator")
        .with_attribute("public_key", &validator);
    let scheme = mv.scheme().clone();
    let rebuilt = build_validator_with_reporter::<P, P::Elector, _, _, _, _, _, _>(
        Some(mv.reporter()),
        ctx,
        oracle,
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
        mv.partition().to_string(),
        pending,
        recovered,
        resolver,
        input.certify,
        input.reporting,
    );
    mv.adopt(rebuilt);
}

/// Enact one schedule action against the cluster.
#[allow(clippy::too_many_arguments)]
async fn enact<P: Simplex>(
    action: Action,
    managed: &mut [ManagedValidator<P>],
    net: &mut Connectivity<PublicKeyOf<P>>,
    context: &deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    input: &crate::FuzzInput,
) where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    match action {
        Action::Kill(i) => lifecycle::crash_stop(&mut managed[i]).await,
        Action::Start(i) => {
            restart_durable(
                &mut managed[i],
                context,
                oracle,
                participants,
                relay,
                input,
                Duration::ZERO,
            )
            .await
        }
        Action::Reload(i) => {
            restart_durable(
                &mut managed[i],
                context,
                oracle,
                participants,
                relay,
                input,
                CHAOS_RESTART_DOWNTIME,
            )
            .await
        }
        Action::Disconnect(i) => net.disconnect(i).await,
        Action::Reconnect(i) => net.reconnect(i).await,
    }
}

/// Snapshot the cluster for the checker: the clock's per-node frontiers, the
/// highest view with any recorded vote/certificate activity, and each
/// reporter's finalized `(view, digest)` pairs (sorted, so a multi-violation
/// observation trips deterministically).
fn snapshot_poll<P: Simplex>(
    clock: &FinalizationClock,
    reporters: &[ChaosReporter<P>],
) -> watch::Poll {
    let mut activity_frontier = 0u64;
    let mut finalized = Vec::with_capacity(reporters.len());
    for reporter in reporters {
        for view in reporter.notarizes.lock().keys() {
            activity_frontier = activity_frontier.max(view.get());
        }
        for view in reporter.nullifies.lock().keys() {
            activity_frontier = activity_frontier.max(view.get());
        }
        for view in reporter.finalizes.lock().keys() {
            activity_frontier = activity_frontier.max(view.get());
        }
        for view in reporter.notarizations.lock().keys() {
            activity_frontier = activity_frontier.max(view.get());
        }
        for view in reporter.nullifications.lock().keys() {
            activity_frontier = activity_frontier.max(view.get());
        }
        let mut entries: Vec<(u64, Sha256Digest)> = reporter
            .finalizations
            .lock()
            .iter()
            .map(|(view, certificate)| (view.get(), certificate.proposal.payload))
            .collect();
        entries.sort_unstable_by_key(|(view, _)| *view);
        if let Some((view, _)) = entries.last() {
            activity_frontier = activity_frontier.max(*view);
        }
        finalized.push(entries);
    }
    watch::Poll {
        latest_views: clock.latest.clone(),
        activity_frontier,
        finalized,
    }
}

/// Publish the schedule's current beliefs, timestamping the moment the
/// liveness expectation last flipped (the settle margin and the liveness
/// window both count from that moment).
fn publish_expectations(
    expectations: &mut watch::Expectations,
    schedule: &Schedule,
    now: SystemTime,
) {
    let expect_liveness = schedule.expect_liveness();
    if expect_liveness != expectations.expect_liveness {
        expectations.since = now;
    }
    expectations.expect_liveness = expect_liveness;
    expectations.conditions = schedule.conditions();
}

/// Run one chaos episode. The deterministic runtime is seeded from
/// `FuzzRng::new(input.raw_bytes)`, chaos's only entropy; there is no
/// cross-input state of any kind, so replaying a saved input reproduces the
/// run exactly.
pub(crate) fn run<P: Simplex>(input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    let steps = CHAOS_EPISODE_STEPS.max(input.required_containers as usize);
    run_with::<P>(input, steps);
}

/// [`run`] with an explicit hard step cap. Production derives the cap from
/// `required_containers`; the ignored integration tests pass a short count so a
/// full deterministic episode finishes in seconds while exercising the same
/// code paths.
fn run_with<P: Simplex>(mut input: crate::FuzzInput, steps: usize)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Four honest validators, fully connected at setup, every node certifying:
    // the schedule owns every fault, and certify slack is mandatory because a
    // sampled non-certifier plus one killed node would be a guaranteed stall.
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;
    input.certify = CertifyChoice::Always;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        // `oracle` and `participants` are retained: restarts re-register
        // channels through the oracle and rebuild engines over the participant
        // set. The connectivity controller gets its own oracle clone.
        let (mut oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;
        crate::print_fuzz_input(crate::Mode::Chaos, &input);

        let n = input.configuration.n as usize;
        let quorum = bounds::quorum(input.configuration.n) as usize;
        let required_containers = input.required_containers;
        let relay = Arc::new(relay::Relay::new());

        let mut managed: Vec<ManagedValidator<P>> = Vec::with_capacity(n);
        for i in 0..n {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            managed.push(build_validator::<P, _, _, _, _, _, _, _>(
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
                pending,
                recovered,
                resolver,
                input.certify,
                input.reporting,
            ));
        }

        let mut net = Connectivity::new(
            oracle.clone(),
            participants.clone(),
            crate::default_link(),
        );
        let mut reporters: Vec<ChaosReporter<P>> = managed.iter().map(|m| m.reporter()).collect();

        // Persistent finalization clock: subscribe ONCE per reporter and keep
        // the monitors so each step drains them synchronously. A durable
        // restart reuses its reporter, so its monitor keeps delivering.
        let mut clock = FinalizationClock {
            latest: vec![0u64; n],
            monitors: Vec::with_capacity(n),
        };
        for (node, managed_validator) in managed.iter().enumerate() {
            let (latest, monitor): (View, ViewReceiver<View>) =
                managed_validator.reporter().subscribe().await;
            clock.latest[node] = latest.get();
            clock.monitors.push((node, monitor));
        }

        let mut schedule = Schedule::new(n, quorum);
        let mut checker = Checker::new(
            n,
            context.current(),
            CHAOS_SETTLE_MARGIN,
            CHAOS_LIVENESS_WINDOW,
        );
        let mut expectations = watch::Expectations {
            conditions: schedule.conditions(),
            expect_liveness: schedule.expect_liveness(),
            since: context.current(),
        };

        let finalization_budget = required_containers as usize;
        let mut observed_finalizations: HashSet<u64> = HashSet::new();
        let mut step = 0usize;
        loop {
            step += 1;

            // (a) Authoritative pre-enact cut, observed under the PREVIOUS
            // step's expectations: a violation that landed before this step's
            // action is judged against the world that produced it, so a heal
            // can never clear a frozen baseline it should have tripped.
            clock.drain();
            let poll = snapshot_poll::<P>(&clock, &reporters);
            log::push(format!(
                "observe pre step={step} now={:?} since={:?} expect={} views={:?} frontier={} {}",
                context.current(),
                expectations.since,
                expectations.expect_liveness,
                poll.latest_views,
                poll.activity_frontier,
                checker.debug_state(),
            ));
            checker.observe(context.current(), &expectations, &poll);

            // (b) Decide, then jitter so the enactment is not phase-locked to
            // the step boundary that woke us.
            let action = schedule.next_action(&mut context);
            let jitter = Duration::from_millis(context.random_range(0..=CHAOS_JITTER_MS));
            context.sleep(jitter).await;

            // (c) Faults publish expectations first and then land; heals land
            // first and then publish.
            let heals = action.is_heal();
            if !heals {
                publish_expectations(&mut expectations, &schedule, context.current());
            }
            enact(
                action,
                &mut managed,
                &mut net,
                &context,
                &mut oracle,
                &participants,
                &relay,
                &input,
            )
            .await;
            if heals {
                publish_expectations(&mut expectations, &schedule, context.current());
            }

            log::push(format!(
                "step={step} action={action:?} conditions={:?} live={}/{n} expect_liveness={}",
                expectations.conditions,
                schedule.live_count(),
                expectations.expect_liveness,
            ));

            // (d) The live set comes from POST-action conditions, and the
            // baseline is the pre-enact cut restricted to it, so a just-killed
            // node's stale events and a just-restarted node's replayed events
            // can never close the step.
            let live: HashSet<usize> = expectations
                .conditions
                .iter()
                .enumerate()
                .filter(|(_, condition)| **condition == Condition::Healthy)
                .map(|(index, _)| index)
                .collect();
            let baseline = clock.baseline(&live);
            let deadline = context.current() + CHAOS_STEP_TIMEOUT;
            let boundary =
                wait_for_step_boundary(&mut context, &mut clock, &live, baseline, deadline).await;

            // (e) Post-boundary observation under the current expectations.
            let poll = snapshot_poll::<P>(&clock, &reporters);
            log::push(format!(
                "observe post step={step} boundary={boundary:?} now={:?} since={:?} expect={} views={:?} frontier={} {}",
                context.current(),
                expectations.since,
                expectations.expect_liveness,
                poll.latest_views,
                poll.activity_frontier,
                checker.debug_state(),
            ));
            checker.observe(context.current(), &expectations, &poll);

            // The `invariants` safety oracle runs ONLINE at every step
            // boundary (and again at episode end): the committee is honest,
            // so a violation is a finding the moment it appears, attributed
            // to the step that produced it.
            for reporter in &reporters {
                reporter.assert_no_faults();
            }
            invariants::check_no_invalid_reports(&reporters);
            invariants::check_vote_invariants_with_byzantine(&HashSet::new(), &reporters);
            let states = invariants::extract(reporters.clone(), n);
            invariants::check::<P>(input.configuration.n, states);

            if let StepBoundary::Finalized { view, .. } = boundary {
                observed_finalizations.insert(view);
            }
            if observed_finalizations.len() >= finalization_budget || step >= steps {
                break;
            }
        }

        // Episode end: heal everything so the liveness oracle runs over the
        // whole committee (heals land, then publish).
        for heal in schedule.heal_everything() {
            enact(
                heal,
                &mut managed,
                &mut net,
                &context,
                &mut oracle,
                &participants,
                &relay,
                &input,
            )
            .await;
        }
        publish_expectations(&mut expectations, &schedule, context.current());

        // Post-heal liveness over ALL FOUR nodes: every node must finalize one
        // view past the highest pre-heal frontier (proving it caught up after
        // the last fault/heal/restart), never below `required_containers`.
        let mut watch_targets: Vec<(usize, u64)> = Vec::with_capacity(n);
        let mut watcher_inputs = Vec::with_capacity(n);
        for (node, reporter) in reporters.iter_mut().enumerate() {
            let (latest, monitor): (View, ViewReceiver<View>) = reporter.subscribe().await;
            watch_targets.push((node, latest.get()));
            watcher_inputs.push((node, latest, monitor));
        }
        let max_baseline = watch_targets
            .iter()
            .map(|&(_, baseline)| baseline)
            .max()
            .unwrap_or(0);
        let target = liveness_target(required_containers, max_baseline);
        let mut watchers = Vec::with_capacity(watcher_inputs.len());
        for (node, mut latest, mut monitor) in watcher_inputs {
            watchers.push(
                context
                    .child("chaos_liveness_watcher")
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
            for &(node, baseline) in &watch_targets {
                let (latest, _): (View, ViewReceiver<View>) = reporters[node].subscribe().await;
                let _ = write!(
                    diag,
                    " node{node}={{baseline={baseline} current={}}}",
                    latest.get()
                );
            }
            panic!(
                "chaos: no post-episode liveness within {POST_GST_WINDOW:?} (target={target} required_containers={required_containers} max_baseline={max_baseline});{diag}"
            );
        }

        // Final synchronous observation (digest stability and agreement over
        // anything that landed during catch-up), then the safety invariants
        // over the honest reporters. The Byzantine set is EMPTY: every node is
        // honest and restarts are durable, so any equivocation, packaged fault
        // evidence, or invalid report is a finding.
        clock.drain();
        let poll = snapshot_poll::<P>(&clock, &reporters);
        log::push(format!(
            "observe final now={:?} since={:?} expect={} views={:?} frontier={} {}",
            context.current(),
            expectations.since,
            expectations.expect_liveness,
            poll.latest_views,
            poll.activity_frontier,
            checker.debug_state(),
        ));
        checker.observe(context.current(), &expectations, &poll);

        for reporter in &reporters {
            reporter.assert_no_faults();
        }
        invariants::check_no_invalid_reports(&reporters);
        invariants::check_vote_invariants_with_byzantine(&HashSet::new(), &reporters);
        let states = invariants::extract(reporters, n);
        invariants::check::<P>(input.configuration.n, states);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FuzzInput, ReporterWiring, simplex::SimplexId, strategy::StrategyChoice};
    use commonware_consensus::simplex::ForwardingPolicy;
    use std::num::NonZeroUsize;

    /// Episode length the ignored integration tests run: short (versus the
    /// production cap) so a full deterministic episode, runtime, schedule,
    /// healing, liveness, and invariants, finishes in seconds.
    const TEST_STEPS: usize = 3;

    fn chaos_input(seed: u64) -> FuzzInput {
        let mut raw_bytes = seed.to_le_bytes().to_vec();
        raw_bytes.extend_from_slice(&[0xc7u8; 96]);
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

    /// A full deterministic episode across several seeds: schedule, enactment
    /// (kills, restarts, link surgery), the online checker, episode-end
    /// healing, liveness, and invariants. Ignored: runs whole episodes.
    #[test]
    #[ignore]
    fn short_episodes_complete() {
        for seed in [7u64, 21, 42] {
            run_with::<SimplexId>(chaos_input(seed), TEST_STEPS);
            let _ = log::take();
        }
    }

    /// Same input bytes, same decision log: the episode is a pure function of
    /// the input (no campaign or cross-input state). Ignored: runs episodes.
    #[test]
    #[ignore]
    fn replay_is_exact() {
        run_with::<SimplexId>(chaos_input(11), TEST_STEPS);
        let first = log::take();
        assert!(!first.is_empty(), "an episode must record its decisions");
        run_with::<SimplexId>(chaos_input(11), TEST_STEPS);
        let second = log::take();
        assert_eq!(
            first, second,
            "replaying identical bytes must reproduce the schedule"
        );
    }
}
