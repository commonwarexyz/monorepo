//! The chaos episode loop: an all-honest committee under a fuzzer-driven
//! crash/network fault schedule.
//!
//! Each step draws one [`Action`] from the pure [`Schedule`], sleeps an
//! RNG-drawn jitter (so faults are not phase-locked to finalization
//! boundaries), enacts it, then waits for a finalization past the step baseline
//! or a deterministic timeout (pure pacing; a timeout is a normal outcome). The
//! `crate::invariants` suite, the audit-history invariants over the recording
//! reporters' lossless event logs plus the summary-map checks and the
//! finalized-payload-uniqueness check, runs at every step boundary with zero
//! Byzantine nodes. When the input's
//! finalization budget or the step cap is reached, the loop stops drawing
//! faults and a finishing phase drains every pending heal through the same
//! paced, safety-checked path, so a recovery the last drawn fault scheduled
//! (whose due step the budget cut short) still exercises restart / journal
//! replay / reconnection safety. A final fixed-window settle then lets any
//! still-runnable recovery work emit before a last safety check, since a paced
//! step returns on the first post-heal finalization and can beat replay /
//! backfill. Chaos asserts no liveness.
//!
//! Kill is `mallory::lifecycle::crash_stop`; Start/Reload are durable restarts
//! (same partition, retained reporter, journal replay); Disconnect/Reconnect
//! are surgical per-edge link changes, so the harness never drops in-flight
//! traffic between healthy quorum members. A failed harness operation panics
//! with wording distinct from `chaos:` oracle findings.

use super::{
    log,
    schedule::{Action, Condition, Schedule},
    watch::Checker,
};
use crate::{
    CertifyChoice, ManagedValidator, N4F0C4, PublicKeyOf, bounds, build_validator_with_reporter,
    invariants,
    mallory::{
        lifecycle,
        runner::{FinalizationClock, StepBoundary, wait_for_step_boundary},
    },
    simplex::Simplex,
    simplex_audit::{RecordingReporter, summaries},
    utils::Partition,
};
use commonware_consensus::{
    Monitor as _,
    simplex::mocks::{relay, reporter::Reporter},
    types::{Epoch, TermLength, View},
};
use commonware_cryptography::{
    PublicKey, certificate::Verifier as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::{Error as SimError, Link, Oracle};
use commonware_runtime::{Clock, Runner, Supervisor, deterministic};
use commonware_utils::{FuzzRng, channel::mpsc::Receiver as ViewReceiver};
use rand::RngExt as _;
use std::{collections::HashSet, sync::Arc, time::Duration};

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
/// Upper bound of the RNG-drawn jitter before each enactment, roughly one view
/// time: the fuzzer controls the protocol phase a fault lands in.
const CHAOS_JITTER_MS: u64 = 2_000;
/// Deterministic window run after the last heal, before the final safety
/// check, so recovery work still runnable after a benign post-heal
/// finalization gets to emit any conflicting or invalid activity before the
/// root future returns. Journal replay is local and finishing-phase restarts
/// use zero downtime, so that activity emerges early; one step timeout is
/// enough, and a larger window would simulate whole extra views of consensus
/// per fuzz iteration for no added coverage. An ordinary observation boundary,
/// never a liveness assertion.
const CHAOS_FINISH_SETTLE: Duration = CHAOS_STEP_TIMEOUT;

/// The recording reporter the runner snapshots for the safety checker.
type ChaosReporter<P> = RecordingReporter<
    deterministic::Context,
    <P as Simplex>::Scheme,
    <P as Simplex>::Elector,
    Sha256Digest,
>;

/// The inner mock summary view the summary-map invariant calls read.
type ChaosSummary<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// The managed-validator instantiation chaos drives: the shared harness with
/// the recording reporter in place of the mock.
type ChaosValidator<P> = ManagedValidator<P, ChaosReporter<P>>;

/// Surgical connectivity controller: touches only the edges adjacent to the
/// node whose state changes. A full-topology reset (`apply_partition`) would
/// drop in-flight traffic between healthy quorum members, which is only
/// repaired by the engines' 10s retry.
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

    /// Remove both directed edges between `node` and each currently-connected
    /// peer, then mark it disconnected. Already-disconnected peers hold no edge
    /// to `node` and are skipped; the state is updated only after every removal
    /// lands, so a harness failure cannot leave a "disconnected" node still
    /// linked.
    async fn disconnect(&mut self, node: usize) {
        if self.disconnected[node] {
            return;
        }
        for peer in 0..self.participants.len() {
            if peer == node || self.disconnected[peer] {
                continue;
            }
            self.remove_edge(node, peer).await;
            self.remove_edge(peer, node).await;
        }
        self.disconnected[node] = true;
    }

    /// Restore both directed edges between `node` and each currently-connected
    /// peer, then mark it connected. The state is updated only after every add
    /// lands.
    async fn reconnect(&mut self, node: usize) {
        if !self.disconnected[node] {
            return;
        }
        for peer in 0..self.participants.len() {
            if peer == node || self.disconnected[peer] {
                continue;
            }
            self.add_edge(node, peer).await;
            self.add_edge(peer, node).await;
        }
        self.disconnected[node] = false;
    }

    /// Remove one directed edge. A live edge removes cleanly; `LinkMissing`
    /// (already absent) is the only tolerated error. Anything else
    /// (`NetworkClosed`, `PeerMissing`, ...) is a harness failure and panics,
    /// so a failed injection is never mistaken for a successful run.
    async fn remove_edge(&self, from: usize, to: usize) {
        match self
            .oracle
            .remove_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
            )
            .await
        {
            Ok(()) | Err(SimError::LinkMissing) => {}
            Err(error) => {
                panic!("chaos harness: remove_link failed for {from}->{to}: {error}")
            }
        }
    }

    /// Add one directed edge. An absent edge adds cleanly; `LinkExists`
    /// (already present) is the only tolerated error. Anything else panics.
    async fn add_edge(&self, from: usize, to: usize) {
        match self
            .oracle
            .add_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
                self.link.clone(),
            )
            .await
        {
            Ok(()) | Err(SimError::LinkExists) => {}
            Err(error) => panic!("chaos harness: add_link failed for {from}->{to}: {error}"),
        }
    }
}

/// Durable restart: abort both handles (no-op after a crash), wait `downtime`,
/// re-register (overwriting mailboxes disconnects the dead incarnation), and
/// rebuild on the SAME partition with the RETAINED reporter, so the engine
/// replays its journal and backfills. `mallory::runner::restart` minus the
/// pump/sniffer/dispatch re-wrap chaos does not install.
#[allow(clippy::too_many_arguments)]
async fn restart_durable<P: Simplex>(
    mv: &mut ChaosValidator<P>,
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
    let rebuilt = build_validator_with_reporter::<P, P::Elector, _, _, _, _, _, _, _>(
        Some(mv.reporter()),
        ctx,
        oracle,
        participants,
        scheme,
        validator,
        P::elector(P::effective_term_length(input.term_length)),
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
    // Stamp the retained audit log so post-restart events carry the new
    // incarnation.
    mv.reporter().set_generation(mv.generation());
}

#[allow(clippy::too_many_arguments)]
async fn enact<P: Simplex>(
    action: Action,
    managed: &mut [ChaosValidator<P>],
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
        Action::Wait => {}
    }
}

/// Every finalize-voted `(view, payload)` from the reporters' append-only
/// `finalizes` maps (so a conflict landing between two polls is never lost).
fn finalize_votes<P: Simplex>(reporters: &[ChaosSummary<P>]) -> Vec<(u64, Sha256Digest)> {
    let mut votes = Vec::new();
    for reporter in reporters {
        for (view, by_payload) in reporter.finalizes.lock().iter() {
            for payload in by_payload.keys() {
                votes.push((view.get(), *payload));
            }
        }
    }
    votes
}

/// Run the full safety suite over the honest reporters. The Byzantine set is
/// EMPTY: every node is honest and restarts are durable, so any conflicting
/// finalization, equivocation, fault evidence, or invalid report is a finding.
fn check_safety<P: Simplex>(
    checker: &mut Checker,
    reporters: &[ChaosReporter<P>],
    term_length: TermLength,
) {
    // Audit-history invariants plus the basic replica-state suite over the
    // lossless per-node event logs. The logs live in the retained reporters,
    // so they hold at every step boundary, including while a node is down.
    invariants::check::<P>(term_length, reporters);

    // Summary-map checks over the inner mock reporters. `summaries` also
    // asserts each log's append order and generation monotonicity.
    let summaries = summaries(reporters);
    // The finalize-vote uniqueness check reads the append-only `finalizes` map.
    // The harness reports individual finalize votes to the reporter directly
    // (no `AttributableReporter` wrapper), so this map is populated for every
    // scheme, attributable or not, and a conflict landing between polls is not
    // lost. On a healthy committee a view holds one payload, so this never
    // false-positives.
    checker.observe(&finalize_votes::<P>(&summaries));
    for reporter in &summaries {
        reporter.assert_no_faults();
    }
    invariants::check_no_invalid_reports(&summaries);
    invariants::check_vote_invariants(
        0,
        P::elector(term_length),
        Epoch::new(crate::EPOCH),
        term_length,
        &summaries,
    );
}

/// Enact one action, then wait a bounded observation window (a finalization
/// past the step baseline over the live set, or a deterministic timeout, which
/// is normal pacing, never a finding), then run the safety suite. Shared by the
/// fault loop and the heal-draining finishing phase, so every enacted action,
/// including a recovery drawn after the episode budget ended, gets a runtime
/// window before it is safety-checked.
#[allow(clippy::too_many_arguments)]
async fn paced_enact<P: Simplex>(
    action: Action,
    managed: &mut [ChaosValidator<P>],
    net: &mut Connectivity<PublicKeyOf<P>>,
    context: &mut deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    relay: &Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    input: &crate::FuzzInput,
    clock: &mut FinalizationClock,
    conditions: &[Condition],
    checker: &mut Checker,
    reporters: &[ChaosReporter<P>],
) -> StepBoundary
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    enact(
        action,
        managed,
        net,
        context,
        oracle,
        participants,
        relay,
        input,
    )
    .await;

    // The live set is the current healthy nodes, over a fresh drain, so a
    // just-killed node's stale events cannot close the step.
    clock.drain();
    let live: HashSet<usize> = conditions
        .iter()
        .enumerate()
        .filter(|(_, condition)| **condition == Condition::Healthy)
        .map(|(index, _)| index)
        .collect();
    let baseline = clock.baseline(&live);
    let deadline = context.current() + CHAOS_STEP_TIMEOUT;
    let boundary = wait_for_step_boundary(context, clock, &live, baseline, deadline).await;

    check_safety::<P>(
        checker,
        reporters,
        P::effective_term_length(input.term_length),
    );
    boundary
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
        // `oracle` and `participants` are retained: restarts re-register and
        // rebuild through them; the connectivity controller gets its own clone.
        let (mut oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;
        crate::print_fuzz_input::<P>(crate::Mode::Chaos, &input);

        let n = input.configuration.n as usize;
        let quorum = bounds::quorum(input.configuration.n) as usize;
        let required_containers = input.required_containers;
        let term_length = P::effective_term_length(input.term_length);
        let relay = Arc::new(relay::Relay::new());

        let mut managed: Vec<ChaosValidator<P>> = Vec::with_capacity(n);
        for i in 0..n {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let partition = validator.to_string();
            managed.push(build_validator_with_reporter::<P, _, _, _, _, _, _, _, _>(
                None,
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                P::elector(term_length),
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
            ));
        }

        let mut net =
            Connectivity::new(oracle.clone(), participants.clone(), crate::default_link());
        let reporters: Vec<ChaosReporter<P>> = managed.iter().map(|m| m.reporter()).collect();

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
        let mut checker = Checker::new();

        let finalization_budget = required_containers as usize;
        let mut observed_finalizations: HashSet<u64> = HashSet::new();
        let mut step = 0usize;
        loop {
            step += 1;

            let action = schedule.next_action(&mut context);
            let jitter = Duration::from_millis(context.random_range(0..=CHAOS_JITTER_MS));
            context.sleep(jitter).await;

            log::push(format!(
                "step={step} action={action:?} conditions={:?} live={}/{n}",
                schedule.conditions(),
                schedule.live_count(),
            ));

            let boundary = paced_enact::<P>(
                action,
                &mut managed,
                &mut net,
                &mut context,
                &mut oracle,
                &participants,
                &relay,
                &input,
                &mut clock,
                &schedule.conditions(),
                &mut checker,
                &reporters,
            )
            .await;

            if let StepBoundary::Finalized { view, .. } = boundary {
                observed_finalizations.insert(view);
            }
            if observed_finalizations.len() >= finalization_budget || step >= steps {
                break;
            }
        }

        // Finishing phase: stop drawing faults and drain every pending heal
        // through the same paced, safety-checked path, so a recovery scheduled
        // by the last drawn fault (whose due step the episode budget cut short)
        // still exercises restart / journal replay / reconnection safety.
        while let Some(heal) = schedule.drain_heal() {
            step += 1;
            log::push(format!(
                "finish step={step} action={heal:?} conditions={:?} live={}/{n}",
                schedule.conditions(),
                schedule.live_count(),
            ));
            paced_enact::<P>(
                heal,
                &mut managed,
                &mut net,
                &mut context,
                &mut oracle,
                &participants,
                &relay,
                &input,
                &mut clock,
                &schedule.conditions(),
                &mut checker,
                &reporters,
            )
            .await;
        }

        // Terminal settle: a paced step returns on the FIRST post-heal
        // finalization, which can beat the just-restarted node's replay and
        // backfill. Run a fixed deterministic window so all still-runnable
        // recovery work executes, then check safety once more, so a conflicting
        // or invalid activity emitted during that catch-up is not missed by the
        // root future returning first. Not a liveness assertion.
        context.sleep(CHAOS_FINISH_SETTLE).await;
        clock.drain();
        check_safety::<P>(&mut checker, &reporters, term_length);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "mocks")]
    use crate::simplex::SimplexCertificateMock;
    use crate::{FuzzInput, ReporterWiring, simplex::SimplexId, strategy::StrategyChoice};
    use commonware_consensus::simplex::ForwardingPolicy;
    use std::num::NonZeroUsize;

    /// Episode length the ignored integration tests run: short (versus the
    /// production cap) so a full deterministic episode, runtime, schedule, and
    /// safety checks, finishes in seconds.
    const TEST_STEPS: usize = 3;

    fn chaos_input(seed: u64) -> FuzzInput {
        let mut raw_bytes = seed.to_le_bytes().to_vec();
        raw_bytes.extend_from_slice(&[0xc7u8; 96]);
        FuzzInput {
            raw_bytes,
            required_containers: 2,
            degraded_network: false,
            configuration: N4F0C4,
            term_length: TermLength::ONE,
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

    /// Full deterministic episodes across several seeds, then a byte-exact
    /// replay check (chaos has no cross-input state). One test, not two: the
    /// decision log is process-global, so concurrent test threads would
    /// interleave their trails.
    #[test]
    #[ignore]
    fn episodes_complete_and_replay_exactly() {
        for seed in [7u64, 21, 42] {
            run_with::<SimplexId>(chaos_input(seed), TEST_STEPS);
            let _ = log::take();
        }
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

    /// The certificate-mock backend runs the full oracle (shared invariant
    /// suite, finalized-payload uniqueness, all lifecycle/network coverage);
    /// a full episode must complete.
    #[cfg(feature = "mocks")]
    #[test]
    #[ignore]
    fn cert_mock_episode_completes() {
        for seed in [3u64, 19, 55] {
            run_with::<SimplexCertificateMock>(chaos_input(seed), TEST_STEPS);
            let _ = log::take();
        }
    }
}
