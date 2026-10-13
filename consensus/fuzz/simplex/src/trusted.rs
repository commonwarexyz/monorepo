//! Trusted entries for target-state scaffolds: the base targets' drivers with a
//! prefix hook (see [commonware_consensus_fuzz_core::continuation]).
//!
//! A scaffold's thin target calls the entry of its base with the generated
//! [Prefix] and the trusted [Observer]. The base driver owns everything the
//! prefix does not: it starts the network and the honest engines behind the
//! runner's taps, runs the prefix, performs the release, starts the base's
//! actors for the compromised identity, and runs its own fault scheduler and
//! safety oracles in the same runtime. A continuation checks safety only: the
//! base runs for its fixed window instead of waiting for progress. The
//! view-indexed faults of the base (an adaptive partition schedule, a dropped
//! block, the Disrupter's faulty views) are re-based on the highest view
//! finalized at the release.

use crate::{
    Coverage, FuzzMode, TwinsRole, configure_block_filter, run, run_audited_standard_once_with,
    run_twins,
};
use commonware_consensus::types::View;
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, FuzzInput, Mode, PublicKeyOf, block_relay,
    continuation::{self, Hook, Observer, Prefix, Role, Runner, Topology},
    default_link, print_fuzz_input, scheduled_partition, simplex,
    utils::{Partition, SetPartition, apply_partition},
};
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Supervisor as _, deterministic};
use std::{panic, sync::Arc};

/// [crate::fuzz] for a Standard, FaultyNet, TwinsMutator or TwinsCampaign base,
/// with `prefix` building the target state and `observer` watching. Panics for
/// another mode: its driver has no hook point.
pub fn fuzz_with_prefix<P, M, C, X, O>(mut input: FuzzInput, prefix: X, observer: O)
where
    P: simplex::Simplex,
    M: FuzzMode,
    C: Coverage,
    X: Prefix<P>,
    O: Observer,
{
    assert!(
        matches!(
            M::MODE,
            Mode::Standard | Mode::FaultyNet | Mode::TwinsMutator | Mode::TwinsCampaign
        ),
        "the {:?} driver has no trusted continuation",
        M::MODE
    );
    let twins = matches!(M::MODE, Mode::TwinsMutator | Mode::TwinsCampaign);
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = Hook::plan(Box::new(prefix), observer.clone(), &mut input, twins);
    if matches!(M::MODE, Mode::FaultyNet) {
        input.partition = Partition::Adaptive(Vec::new());
    }
    if !twins {
        print_fuzz_input::<P>(M::MODE, &input);
    }
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| match M::MODE {
        Mode::TwinsMutator => {
            let _ = run_twins::<P>(
                input,
                TwinsRole::Mutator,
                C::STATE,
                C::HAPPENS_BEFORE,
                false,
                Some(hook),
            );
        }
        Mode::TwinsCampaign => {
            let _ = run_twins::<P>(
                input,
                TwinsRole::Campaign,
                C::STATE,
                C::HAPPENS_BEFORE,
                false,
                Some(hook),
            );
        }
        _ => run::<P>(input, C::STATE, C::HAPPENS_BEFORE, Some(hook)),
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [crate::fuzz_audit] with a prefix. Rejected certification is not sampled: its
/// view is an early absolute view the prefix would pass.
pub fn fuzz_audit_with_prefix<P, X, O>(mut input: FuzzInput, prefix: X, observer: O)
where
    P: simplex::Simplex,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = Hook::plan(Box::new(prefix), observer.clone(), &mut input, false);
    print_fuzz_input::<P>(Mode::Standard, &input);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_audited_standard_once_with::<P>(input, None, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [crate::fuzz_twins_audit] with a prefix.
pub fn fuzz_twins_audit_with_prefix<P, M, X, O>(input: FuzzInput, prefix: X, observer: O)
where
    P: simplex::Simplex,
    M: FuzzMode,
    X: Prefix<P>,
    O: Observer,
{
    let role = match M::MODE {
        Mode::TwinsMutator => TwinsRole::Mutator,
        Mode::TwinsCampaign => TwinsRole::Campaign,
        mode => panic!("fuzz_twins_audit_with_prefix requires a Twins mode, got {mode:?}"),
    };
    let mut input = input;
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = Hook::plan(Box::new(prefix), observer.clone(), &mut input, true);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_twins::<P>(input, role, false, false, true, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// Rethrows a run's panic as the base entries do, or reports the end of the run.
fn finish(result: std::thread::Result<()>, raw_bytes: Vec<u8>, observer: &dyn Observer) {
    if let Err(payload) = result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes);
        panic::resume_unwind(payload);
    }
    observer.done();
}

/// Starts the runner of a Standard driver after its network exists and before any
/// engine starts: participant 0 is B when the configuration has a fault, and the
/// base starts a Disrupter for it.
pub(crate) fn start_standard<P: simplex::Simplex>(
    hook: Hook<P>,
    context: &deterministic::Context,
    input: &FuzzInput,
    participants: &[PublicKeyOf<P>],
    schemes: &[P::Scheme],
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    relay: &Arc<block_relay::Relay<PublicKeyOf<P>>>,
) -> Runner<P> {
    let byzantine = (input.configuration.faults > 0).then_some(0);
    let term_length = P::effective_term_length(input.term_length);
    let links = input.clone();
    let n = participants.len();
    Runner::start(
        hook,
        context,
        Topology {
            participants: participants.to_vec(),
            schemes: schemes.to_vec(),
            byzantine,
            required: vec![Role::Disrupter],
            term_length,
            optimistic_views: input.optimistic_views,
            scripted_views: 0,
            relay: relay.clone(),
            oracle: oracle.clone(),
            base_link: Box::new(move |from, to| continuation::standard_link(&links, n, from, to)),
        },
        P::elector(term_length, input.optimistic_views),
    )
}

/// The release of a Standard driver: runs the prefix and the release, re-bases the
/// base's view-indexed faults on the highest view finalized by then, applies the
/// network faults the base applies at its start, and starts B's Disrupter. Returns
/// the re-base and the partition the fault scheduler starts from.
pub(crate) async fn release_standard<P: simplex::Simplex>(
    runner: &mut Runner<P>,
    context: &deterministic::Context,
    input: &mut FuzzInput,
    participants: &[PublicKeyOf<P>],
    schemes: &[P::Scheme],
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    relay: &Arc<block_relay::Relay<PublicKeyOf<P>>>,
) -> (u64, Option<SetPartition>) {
    let (channels, release) = runner.run().await;
    let base = release.base;
    rebase(input, base);
    let initial = input
        .partition
        .schedule()
        .and_then(|schedule| scheduled_partition(schedule, base + 1));
    if initial.is_some() {
        apply_partition(oracle, participants, initial.as_ref(), &default_link()).await;
    }
    configure_block_filter::<P>(relay, participants, &input.partition, input.block_filter);
    if let (Some(channels), Some(index)) = (channels, runner.byzantine()) {
        let ctx = context
            .child("validator")
            .with_attribute("public_key", &participants[index])
            .child("disrupter");
        let registry = runner.registry();
        let handle = continuation::start_disrupter::<P>(
            ctx,
            schemes[index].clone(),
            &input.strategy,
            input.required_containers,
            channels,
            Some(relay.clone()),
            base,
            registry.marker(index, Role::Disrupter),
        );
        registry.register(index, Role::Disrupter, handle);
    }
    runner.check_release().await;
    (base, initial)
}

/// Moves the base's view-indexed faults `base` views later.
fn rebase(input: &mut FuzzInput, base: u64) {
    if let Partition::Adaptive(schedule) = &mut input.partition {
        for (view, _) in schedule.iter_mut() {
            *view = View::new(view.get().saturating_add(base));
        }
    }
    if let BlockFilterChoice::DropRecipient { view, .. } = &mut input.block_filter {
        *view = View::new(view.get().saturating_add(base));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CodeCoverage, HappensBeforeCoverage, MockTwinsBackend, Standard, TwinsCampaign,
        TwinsMutator, run_standard_once,
    };
    use commonware_consensus::{
        Handoff, Viewable,
        simplex::{ForwardPolicy, types::Activity},
        types::{Epoch, Round, TermLength, ViewDelta},
    };
    use commonware_consensus_fuzz_core::{
        CertifyChoice, Configuration, DEFAULT_MAILBOX_SIZE, EPOCH, FAULT_PHASE, N4F0C4, N4F1C3,
        ReporterWiring, SimplexCertificateMock, bounded_fuzz_runtime_config, byzantine,
        continuation::{
            ActorCheck, ActorState, Budget, Channel, LOG_CAP, Latencies, MAX_PREFIX_BUDGET, Pins,
            PrefixContext, PrefixFuture, Release,
        },
        disrupter, run_twins_with_backend, run_twins_with_backend_and_hook,
        strategy::StrategyChoice,
        twins_prefix_views,
    };
    use commonware_runtime::Runner as _;
    use commonware_utils::sync::Mutex;
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        time::Duration,
    };

    /// What a test observer saw.
    #[derive(Default)]
    struct Seen {
        compromised: Vec<Vec<usize>>,
        checks: Vec<ActorCheck>,
        releases: Vec<Release>,
        dropped: Vec<u64>,
        done: bool,
    }

    #[derive(Clone, Default)]
    struct Watch {
        seen: Arc<Mutex<Seen>>,
        position: Arc<AtomicU64>,
    }

    impl Observer for Watch {
        fn position(&self) -> (u64, u32) {
            (self.position.fetch_add(1, Ordering::Relaxed) + 1, 1)
        }

        fn compromised(&self, identities: &[usize]) {
            self.seen.lock().compromised.push(identities.to_vec());
        }

        fn actors(&self, check: &ActorCheck) {
            self.seen.lock().checks.push(check.clone());
        }

        fn released(&self, release: &Release) {
            self.seen.lock().releases.push(release.clone());
        }

        fn done(&self) {
            self.seen.lock().done = true;
        }

        fn dropped(&self, seq: u64) {
            self.seen.lock().dropped.push(seq);
        }
    }

    fn input(seed: u64, containers: u64, configuration: Configuration) -> FuzzInput {
        FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            partition: Partition::Connected,
            configuration,
            required_containers: containers,
            term_length: TermLength::ONE,
            optimistic_views: ViewDelta::zero(),
            heterogeneous_optimism: false,
            handoff: Handoff::Wait,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
            mailbox_size: DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardPolicy::Disabled,
            certify: CertifyChoice::Always,
            block_filter: BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    /// A prefix that waits, so the honest replicas make progress before the release.
    struct Idle;

    impl<P: simplex::Simplex> Prefix<P> for Idle {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget {
                prefix: Duration::from_secs(2),
                release: Duration::from_secs(1),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> continuation::PrefixFuture {
            Box::pin(async move { cx.sleep(Duration::from_secs(2)).await })
        }
    }

    /// A prefix that never returns: the runner ends it at its budget.
    struct Overrun;

    impl<P: simplex::Simplex> Prefix<P> for Overrun {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_secs(1),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                loop {
                    cx.sleep(Duration::from_secs(1)).await;
                }
            })
        }
    }

    /// A prefix that changes everything the release must revert: it holds every
    /// message to one honest replica, removes a link, slows an application down and
    /// crashes a replica, then hands off.
    struct Meddle;

    impl<P: simplex::Simplex> Prefix<P> for Meddle {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(10),
                release: Duration::from_secs(2),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let b = cx.byzantine().expect("N4F1C3 has a compromised identity");
                let honest = cx.honest();
                let (r, s, t) = (honest[0], honest[1], honest[2]);
                cx.hold(r, |_| true);
                cx.hold_blocks(r, |_, _| true);
                assert!(cx.set_link(s, t, None).await);
                let slow = (2_000.0, 0.0);
                assert!(cx.set_latency(
                    t,
                    Some(Latencies {
                        propose: slow,
                        verify: slow,
                        certify: slow,
                    })
                ));
                assert!(cx.crash(s).await);
                assert!(cx.crashed(s));
                // B's own channel reaches an honest replica, which records it.
                assert_eq!(cx.send(Channel::Vote, &[t], vec![0u8; 8]), 1);
                cx.sleep(Duration::from_secs(5)).await;
                assert!(
                    cx.deliveries(t)
                        .iter()
                        .any(|entry| entry.value.from == Some(b)),
                    "the honest replica recorded no message from B"
                );
                assert!(!cx.held(r).is_empty(), "the gate held nothing");
                assert!(!cx.inbox().is_empty(), "B received nothing");
                // The capabilities end at the handoff: a leaked clone could do nothing.
            })
        }
    }

    /// A prefix that holds every block to one honest replica and then crashes it: the
    /// release restarts it before it delivers what it held.
    struct HoldThenCrash;

    impl<P: simplex::Simplex> Prefix<P> for HoldThenCrash {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F0C4));
            Budget {
                prefix: Duration::from_secs(10),
                release: Duration::from_secs(1),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let r = cx.honest()[0];
                cx.hold_blocks(r, |_, _| true);
                cx.sleep(Duration::from_secs(5)).await;
                assert!(cx.crash(r).await);
                cx.sleep(Duration::from_secs(1)).await;
            })
        }
    }

    #[test]
    fn blocks_held_for_a_crashed_replica_reach_its_restarted_application() {
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(9, 3, N4F0C4),
            HoldThenCrash,
            watch.clone(),
        );
        let seen = watch.seen.lock();
        let release = &seen.releases[0];
        assert_eq!(release.restarted, vec![0]);
        // Counted by the applications that took them: the restarted one did.
        assert!(release.blocks > 0, "{release:?}");
        assert!(seen.done, "the run did not reach its oracles");
    }

    fn last_two(watch: &Watch) -> (ActorCheck, ActorCheck) {
        let seen = watch.seen.lock();
        assert!(seen.done, "the run did not end");
        let checks = &seen.checks;
        assert_eq!(checks.len(), 2, "{checks:?}");
        (checks[0].clone(), checks[1].clone())
    }

    fn roles(check: &ActorCheck) -> Vec<(Role, ActorState)> {
        check
            .actors
            .iter()
            .map(|actor| (actor.role, actor.state))
            .collect()
    }

    #[test]
    fn standard_continuation_runs_the_disrupter_after_the_release() {
        let watch = Watch::default();
        byzantine::reset();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(1, 3, N4F1C3),
            Idle,
            watch.clone(),
        );
        // The prefix sent nothing as B: every send counted is the Disrupter's.
        assert!(
            byzantine::count(disrupter::ACTOR) > 0,
            "{:?}",
            byzantine::snapshot()
        );
        let (release, end) = last_two(&watch);
        assert_eq!(release.at, "release");
        assert_eq!(end.at, "end");
        for check in [&release, &end] {
            assert!(check.ok(), "{check}");
            assert_eq!(roles(check), vec![(Role::Disrupter, ActorState::Running)]);
            assert_eq!(check.actors[0].identity, 0);
        }
        assert_eq!(watch.seen.lock().compromised, vec![vec![0]]);
        // A prefix that returns at its budget is not ended by the runner.
        assert!(!watch.seen.lock().releases[0].overran);
    }

    #[test]
    fn a_prefix_past_its_budget_is_ended_there() {
        for twins in [false, true] {
            let watch = Watch::default();
            if twins {
                fuzz_with_prefix::<SimplexCertificateMock, TwinsMutator, CodeCoverage, _, _>(
                    input(21, 2, N4F1C3),
                    Overrun,
                    watch.clone(),
                );
            } else {
                fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
                    input(21, 2, N4F1C3),
                    Overrun,
                    watch.clone(),
                );
            }
            let (release, end) = last_two(&watch);
            assert!(release.ok() && end.ok(), "{release} / {end}");
            assert!(watch.seen.lock().releases[0].overran);
        }
    }

    #[test]
    fn a_continuation_checks_safety_without_waiting_for_progress() {
        // The base would wait for more finalizations than the window yields (it
        // finalizes about 140 views): the continuation ends after the window, with
        // every oracle run.
        let target = 1_000;
        let mut input = input(22, target, N4F1C3);
        let watch = Watch::default();
        let observer: Arc<dyn Observer> = Arc::new(watch.clone());
        let hook = Hook::plan(Box::new(Idle), observer, &mut input, false);
        let audit = run_standard_once::<SimplexCertificateMock>(
            input,
            false,
            true,
            false,
            None,
            Some(hook),
        )
        .expect("a valid run is audited");
        let finalized = audit
            .reporter_states
            .values()
            .filter_map(|state| state.finalizations.keys().max().copied())
            .max()
            .unwrap_or(0);
        assert!(
            finalized < target,
            "the window finalized {finalized} views; pick a target it cannot reach"
        );
        let checks = &watch.seen.lock().checks;
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert!(checks.iter().all(ActorCheck::ok), "{checks:?}");
    }

    #[test]
    fn standard_continuation_requires_no_actor_without_a_fault() {
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, HappensBeforeCoverage, _, _>(
            input(2, 2, N4F0C4),
            Idle,
            watch.clone(),
        );
        let (release, end) = last_two(&watch);
        assert!(release.ok() && release.actors.is_empty());
        assert_eq!(end.to_string(), "end ok -");
    }

    #[test]
    fn audited_standard_continuation_runs_the_disrupter() {
        let watch = Watch::default();
        fuzz_audit_with_prefix::<SimplexCertificateMock, _, _>(
            input(3, 3, N4F1C3),
            Idle,
            watch.clone(),
        );
        let (release, end) = last_two(&watch);
        assert!(release.ok() && end.ok(), "{release} / {end}");
        assert_eq!(roles(&end), vec![(Role::Disrupter, ActorState::Running)]);
    }

    #[test]
    fn twins_campaign_continuation_runs_both_twin_engines() {
        let watch = Watch::default();
        byzantine::reset();
        fuzz_with_prefix::<SimplexCertificateMock, TwinsCampaign, CodeCoverage, _, _>(
            input(4, 2, N4F1C3),
            Idle,
            watch.clone(),
        );
        assert!(
            byzantine::count(byzantine::TWIN_SECONDARY) > 0,
            "{:?}",
            byzantine::snapshot()
        );
        let (release, end) = last_two(&watch);
        for check in [&release, &end] {
            assert!(check.ok(), "{check}");
            assert_eq!(
                roles(check),
                vec![
                    (Role::Primary, ActorState::Running),
                    (Role::Secondary, ActorState::Running)
                ]
            );
        }
    }

    #[test]
    fn twins_mutator_continuation_runs_the_primary_and_the_disrupter() {
        let watch = Watch::default();
        byzantine::reset();
        fuzz_with_prefix::<SimplexCertificateMock, TwinsMutator, CodeCoverage, _, _>(
            input(5, 2, N4F1C3),
            Idle,
            watch.clone(),
        );
        assert!(
            byzantine::count(byzantine::TWIN_SECONDARY) > 0,
            "{:?}",
            byzantine::snapshot()
        );
        let (release, end) = last_two(&watch);
        for check in [&release, &end] {
            assert!(check.ok(), "{check}");
            assert_eq!(
                roles(check),
                vec![
                    (Role::Primary, ActorState::Running),
                    (Role::Disrupter, ActorState::Running)
                ]
            );
        }
    }

    #[test]
    fn twins_audit_continuation_runs_the_twin_pair() {
        let watch = Watch::default();
        fuzz_twins_audit_with_prefix::<SimplexCertificateMock, TwinsCampaign, _, _>(
            input(6, 2, N4F1C3),
            Idle,
            watch.clone(),
        );
        let (release, end) = last_two(&watch);
        assert!(release.ok() && end.ok(), "{release} / {end}");
    }

    #[test]
    fn the_release_reverts_every_prefix_change() {
        for (seed, twins) in [(7, false), (8, true)] {
            let watch = Watch::default();
            if twins {
                fuzz_with_prefix::<SimplexCertificateMock, TwinsCampaign, CodeCoverage, _, _>(
                    input(seed, 3, N4F0C4),
                    Meddle,
                    watch.clone(),
                );
            } else {
                fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
                    input(seed, 3, N4F0C4),
                    Meddle,
                    watch.clone(),
                );
            }
            // The release reverted the held replica, the cut link, the slow
            // application and the crashed replica.
            let (release, end) = last_two(&watch);
            assert!(release.ok() && end.ok(), "{release} / {end}");
            let seen = watch.seen.lock();
            let reverted = &seen.releases[0];
            let b = if twins { None } else { Some(0) };
            let honest: Vec<usize> = (0..4).filter(|index| Some(*index) != b).collect();
            let (r, s, t) = if twins {
                // The Twins case picks B; the prefix took the first three others.
                let byzantine = seen.compromised[0][0];
                let others: Vec<usize> = (0..4).filter(|index| *index != byzantine).collect();
                (others[0], others[1], others[2])
            } else {
                (honest[0], honest[1], honest[2])
            };
            assert_eq!(reverted.gates, vec![r]);
            assert!(reverted.delivered > 0);
            assert_eq!(reverted.links, vec![(s, t)]);
            assert_eq!(reverted.latencies, vec![t]);
            assert_eq!(reverted.restarted, vec![s]);
        }
    }

    /// The auditor states of ordinary runs on the harness before the hook point
    /// existed: a driver without a prefix runs exactly what it ran.
    #[test]
    fn ordinary_runs_are_unchanged() {
        let small = StrategyChoice::SmallScope {
            fault_rounds: 2,
            fault_rounds_bound: 3,
        };
        let mut connected = input(7, 3, N4F1C3);
        connected.raw_bytes = 7u64.to_be_bytes().to_vec();
        let mut adaptive = input(9, 3, N4F1C3);
        adaptive.partition = Partition::Adaptive(Vec::new());
        adaptive.strategy = small;
        let honest = input(11, 2, N4F0C4);
        // Multi-view terms with an early handoff decision take main's prepare
        // path at every term start.
        let mut vote = input(101, 2, N4F0C4);
        vote.term_length = TermLength::new(commonware_utils::NZU32!(3));
        vote.handoff = Handoff::Vote(());
        let mut stage = input(102, 2, N4F0C4);
        stage.term_length = TermLength::new(commonware_utils::NZU32!(3));
        stage.handoff = Handoff::Stage(());
        let standard = [
            (
                connected,
                "82ee8ef9988526d27de83be782eefa9f8045ff1c3e09044f48bac7af9ae39822",
            ),
            (
                adaptive,
                "565cb02f413058a284f47487949dcc8c658a94eceafaf2032cd8bb1fbb82533d",
            ),
            (
                honest,
                "aa67df779e357a327c91290428da11bb5c376c36473e131cad3e6862deba91f8",
            ),
            (
                vote,
                "2154f9a4a549431e29b7119aa7ac2cb7cce2aa1ea73a95eaf552589615776f4f",
            ),
            (
                stage,
                "f31dd4cf9affda8bbf3c37b72276d82daf3e763fcf94cc8c44d4438896321fa7",
            ),
        ];
        for (input, expected) in standard {
            for happens_before in [false, true] {
                let audit = run_standard_once::<SimplexCertificateMock>(
                    input.clone(),
                    false,
                    true,
                    happens_before,
                    None,
                    None,
                )
                .expect("a valid run is audited");
                assert_eq!(audit.auditor_state, expected);
            }
        }
        let mut twins = input(13, 3, N4F1C3);
        twins.strategy = small;
        for (role, expected) in [
            (
                TwinsRole::Campaign,
                "0fbcd75a3fb8eb95951ab6af966a397355b50771af9634df01301066c4b0d0e5",
            ),
            (
                TwinsRole::Mutator,
                "a3db6cc5dda47688cc95aa639dc18dbae60d30c6931c1d87771f2ed77e99cc9d",
            ),
        ] {
            let input = twins.clone();
            let cfg = bounded_fuzz_runtime_config(
                &input.raw_bytes,
                input.required_containers,
                twins_prefix_views(input.required_containers, input.term_length),
            );
            let state = deterministic::Runner::new(cfg).start(|mut context| async move {
                let entropy = input.raw_bytes.clone();
                let mut backend = MockTwinsBackend::<SimplexCertificateMock>::new(
                    input, role, false, false, None, None,
                );
                run_twins_with_backend::<SimplexCertificateMock, _>(
                    &mut context,
                    &mut backend,
                    entropy,
                )
                .await;
                context.auditor().state()
            });
            assert_eq!(state, expected);
        }
    }

    /// What [Fill] noted of one activity log: its length, the highest finalization in
    /// it, the position of the first entry it dropped, and its last entry's position.
    type Filled = (usize, u64, Option<u64>, u64);

    /// A prefix that sleeps `secs`, then, when `read`, notes each honest replica's
    /// activity log.
    struct Fill {
        secs: u64,
        read: bool,
        logs: Arc<Mutex<Vec<Filled>>>,
    }

    impl<P: simplex::Simplex> Prefix<P> for Fill {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget {
                prefix: Duration::from_secs(self.secs + 1),
                release: Duration::from_secs(1),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                cx.sleep(Duration::from_secs(self.secs)).await;
                if !self.read {
                    return;
                }
                for r in cx.honest() {
                    let log = cx.activities(r);
                    let finalized = log
                        .iter()
                        .filter(|entry| matches!(entry.value, Activity::Finalization(_)))
                        .map(|entry| entry.value.view().get())
                        .max()
                        .unwrap_or(0);
                    let last = log.last().map_or(0, |entry| entry.stamp.seq());
                    self.logs
                        .lock()
                        .push((log.len(), finalized, log.dropped(), last));
                }
            })
        }
    }

    #[test]
    fn the_release_base_counts_finalizations_past_the_log_cap() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let mut input = input(22, 3, N4F1C3);
        input.strategy = StrategyChoice::SmallScope {
            fault_rounds: 2,
            fault_rounds_bound: 3,
        };
        let watch = Watch::default();
        byzantine::reset();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input,
            Fill {
                secs: 35,
                read: true,
                logs: logs.clone(),
            },
            watch.clone(),
        );
        let logs = logs.lock();
        assert!(
            logs.iter().any(|(len, ..)| *len == LOG_CAP),
            "no activity log reached its cap: {logs:?}"
        );
        let logged = logs
            .iter()
            .map(|(_, finalized, ..)| *finalized)
            .max()
            .unwrap();
        let base = watch.seen.lock().releases[0].base;
        assert!(base > logged, "base {base}, logged {logged}");
        // Each full log the prefix read reported its first drop, which came after every
        // entry it kept; a log under its cap dropped nothing.
        let reported = watch.seen.lock().dropped.clone();
        for (len, _, dropped, last) in logs.iter() {
            match dropped {
                Some(seq) => {
                    assert_eq!(*len, LOG_CAP);
                    assert!(seq > last, "dropped at {seq}, last kept {last}");
                    assert!(reported.contains(seq), "{seq} not in {reported:?}");
                }
                None => assert!(*len < LOG_CAP, "{logs:?}"),
            }
        }
        assert!(!reported.is_empty(), "no drop was reported");
        // The Disrupter's faulty views follow the base, so it acts in the window.
        assert!(
            byzantine::count(disrupter::ACTOR) > 0,
            "{:?}",
            byzantine::snapshot()
        );
    }

    #[test]
    fn a_full_log_the_prefix_never_reads_cuts_nothing() {
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(22, 3, N4F1C3),
            Fill {
                secs: 35,
                read: false,
                logs: Arc::default(),
            },
            watch.clone(),
        );
        assert!(watch.seen.lock().done);
        assert_eq!(watch.seen.lock().dropped, Vec::<u64>::new());
    }

    /// A prefix that builds one block more than B keeps.
    struct Blocks;

    impl<P: simplex::Simplex> Prefix<P> for Blocks {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(1),
                release: Duration::ZERO,
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let round = Round::new(Epoch::new(EPOCH), View::new(1));
                let parent = commonware_cryptography::sha256::Digest::from([0u8; 32]);
                let digests: Vec<_> = (0..=LOG_CAP).map(|_| cx.block(round, parent)).collect();
                let honest = cx.honest();
                assert!(cx.send_block(digests[0], &honest), "a kept block is sent");
                assert!(
                    !cx.send_block(digests[LOG_CAP], &honest),
                    "a block past the cap is not kept"
                );
            })
        }
    }

    #[test]
    fn b_keeps_at_most_log_cap_blocks() {
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(24, 2, N4F1C3),
            Blocks,
            watch.clone(),
        );
        assert!(watch.seen.lock().done);
        assert!(!watch.seen.lock().releases[0].overran);
    }

    /// The auditor state of a Standard run with `prefix`.
    fn standard_state<X: Prefix<SimplexCertificateMock>>(seed: u64, prefix: X) -> String {
        let mut input = input(seed, 2, N4F1C3);
        let hook = Hook::plan(
            Box::new(prefix),
            Arc::new(Watch::default()),
            &mut input,
            false,
        );
        run_standard_once::<SimplexCertificateMock>(input, false, true, false, None, Some(hook))
            .expect("a valid run is audited")
            .auditor_state
    }

    /// The auditor state of a Twins run with `prefix`.
    fn twins_state<X: Prefix<SimplexCertificateMock>>(
        seed: u64,
        role: TwinsRole,
        prefix: X,
    ) -> String {
        let mut input = input(seed, 2, N4F1C3);
        let hook = Hook::plan(
            Box::new(prefix),
            Arc::new(Watch::default()),
            &mut input,
            true,
        );
        let cfg = bounded_fuzz_runtime_config(
            &input.raw_bytes,
            input.required_containers,
            twins_prefix_views(input.required_containers, input.term_length),
        );
        deterministic::Runner::new(cfg).start(|mut context| async move {
            let entropy = input.raw_bytes.clone();
            let mut backend = MockTwinsBackend::<SimplexCertificateMock>::new(
                input, role, false, false, None, None,
            );
            run_twins_with_backend_and_hook::<SimplexCertificateMock, _>(
                &mut context,
                &mut backend,
                entropy,
                Some(hook),
            )
            .await;
            context.auditor().state()
        })
    }

    #[test]
    fn runs_with_a_prefix_are_deterministic() {
        // Gates, a cut link, a latency override, a crash and a restart at the release,
        // and B's own sends; then a prefix the runner ends at its budget.
        for seed in [31, 32] {
            assert_eq!(standard_state(seed, Meddle), standard_state(seed, Meddle));
            assert_eq!(standard_state(seed, Overrun), standard_state(seed, Overrun));
            for role in [TwinsRole::Campaign, TwinsRole::Mutator] {
                assert_eq!(
                    twins_state(seed, role, Meddle),
                    twins_state(seed, role, Meddle)
                );
            }
        }
        // A different input gives a different run, so the comparison can fail.
        assert_ne!(standard_state(31, Meddle), standard_state(32, Meddle));
    }

    /// A prefix that asks for no limit and returns after a second.
    struct Unbounded;

    impl<P: simplex::Simplex> Prefix<P> for Unbounded {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget {
                prefix: Duration::MAX,
                release: Duration::MAX,
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move { cx.sleep(Duration::from_secs(1)).await })
        }
    }

    #[test]
    fn an_unbounded_budget_is_cut() {
        let mut input = input(23, 2, N4F1C3);
        let hook = Hook::<SimplexCertificateMock>::plan(
            Box::new(Unbounded),
            Arc::new(Watch::default()),
            &mut input,
            false,
        );
        assert_eq!(
            hook.budget(),
            Budget {
                prefix: MAX_PREFIX_BUDGET,
                release: FAULT_PHASE,
            }
        );
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input,
            Unbounded,
            watch.clone(),
        );
        let (release, end) = last_two(&watch);
        assert!(release.ok() && end.ok(), "{release} / {end}");
    }

    /// A prefix that crashes and restarts honest replicas in turn.
    struct Bounce;

    impl<P: simplex::Simplex> Prefix<P> for Bounce {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(20),
                release: Duration::from_millis(500),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                for round in 0..12u64 {
                    let r = cx.honest()[(round % 3) as usize];
                    cx.sleep(Duration::from_millis(300 + 97 * round)).await;
                    assert!(cx.crash(r).await);
                    cx.sleep(Duration::from_millis(50 + 31 * round)).await;
                    assert!(cx.restart(r).await);
                }
            })
        }
    }

    #[test]
    fn a_restart_under_an_audited_base_is_a_new_incarnation() {
        // A restarted engine replays its journal: without a new generation, a nullify
        // and a replayed notarize of one view read as one incarnation's, which the
        // audited oracles reject.
        for seed in 200..205 {
            let watch = Watch::default();
            fuzz_audit_with_prefix::<SimplexCertificateMock, _, _>(
                input(seed, 3, N4F1C3),
                Bounce,
                watch.clone(),
            );
            assert!(watch.seen.lock().done);
            let watch = Watch::default();
            fuzz_twins_audit_with_prefix::<SimplexCertificateMock, TwinsCampaign, _, _>(
                input(seed, 3, N4F1C3),
                Bounce,
                watch.clone(),
            );
            assert!(watch.seen.lock().done);
        }
    }

    /// A prefix whose selectors call the context.
    struct Reenter;

    impl<P: simplex::Simplex> Prefix<P> for Reenter {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_millis(500),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let r = cx.honest()[0];
                cx.hold(r, |_| true);
                cx.hold_blocks(r, |_, _| true);
                cx.sleep(Duration::from_secs(1)).await;
                assert!(!cx.held(r).is_empty(), "the gate held nothing");
                cx.pass(r, |_| cx.held(r).is_empty());
                cx.pass_blocks(r, |_, _| {
                    cx.hold_blocks(r, |_, _| false);
                    true
                });
            })
        }
    }

    /// Runs `run` on its own thread; false if it has not returned within 60 s.
    fn returns(run: impl FnOnce() + Send + 'static) -> bool {
        let (done, wait) = mpsc::channel();
        std::thread::spawn(move || {
            run();
            let _ = done.send(());
        });
        wait.recv_timeout(Duration::from_secs(60)).is_ok()
    }

    #[test]
    fn a_selector_may_call_the_context() {
        assert!(
            returns(
                || fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
                    input(32, 2, N4F1C3),
                    Reenter,
                    Watch::default(),
                )
            ),
            "the run hung: a selector re-locked its gate"
        );
    }

    /// A prefix whose block filter calls the context, which locks the block gate and the
    /// relay: each block to the first honest replica passes those held before it and
    /// sends one of B's blocks, which the filter would hold, to that replica and another.
    /// Counts the blocks sent.
    struct ReenterBlocks {
        sent: Arc<AtomicU64>,
    }

    impl<P: simplex::Simplex> Prefix<P> for ReenterBlocks {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_millis(500),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let cx = Arc::new(cx);
                let (r, s) = (cx.honest()[0], cx.honest()[1]);
                let round = Round::new(Epoch::new(EPOCH), View::new(1));
                let digest = cx.block(round, commonware_cryptography::sha256::Digest([0; 32]));
                let inner = cx.clone();
                let sent = self.sent.clone();
                cx.hold_blocks(r, move |_, _| {
                    inner.pass_blocks(r, |_, _| true);
                    if inner.send_block(digest, &[r, s]) {
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                    true
                });
                cx.sleep(Duration::from_secs(2)).await;
            })
        }
    }

    #[test]
    fn a_block_filter_may_call_the_context() {
        let sent = Arc::new(AtomicU64::new(0));
        let prefix = ReenterBlocks { sent: sent.clone() };
        assert!(
            returns(
                || fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
                    input(33, 2, N4F1C3),
                    prefix,
                    Watch::default(),
                )
            ),
            "the run hung: a block filter re-locked the gate or the relay"
        );
        assert!(
            sent.load(Ordering::Relaxed) > 0,
            "no filter ran in the prefix"
        );
    }

    /// A prefix whose filter on the first honest replica holds nothing and fails once a
    /// read that answered in the prefix stops answering. Counts the filter's calls, and
    /// those made by the handoff.
    struct LateRead {
        calls: Arc<AtomicU64>,
        at_handoff: Arc<AtomicU64>,
    }

    impl<P: simplex::Simplex> Prefix<P> for LateRead {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_secs(2),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let cx = Arc::new(cx);
                let r = cx.honest()[0];
                cx.sleep(Duration::from_secs(1)).await;
                assert!(!cx.activities(r).is_empty(), "r reported nothing");
                let inner = cx.clone();
                let calls = self.calls.clone();
                cx.hold(r, move |_| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    assert!(!inner.activities(r).is_empty(), "a read stopped answering");
                    false
                });
                cx.sleep(Duration::from_secs(1)).await;
                self.at_handoff
                    .store(self.calls.load(Ordering::Relaxed), Ordering::Relaxed);
            })
        }
    }

    #[test]
    fn a_filter_reads_the_context_until_the_release() {
        let calls = Arc::new(AtomicU64::new(0));
        let at_handoff = Arc::new(AtomicU64::new(0));
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(37, 2, N4F1C3),
            LateRead {
                calls: calls.clone(),
                at_handoff: at_handoff.clone(),
            },
            Watch::default(),
        );
        assert!(
            calls.load(Ordering::Relaxed) > at_handoff.load(Ordering::Relaxed),
            "the filter did not run past the handoff"
        );
    }

    /// A prefix that holds every block to the first honest replica, then passes them
    /// while the filter still accepts them; notes how many its application took.
    struct PassHeld {
        taken: Arc<AtomicU64>,
    }

    impl<P: simplex::Simplex> Prefix<P> for PassHeld {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_millis(500),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let r = cx.honest()[0];
                cx.hold_blocks(r, |_, _| true);
                cx.sleep(Duration::from_secs(2)).await;
                let taken = cx.pass_blocks(r, |_, _| true);
                self.taken.store(taken as u64, Ordering::Relaxed);
            })
        }
    }

    #[test]
    fn passed_blocks_are_delivered_past_the_filter_that_held_them() {
        let taken = Arc::new(AtomicU64::new(0));
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(41, 2, N4F1C3),
            PassHeld {
                taken: taken.clone(),
            },
            Watch::default(),
        );
        assert!(
            taken.load(Ordering::Relaxed) > 0,
            "pass_blocks delivered nothing"
        );
    }

    /// A prefix that sleeps its duration again and again, forever.
    struct Spin(Duration);

    impl<P: simplex::Simplex> Prefix<P> for Spin {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget {
                prefix: Duration::from_secs(1),
                release: Duration::ZERO,
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                loop {
                    cx.sleep(self.0).await;
                }
            })
        }
    }

    #[test]
    fn a_prefix_that_sleeps_nothing_or_forever_is_ended_at_its_budget() {
        for sleep in [Duration::ZERO, Duration::MAX] {
            let watch = Watch::default();
            let observer = watch.clone();
            let run = move || {
                fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
                    input(34, 2, N4F1C3),
                    Spin(sleep),
                    observer,
                )
            };
            assert!(
                returns(run),
                "the run with sleeps of {sleep:?} hung or panicked"
            );
            assert!(watch.seen.lock().releases[0].overran);
        }
    }

    /// A prefix that crashes the first honest replica, then restarts it twice at once.
    struct DoubleRestart {
        restarted: Arc<Mutex<Vec<bool>>>,
    }

    impl<P: simplex::Simplex> Prefix<P> for DoubleRestart {
        fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
            assert!(pins.configuration(N4F1C3));
            Budget {
                prefix: Duration::from_secs(3),
                release: Duration::from_millis(500),
            }
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async move {
                let r = cx.honest()[0];
                cx.sleep(Duration::from_secs(1)).await;
                assert!(cx.crash(r).await);
                let (first, second) = futures::join!(cx.restart(r), cx.restart(r));
                self.restarted.lock().extend([first, second]);
                cx.sleep(Duration::from_secs(1)).await;
            })
        }
    }

    #[test]
    fn concurrent_restarts_start_one_incarnation() {
        let restarted = Arc::new(Mutex::new(Vec::new()));
        let watch = Watch::default();
        fuzz_with_prefix::<SimplexCertificateMock, Standard, CodeCoverage, _, _>(
            input(35, 2, N4F1C3),
            DoubleRestart {
                restarted: restarted.clone(),
            },
            watch.clone(),
        );
        assert_eq!(*restarted.lock(), vec![true, false]);
        let seen = watch.seen.lock();
        assert!(seen.done, "the run did not reach its oracles");
        // The prefix restarted the replica: the release has nothing to restart.
        assert!(seen.releases[0].restarted.is_empty());
    }
}
