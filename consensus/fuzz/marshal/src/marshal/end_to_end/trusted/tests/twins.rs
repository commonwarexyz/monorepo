//! The Twins bases: the general standard Twins, both split-header Twins and the coding
//! Twins, through the core Twins driver's hook.

use super::*;
use crate::marshal::end_to_end::{FloorStart, app::FaultTable, coding_stack::FaultScope};
use commonware_consensus_fuzz_core::byzantine::TWIN_SECONDARY;

type Mock = SimplexCertificateMock;

/// The marshal Twins bases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Twins {
    Standard,
    Deferred,
    Inline,
    Coding,
}

/// Every Twins base.
const TWINS: [Twins; 4] = [
    Twins::Standard,
    Twins::Deferred,
    Twins::Inline,
    Twins::Coding,
];

/// A Twins input; the split-header bases run at least four rounds whatever `rounds` is.
/// The tests use raw bytes for which every base selects a case: a split-header base
/// finds no attack layout for about a third of them, as without a prefix.
fn twins_input(raw_bytes: Vec<u8>, rounds: u8) -> MarshalTwinsInput {
    MarshalTwinsInput {
        raw_bytes,
        rounds,
        case_selector: 0,
        sustained: false,
        strategy: StrategyChoice::AnyScope,
        trailing_blocks: 1,
        forwarding: ForwardPolicy::Disabled,
        floor: None,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        handoff: Handoff::Wait,
        fault_table: FaultTable::Sampled,
        fault_scope: FaultScope::Term,
    }
}

/// The canonical input, which a reach check replays.
fn canonical() -> MarshalTwinsInput {
    use arbitrary::{Arbitrary as _, Unstructured};

    MarshalTwinsInput::arbitrary(&mut Unstructured::new(&[])).unwrap()
}

/// Runs `base`'s trusted entry on `input` with `prefix`; returns what it saw.
fn run_twins<X: Prefix<Mock>>(base: Twins, input: MarshalTwinsInput, prefix: X) -> Watch {
    let watch = Watch::default();
    match base {
        Twins::Standard => {
            fuzz_marshal_standard_twins_with_prefix(input, prefix, watch.clone());
        }
        Twins::Deferred => fuzz_marshal_standard_deferred_cert_mock_twins_split_header_with_prefix(
            input,
            prefix,
            watch.clone(),
        ),
        Twins::Inline => fuzz_marshal_standard_inline_cert_mock_twins_split_header_with_prefix(
            input,
            prefix,
            watch.clone(),
        ),
        Twins::Coding => {
            fuzz_marshal_coding_twins_with_prefix::<Mock, _, _>(input, prefix, watch.clone());
        }
    }
    watch
}

/// The node that joined from a floor, the auditor state and the end of a run of `base`'s
/// driver on `input` with `prefix`, or without one.
fn drive_twins<X: Prefix<Mock>>(
    base: Twins,
    mut input: MarshalTwinsInput,
    prefix: Option<X>,
    watch: &Watch,
) -> (Option<(usize, Height)>, String, Duration) {
    let observer: Arc<dyn Observer> = Arc::new(watch.clone());
    if matches!(base, Twins::Deferred | Twins::Inline) {
        force_split_header(&mut input);
    }
    let hook = prefix.map(|prefix| plan_twins::<Mock>(&mut input, Box::new(prefix), observer));
    match base {
        Twins::Standard => run_standard_twins(input, hook),
        Twins::Deferred => {
            run_split_header_twins::<DeferredMarshal>(input, MarshalChoice::Deferred, hook)
        }
        Twins::Inline => {
            run_split_header_twins::<InlineMarshal>(input, MarshalChoice::Inline, hook)
        }
        Twins::Coding => {
            let (state, end) = run_coding_twins::<Mock>(input, hook);
            (None, state, end)
        }
    }
}

/// The roles the release starts for B on `base`: the twin pair.
const fn pair(base: Twins) -> [Role; 2] {
    match base {
        Twins::Coding => [Role::Primary, Role::Secondary],
        _ => [Role::Primary, Role::Disrupter],
    }
}

/// The compromised identity a run published.
fn compromised(watch: &Watch) -> usize {
    let seen = watch.seen.lock();
    assert_eq!(
        seen.compromised.len(),
        1,
        "the input selected no Twins case: {:?}",
        seen.compromised
    );
    assert_eq!(seen.compromised[0].len(), 1, "{:?}", seen.compromised);
    seen.compromised[0][0]
}

#[test]
fn twins_continuations_run_the_twin_pair() {
    for base in TWINS {
        byzantine::reset();
        let watch = run_twins(base, twins_input(vec![32, 3, 0], 2), Idle::new(3, 1));
        let b = compromised(&watch);
        let (release, end) = watch.checks();
        for check in [&release, &end] {
            assert!(check.ok(), "{base:?}: {check}");
            assert_eq!(
                roles(check),
                pair(base)
                    .map(|role| (b, role, ActorState::Running))
                    .to_vec(),
                "{base:?}"
            );
        }
        let release = watch.release();
        assert!(!release.overran, "{base:?}");
        // The reporters feed the release, which moves the secondary's views.
        assert!(release.base > 0, "{base:?}: {release:?}");
        assert!(release.view >= release.base, "{base:?}: {release:?}");
        // The prefix sent nothing as B: what the secondary half sent is the pair's.
        assert!(
            byzantine::count(TWIN_SECONDARY) > 0,
            "{base:?}: {:?}",
            byzantine::snapshot()
        );
    }
}

#[test]
fn the_canonical_input_yields_a_twins_case() {
    let input = canonical();
    assert_eq!(input.rounds, 1);
    assert_eq!(input.case_selector, 0);
    assert!(!input.sustained);
    assert!(matches!(input.strategy, StrategyChoice::AnyScope));
    assert_eq!(input.trailing_blocks, 1);
    assert!(matches!(input.forwarding, ForwardPolicy::Disabled));
    assert!(input.floor.is_none());
    assert_eq!(input.raw_bytes, vec![0]);
    // With no knob byte split off, and with the one raw byte split off, every base
    // selects a case: the runner publishes B and both checks pass.
    for base in TWINS {
        let watch = run_twins(base, input.clone(), Idle::new(1, 0));
        compromised(&watch);
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let seen = Arc::new(Mutex::new(Repinned::default()));
        let watch = run_twins(base, input.clone(), Repin(seen.clone()));
        compromised(&watch);
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let planned = seen.lock().planned.clone().expect("the prefix was planned");
        assert_eq!(planned.raw_bytes, vec![0], "{base:?}");
    }
}

/// A prefix that notes that it ran.
struct Ran(Arc<AtomicU64>);

impl Prefix<Mock> for Ran {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(1),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, _cx: PrefixContext<Mock>) -> PrefixFuture {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {})
    }
}

#[test]
fn an_empty_twins_case_runs_no_prefix() {
    // The split-header bases find no attack layout for these raw bytes: the driver
    // returns before the runner starts, as it returns without a prefix, so nothing is
    // published, no prefix runs and no actor is checked.
    for base in [Twins::Deferred, Twins::Inline] {
        let ran = Arc::new(AtomicU64::new(0));
        let watch = run_twins(base, twins_input(vec![3, 0], 2), Ran(ran.clone()));
        let seen = watch.seen.lock();
        assert!(seen.done, "{base:?}");
        assert!(
            seen.compromised.is_empty() && seen.checks.is_empty(),
            "{base:?}"
        );
        assert_eq!(ran.load(Ordering::Relaxed), 0, "{base:?}");
    }
}

#[test]
fn twins_pins_reach_only_what_the_base_honors() {
    for base in TWINS {
        let seen = Arc::new(Mutex::new(Repinned::default()));
        let watch = run_twins(base, twins_input(vec![9, 1, 2, 0], 4), Repin(seen.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let seen = seen.lock();
        let planned = seen.planned.as_ref().expect("the prefix was planned");
        // The plan is shown what the base runs.
        assert_eq!(planned.configuration, N4F1C3);
        assert_eq!(planned.optimistic_views, PINNED_OPTIMISTIC_VIEWS);
        assert_eq!(planned.term_length, TermLength::ONE);
        assert_eq!(planned.partition, Partition::Connected);
        assert!(!planned.degraded_network);
        assert_eq!(planned.required_containers, 1);
        assert_eq!(planned.raw_bytes, vec![9, 1, 2, 0]);
        match base {
            Twins::Deferred | Twins::Inline => assert!(
                matches!(
                    planned.strategy,
                    StrategyChoice::SplitHeader {
                        fault_rounds: 4,
                        fault_rounds_bound: 4
                    }
                ),
                "{base:?}: {:?}",
                planned.strategy
            ),
            _ => assert!(matches!(planned.strategy, StrategyChoice::AnyScope)),
        }
        // N4F0C4 is refused and N4F1C3 is what runs; the pinned lookahead, handoff and
        // three-view term reach the base.
        assert_eq!(seen.pinned, (false, true, true, true), "{base:?}");
        assert_eq!(
            seen.term_length,
            Some(TermLength::new(commonware_utils::NZU32!(3))),
            "{base:?}"
        );
        assert_eq!(seen.optimistic_views, Some(ViewDelta::new(1)), "{base:?}");
    }
}

/// A prefix that waits, then reads every honest replica's recorders and marshal, and
/// B's: notes which logs had entries, the reads' answers, and the positions of the reads
/// of the logs the base does not feed (`coding`: also the activities and automaton).
struct TwinsRecorders {
    seen: Arc<Mutex<TwinsRecorded>>,
    coding: bool,
}

impl TwinsRecorders {
    fn new(base: Twins, seen: &Arc<Mutex<TwinsRecorded>>) -> Self {
        Self {
            seen: seen.clone(),
            coding: base == Twins::Coding,
        }
    }
}

/// What [TwinsRecorders] saw.
#[derive(Default)]
struct TwinsRecorded {
    logs: Vec<RecorderRead>,
    reads: Vec<ReadOf>,
    byzantine: Option<Option<Sha256Digest>>,
    cuts: Vec<u64>,
}

impl Prefix<Mock> for TwinsRecorders {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(12),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move {
            cx.sleep(Duration::from_secs(10)).await;
            let coding = self.coding;
            let mut cuts = Vec::new();
            // Each read takes the position after the stamp: no task runs between them.
            let mut cut = |read: &dyn Fn()| {
                let at = cx.stamp().seq();
                read();
                cuts.push(at + 1);
            };
            let mut logs = Vec::new();
            for r in cx.honest() {
                logs.push(("deliveries", r, !cx.deliveries(r).is_empty()));
                logs.push(("elections", r, !cx.elections(r).is_empty()));
                if !coding {
                    logs.push(("activities", r, !cx.activities(r).is_empty()));
                    logs.push(("automaton", r, !cx.automaton(r).is_empty()));
                }
            }
            logs.push(("inbox", 0, !cx.inbox().is_empty()));
            let r = cx.honest()[0];
            cut(&|| assert!(cx.blocks(r).is_empty()));
            cut(&|| assert!(cx.marshal_deliveries(r).is_empty()));
            cut(&|| assert!(cx.held_marshal(r).is_empty()));
            cut(&|| assert!(cx.marshal_inbox().is_empty()));
            if coding {
                cut(&|| assert!(cx.activities(r).is_empty()));
                cut(&|| assert!(cx.automaton(r).is_empty()));
            }
            let mut reads = Vec::new();
            for r in cx.honest() {
                reads.push((
                    cx.finalized_block(r, 1).await,
                    cx.processed_height(r).await,
                    cx.finalized_block(r, 1_000).await,
                ));
            }
            let byzantine = cx.byzantine().expect("a Twins case has B");
            let b = cx.finalized_block(byzantine, 1).await;
            *self.seen.lock() = TwinsRecorded {
                logs,
                reads,
                byzantine: b,
                cuts,
            };
        })
    }
}

#[test]
fn twins_reads_and_recorders_answer() {
    for base in TWINS {
        let seen = Arc::new(Mutex::new(TwinsRecorded::default()));
        let watch = run_twins(
            base,
            twins_input(vec![31, 3, 0], 2),
            TwinsRecorders::new(base, &seen),
        );
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let seen = seen.lock();
        // Every fed log recorded something, on every honest replica.
        for (log, replica, recorded) in &seen.logs {
            assert!(recorded, "{base:?}: no {log} recorded at {replica}");
        }
        // No blocker and no marshal channel is tapped on Twins, and coding records no
        // activities or automaton: those reads, and only those, are cut, each at its own
        // position.
        assert_eq!(watch.seen.lock().dropped, seen.cuts, "{base:?}");
        // Every honest marshal answers, and they agree; B has no marshal the runner reads.
        assert_eq!(seen.byzantine, None, "{base:?}");
        let mut digests = Vec::new();
        for (finalized, processed, absent) in &seen.reads {
            let Some(Some(digest)) = finalized else {
                panic!("{base:?}: height 1 read {finalized:?}");
            };
            digests.push(*digest);
            assert!(
                matches!(processed, Some(Some(height)) if *height >= 1),
                "{base:?}: processed {processed:?}"
            );
            assert_eq!(*absent, Some(None), "{base:?}");
        }
        assert_eq!(digests.len(), 3, "{base:?}");
        assert!(
            digests.windows(2).all(|pair| pair[0] == pair[1]),
            "{base:?}"
        );
    }
}

/// A prefix that changes what the release reverts on a Twins base: it holds every engine
/// message to one honest replica, cuts a link and sends as B on its vote channel, and
/// finds the marshal and block capabilities a Twins base does not have inert.
struct TwinsMeddle(Arc<Mutex<Vec<bool>>>);

impl Prefix<Mock> for TwinsMeddle {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(6),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let (r, s, t) = (honest[0], honest[1], honest[2]);
            cx.hold(r, |_| true);
            assert!(cx.set_link(s, t, None).await);
            assert_eq!(cx.send(Channel::Vote, &[r], vec![2u8; 8]), 1);
            let round = Round::new(cx.epoch(), View::new(1));
            let digest = cx.block(round, Sha256Digest::from([0u8; 32]));
            let inert = [
                cx.marshal_lanes(),
                cx.hold_marshal(r, |_| true),
                cx.send_marshal(MarshalChannel::Backfill, &[r, s, t], vec![0u8; 8]) > 0,
                cx.send_marshal(MarshalChannel::Broadcast, &[r], vec![1u8; 8]) > 0,
                cx.pass_marshal(r, |_| true) > 0,
                cx.crash(s).await,
                cx.restart(s).await,
                cx.crashed(s),
                cx.set_latency(s, None),
                cx.send_block(digest, &[s]),
                cx.pass_blocks(s, |_, _| true) > 0,
            ];
            self.0.lock().extend(inert);
            cx.hold_blocks(s, |_, _| true);
            cx.sleep(Duration::from_secs(4)).await;
            assert!(!cx.held(r).is_empty(), "the engine gate held nothing");
            assert!(!cx.inbox().is_empty(), "B received nothing");
            assert_eq!(cx.epoch(), Epoch::zero());
        })
    }
}

#[test]
fn the_release_reverts_twins_changes() {
    for base in TWINS {
        let inert = Arc::new(Mutex::new(Vec::new()));
        let watch = run_twins(
            base,
            twins_input(vec![2, 0, 0, 2, 0], 2),
            TwinsMeddle(inert.clone()),
        );
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        // No marshal lane, no marshal gate, no crash or restart, and no block relay.
        assert_eq!(*inert.lock(), vec![false; 11], "{base:?}");
        let release = watch.release();
        assert_eq!(release.gates.len(), 1, "{base:?}");
        assert!(release.delivered > 0, "{base:?}");
        assert_eq!(release.links.len(), 1, "{base:?}");
        assert!(release.restarted.is_empty() && release.latencies.is_empty());
        assert_eq!(release.blocks, 0);
        assert!(watch.seen.lock().dropped.is_empty(), "{base:?}");
    }
}

#[test]
fn a_twins_floor_node_is_not_held_back_under_a_prefix() {
    // The input of the floor-join test: without a prefix the node in slot 1 waits for
    // the others to finalize height 3, then joins from that floor.
    let mut input = twins_input(vec![0, 0b11_0000], 1);
    input.strategy = StrategyChoice::SmallScope {
        fault_rounds: 1,
        fault_rounds_bound: 1,
    };
    input.trailing_blocks = 2;
    input.floor = Some(FloorStart { slot: 1, height: 3 });
    let seen = Arc::new(Mutex::new(TwinsRecorded::default()));
    let watch = Watch::default();
    let (floor, _, _) = drive_twins(
        Twins::Standard,
        input,
        Some(TwinsRecorders::new(Twins::Standard, &seen)),
        &watch,
    );
    let checks = watch.seen.lock().checks.clone();
    assert!(
        checks.len() == 2 && checks.iter().all(ActorCheck::ok),
        "{checks:?}"
    );
    // Every honest node ran from genesis from the start.
    assert_eq!(floor, None);
    let seen = seen.lock();
    assert_eq!(seen.reads.len(), 3);
    for (_, processed, _) in &seen.reads {
        assert!(
            matches!(processed, Some(Some(height)) if *height >= 1),
            "{:?}",
            seen.reads
        );
    }
}

#[test]
fn a_twins_continuation_never_waits_for_progress() {
    // No block past the epoch boundary is ever finalized, so trailing blocks past it are
    // never delivered: the ordinary run waits for them and fails its liveness check,
    // while the continuation ends after its window with both checks passing.
    let mut unreachable = twins_input(vec![9, 9, 0], 1);
    unreachable.trailing_blocks = 200;
    let window = Duration::from_secs(2 + 1) + MAX_SLEEP_DURATION;
    let bound = window + Duration::from_secs(1);
    for base in [Twins::Standard, Twins::Coding] {
        let watch = Watch::default();
        let (_, _, hooked) = drive_twins(base, unreachable.clone(), Some(Idle::new(2, 1)), &watch);
        assert!(
            hooked >= window && hooked < bound,
            "{base:?} ended at {hooked:?}"
        );
        let checks = watch.seen.lock().checks.clone();
        assert!(
            checks.len() == 2 && checks.iter().all(ActorCheck::ok),
            "{base:?}: {checks:?}"
        );
        let ordinary = panic::catch_unwind(|| {
            drive_twins(base, unreachable.clone(), None::<Idle>, &Watch::default())
        })
        .expect_err("the ordinary run reached an unreachable target");
        let message = ordinary
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(
            message.contains("made no post-prefix progress"),
            "{base:?}: {message}"
        );
    }
}

#[test]
fn hooked_twins_runs_are_deterministic() {
    let state = |base: Twins, seed: u8| {
        let inert = Arc::new(Mutex::new(Vec::new()));
        drive_twins(
            base,
            twins_input(vec![seed, 3, 0], 2),
            Some(TwinsMeddle(inert)),
            &Watch::default(),
        )
        .1
    };
    for base in TWINS {
        assert_eq!(state(base, 31), state(base, 31), "{base:?}");
        let overrun = |seed: u8| {
            drive_twins(
                base,
                twins_input(vec![seed, 0], 2),
                Some(Overrun),
                &Watch::default(),
            )
            .1
        };
        assert_eq!(overrun(32), overrun(32), "{base:?}");
    }
    // A different input gives a different run, so the comparison can fail.
    assert_ne!(state(Twins::Standard, 31), state(Twins::Standard, 32));
    assert_ne!(state(Twins::Coding, 31), state(Twins::Coding, 32));
}

#[test]
fn a_twins_prefix_past_its_budget_or_inside_a_read_is_ended() {
    for base in TWINS {
        let watch = run_twins(base, twins_input(vec![7, 0], 2), Overrun);
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        assert!(watch.release().overran, "{base:?}");
        let reads = Arc::new(AtomicU64::new(0));
        let watch = run_twins(base, twins_input(vec![8, 0], 2), ReadForever(reads.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        assert!(watch.release().overran, "{base:?}");
        assert!(reads.load(Ordering::Relaxed) > 10, "{base:?}");
    }
}

#[test]
fn the_twins_inline_epoch_boundary_is_safe() {
    // A minute of the honest replicas, B silent, reaches the epoch-0 boundary under the
    // Inline wrapper (selector bit 1); the release, the twin pair and the window run there.
    let seen = BoundarySeen::default();
    let watch = run_twins(
        Twins::Standard,
        twins_input(vec![4, 2, 0b10], 1),
        Boundary(seen.clone()),
    );
    assert!(watch.ok(), "{:?}", watch.checks());
    let last = BLOCKS_PER_EPOCH.get() - 1;
    let seen = seen.lock();
    assert_eq!(seen.len(), 3);
    for (processed, boundary, past) in seen.iter() {
        assert_eq!(*processed, Some(Some(last)));
        assert!(*boundary);
        assert_eq!(*past, Some(None));
    }
}

#[test]
fn card_prefixes_leave_every_twins_base_reliable() {
    // On Twins B has no marshal channel and no honest marshal gate: TS-0002 stops at E2,
    // which gates R's marshal channels, and TS-0001 at E2, which reads the block B
    // received on its broadcast channel. Both leave the base reliable.
    for base in TWINS {
        for (name, input) in [
            ("canonical", canonical()),
            ("connected", twins_input(vec![2, 0, 0, 2, 0], 2)),
        ] {
            let card = Card::default();
            let watch = run_twins(base, input.clone(), Ts0002(card.clone()));
            let report = card.report(&format!("TS-0002 on {base:?}, {name} input"));
            println!("{report}");
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
            assert!(card.holds("E1") && !card.holds("E2"), "{report}");
            let card = Card::default();
            let watch = run_twins(base, input, Ts0001(card.clone()));
            let report = card.report(&format!("TS-0001 on {base:?}, {name} input"));
            println!("{report}");
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
            assert!(!card.holds("E2"), "{report}");
        }
    }
}
