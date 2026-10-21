//! The coding bases: the coding disrupter and the block poison.

use super::*;
use crate::marshal::end_to_end::{
    coding_stack::{CodingB, MAX_BLOCK_SIZE},
    twins::stack::{register_engine_networks, setup_network, setup_network_links},
};
use commonware_coding::ReedSolomon;
use commonware_consensus::{marshal::coding::types::Shard, simplex::types::Certificate};
use commonware_consensus_fuzz_core::continuation::{
    ActorRegistry, AutomatonEvent, Completion, Log, MarshalInbound, Recorded,
};
use commonware_cryptography::Sha256;
use commonware_p2p::Receiver as _;

type Mock = SimplexCertificateMock;
type Commit = CommitmentOf<Mock>;
type MockScheme = <Mock as Simplex>::Scheme;

/// Runs `base`'s trusted entry, a coding one, on `input` with a prefix only coding runs,
/// watched by `watch`.
fn run_coding_watched<X: Prefix<Mock>>(
    base: Base,
    input: MarshalDisrupterInput,
    prefix: X,
    watch: &Watch,
) {
    match base {
        Base::CodingDisrupter => {
            fuzz_marshal_coding_disrupter_with_prefix::<Mock, _, _>(input, prefix, watch.clone())
        }
        Base::CodingPoison => {
            fuzz_marshal_coding_block_poison_with_prefix::<Mock, _, _>(input, prefix, watch.clone())
        }
        _ => panic!("{base:?} is not a coding base"),
    }
}

/// [run_coding_watched] with a watch of its own, which it returns.
fn run_coding<X: Prefix<Mock>>(base: Base, input: MarshalDisrupterInput, prefix: X) -> Watch {
    let watch = Watch::default();
    run_coding_watched(base, input, prefix, &watch);
    watch
}

#[test]
fn coding_continuations_run_the_base_actor() {
    for base in CODING {
        let watch = run(base, input(vec![3, 1, 4], 4), Idle::new(3, 1));
        let (release, end) = watch.checks();
        for check in [&release, &end] {
            assert!(check.ok(), "{base:?}: {check}");
            assert_eq!(
                roles(check),
                vec![(BYZANTINE_IDX, Role::Disrupter, ActorState::Running)],
                "{base:?}"
            );
        }
        assert_eq!(watch.seen.lock().compromised, vec![vec![BYZANTINE_IDX]]);
        let release = watch.release();
        assert!(!release.overran);
        // The coding elector and reporter feed the release, which moves the actor's views;
        // the poison base's lossy cluster may finalize nothing in the prefix.
        assert!(release.view >= release.base, "{base:?}: {release:?}");
        assert!(
            release.view > 0 && (base == Base::CodingPoison || release.base > 0),
            "{base:?}: {release:?}"
        );
    }
    // The prefix sends nothing as B, so every action counted is the actor's: the coding
    // disrupter votes from its start, and the poisoner answers a lossy replica's
    // backfill, for some seed.
    byzantine::reset();
    run(
        Base::CodingDisrupter,
        input(vec![3, 1, 4], 4),
        Idle::new(3, 1),
    );
    assert!(
        byzantine::count(coding_disrupter::ACTOR) > 0,
        "{:?}",
        byzantine::snapshot()
    );
    let answered = (0..16u8).any(|seed| {
        byzantine::reset();
        let watch = run(Base::CodingPoison, input(vec![seed, 7], 6), Idle::new(1, 0));
        assert!(watch.ok(), "seed {seed}: {:?}", watch.checks());
        byzantine::count(coding_disrupter::BACKFILL_POISON_ACTOR) > 0
    });
    assert!(answered, "the poisoner never answered after a release");
}

/// What [CodingRecorders] saw: per honest replica, whether each fed log had entries, and
/// the positions of its activities and automaton reads.
type RecordersSeen = Arc<Mutex<(Vec<RecorderRead>, Vec<u64>)>>;

/// A prefix that waits, then reads every recorder of every honest replica: the fed ones
/// first, then the activities and automaton logs coding does not record.
struct CodingRecorders(RecordersSeen, Watch);

impl Prefix<Mock> for CodingRecorders {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(5),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move {
            cx.sleep(Duration::from_secs(4)).await;
            let mut seen = self.0.lock();
            for r in cx.honest() {
                seen.0.push(("deliveries", r, !cx.deliveries(r).is_empty()));
                seen.0.push((
                    "marshal deliveries",
                    r,
                    !cx.marshal_deliveries(r).is_empty(),
                ));
                seen.0.push(("elections", r, !cx.elections(r).is_empty()));
                let _ = (cx.blocks(r), cx.held(r), cx.held_marshal(r));
                seen.0.push(("inbox", 0, !cx.inbox().is_empty()));
                seen.0
                    .push(("marshal inbox", 0, !cx.marshal_inbox().is_empty()));
                // No read of a fed log was cut.
                assert_eq!(self.1.seen.lock().dropped, seen.1, "{r}");
                // The read takes the position after the stamp: no task runs between them.
                let at = cx.stamp().seq();
                assert!(cx.activities(r).is_empty());
                seen.1.push(at + 1);
                let at = cx.stamp().seq();
                assert!(cx.automaton(r).is_empty());
                seen.1.push(at + 1);
            }
        })
    }
}

#[test]
fn coding_activity_and_automaton_logs_read_as_cut() {
    for base in CODING {
        let seen = RecordersSeen::default();
        let watch = Watch::default();
        run_coding_watched(
            base,
            input(vec![1, 1], 3),
            CodingRecorders(seen.clone(), watch.clone()),
            &watch,
        );
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        // Each activities or automaton read is cut at its own position, and nothing else.
        let (reads, cuts) = seen.lock().clone();
        assert_eq!(cuts.len(), 6, "{base:?}");
        assert_eq!(watch.seen.lock().dropped, cuts, "{base:?}");
        // Every fed log recorded something on some replica.
        for kind in [
            "deliveries",
            "marshal deliveries",
            "elections",
            "inbox",
            "marshal inbox",
        ] {
            assert!(
                reads
                    .iter()
                    .any(|(log, _, recorded)| *log == kind && *recorded),
                "{base:?}: no {kind} recorded: {reads:?}"
            );
        }
    }
}

/// What [CodedAutomaton] read: per honest replica, its coded automaton log.
type CodedSeen = Arc<Mutex<Vec<(usize, Log<Recorded<AutomatonEvent<Commit>>>)>>>;

/// A prefix that echoes the honest replicas' votes as B for a while, so the cluster
/// certifies blocks, then reads every honest replica's coded automaton log.
struct CodedAutomaton(CodedSeen);

impl Prefix<Mock> for CodedAutomaton {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(6),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let mut echo = Echo::default();
            let until = cx.now() + Duration::from_secs(5);
            while cx.now() < until {
                echo.step_as::<Mock, Commit>(&cx, &honest);
                cx.sleep(STEP).await;
            }
            let mut seen = self.0.lock();
            for r in honest {
                seen.push((r, cx.coded_automaton::<Commit>(r)));
            }
        })
    }
}

/// Takes the automaton events of one kind: their round and payload.
type Pick = fn(&AutomatonEvent<Commit>) -> Option<(Round, Commit)>;

/// Whether `log` holds a request `ask` takes and, recorded after it, an answer `answer`
/// takes for the same round and payload.
fn answered(log: &[Recorded<AutomatonEvent<Commit>>], ask: Pick, answer: Pick) -> bool {
    log.iter().any(|request| {
        ask(&request.value).is_some_and(|asked| {
            log.iter().any(|outcome| {
                outcome.stamp.seq() > request.stamp.seq() && answer(&outcome.value) == Some(asked)
            })
        })
    })
}

#[test]
fn every_coding_automaton_log_is_fed() {
    let verify: Pick = |event| match event {
        AutomatonEvent::Verify { round, payload, .. } => Some((*round, *payload)),
        _ => None,
    };
    let verified: Pick = |event| match event {
        AutomatonEvent::Verified {
            round,
            payload,
            valid: Completion::Returned(_),
        } => Some((*round, *payload)),
        _ => None,
    };
    let certify: Pick = |event| match event {
        AutomatonEvent::Certify { round, payload } => Some((*round, *payload)),
        _ => None,
    };
    let certified: Pick = |event| match event {
        AutomatonEvent::Certified {
            round,
            payload,
            certified: Completion::Returned(_),
        } => Some((*round, *payload)),
        _ => None,
    };
    for base in CODING {
        let seen = CodedSeen::default();
        let watch = run_coding(base, input(vec![1, 1], 3), CodedAutomaton(seen.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        // No read was cut: the base feeds every honest replica's coded automaton log, as
        // commitments, and none reached its cap.
        assert!(watch.seen.lock().dropped.is_empty(), "{base:?}");
        let seen = seen.lock();
        assert_eq!(seen.len(), 3, "{base:?}");
        // Every honest replica's automaton was asked something. Some replica answered a
        // verification, and some a certification, recorded after its request: the poison
        // base's lossy cluster may have run one view, whose leader verifies nothing.
        for (r, log) in seen.iter() {
            assert!(!log.is_empty(), "{base:?}: replica {r} recorded nothing");
        }
        for (ask, answer, name) in [
            (verify, verified, "verification"),
            (certify, certified, "certification"),
        ] {
            assert!(
                seen.iter().any(|(_, log)| answered(log, ask, answer)),
                "{base:?}: no {name} answered"
            );
        }
    }
}

/// The coded shard a marshal broadcast message carries, if it decodes as one.
fn shard_of(
    payload: &commonware_runtime::IoBuf,
) -> Option<Shard<CodingB<Mock>, ReedSolomon<Sha256>, Sha256>> {
    Shard::decode_cfg(payload.clone(), &MAX_BLOCK_SIZE).ok()
}

/// A certificate of the coded block of `digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Certified {
    Notarization,
    Finalization,
}

/// Which certificate of the coded block of `digest` `payload` is, if any.
fn certificate_of(
    payload: &commonware_runtime::IoBuf,
    scheme: &MockScheme,
    digest: Sha256Digest,
) -> Option<Certified> {
    match Certificate::<MockScheme, Commit>::decode_cfg(
        payload.clone(),
        &scheme.certificate_codec_config(),
    )
    .ok()?
    {
        Certificate::Notarization(notarization)
            if notarization.proposal.payload.block() == digest =>
        {
            Some(Certified::Notarization)
        }
        Certificate::Finalization(finalization)
            if finalization.proposal.payload.block() == digest =>
        {
            Some(Certified::Finalization)
        }
        _ => None,
    }
}

/// What [HoldShards] saw.
struct HeldShards {
    /// R's processed height while its marshal channels were held.
    stalled: Option<Option<u64>>,
    /// The others' processed heights then.
    others: Vec<Option<Option<u64>>>,
    /// How many held messages were shards.
    shards: usize,
    /// How many held messages were passed.
    passed: usize,
    /// R's processed height after they were passed.
    after: Option<Option<u64>>,
}

type HoldShardsSeen = Arc<Mutex<Option<HeldShards>>>;

/// A prefix that holds every marshal message to R, the last participant, while B echoes
/// the others' votes, so the others finalize blocks R cannot reconstruct; then it passes
/// what R holds.
struct HoldShards(HoldShardsSeen);

impl Prefix<Mock> for HoldShards {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(60),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let r = honest[honest.len() - 1];
            assert!(cx.hold_marshal(r, |_| true));
            let mut echo = Echo::default();
            let until = cx.now() + Duration::from_secs(10);
            while cx.now() < until {
                echo.step_as::<Mock, Commit>(&cx, &honest);
                cx.sleep(STEP).await;
            }
            let held = cx.held_marshal(r);
            let shards = held
                .iter()
                .filter(|message| {
                    message.channel == MarshalChannel::Broadcast
                        && shard_of(&message.payload).is_some()
                })
                .count();
            let stalled = cx.processed_height(r).await;
            let mut others = Vec::new();
            for other in honest.iter().filter(|other| **other != r) {
                others.push(cx.processed_height(*other).await);
            }
            assert!(cx.hold_marshal(r, |_| false));
            let passed = cx.pass_marshal(r, |_| true);
            let until = cx.now() + Duration::from_secs(40);
            let mut after = None;
            while cx.now() < until {
                echo.step_as::<Mock, Commit>(&cx, &honest);
                after = cx.processed_height(r).await;
                if matches!((after, stalled), (Some(Some(now)), Some(Some(then))) if now > then) {
                    break;
                }
                cx.sleep(STEP).await;
            }
            *self.0.lock() = Some(HeldShards {
                stalled,
                others,
                shards,
                passed,
                after,
            });
        })
    }
}

#[test]
fn coding_marshal_gates_hold_shards() {
    // A seed on which the others finalize while R is held: on some seeds they process
    // nothing within the window, with or without the automaton recorder.
    for base in CODING {
        let seen = HoldShardsSeen::default();
        let watch = run_coding(base, input(vec![0, 3], 3), HoldShards(seen.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let HeldShards {
            stalled,
            others,
            shards,
            passed,
            after,
        } = seen.lock().take().expect("the prefix ran to its end");
        // While held, R delivers at most the block it proposed itself, the others
        // deliver past it, and what R holds are shards.
        let Some(Some(stalled)) = stalled else {
            panic!("{base:?}: R read {stalled:?}");
        };
        assert!(
            others
                .iter()
                .all(|height| matches!(height, Some(Some(h)) if *h > stalled)),
            "{base:?}: R {stalled}, the others {others:?}"
        );
        assert!(
            shards > 0 && passed >= shards,
            "{base:?}: {shards} {passed}"
        );
        // Passed, the shards and answers let R catch up.
        assert!(
            matches!(after, Some(Some(height)) if height > stalled),
            "{base:?}: {after:?}"
        );
        assert!(watch.seen.lock().dropped.is_empty(), "{base:?}");
    }
}

/// The views of the notarize votes a coding disrupter started with `strategy`,
/// `required` and `view_offset` sends first, as a peer receives them in its first second.
fn first_votes(
    strategy: StrategyChoice,
    required: u64,
    view_offset: u64,
) -> (Vec<u64>, ActorState) {
    deterministic::Runner::default().start(|mut context| async move {
        let (participants, schemes) = Mock::setup(&mut context, b"coding_offset", 4);
        let mut oracle =
            setup_network::<Mock>(context.child("network"), participants.clone()).await;
        setup_network_links::<Mock>(&mut oracle, &participants).await;
        let channels = register_engine_networks::<Mock>(&oracle, participants[0].clone()).await;
        let ((_, mut votes), _, _) =
            register_engine_networks::<Mock>(&oracle, participants[1].clone()).await;
        let registry = ActorRegistry::default();
        let (vote, certificate, resolver) = channels;
        let handle = coding_disrupter::start::<Mock>(
            context.child("disrupter"),
            schemes[0].clone(),
            strategy,
            required,
            vote,
            certificate,
            resolver,
            CodingFaults::none(),
            view_offset,
            Some(registry.marker(0, Role::Disrupter)),
        );
        registry.register(0, Role::Disrupter, handle);
        let mut views = Vec::new();
        let deadline = context.current() + Duration::from_secs(1);
        while context.current() < deadline {
            commonware_macros::select! {
                message = votes.recv() => {
                    let Ok((_, payload)) = message else {
                        break;
                    };
                    if let Ok(Vote::Notarize(vote)) = Vote::<MockScheme, Commit>::decode(payload) {
                        views.push(vote.proposal.round.view().get());
                    }
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
        }
        let state = registry.check("test", &[(0, Role::Disrupter)]).actors[0].state;
        views.sort_unstable();
        (views, state)
    })
}

#[test]
fn the_coding_disrupter_views_follow_the_release() {
    // Without a sample, B notarizes every view up to the target, once each with the seed
    // and its conflicting twin, from the view after the offset on.
    let (views, state) = first_votes(StrategyChoice::AnyScope, 3, 0);
    assert_eq!(views, vec![1, 1, 2, 2, 3, 3]);
    assert_eq!(state, ActorState::Running);
    let (views, state) = first_votes(StrategyChoice::AnyScope, 3, 40);
    assert_eq!(views, vec![41, 41, 42, 42, 43, 43]);
    assert_eq!(state, ActorState::Running);
    // A sampled view moves by the offset.
    let small = StrategyChoice::SmallScope {
        fault_rounds: 2,
        fault_rounds_bound: 5,
    };
    let (unshifted, _) = first_votes(small, 5, 0);
    let (shifted, _) = first_votes(small, 5, 100);
    assert!(!unshifted.is_empty());
    assert_eq!(
        shifted,
        unshifted.iter().map(|view| view + 100).collect::<Vec<_>>()
    );
}

#[test]
fn the_coding_epoch_boundary_is_safe() {
    // As on standard: a minute of an honest coding cluster reaches the epoch-0 boundary,
    // and the release and the window run there.
    let seen = BoundarySeen::default();
    let watch = run(
        Base::CodingDisrupter,
        input(vec![4, 2], 4),
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

/// TS-0002 to E3 on a coding base: as [Ts0002], with coding payloads. B echoes the
/// others' votes while R is cut off. R is passed the shards of the block the others
/// finalized at h + 1, with B's own shard of it, which B gossips as an honest B would,
/// then its notarization, which starts R's reconstruction from those shards, and its
/// finalization; B relays unchanged a certificate R's lossy links lost. R then requests h
/// by height from B.
struct Ts0002Coding(Card);

impl Prefix<Mock> for Ts0002Coding {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(50),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<Mock>) -> PrefixFuture {
        Box::pin(async move { ts0002_coding(&cx, &self.0).await })
    }
}

async fn ts0002_coding(cx: &PrefixContext<Mock>, card: &Card) {
    let (Some(b), Some(scheme)) = (cx.byzantine(), cx.scheme()) else {
        card.missed("E1", "the base runs no B");
        return;
    };
    let honest = cx.honest();
    let r = honest[honest.len() - 1];
    let others: Vec<usize> = honest.iter().copied().filter(|i| *i != r).collect();
    if cx.epoch() != Epoch::zero() || TS0002_ABOVE >= BLOCKS_PER_EPOCH.get() {
        card.missed("E1", format!("epoch {}", cx.epoch()));
        return;
    }
    card.held("E1", format!("R={r} B={b} h={TS0002_H} e=0"));

    // E2: R is cut off; the others finalize past h with B's votes.
    cx.hold(r, |_| true);
    if !cx.hold_marshal(r, |_| true) {
        card.missed("E2", "the base gates no marshal channel");
        return;
    }
    let mut echo = Echo::default();
    let deadline = cx.now() + Duration::from_secs(20);
    let mut above = None;
    while above.is_none() && cx.now() < deadline {
        echo.step_as::<Mock, Commit>(cx, &others);
        match cx.finalized_block(others[0], TS0002_ABOVE).await {
            Some(Some(digest)) => above = Some(digest),
            _ => cx.sleep(STEP).await,
        }
    }
    let Some(above) = above else {
        card.missed("E2", "the others did not finalize h + 1");
        return;
    };
    // R takes the shards of the block, B's among them, then its notarization and
    // finalization. B relays, unchanged and every half second, what R's gate still lacks:
    // its own shard and the certificates it received.
    let shard_of_above = |message: &MarshalInbound, index: Option<usize>| {
        message.channel == MarshalChannel::Broadcast
            && shard_of(&message.payload).is_some_and(|shard| {
                shard.commitment().block() == above
                    && index.is_none_or(|index| usize::from(shard.index()) == index)
            })
    };
    let (mut gossiped, mut shards, mut passed) = (false, 0, Vec::new());
    let mut steps = 0u64;
    while passed.len() < 2 && cx.now() < deadline {
        echo.step_as::<Mock, Commit>(cx, &others);
        let relay = steps.is_multiple_of(25);
        steps += 1;
        if !gossiped {
            gossiped = cx
                .held_marshal(r)
                .iter()
                .any(|message| message.from == Some(b) && shard_of_above(message, Some(b)));
            if !gossiped
                && relay
                && let Some(entry) = cx
                    .marshal_inbox()
                    .iter()
                    .find(|entry| shard_of_above(&entry.value, Some(b)))
            {
                cx.send_marshal(MarshalChannel::Broadcast, &[r], entry.value.payload.clone());
            }
        }
        if gossiped {
            shards += cx.pass_marshal(r, |message| shard_of_above(message, None));
        }
        for kind in [Certified::Notarization, Certified::Finalization] {
            if shards == 0 || passed.contains(&kind) {
                continue;
            }
            let of_kind = |payload: &commonware_runtime::IoBuf| {
                certificate_of(payload, scheme, above) == Some(kind)
            };
            if cx.pass(r, |message| {
                message.channel == Channel::Certificate && of_kind(&message.payload)
            }) > 0
            {
                passed.push(kind);
            } else if relay
                && let Some(entry) = cx.inbox().iter().find(|entry| {
                    entry.value.channel == Channel::Certificate && of_kind(&entry.value.payload)
                })
            {
                cx.send(Channel::Certificate, &[r], entry.value.payload.clone());
            }
        }
        cx.sleep(STEP).await;
    }
    let mut stored = false;
    while !stored && cx.now() < deadline {
        echo.step_as::<Mock, Commit>(cx, &others);
        stored = cx.finalized_block(r, TS0002_ABOVE).await == Some(Some(above));
        cx.sleep(STEP).await;
    }
    let gap = cx.finalized_block(r, TS0002_H).await;
    let processed = cx.processed_height(r).await;
    if !stored || gap != Some(None) || !matches!(processed, Some(Some(p)) if p < TS0002_H) {
        card.missed(
            "E2",
            format!(
                "gossiped {gossiped}, passed shards={shards} certificates={passed:?} \
                 stored={stored} \
                 gap={gap:?} processed={processed:?}"
            ),
        );
        return;
    }
    card.held(
        "E2",
        format!("R stores {above} at h + 1, none at h, processed {processed:?}"),
    );

    // E3: R requests h by its height; B receives the request.
    let deadline = cx.now() + Duration::from_secs(20);
    let mut request = None;
    while request.is_none() && cx.now() < deadline {
        echo.step_as::<Mock, Commit>(cx, &others);
        request = cx.marshal_inbox().iter().find_map(|entry| {
            if entry.value.from != Some(r) || entry.value.channel != MarshalChannel::Backfill {
                return None;
            }
            let message =
                ResolverMessage::<MarshalKey<Commit>>::decode(entry.value.payload.clone()).ok()?;
            match message.payload {
                ResolverPayload::Request(MarshalKey::Finalized { height })
                    if height.get() == TS0002_H =>
                {
                    Some(message.id)
                }
                _ => None,
            }
        });
        if request.is_none() {
            cx.sleep(STEP).await;
        }
    }
    let Some(id) = request else {
        card.missed("E3", "B received no request of R for h by height");
        return;
    };
    let gap = cx.finalized_block(r, TS0002_H).await;
    if gap != Some(None) {
        card.missed("E3", format!("R holds {gap:?} at h"));
        return;
    }
    card.held("E3", format!("R asked B for h by height (request {id})"));
}

#[test]
fn card_prefixes_leave_every_coding_base_reliable() {
    use arbitrary::{Arbitrary as _, Unstructured};

    // The standard card prefixes read standard payloads, so on coding they end in an
    // early miss; the coding TS-0002 reaches its request. Every run stays reliable.
    let canonical = MarshalDisrupterInput::arbitrary(&mut Unstructured::new(&[])).unwrap();
    for base in CODING {
        for (name, input) in [
            ("canonical", canonical.clone()),
            ("connected", input(vec![2, 0, 0, 2], 4)),
        ] {
            let card = Card::default();
            let watch = run(base, input.clone(), Ts0002(card.clone()));
            println!(
                "{}",
                card.report(&format!("TS-0002 on {base:?}, {name} input"))
            );
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
            assert!(!card.holds("E2"), "{base:?}");
            let card = Card::default();
            let watch = run(base, input.clone(), Ts0001(card.clone()));
            println!(
                "{}",
                card.report(&format!("TS-0001 on {base:?}, {name} input"))
            );
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
            assert!(!card.holds("E2"), "{base:?}");
            let card = Card::default();
            let watch = run_coding(base, input, Ts0002Coding(card.clone()));
            println!(
                "{}",
                card.report(&format!("coding TS-0002 on {base:?}, {name} input"))
            );
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
        }
    }
}

#[test]
fn ts0002_reaches_its_request_on_the_coding_disrupter() {
    let card = Card::default();
    let watch = run_coding(
        Base::CodingDisrupter,
        input(vec![2, 0, 0, 2], 4),
        Ts0002Coding(card.clone()),
    );
    let report = card.report("coding TS-0002 on the coding disrupter");
    println!("{report}");
    assert!(watch.ok(), "{:?}", watch.checks());
    for stage in ["E1", "E2", "E3"] {
        assert!(card.holds(stage), "{report}");
    }
}
