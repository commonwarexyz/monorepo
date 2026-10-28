use super::*;
use crate::marshal::end_to_end::{HeightOffset, block_disrupter::ANNOUNCE_ACTOR};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_consensus::{
    CertifiableBlock as _,
    marshal::{mocks::harness::BLOCKS_PER_EPOCH, resolver::handler::Key as MarshalKey},
    simplex::{
        ForwardPolicy,
        types::{Certificate, Finalization, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Round, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    SimplexCertificateMock, SimplexCertificateMockByzantineFirstLeader, byzantine,
    continuation::{
        ActorCheck, ActorState, Budget, Channel, MAX_MESSAGE, MarshalChannel, Pins, PrefixContext,
        PrefixFuture, Release,
    },
    disrupter,
    strategy::StrategyChoice,
};
use commonware_cryptography::certificate::Verifier as _;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::Runner as _;
use commonware_utils::sync::Mutex;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
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

impl Watch {
    /// The release and end checks of a run that reached its oracles.
    fn checks(&self) -> (ActorCheck, ActorCheck) {
        let seen = self.seen.lock();
        assert!(seen.done, "the run did not reach its oracles");
        assert_eq!(seen.checks.len(), 2, "{:?}", seen.checks);
        (seen.checks[0].clone(), seen.checks[1].clone())
    }

    /// Both checks of a run that reached its oracles passed.
    fn ok(&self) -> bool {
        let (release, end) = self.checks();
        release.ok() && end.ok()
    }

    /// [Self::ok] for a run of `base` released past the end of epoch 0: there the block
    /// disseminator has no view to attack, so its end check fails naming that.
    fn ok_past_epoch_zero(&self, base: Base) -> bool {
        if base != Base::Dissemination {
            return self.ok();
        }
        let (release, end) = self.checks();
        release.ok()
            && end.to_string()
                == format!("end failed {BYZANTINE_IDX}:disrupter=running base=no-dissemination")
    }

    fn release(&self) -> Release {
        self.seen.lock().releases[0].clone()
    }
}

fn input(raw_bytes: Vec<u8>, required_containers: u64) -> MarshalDisrupterInput {
    MarshalDisrupterInput {
        raw_bytes,
        required_containers,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        handoff: Handoff::Wait,
        height_offset: HeightOffset::Zero,
        application: ApplicationChoice::AlwaysAccept,
        degraded_network: false,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        forwarding: ForwardPolicy::Disabled,
    }
}

/// The marshal disrupter bases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base {
    Disrupter,
    Poison,
    Dissemination,
    CodingDisrupter,
    CodingPoison,
}

/// The standard bases.
const BASES: [Base; 3] = [Base::Disrupter, Base::Poison, Base::Dissemination];

/// The coding bases.
const CODING: [Base; 2] = [Base::CodingDisrupter, Base::CodingPoison];

/// Every base.
const ALL: [Base; 5] = [
    Base::Disrupter,
    Base::Poison,
    Base::Dissemination,
    Base::CodingDisrupter,
    Base::CodingPoison,
];

/// A prefix every base's scheme runs.
trait AnyPrefix:
    Prefix<SimplexCertificateMock> + Prefix<SimplexCertificateMockByzantineFirstLeader>
{
}

impl<X> AnyPrefix for X where
    X: Prefix<SimplexCertificateMock> + Prefix<SimplexCertificateMockByzantineFirstLeader>
{
}

/// Runs `base`'s trusted entry on `input` with `prefix`; returns what it saw.
fn run<X: AnyPrefix>(base: Base, input: MarshalDisrupterInput, prefix: X) -> Watch {
    let watch = Watch::default();
    match base {
        Base::Disrupter => fuzz_marshal_standard_disrupter_with_prefix::<
            SimplexCertificateMock,
            _,
            _,
        >(input, prefix, watch.clone()),
        Base::Poison => fuzz_marshal_standard_certificate_poison_with_prefix::<
            SimplexCertificateMock,
            _,
            _,
        >(input, prefix, watch.clone()),
        Base::Dissemination => fuzz_marshal_standard_block_dissemination_with_prefix::<
            SimplexCertificateMockByzantineFirstLeader,
            _,
            _,
        >(input, prefix, watch.clone()),
        Base::CodingDisrupter => fuzz_marshal_coding_disrupter_with_prefix::<
            SimplexCertificateMock,
            _,
            _,
        >(input, prefix, watch.clone()),
        Base::CodingPoison => fuzz_marshal_coding_block_poison_with_prefix::<
            SimplexCertificateMock,
            _,
            _,
        >(input, prefix, watch.clone()),
    }
    watch
}

/// The auditor state and end of a run of `base`'s driver on `input` with `prefix`, or
/// without one.
fn drive<X: AnyPrefix>(
    base: Base,
    mut input: MarshalDisrupterInput,
    prefix: Option<X>,
    watch: &Watch,
) -> (String, Duration) {
    let observer: Arc<dyn Observer> = Arc::new(watch.clone());
    match base {
        Base::Disrupter | Base::Poison => {
            let poison = (base == Base::Poison).then(|| {
                force_poison(&mut input);
                CertificatePoison::disarmed()
            });
            let extensions = if base == Base::Poison {
                Extensions::Forced
            } else {
                Extensions::Pinnable
            };
            let hook = prefix.map(|prefix| {
                plan::<SimplexCertificateMock>(&mut input, Box::new(prefix), observer, extensions)
            });
            let poison = match (poison, &hook) {
                (Some(_), None) => Some(CertificatePoison::new()),
                (poison, _) => poison,
            };
            let (state, end, _) =
                run_standard_disrupter::<SimplexCertificateMock>(input, poison, None, hook);
            (state, end)
        }
        Base::Dissemination => {
            let hook = prefix.map(|prefix| {
                plan::<SimplexCertificateMockByzantineFirstLeader>(
                    &mut input,
                    Box::new(prefix),
                    observer,
                    Extensions::OwnTerm,
                )
            });
            let fault = MarshalBroadcastFault::sample(&mut FuzzRng::new(input.raw_bytes.clone()));
            let (state, end, _) = run_standard_disrupter::<
                SimplexCertificateMockByzantineFirstLeader,
            >(input, None, Some(fault), hook);
            (state, end)
        }
        Base::CodingDisrupter | Base::CodingPoison => {
            let poison = base == Base::CodingPoison;
            if poison {
                force_poison(&mut input);
            }
            let extensions = if poison {
                Extensions::Forced
            } else {
                Extensions::Pinnable
            };
            let hook = prefix.map(|prefix| {
                plan::<SimplexCertificateMock>(&mut input, Box::new(prefix), observer, extensions)
            });
            run_coding_disrupter::<SimplexCertificateMock>(input, poison, hook)
        }
    }
}

/// A prefix that waits `prefix`, with a release delay of `release`.
struct Idle {
    prefix: Duration,
    release: Duration,
}

impl Idle {
    const fn new(prefix: u64, release: u64) -> Self {
        Self {
            prefix: Duration::from_secs(prefix),
            release: Duration::from_secs(release),
        }
    }
}

impl<P: Simplex> Prefix<P> for Idle {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: self.prefix,
            release: self.release,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move { cx.sleep(self.prefix).await })
    }
}

fn roles(check: &ActorCheck) -> Vec<(usize, Role, ActorState)> {
    check
        .actors
        .iter()
        .map(|actor| (actor.identity, actor.role, actor.state))
        .collect()
}

#[test]
fn standard_continuations_run_the_base_actor() {
    for base in BASES {
        byzantine::reset();
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
        assert!(!watch.release().overran);
        // The prefix sent nothing as B: every action counted is the actor's.
        let actor = match base {
            Base::Disrupter | Base::Poison => disrupter::ACTOR,
            Base::Dissemination => ANNOUNCE_ACTOR,
            Base::CodingDisrupter | Base::CodingPoison => unreachable!("a standard base"),
        };
        assert!(
            byzantine::count(actor) > 0,
            "{base:?}: {:?}",
            byzantine::snapshot()
        );
    }
}

/// Simulated time between two polls of a card prefix.
const STEP: Duration = Duration::from_millis(20);

/// One stage a card prefix recorded: (stage, held, detail).
type StageOutcome = (&'static str, bool, String);

/// The stages a card prefix recorded, in order.
#[derive(Clone, Default)]
struct Card(Arc<Mutex<Vec<StageOutcome>>>);

impl Card {
    fn held(&self, stage: &'static str, detail: impl Into<String>) {
        self.0.lock().push((stage, true, detail.into()));
    }

    fn missed(&self, stage: &'static str, detail: impl Into<String>) {
        self.0.lock().push((stage, false, detail.into()));
    }

    fn holds(&self, stage: &str) -> bool {
        self.0
            .lock()
            .iter()
            .any(|(name, held, _)| *name == stage && *held)
    }

    fn report(&self, title: &str) -> String {
        let mut text = format!("{title}:");
        for (stage, held, detail) in self.0.lock().iter() {
            let outcome = if *held { "held" } else { "missed" };
            text.push_str(&format!("\n  {stage} {outcome}: {detail}"));
        }
        text
    }
}

/// B's votes, signed as itself, on what the honest replicas vote: B and two honest
/// replicas then form quorums while the third is cut off. B votes at most once per kind
/// and view, and never both nullifies and finalizes a view.
#[derive(Default)]
struct Echo {
    read: usize,
    /// Per view: whether B notarized, nullified and finalized it.
    views: BTreeMap<u64, [bool; 3]>,
    /// Views B leaves to the prefix, inclusive.
    skip: Option<(u64, u64)>,
}

impl Echo {
    fn step<P: Simplex>(&mut self, cx: &PrefixContext<P>, to: &[usize]) {
        self.step_as::<P, Sha256Digest>(cx, to);
    }

    /// [Self::step] for votes on payloads of type `D`.
    fn step_as<P, D>(&mut self, cx: &PrefixContext<P>, to: &[usize])
    where
        P: Simplex,
        D: commonware_cryptography::Digest,
        P::Scheme: commonware_consensus::simplex::scheme::Scheme<D>,
    {
        let Some(scheme) = cx.scheme() else {
            return;
        };
        let inbox = cx.inbox();
        for entry in inbox.iter().skip(self.read) {
            if entry.value.channel != Channel::Vote {
                continue;
            }
            let Ok(vote) = Vote::<P::Scheme, D>::decode(entry.value.payload.clone()) else {
                continue;
            };
            let (view, kind) = match &vote {
                Vote::Notarize(vote) => (vote.proposal.round.view(), 0),
                Vote::Nullify(vote) => (vote.round.view(), 1),
                Vote::Finalize(vote) => (vote.proposal.round.view(), 2),
            };
            if self
                .skip
                .is_some_and(|(low, high)| (low..=high).contains(&view.get()))
            {
                continue;
            }
            let seen = self.views.entry(view.get()).or_default();
            let allowed = !seen[kind]
                && match kind {
                    0 => !seen[1],
                    1 => !seen[2],
                    _ => !seen[1],
                };
            if !allowed {
                continue;
            }
            let echoed = match vote {
                Vote::Notarize(vote) => Notarize::sign(scheme, vote.proposal).map(Vote::Notarize),
                Vote::Nullify(vote) => Nullify::sign::<D>(scheme, vote.round).map(Vote::Nullify),
                Vote::Finalize(vote) => Finalize::sign(scheme, vote.proposal).map(Vote::Finalize),
            };
            if let Some(echoed) = echoed {
                seen[kind] = true;
                cx.send(Channel::Vote, to, echoed.encode());
            }
        }
        self.read = inbox.len();
    }
}

/// Whether `payload` is a finalization of `digest`.
fn finalizes<P: Simplex>(
    payload: &commonware_runtime::IoBuf,
    scheme: &P::Scheme,
    digest: Sha256Digest,
) -> Option<Finalization<P::Scheme, Sha256Digest>> {
    match Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
        payload.clone(),
        &scheme.certificate_codec_config(),
    ) {
        Ok(Certificate::Finalization(finalization)) if finalization.proposal.payload == digest => {
            Some(finalization)
        }
        _ => None,
    }
}

/// The block `payload` carries on the broadcast channel, if it is the one of `digest`.
fn block_of<P: Simplex>(payload: &commonware_runtime::IoBuf, digest: Sha256Digest) -> Option<B<P>> {
    B::<P>::decode(payload.clone())
        .ok()
        .filter(|block| block.digest() == digest)
}

/// TS-0002 at its source values: h = 1 in epoch 0, and R learns the block at h + 1.
const TS0002_H: u64 = 1;
const TS0002_ABOVE: u64 = TS0002_H + 1;

/// TS-0002 as a prefix: R, the last honest replica, is cut off by its gates from the
/// start while B echoes the others' votes. R is passed only the block the others
/// finalized at h + 1 and its finalization, which B relays unchanged if R's lossy links
/// lost them, so it stores it and requests h by height.
/// B receives that request and answers it with the cluster's finalization of h, its
/// round claiming epoch 1, and the block the cluster finalized at h.
struct Ts0002(Card);

impl<P: Simplex> Prefix<P> for Ts0002 {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(50),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move { ts0002(&cx, &self.0).await })
    }
}

async fn ts0002<P: Simplex>(cx: &PrefixContext<P>, card: &Card) {
    let (Some(b), Some(scheme)) = (cx.byzantine(), cx.scheme()) else {
        card.missed("E1", "the base runs no B");
        return;
    };
    // R is the last participant, whose links a degraded network makes lossy, so the
    // others, with B, form quorums at full speed while R is cut off.
    let honest = cx.honest();
    let r = honest[honest.len() - 1];
    let others: Vec<usize> = honest.iter().copied().filter(|i| *i != r).collect();

    // E1: h lies in the epoch the engines run, below the epoch-0 boundary.
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
        echo.step(cx, &others);
        match cx.finalized_block(others[0], TS0002_ABOVE).await {
            Some(Some(digest)) => above = Some(digest),
            _ => cx.sleep(STEP).await,
        }
    }
    let Some(above) = above else {
        card.missed("E2", "the others did not finalize h + 1");
        return;
    };
    // R takes the block, then its finalization. Either may have been lost on R's links:
    // B relays, unchanged, the copy it received, until R's gate holds one.
    let (mut block, mut finalization) = (0, 0);
    while finalization == 0 && cx.now() < deadline {
        echo.step(cx, &others);
        if block == 0 {
            block = cx.pass_marshal(r, |message| {
                message.channel == MarshalChannel::Broadcast
                    && block_of::<P>(&message.payload, above).is_some()
            });
            if block == 0
                && let Some(entry) = cx.marshal_inbox().iter().find(|entry| {
                    entry.value.channel == MarshalChannel::Broadcast
                        && block_of::<P>(&entry.value.payload, above).is_some()
                })
            {
                cx.send_marshal(MarshalChannel::Broadcast, &[r], entry.value.payload.clone());
            }
        }
        if block > 0 {
            finalization = cx.pass(r, |message| {
                message.channel == Channel::Certificate
                    && finalizes::<P>(&message.payload, scheme, above).is_some()
            });
            if finalization == 0
                && let Some(entry) = cx.inbox().iter().find(|entry| {
                    entry.value.channel == Channel::Certificate
                        && finalizes::<P>(&entry.value.payload, scheme, above).is_some()
                })
            {
                cx.send(Channel::Certificate, &[r], entry.value.payload.clone());
            }
        }
        cx.sleep(STEP).await;
    }
    let mut stored = false;
    while !stored && cx.now() < deadline {
        echo.step(cx, &others);
        stored = cx.finalized_block(r, TS0002_ABOVE).await == Some(Some(above));
        cx.sleep(STEP).await;
    }
    let gap = cx.finalized_block(r, TS0002_H).await;
    let processed = cx.processed_height(r).await;
    if !stored || gap != Some(None) || !matches!(processed, Some(Some(p)) if p < TS0002_H) {
        card.missed(
            "E2",
            format!(
                "passed block={block} finalization={finalization} stored={stored} \
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
        echo.step(cx, &others);
        request = cx.marshal_inbox().iter().find_map(|entry| {
            if entry.value.from != Some(r) || entry.value.channel != MarshalChannel::Backfill {
                return None;
            }
            let message =
                ResolverMessage::<MarshalKey<Sha256Digest>>::decode(entry.value.payload.clone())
                    .ok()?;
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

    // E4: B answers with the cluster's finalization of h claiming epoch 1, and its block.
    let Some(Some(digest)) = cx.finalized_block(others[0], TS0002_H).await else {
        card.missed("E4", "the others hold no finalized block at h");
        return;
    };
    let finalized = cx.inbox().iter().find_map(|entry| {
        (entry.value.channel == Channel::Certificate)
            .then(|| finalizes::<P>(&entry.value.payload, scheme, digest))
            .flatten()
    });
    let block = cx.marshal_inbox().iter().find_map(|entry| {
        (entry.value.channel == MarshalChannel::Broadcast)
            .then(|| block_of::<P>(&entry.value.payload, digest))
            .flatten()
    });
    let (Some(finalized), Some(block)) = (finalized, block) else {
        card.missed("E4", "B holds no finalization of h or no block of h");
        return;
    };
    let proposal = finalized.proposal;
    let claimed = Finalization::<P::Scheme, Sha256Digest> {
        proposal: Proposal::new(
            Round::new(Epoch::new(1), proposal.round.view()),
            proposal.parent,
            proposal.payload,
        ),
        certificate: finalized.certificate,
    };
    let response = ResolverMessage::<MarshalKey<Sha256Digest>> {
        id,
        payload: ResolverPayload::Response((claimed, block).encode()),
    };
    // B's response may be lost on R's links: B sends it again until R's gate holds it.
    let response = response.encode();
    let deadline = cx.now() + Duration::from_secs(4);
    let mut passed = 0;
    while passed == 0 && cx.now() < deadline {
        cx.send_marshal(MarshalChannel::Backfill, &[r], response.clone());
        cx.sleep(Duration::from_millis(250)).await;
        passed = cx.pass_marshal(r, |message| {
            message.from == Some(b) && message.channel == MarshalChannel::Backfill
        });
    }
    cx.sleep(Duration::from_millis(500)).await;
    let blamed = cx.blocks(r).iter().any(|entry| entry.value == b);
    let gap = cx.finalized_block(r, TS0002_H).await;
    if passed == 0 || !blamed || gap != Some(None) {
        card.missed("E4", format!("passed={passed} blamed={blamed} gap={gap:?}"));
        return;
    }
    card.held(
        "E4",
        "R took B's epoch-1 finalization, blamed B and holds no block at h",
    );
}

#[test]
fn ts0002_reaches_its_request_on_the_standard_disrupter() {
    let card = Card::default();
    let watch = run(
        Base::Disrupter,
        input(vec![2, 0, 0, 2], 4),
        Ts0002(card.clone()),
    );
    let report = card.report("TS-0002 on the standard disrupter");
    println!("{report}");
    assert!(watch.ok(), "{:?}", watch.checks());
    for stage in ["E1", "E2", "E3"] {
        assert!(card.holds(stage), "{report}");
    }
}

#[test]
fn canonical_inputs_decode_as_documented() {
    use arbitrary::{Arbitrary as _, Unstructured};

    let input = MarshalDisrupterInput::arbitrary(&mut Unstructured::new(&[])).unwrap();
    assert_eq!(input.partition, Partition::Connected);
    assert!(input.degraded_network);
    assert_eq!(input.required_containers, 1);
    assert_eq!(input.term_length, TermLength::ONE);
    assert!(matches!(input.strategy, StrategyChoice::AnyScope));
    assert!(matches!(input.forwarding, ForwardPolicy::Disabled));
    assert!(input.raw_bytes.is_empty());
    // Every base runs the canonical input to its oracles with both checks passing.
    for base in ALL {
        let watch = run(base, input.clone(), Idle::new(1, 0));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
    }
}

/// What [Repin] saw.
#[derive(Default)]
struct Repinned {
    planned: Option<FuzzInput>,
    pinned: (bool, bool, bool, bool),
    term_length: Option<TermLength>,
    optimistic_views: Option<ViewDelta>,
}

/// A prefix that splits one knob byte off and pins N4F0C4, a lookahead of one, a `Vote`
/// handoff and a three-view term.
struct Repin(Arc<Mutex<Repinned>>);

impl<P: Simplex> Prefix<P> for Repin {
    fn plan(&mut self, pins: &mut Pins<'_>) -> Budget {
        let mut seen = self.0.lock();
        seen.planned = Some(pins.input().clone());
        pins.raw_bytes().remove(0);
        let configuration = pins.configuration(commonware_consensus_fuzz_core::N4F0C4);
        let lookahead = pins.lookahead(ViewDelta::new(1));
        let handoff = pins.handoff(Handoff::Vote(()));
        pins.term_length(TermLength::new(commonware_utils::NZU32!(3)));
        let n4f1c3 = pins.configuration(N4F1C3);
        seen.pinned = (configuration, lookahead, handoff, n4f1c3);
        Budget {
            prefix: Duration::from_secs(1),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            {
                let mut seen = self.0.lock();
                seen.term_length = Some(cx.term_length());
                seen.optimistic_views = Some(cx.optimistic_views());
            }
            cx.sleep(Duration::from_millis(500)).await;
        })
    }
}

#[test]
fn pins_reach_only_what_the_base_honors() {
    let mut fields = input(vec![9, 1, 2], 3);
    fields.partition = Partition::Static(SetPartition::n4(5));
    fields.degraded_network = false;
    fields.term_length = TermLength::new(commonware_utils::NZU32!(2));
    for base in ALL {
        let seen = Arc::new(Mutex::new(Repinned::default()));
        let watch = run(base, fields.clone(), Repin(seen.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        let seen = seen.lock();
        let planned = seen.planned.as_ref().expect("the prefix was planned");
        // The plan is shown what the base runs.
        assert_eq!(planned.configuration, N4F1C3);
        assert_eq!(planned.optimistic_views, PINNED_OPTIMISTIC_VIEWS);
        assert_eq!(planned.raw_bytes, vec![9, 1, 2]);
        // N4F0C4 is refused and N4F1C3 is what runs; the extensions reach every base
        // but the poison bases, which force them.
        let forced = matches!(base, Base::Poison | Base::CodingPoison);
        assert_eq!(seen.pinned, (false, !forced, !forced, true), "{base:?}");
        match base {
            Base::Poison | Base::CodingPoison => {
                assert_eq!(planned.partition, Partition::Connected);
                assert!(planned.degraded_network);
            }
            _ => {
                assert_eq!(planned.partition, Partition::Static(SetPartition::n4(5)));
                assert!(!planned.degraded_network);
            }
        }
        // The plan shows the block-dissemination base its own term and every other base
        // a single view; the pinned term and lookahead run unless the base forces them.
        let shown = if base == Base::Dissemination { 2 } else { 1 };
        let (ran, lookahead) = if forced { (1, 0) } else { (3, 1) };
        assert_eq!(planned.term_length.get(), shown, "{base:?}");
        assert_eq!(
            seen.term_length.map(|term| term.get()),
            Some(ran),
            "{base:?}"
        );
        assert_eq!(
            seen.optimistic_views.map(|views| views.get()),
            Some(lookahead),
            "{base:?}"
        );
    }
}

/// A prefix that changes what the release reverts on a marshal base: it holds every
/// engine and marshal message to one honest replica, cuts a link, sends as B on its
/// engine and both marshal channels, and finds the capabilities a marshal base does not
/// have inert.
struct Meddle {
    inert: Arc<Mutex<Vec<bool>>>,
}

impl<P: Simplex> Prefix<P> for Meddle {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(6),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            let b = cx.byzantine().expect("a marshal base has B");
            let honest = cx.honest();
            let (r, s, t) = (honest[0], honest[1], honest[2]);
            assert!(cx.marshal_lanes());
            cx.hold(r, |_| true);
            assert!(cx.hold_marshal(r, |_| true));
            assert!(cx.set_link(s, t, None).await);
            // B's own messages reach the held replica whatever the cluster does.
            assert_eq!(cx.send(Channel::Vote, &[r], vec![2u8; 8]), 1);
            assert_eq!(
                cx.send_marshal(MarshalChannel::Backfill, &[r, s, t], vec![0u8; 8]),
                3
            );
            assert_eq!(
                cx.send_marshal(MarshalChannel::Broadcast, &[r, t], vec![1u8; 8]),
                2
            );
            let round = Round::new(cx.epoch(), View::new(1));
            let digest = cx.block(round, Sha256Digest::from([0u8; 32]));
            let inert = [
                cx.crash(s).await,
                cx.restart(s).await,
                cx.crashed(s),
                cx.set_latency(s, None),
                cx.send_block(digest, &[s]),
                cx.pass_blocks(s, |_, _| true) > 0,
            ];
            self.inert.lock().extend(inert);
            cx.hold_blocks(s, |_, _| true);
            cx.sleep(Duration::from_secs(4)).await;
            assert!(!cx.held(r).is_empty(), "the engine gate held nothing");
            assert!(
                !cx.held_marshal(r).is_empty(),
                "the marshal gate held nothing"
            );
            assert!(
                cx.marshal_deliveries(t)
                    .iter()
                    .any(|entry| entry.value.from == Some(b)),
                "t recorded nothing B sent on its marshal channels"
            );
            assert!(!cx.marshal_inbox().is_empty(), "B received nothing");
        })
    }
}

#[test]
fn the_release_reverts_marshal_changes() {
    for base in ALL {
        let inert = Arc::new(Mutex::new(Vec::new()));
        let watch = run(
            base,
            input(vec![5, 5], 3),
            Meddle {
                inert: inert.clone(),
            },
        );
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        // No marshal replica crashes or restarts, and the block and latency
        // capabilities do nothing without a block relay.
        assert_eq!(*inert.lock(), vec![false; 6], "{base:?}");
        let release = watch.release();
        assert_eq!(release.gates, vec![1], "{base:?}");
        assert!(release.delivered > 0, "{base:?}");
        assert_eq!(release.links, vec![(2, 3)], "{base:?}");
        assert!(release.restarted.is_empty() && release.latencies.is_empty());
        assert_eq!(release.blocks, 0);
        assert!(watch.seen.lock().dropped.is_empty(), "{base:?}");
    }
}

/// A prefix that asks to crash and restart honest replicas in turn, as the simplex
/// bases allow; notes every answer.
struct Bounce(Arc<Mutex<Vec<bool>>>);

impl<P: Simplex> Prefix<P> for Bounce {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(15),
            release: Duration::from_millis(500),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            for round in 0..12u64 {
                let r = cx.honest()[(round % 3) as usize];
                cx.sleep(Duration::from_millis(300 + 97 * round)).await;
                let crashed = cx.crash(r).await;
                let down = cx.crashed(r);
                cx.sleep(Duration::from_millis(50 + 31 * round)).await;
                let restarted = cx.restart(r).await;
                self.0.lock().extend([crashed, down, restarted]);
            }
        })
    }
}

#[test]
fn a_marshal_replica_is_never_crashed_or_restarted() {
    // A crashed marshal replica's tasks cannot all be aborted and awaited (the resolver
    // engine is hidden), and a restarted one would redeliver blocks the oracles count
    // once: the runner refuses both, so no incarnation ever reopens a live journal.
    for base in ALL {
        let answers = Arc::new(Mutex::new(Vec::new()));
        let watch = run(base, input(vec![2, 9], 3), Bounce(answers.clone()));
        assert!(
            watch.ok_past_epoch_zero(base),
            "{base:?}: {:?}",
            watch.checks()
        );
        let answers = answers.lock();
        assert_eq!(answers.len(), 36, "{base:?}");
        assert!(
            answers.iter().all(|answer| !answer),
            "{base:?}: {answers:?}"
        );
        assert!(watch.release().restarted.is_empty(), "{base:?}");
    }
}

/// A prefix that retries a crash (or, when false, a restart) of an honest replica until
/// it is granted, with no sleep in the loop, at most 10k times.
struct Retry(bool);

impl<P: Simplex> Prefix<P> for Retry {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(3),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            let r = cx.honest()[0];
            for _ in 0..10_000 {
                let granted = if self.0 {
                    cx.crash(r).await
                } else {
                    cx.restart(r).await
                };
                if granted {
                    break;
                }
            }
        })
    }
}

#[test]
fn a_refused_crash_or_restart_loop_is_ended_at_its_budget() {
    // A refusal costs simulated time, so the runner's budget ends the loop before its
    // 10k tries; a free refusal would leave the clock where it was.
    for base in ALL {
        for crash in [true, false] {
            let watch = run(base, input(vec![4], 3), Retry(crash));
            assert!(watch.ok(), "{base:?} {crash}: {:?}", watch.checks());
            assert!(watch.release().overran, "{base:?} {crash}");
        }
    }
}

/// A prefix that sends B's honest peers a message over the networks' largest, on each of
/// its channels; notes how many each send went to.
struct Oversized(Arc<Mutex<Vec<usize>>>);

impl<P: Simplex> Prefix<P> for Oversized {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(2),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let big = || vec![0u8; MAX_MESSAGE as usize + 1];
            let sent = [
                cx.send(Channel::Vote, &honest, big()),
                cx.send_marshal(MarshalChannel::Backfill, &honest, big()),
                cx.send_marshal(MarshalChannel::Broadcast, &honest, big()),
            ];
            self.0.lock().extend(sent);
            cx.sleep(Duration::from_secs(1)).await;
        })
    }
}

#[test]
fn an_oversized_send_goes_nowhere() {
    for base in ALL {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let watch = run(base, input(vec![6], 3), Oversized(sent.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        assert_eq!(*sent.lock(), vec![0; 3], "{base:?}");
    }
}

/// A prefix that never returns: the runner ends it at its budget.
struct Overrun;

impl<P: Simplex> Prefix<P> for Overrun {
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

#[test]
fn a_marshal_prefix_past_its_budget_is_ended() {
    for base in ALL {
        let watch = run(base, input(vec![7], 3), Overrun);
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        assert!(watch.release().overran, "{base:?}");
    }
}

/// A prefix that reads honest marshals until the runner ends it, inside a read.
struct ReadForever(Arc<AtomicU64>);

impl<P: Simplex> Prefix<P> for ReadForever {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_millis(2_500),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let mut round = 0u64;
            loop {
                let r = honest[(round % 3) as usize];
                let _ = cx.finalized_block(r, round % 4).await;
                let _ = cx.processed_height(r).await;
                self.0.fetch_add(1, Ordering::Relaxed);
                round += 1;
            }
        })
    }
}

#[test]
fn a_prefix_ended_inside_a_marshal_read_releases_cleanly() {
    for base in ALL {
        let reads = Arc::new(AtomicU64::new(0));
        let watch = run(base, input(vec![8], 3), ReadForever(reads.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        assert!(watch.release().overran, "{base:?}");
        assert!(reads.load(Ordering::Relaxed) > 10, "{base:?}");
    }
}

#[test]
fn a_marshal_continuation_never_waits_for_progress() {
    // No block past the epoch boundary is ever finalized, so a target past it is never
    // reached: the ordinary run waits for it and fails its liveness check, while the
    // continuation ends after its fixed window with both checks passing.
    let unreachable = input(vec![9, 9], 1_000);
    let window = Duration::from_secs(2 + 1) + FAULT_PHASE + MAX_SLEEP_DURATION;
    let bound = window + Duration::from_secs(1);
    for base in [Base::Disrupter, Base::Dissemination, Base::CodingDisrupter] {
        let watch = Watch::default();
        let (_, hooked) = drive(base, unreachable.clone(), Some(Idle::new(2, 1)), &watch);
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
            drive(base, unreachable.clone(), None::<Idle>, &Watch::default())
        })
        .expect_err("the ordinary run reached an unreachable target");
        let message = ordinary
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(
            message.contains("no post-GST progress"),
            "{base:?}: {message}"
        );
    }
}

#[test]
fn hooked_marshal_runs_are_deterministic() {
    let state = |base: Base, seed: u8| {
        let inert = Arc::new(Mutex::new(Vec::new()));
        drive(
            base,
            input(vec![seed, 3], 3),
            Some(Meddle { inert }),
            &Watch::default(),
        )
        .0
    };
    for base in ALL {
        assert_eq!(state(base, 31), state(base, 31), "{base:?}");
        let overrun =
            |seed: u8| drive(base, input(vec![seed], 3), Some(Overrun), &Watch::default()).0;
        assert_eq!(overrun(32), overrun(32), "{base:?}");
    }
    // A different input gives a different run, so the comparison can fail.
    assert_ne!(state(Base::Disrupter, 31), state(Base::Disrupter, 32));
    assert_ne!(
        state(Base::CodingDisrupter, 31),
        state(Base::CodingDisrupter, 32)
    );
}

/// What [PoisonWatch] saw at its end: whether the poison was armed and how many
/// answers it had poisoned.
type PoisonSeen = Arc<Mutex<Option<(bool, u64)>>>;

/// A prefix that waits, with B silent, then notes the poison's state.
struct PoisonWatch {
    poison: CertificatePoison<PublicKeyOf<SimplexCertificateMock>>,
    seen: PoisonSeen,
}

impl Prefix<SimplexCertificateMock> for PoisonWatch {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(40),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<SimplexCertificateMock>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let mut echo = Echo::default();
            let until = cx.now() + Duration::from_secs(39);
            while cx.now() < until {
                echo.step(&cx, &honest);
                cx.sleep(STEP).await;
            }
            *self.seen.lock() = Some((
                self.poison.armed(),
                byzantine::count(commonware_consensus_fuzz_core::network::POISON_ACTOR),
            ));
        })
    }
}

/// Runs the certificate-poison driver with [PoisonWatch] and `poison`; returns what the
/// prefix saw at its end.
fn watch_poison(
    seed: u8,
    poison: CertificatePoison<PublicKeyOf<SimplexCertificateMock>>,
) -> (bool, u64) {
    let seen = PoisonSeen::default();
    let mut input = input(vec![seed], 8);
    force_poison(&mut input);
    let prefix = PoisonWatch {
        poison: poison.clone(),
        seen: seen.clone(),
    };
    let hook = plan::<SimplexCertificateMock>(
        &mut input,
        Box::new(prefix),
        Arc::new(Watch::default()),
        Extensions::Forced,
    );
    run_standard_disrupter::<SimplexCertificateMock>(input, Some(poison), None, Some(hook));
    let seen = *seen.lock();
    seen.expect("the prefix ran to its end")
}

#[test]
fn the_poison_is_armed_only_at_the_release() {
    use commonware_consensus_fuzz_core::network::POISON_ACTOR;

    // While B echoes the others' votes the lossy last replica falls behind and
    // backfills a nullified view B leads: a poison armed from the start poisons that
    // answer inside the prefix, for some seed (23 when written).
    let seed = (0..48u8)
        .find(|seed| {
            byzantine::reset();
            watch_poison(*seed, CertificatePoison::new()).1 > 0
        })
        .expect("an armed poison acted inside some prefix");
    // The continuation's poison stays disarmed through the prefix, then is armed.
    byzantine::reset();
    let poison = CertificatePoison::disarmed();
    assert_eq!(
        watch_poison(seed, poison.clone()),
        (false, 0),
        "seed {seed}"
    );
    assert!(poison.armed());
    // From the release on it acts as the base's does, for some seed (4 when written).
    let fired = (0..16u8).any(|seed| {
        byzantine::reset();
        let watch = run(Base::Poison, input(vec![seed], 4), Idle::new(1, 0));
        assert!(watch.ok(), "seed {seed}: {:?}", watch.checks());
        byzantine::count(POISON_ACTOR) > 0
    });
    assert!(fired, "the poison never acted after a release");
}

/// Per honest replica, the views of the blocks B led that it was delivered, after a run
/// of the block-dissemination driver on `raw_bytes` with term length `term`, with
/// `prefix` or without one.
fn disseminated<X>(raw_bytes: Vec<u8>, term: u32, prefix: Option<X>) -> Vec<Vec<u64>>
where
    X: Prefix<SimplexCertificateMockByzantineFirstLeader>,
{
    type P = SimplexCertificateMockByzantineFirstLeader;
    let term_length = TermLength::new(std::num::NonZeroU32::new(term).unwrap());
    // Who leads a view depends only on the participant count and the term length.
    let led = deterministic::Runner::default().start(|mut context| async move {
        let (_, schemes) = P::setup(&mut context, b"led", 4);
        byzantine_led::<P>(&schemes[BYZANTINE_IDX], term_length)
    });
    let mut input = input(raw_bytes, 4);
    input.term_length = term_length;
    let hook = prefix.map(|prefix| {
        plan::<P>(
            &mut input,
            Box::new(prefix),
            Arc::new(Watch::default()),
            Extensions::OwnTerm,
        )
    });
    let fault = MarshalBroadcastFault::sample(&mut FuzzRng::new(input.raw_bytes.clone()));
    let (_, _, honest) = run_standard_disrupter::<P>(input, None, Some(fault), hook);
    honest
        .iter()
        .map(|(_, application)| {
            application
                .blocks()
                .values()
                .map(|block| block.context().round.view())
                .filter(|view| !view.is_zero() && led(*view))
                .map(View::get)
                .collect()
        })
        .collect()
}

#[test]
fn the_block_disseminator_attacks_the_live_chain() {
    let fault = |byte: u8| MarshalBroadcastFault::sample(&mut FuzzRng::new(vec![byte]));
    assert_eq!(fault(1), MarshalBroadcastFault::Partition);
    assert_eq!(fault(4), MarshalBroadcastFault::Equivocate);
    // The ordinary run attacks view 1 on genesis, and every honest replica delivers it.
    for raw_bytes in [vec![1], vec![4]] {
        let ordinary = disseminated(raw_bytes.clone(), 1, None::<Idle>);
        assert_eq!(ordinary, vec![vec![1]; 3], "{raw_bytes:?}");
    }
    // After a prefix, under the Partition (1) and Equivocate (4) faults and terms of one
    // and two views, the attack lands past the release: every honest replica delivers
    // a block B led above view 1.
    for raw_bytes in [vec![1], vec![4]] {
        for term in [1, 2] {
            let delivered = disseminated(raw_bytes.clone(), term, Some(Idle::new(1, 0)));
            assert_eq!(delivered.len(), 3);
            assert!(
                delivered
                    .iter()
                    .all(|views| !views.is_empty() && views.iter().all(|view| *view > 1)),
                "{raw_bytes:?} term {term}: {delivered:?}"
            );
        }
    }
    // A release after the cluster reached the last height of epoch 0 leaves no view to
    // attack.
    let late = disseminated(vec![1], 1, Some(Idle::new(8, 0)));
    assert_eq!(late, vec![Vec::<u64>::new(); 3]);
}

#[test]
fn a_disseminator_that_never_attacks_fails_the_end_check() {
    // Under the Partition (1) and Equivocate (4) faults: an early release attacks and
    // passes both checks; a release past the end of epoch 0 sends nothing, and its end
    // check fails although the disseminator's engine still runs.
    for raw_bytes in [vec![1], vec![4]] {
        byzantine::reset();
        let early = run(
            Base::Dissemination,
            input(raw_bytes.clone(), 4),
            Idle::new(1, 0),
        );
        assert!(early.ok(), "{raw_bytes:?}: {:?}", early.checks());
        assert!(byzantine::count(ANNOUNCE_ACTOR) > 0, "{raw_bytes:?}");

        byzantine::reset();
        let late = run(
            Base::Dissemination,
            input(raw_bytes.clone(), 4),
            Idle::new(8, 0),
        );
        let (release, end) = late.checks();
        assert!(release.ok(), "{raw_bytes:?}: {release}");
        assert_eq!(
            end.to_string(),
            "end failed 0:disrupter=running base=no-dissemination",
            "{raw_bytes:?}"
        );
        assert_eq!(byzantine::count(ANNOUNCE_ACTOR), 0, "{raw_bytes:?}");
    }
}

/// What [Reads] saw: per honest replica, the digest it finalized at height 1, its
/// processed height and its answer for a height no block reaches; then B's answer.
type ReadsSeen = Arc<Mutex<Option<(Vec<ReadOf>, Option<Option<Sha256Digest>>)>>>;
type ReadOf = (
    Option<Option<Sha256Digest>>,
    Option<Option<u64>>,
    Option<Option<Sha256Digest>>,
);

/// A prefix that echoes the honest replicas' votes as B for a while, standard or coding,
/// so a cluster with a lossy replica finalizes without it; then it reads every honest
/// replica's marshal and B's.
struct Reads(ReadsSeen);

impl<P: Simplex> Prefix<P> for Reads
where
    P::Scheme: commonware_consensus::simplex::scheme::Scheme<CommitmentOf<P>>,
{
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(20),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            let honest = cx.honest();
            let (mut standard, mut coding) = (Echo::default(), Echo::default());
            let until = cx.now() + Duration::from_secs(15);
            while cx.now() < until {
                standard.step(&cx, &honest);
                coding.step_as::<P, CommitmentOf<P>>(&cx, &honest);
                cx.sleep(STEP).await;
            }
            let mut reads = Vec::new();
            for r in cx.honest() {
                reads.push((
                    cx.finalized_block(r, 1).await,
                    cx.processed_height(r).await,
                    cx.finalized_block(r, 1_000).await,
                ));
            }
            let byzantine = cx.byzantine().expect("a marshal base has B");
            let b = cx.finalized_block(byzantine, 1).await;
            *self.0.lock() = Some((reads, b));
        })
    }
}

#[test]
fn marshal_reads_answer_on_every_base() {
    for base in ALL {
        let seen = ReadsSeen::default();
        let watch = run(base, input(vec![6, 6], 3), Reads(seen.clone()));
        assert!(
            watch.ok_past_epoch_zero(base),
            "{base:?}: {:?}",
            watch.checks()
        );
        let (reads, b) = seen.lock().take().expect("the prefix read");
        // B has no marshal the runner reads.
        assert_eq!(b, None, "{base:?}");
        // Every honest marshal answers. A lossy replica of a poison base may not have
        // finalized height 1 yet; every other one has, and they agree.
        let mut digests = Vec::new();
        for (index, (finalized, processed, absent)) in reads.into_iter().enumerate() {
            let lossy = matches!(base, Base::Poison | Base::CodingPoison) && index == 2;
            match finalized {
                Some(Some(digest)) => {
                    digests.push(digest);
                    assert!(
                        matches!(processed, Some(Some(height)) if height >= 1),
                        "{base:?}: processed {processed:?}"
                    );
                }
                Some(None) if lossy => {
                    assert_eq!(processed, Some(Some(0)), "{base:?}");
                }
                _ => panic!("{base:?}: height 1 read {finalized:?}"),
            }
            assert_eq!(absent, Some(None), "{base:?}");
        }
        assert!(digests.len() >= 2, "{base:?}");
        assert!(
            digests.windows(2).all(|pair| pair[0] == pair[1]),
            "{base:?}"
        );
    }
}

#[test]
fn a_dead_marshal_read_is_no_answer() {
    use super::super::twins::stack::{genesis_block, setup_network, setup_validator};
    use commonware_consensus::marshal::{Start, mocks::block::ready};
    use commonware_cryptography::certificate::ConstantProvider;
    use futures::FutureExt as _;

    deterministic::Runner::default().start(|mut context| async move {
        let (participants, schemes) = SimplexCertificateMock::setup(&mut context, b"dead_read", 4);
        let mut oracle =
            setup_network::<SimplexCertificateMock>(context.child("network"), participants.clone())
                .await;
        let validator = setup_validator::<SimplexCertificateMock>(
            context.child("marshal"),
            &mut oracle,
            participants[1].clone(),
            ConstantProvider::new(schemes[1].clone()),
            Start::Genesis(ready(genesis_block::<SimplexCertificateMock>(
                participants[0].clone(),
            ))),
            None,
            commonware_utils::NZUsize!(8),
            None,
        )
        .await;
        let reads = StandardReads::<SimplexCertificateMock>::new(validator.mailbox.clone());
        // The actor was never started: dropping it closes its mailbox, and a read is
        // answered at its first poll, which the runner counts as no answer.
        drop(validator);
        assert_eq!(reads.finalized(1).now_or_never(), Some(None));
        assert_eq!(reads.processed().now_or_never(), Some(None));
    });
}

/// What [Boundary] read near the end of a long prefix: each honest replica's processed
/// height and its answers at the epoch-0 boundary and one past it.
type BoundarySeen = Arc<Mutex<Vec<(Option<Option<u64>>, bool, Option<Option<Sha256Digest>>)>>>;

/// A prefix that runs for most of the longest budget, then reads every honest marshal.
struct Boundary(BoundarySeen);

impl<P: Simplex> Prefix<P> for Boundary {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: continuation::MAX_PREFIX_BUDGET,
            release: FAULT_PHASE,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            cx.sleep(continuation::MAX_PREFIX_BUDGET - Duration::from_secs(2))
                .await;
            let last = BLOCKS_PER_EPOCH.get() - 1;
            for r in cx.honest() {
                let processed = cx.processed_height(r).await;
                let boundary = matches!(cx.finalized_block(r, last).await, Some(Some(_)));
                let past = cx.finalized_block(r, last + 1).await;
                self.0.lock().push((processed, boundary, past));
            }
        })
    }
}

#[test]
fn the_standard_epoch_boundary_is_safe() {
    // A minute of an honest cluster reaches the epoch-0 boundary, where the Deferred
    // wrapper re-proposes the boundary block; the release and the window run there.
    let seen = BoundarySeen::default();
    let watch = run(
        Base::Disrupter,
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

/// A prefix that waits, then reads every recorder of every honest replica and B's
/// inboxes; notes which logs had entries.
struct Recorders(Arc<Mutex<Vec<RecorderRead>>>);

/// A log a [Recorders] prefix read: its name, the replica, and whether it had entries.
type RecorderRead = (&'static str, usize, bool);

impl<P: Simplex> Prefix<P> for Recorders {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(5),
            release: Duration::ZERO,
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move {
            cx.sleep(Duration::from_secs(4)).await;
            let mut seen = self.0.lock();
            for r in cx.honest() {
                seen.push(("deliveries", r, !cx.deliveries(r).is_empty()));
                seen.push((
                    "marshal deliveries",
                    r,
                    !cx.marshal_deliveries(r).is_empty(),
                ));
                seen.push(("activities", r, !cx.activities(r).is_empty()));
                seen.push(("automaton", r, !cx.automaton(r).is_empty()));
                seen.push(("elections", r, !cx.elections(r).is_empty()));
                let _ = (cx.blocks(r), cx.held(r), cx.held_marshal(r));
            }
            seen.push(("inbox", 0, !cx.inbox().is_empty()));
            seen.push(("marshal inbox", 0, !cx.marshal_inbox().is_empty()));
        })
    }
}

#[test]
fn every_standard_recorder_is_fed() {
    for base in BASES {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let watch = run(base, input(vec![1, 1], 3), Recorders(seen.clone()));
        assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
        // No read was cut: the base feeds every recorder, and none reached its cap.
        assert!(watch.seen.lock().dropped.is_empty(), "{base:?}");
        // Every kind of log recorded something on some replica (a lossy replica may
        // have been asked nothing yet).
        let seen = seen.lock();
        let kinds: std::collections::BTreeSet<_> = seen.iter().map(|(log, ..)| *log).collect();
        for kind in kinds {
            assert!(
                seen.iter()
                    .any(|(log, _, recorded)| *log == kind && *recorded),
                "{base:?}: no {kind} recorded: {seen:?}"
            );
        }
    }
}

/// The view of an engine message that is a vote or a certificate.
fn view_of<P: Simplex>(inbound: &continuation::Inbound, scheme: &P::Scheme) -> Option<u64> {
    let view = match inbound.channel {
        Channel::Vote => {
            match Vote::<P::Scheme, Sha256Digest>::decode(inbound.payload.clone()).ok()? {
                Vote::Notarize(vote) => vote.proposal.round.view(),
                Vote::Nullify(vote) => vote.round.view(),
                Vote::Finalize(vote) => vote.proposal.round.view(),
            }
        }
        Channel::Certificate => match Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
            inbound.payload.clone(),
            &scheme.certificate_codec_config(),
        )
        .ok()?
        {
            Certificate::Notarization(certificate) => certificate.proposal.round.view(),
            Certificate::Nullification(certificate) => certificate.round.view(),
            Certificate::Finalization(certificate) => certificate.proposal.round.view(),
        },
        Channel::Resolver => return None,
    };
    Some(view.get())
}

/// Whether `inbound` is a vote of `kind` (0 notarize, 1 nullify, 2 finalize) for `view`.
fn is_vote<P: Simplex>(inbound: &continuation::Inbound, kind: usize, view: u64) -> bool {
    inbound.channel == Channel::Vote
        && matches!(
            (kind, Vote::<P::Scheme, Sha256Digest>::decode(inbound.payload.clone())),
            (0, Ok(Vote::Notarize(vote))) if vote.proposal.round.view().get() == view
        ) | matches!(
            (kind, Vote::<P::Scheme, Sha256Digest>::decode(inbound.payload.clone())),
            (1, Ok(Vote::Nullify(vote))) if vote.round.view().get() == view
        )
}

/// TS-0001 as a prefix: B leads v, T leads p2 = v - 1 and S and R are the other honest
/// replicas. Every message of p2 is held at S and T (but T's proposal at S) and every
/// message from p2 on at R, so all three nullify p2 while S and T also notarize it; S
/// and T then take everything and R only the nullification of p2. As the leader of v, B
/// builds one block on p2's and proposes it to S and T under the header that names p2
/// and to R under one that names p1 = v - 2; S, T and B notarize it, and R is passed
/// that notarization once it rejected its header.
struct Ts0001(Card);

impl<P: Simplex> Prefix<P> for Ts0001 {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget {
            prefix: Duration::from_secs(40),
            release: Duration::from_secs(1),
        }
    }

    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async move { ts0001(&cx, &self.0).await })
    }
}

async fn ts0001<P: Simplex>(cx: &PrefixContext<P>, card: &Card) {
    let (Some(b), Some(scheme)) = (cx.byzantine(), cx.scheme()) else {
        card.missed("E1", "the base runs no B");
        return;
    };
    // E1: the first view from 4 on that B leads, after two honest-led views.
    let Some(v) = (4..64u64).find(|v| {
        cx.leader(View::new(*v)) == b
            && cx.leader(View::new(v - 1)) != b
            && cx.leader(View::new(v - 2)) != b
    }) else {
        card.missed("E1", "B leads no view after two honest-led ones");
        return;
    };
    let (p1, p2) = (v - 2, v - 1);
    let t = cx.leader(View::new(p2));
    let honest = cx.honest();
    let r = *honest
        .iter()
        .find(|i| **i != t)
        .expect("three honest replicas");
    let s = *honest
        .iter()
        .find(|i| **i != t && **i != r)
        .expect("three honest replicas");
    card.held(
        "E1",
        format!("R={r} B={b} v={v} p1={p1} p2={p2} (S={s} T={t})"),
    );

    // Hold p2 at S and T (T's proposal reaches S) and everything from p2 on at R.
    let held = |replica: usize, from_p2_on: bool| {
        let scheme = scheme.clone();
        move |inbound: &continuation::Inbound| {
            if inbound.channel == Channel::Resolver {
                return true;
            }
            let Some(view) = view_of::<P>(inbound, &scheme) else {
                return false;
            };
            if from_p2_on {
                return view >= p2;
            }
            view == p2 && !(replica == s && inbound.from == Some(t) && is_vote::<P>(inbound, 0, p2))
        }
    };
    cx.hold(r, held(r, true));
    cx.hold(s, held(s, false));
    cx.hold(t, held(t, false));
    let mut echo = Echo {
        skip: Some((p2, v)),
        ..Echo::default()
    };
    // B notarizes T's proposal of p2, then nullifies p2 once all three honest did.
    let deadline = cx.now() + Duration::from_secs(15);
    let (mut notarized, mut nullifiers) = (false, Vec::new());
    while nullifiers.len() < 3 && cx.now() < deadline {
        echo.step(cx, &honest);
        let inbox = cx.inbox();
        if !notarized
            && let Some(proposal) = inbox.iter().find_map(|entry| {
                (entry.value.from == Some(t)).then_some(())?;
                match Vote::<P::Scheme, Sha256Digest>::decode(entry.value.payload.clone()).ok()? {
                    Vote::Notarize(vote) if vote.proposal.round.view().get() == p2 => {
                        Some(vote.proposal)
                    }
                    _ => None,
                }
            })
            && let Some(vote) = Notarize::sign(scheme, proposal)
        {
            cx.send(Channel::Vote, &honest, Vote::Notarize(vote).encode());
            notarized = true;
        }
        nullifiers = honest
            .iter()
            .copied()
            .filter(|replica| {
                inbox.iter().any(|entry| {
                    entry.value.from == Some(*replica) && is_vote::<P>(&entry.value, 1, p2)
                })
            })
            .collect();
        cx.sleep(STEP).await;
    }
    let round = |view: u64| Round::new(cx.epoch(), View::new(view));
    if let Some(vote) = Nullify::sign::<Sha256Digest>(scheme, round(p2)) {
        cx.send(
            Channel::Vote,
            &honest,
            Vote::<P::Scheme, Sha256Digest>::Nullify(vote).encode(),
        );
    }

    // E2: R finalized p1, holds the block of p2 and no certificate of it.
    let block_p2 = cx.marshal_inbox().iter().find_map(|entry| {
        (entry.value.channel == MarshalChannel::Broadcast).then_some(())?;
        let block = B::<P>::decode(entry.value.payload.clone()).ok()?;
        (block.context().round.view().get() == p2).then_some(block)
    });
    let Some(block_p2) = block_p2 else {
        card.missed(
            "E2",
            format!("B holds no block of p2; nullifiers {nullifiers:?}"),
        );
        return;
    };
    let finalized_p1 = cx.activities(r).iter().any(|entry| {
        matches!(&entry.value, commonware_consensus::simplex::types::Activity::Finalization(f)
                if f.proposal.round.view().get() == p1)
    });
    let stored_p2 = cx.marshal_deliveries(r).iter().any(|entry| {
        entry.value.channel == MarshalChannel::Broadcast
            && block_of::<P>(&entry.value.payload, block_p2.digest()).is_some()
    });
    let certified_p2 = cx.activities(r).iter().any(|entry| {
        matches!(&entry.value, commonware_consensus::simplex::types::Activity::Notarization(n)
            if n.proposal.round.view().get() == p2)
    });
    if !(finalized_p1 && stored_p2 && !certified_p2) || nullifiers.len() < 3 {
        card.missed(
            "E2",
            format!(
                "finalized p1 {finalized_p1}, block of p2 {stored_p2}, certificate of p2 \
                 {certified_p2}, nullifiers of p2 {nullifiers:?}"
            ),
        );
        return;
    }
    card.held("E2", "R finalized p1 and holds the block of p2 uncertified");

    // E3: S and T take everything; R only the nullification of p2.
    for replica in [s, t] {
        cx.hold(replica, |_| false);
        cx.pass(replica, |_| true);
    }
    let deadline = cx.now() + Duration::from_secs(5);
    let mut entered = false;
    while !entered && cx.now() < deadline {
        echo.step(cx, &honest);
        cx.pass(r, |inbound| {
            is_vote::<P>(inbound, 1, p2)
                || (inbound.channel == Channel::Certificate
                    && matches!(
                        Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                            inbound.payload.clone(),
                            &scheme.certificate_codec_config(),
                        ),
                        Ok(Certificate::Nullification(n)) if n.round.view().get() == p2
                    ))
        });
        entered = cx.elections(r).iter().any(|entry| entry.value.0.get() == v);
        cx.sleep(STEP).await;
    }
    if !entered {
        card.missed("E3", "R did not enter v");
        return;
    }
    card.held("E3", "R holds the nullification of p2 and is in v");

    // E4-E6: B proposes one block on p2's, under two headers.
    let context = commonware_consensus::simplex::types::Context {
        round: round(v),
        leader: cx.participants()[b].clone(),
        parent: (View::new(p2), block_p2.digest()),
    };
    let block = B::<P>::new::<commonware_cryptography::Sha256>(
        context,
        block_p2.digest(),
        block_p2.height.next(),
        0,
    );
    let d = block.digest();
    cx.send_marshal(MarshalChannel::Broadcast, &[r, s, t], block.encode());
    for (to, parent) in [(vec![s, t], p2), (vec![r], p1)] {
        if let Some(vote) = Notarize::sign(scheme, Proposal::new(round(v), View::new(parent), d)) {
            cx.send(Channel::Vote, &to, Vote::Notarize(vote).encode());
        }
    }
    let deadline = cx.now() + Duration::from_secs(6);
    let (mut verify, mut rejected, mut notarization, mut certify) = (false, false, false, None);
    while cx.now() < deadline && !(rejected && certify.is_some()) {
        cx.pass(r, |inbound| {
            (inbound.from == Some(b) && is_vote::<P>(inbound, 0, v))
                || (rejected
                    && inbound.channel == Channel::Certificate
                    && matches!(
                        Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                            inbound.payload.clone(),
                            &scheme.certificate_codec_config(),
                        ),
                        Ok(Certificate::Notarization(n))
                            if n.proposal.round.view().get() == v && n.proposal.payload == d
                    ))
        });
        let automaton = cx.automaton(r);
        verify |= automaton.iter().any(|entry| {
            matches!(&entry.value, continuation::AutomatonEvent::Verify { round, parent, payload, .. }
                if round.view().get() == v && parent.0.get() == p1 && *payload == d)
        });
        rejected |= automaton.iter().any(|entry| {
            matches!(&entry.value, continuation::AutomatonEvent::Verified { round, payload, valid }
                if round.view().get() == v && *payload == d
                    && *valid == continuation::Completion::Returned(false))
        });
        notarization |= cx.activities(r).iter().any(|entry| {
            matches!(&entry.value, commonware_consensus::simplex::types::Activity::Notarization(n)
                if n.proposal.round.view().get() == v && n.proposal.payload == d)
        });
        certify = certify.or_else(|| {
            automaton.iter().find_map(|entry| {
                matches!(&entry.value, continuation::AutomatonEvent::Certify { round, payload }
                    if round.view().get() == v && *payload == d)
                .then_some(entry.stamp.seq())
            })
        });
        cx.sleep(STEP).await;
    }
    // R's nullify of v, as B received it.
    let nullified = cx.inbox().iter().find_map(|entry| {
        (entry.value.from == Some(r) && is_vote::<P>(&entry.value, 1, v))
            .then_some(entry.stamp.seq())
    });
    let nullified_v = nullified.is_some();
    if verify {
        card.held("E4", "R verifies d for v under the header naming p1");
    } else {
        card.missed("E4", "R verified no d under the header naming p1");
        return;
    }
    if rejected && nullified_v {
        card.held("E5", "R rejected that header and nullified v");
    } else {
        card.missed(
            "E5",
            format!("rejected {rejected}, nullified v {nullified_v}"),
        );
    }
    if notarization {
        card.held("E6", "R holds the notarization of d for v under p2");
    } else {
        card.missed("E6", "R holds no notarization of d for v");
        return;
    }
    // E7 is a moment: R was asked to certify d after its nullify of v had reached B.
    match (certify, nullified) {
        (Some(asked), Some(nullify)) if nullify < asked => card.held(
            "E7",
            format!("R certifies d for v (at {asked}) holding its nullify of v (at {nullify})"),
        ),
        other => card.missed("E7", format!("certify and nullify of v at {other:?}")),
    }
}

#[test]
fn card_prefixes_leave_every_standard_base_reliable() {
    use arbitrary::{Arbitrary as _, Unstructured};

    // The canonical input, which a reach check replays, and a connected one.
    let canonical = MarshalDisrupterInput::arbitrary(&mut Unstructured::new(&[])).unwrap();
    for base in BASES {
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
            let card = Card::default();
            let watch = run(base, input, Ts0001(card.clone()));
            println!(
                "{}",
                card.report(&format!("TS-0001 on {base:?}, {name} input"))
            );
            assert!(watch.ok(), "{base:?}: {:?}", watch.checks());
            assert!(!watch.release().overran, "{base:?}");
        }
    }
}

mod coding;
mod twins;
