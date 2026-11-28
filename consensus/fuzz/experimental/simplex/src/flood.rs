//! A directed flood: one Byzantine participant sends honest engines far more votes
//! than the protocol needs, and the run checks that they keep bounded state and keep
//! finalizing.
//!
//! Four participants run on a connected, lossless network. Index 0 is the flooder
//! and runs no engine; the other three run production engines on the mock
//! certificate scheme. The flooder sends only votes it signs itself, for the run's
//! epoch, on the vote channel, in bursts of three classes ([`FloodClass`]). A burst
//! starts when the flooder first receives an honest vote for the burst's start view
//! or a later one. The first burst is [`FloodClass::Far`] and starts at view 1, so
//! every input floods; the flooder draws every later start view and class, and
//! every burst's size and votes, from its runtime context, with [`sample_next`] and
//! [`sample_burst`]. Each burst reports where on the input's random stream those draws
//! began, so a test can repeat them on [`stream_at`].
//!
//! The run ends once every honest node has finalized `required_containers`
//! containers; a stall ends it in the runtime's timeout panic (`C6-I4`). After
//! [`SETTLE`] it checks the three bounds of
//! [`commonware_consensus_fuzz_core::state_bounds`] (`C6-I1` to `C6-I3`) for every
//! honest node and then the safety invariants of the Standard driver.
//!
//! A tap on each honest node's vote receiver counts the flood votes its engine took,
//! by class. One run asserts nothing about these counts; [`check_floors`] does, over
//! the reports of [`fixed_corpus`] (`C6-I5`).

use crate::invariants;
use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_consensus::{
    Handoff, Monitor, Reporter as _, Viewable,
    simplex::{
        ForwardPolicy,
        types::{Activity, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Attributable, Epoch, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX, BlockFilterChoice, CertifyChoice, DEFAULT_MAILBOX_SIZE, EPOCH,
    FuzzInput as BaseInput, MAX_RAW_BYTES, MAX_TERM_LENGTH, N4F1C3, PublicKeyOf, ReporterWiring,
    SimplexCertificateMock, block_relay,
    byzantine::Counting,
    fuzz_mailbox_size, fuzz_runtime_timeout, sample_optimistic_views, setup_network,
    simplex::Simplex,
    simplex_audit::{ActivityRecorder, Event, summaries},
    spawn_filtered_validator_with_reporter,
    state_bounds::{self, Measurement, PeerVote, VoteKind},
    strategy::StrategyChoice,
    utils::Partition,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_runtime::{Clock, IoBuf, Metrics, Runner, Spawner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZU32, SystemTimeExt as _, sync::Mutex};
use futures::future::join_all;
use rand::{Rng, RngExt as _, TryCryptoRng, TryRng};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Fewest containers a run makes every honest node finalize.
pub const MIN_REQUIRED_CONTAINERS: u64 = 30;

/// Most containers a run makes every honest node finalize.
pub const MAX_REQUIRED_CONTAINERS: u64 = 60;

/// Most bursts of one run.
pub const MAX_BURSTS: u8 = 6;

/// Fewest votes of a [`FloodClass::Far`] or [`FloodClass::Repeat`] burst.
pub const MIN_BURST_VOTES: usize = 64;

/// Most votes of a burst of any class.
pub const MAX_BURST_VOTES: usize = 512;

/// A [`FloodClass::Far`] vote is at least this many views above the highest view of
/// any honest vote the flooder has received.
pub const FAR_DISTANCE: u64 = 1_000;

/// A [`FloodClass::Repeat`] burst's view is at most this many views below the
/// highest view the flooder has received.
pub const REPEAT_BEHIND: u64 = 2;

/// A [`FloodClass::Repeat`] burst's view is at most this many views above the
/// highest view the flooder has received.
pub const REPEAT_AHEAD: u64 = 1;

/// A [`FloodClass::Sweep`] burst covers this many views on each side of the highest
/// view the flooder has received.
pub const SWEEP_RADIUS: u64 = 12;

/// Simulated time between the last required finalization and the measurement.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Votes of each class every honest node must have taken over [`fixed_corpus`].
pub const FLOOR: u64 = 64;

/// Seeds of [`fixed_corpus`]: `0..FIXED_SEEDS`.
pub const FIXED_SEEDS: u64 = 25;

/// Containers of every [`fixed_corpus`] input.
pub const FIXED_CONTAINERS: u64 = 40;

/// Bursts of every [`fixed_corpus`] input.
pub const FIXED_BURSTS: u8 = 3;

/// Label the flooder's sends count under.
pub const ACTOR: &str = "flooder";

/// Participant index of the flooder.
pub const FLOODER: usize = BYZANTINE_IDX;

/// The kinds a [`FloodClass::Far`] vote is drawn from.
const KINDS: [VoteKind; 3] = [VoteKind::Notarize, VoteKind::Nullify, VoteKind::Finalize];

/// Bytes [`stream_at`] skips at a time.
const STREAM_SKIP: usize = 4_096;

const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

type P = SimplexCertificateMock;
type Scheme = <P as Simplex>::Scheme;
type PublicKey = PublicKeyOf<P>;
type Recorder =
    ActivityRecorder<deterministic::Context, Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// What a burst sends, relative to `seen`, the highest view of any honest vote the
/// flooder has received when the burst starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FloodClass {
    /// Votes of any kind for views drawn from `seen + FAR_DISTANCE` up to the highest
    /// view there is: far beyond what any honest engine may track.
    Far,
    /// Notarize votes for one view within [`REPEAT_BEHIND`] and [`REPEAT_AHEAD`] of
    /// `seen`: the first vote and exact copies of it at the even positions, and a
    /// vote for another payload at every odd position.
    Repeat,
    /// One notarize, one nullify and one finalize vote for every view within
    /// [`SWEEP_RADIUS`] of `seen`: both edges of what an engine tracks.
    Sweep,
}

impl FloodClass {
    pub const ALL: [Self; 3] = [Self::Far, Self::Repeat, Self::Sweep];
}

/// Votes by [`FloodClass`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassCounts {
    pub far: u64,
    pub repeat: u64,
    pub sweep: u64,
}

impl ClassCounts {
    pub const fn of(&self, class: FloodClass) -> u64 {
        match class {
            FloodClass::Far => self.far,
            FloodClass::Repeat => self.repeat,
            FloodClass::Sweep => self.sweep,
        }
    }

    const fn add(&mut self, class: FloodClass, votes: u64) {
        match class {
            FloodClass::Far => self.far += votes,
            FloodClass::Repeat => self.repeat += votes,
            FloodClass::Sweep => self.sweep += votes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzInput {
    /// Seeds the runtime, whose context the flooder draws its bursts from.
    pub raw_bytes: Vec<u8>,
    /// Containers every honest node must finalize.
    pub required_containers: u64,
    pub term_length: TermLength,
    /// Optimistic lookahead of every honest engine.
    pub optimistic_views: ViewDelta,
    /// Mailbox capacity of every honest engine.
    pub mailbox_size: NonZeroUsize,
    /// Bursts the flooder sends.
    pub bursts: u8,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        // A copy of the whole input, so the runtime's tape differs between short
        // inputs although the fields below read the same first bytes.
        let raw_bytes = u
            .peek_bytes(u.len().min(MAX_RAW_BYTES))
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let required_containers =
            u.int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTAINERS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));
        let optimistic_views = ViewDelta::new(sample_optimistic_views(u, term_length)?);
        let mailbox_size = fuzz_mailbox_size(u)?;
        let bursts = u.int_in_range(1..=MAX_BURSTS)?;
        Ok(Self {
            raw_bytes,
            required_containers,
            term_length,
            optimistic_views,
            mailbox_size,
            bursts,
        })
    }
}

/// A fault planted into one run, for the negative controls of the invariants.
/// [`fuzz`] and [`run`] plant none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    /// At the measurement, the reporter of honest participant `node` is given one
    /// notarize vote of the flooder [`FAR_DISTANCE`] views beyond the node's
    /// admission bound; the engine's state does not change. `C6-I1` must fire.
    FarVote { node: usize },
    /// At the measurement, the reporter of honest participant `node` is given every
    /// peer vote it recorded a second time. `C6-I2` must fire.
    DuplicateVotes { node: usize },
    /// Honest participant `node` has no link to the other two honest participants
    /// for the whole run. The flooder never votes honestly, so no quorum is left and
    /// the run must end in the runtime's timeout panic.
    Isolate { node: usize },
    /// The taps do not count the [`FloodClass::Sweep`] votes they see; what is sent,
    /// taken and recorded does not change. [`check_floors`] must fail.
    UncountedSweep,
}

/// One burst, as the flooder sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burst {
    pub class: FloodClass,
    /// The burst waited for an honest vote for this view or a later one.
    pub start: View,
    /// Position in [`Report::heard`] of the honest vote that started the burst.
    pub trigger: usize,
    /// The highest view of any honest vote the flooder had received when the burst
    /// started.
    pub seen: View,
    /// Bytes drawn from the run's random stream ([`stream_at`]) before the flooder
    /// drew this burst's start view and class with [`sample_next`]: `previous` was
    /// the start view of the burst before, `last_start` the input's
    /// `required_containers`, `after` the number of bursts after this one. `None`
    /// for the first burst, whose start view and class are fixed.
    pub scheduled_at: Option<u64>,
    /// Bytes drawn from the run's random stream before the flooder drew this burst's
    /// votes with [`sample_burst`], on `class` and `seen`.
    pub sampled_at: u64,
    /// The encoded votes handed to the network so far, in send order: the drawn
    /// choices, signed. Each one went to all three honest nodes.
    pub votes: Vec<Vec<u8>>,
}

/// What one honest node did with the flood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Participant index.
    pub index: usize,
    /// Flood votes the node's engine took off its vote channel, as the tap counted
    /// them.
    pub taken: ClassCounts,
    /// Every flood vote the node's engine took off its vote channel, encoded, in
    /// the order taken.
    pub received: Vec<Vec<u8>>,
    /// Flood votes in the node's peer-vote log.
    pub recorded: ClassCounts,
    /// Containers the node finalized.
    pub finalized: u64,
    /// The node's state at the measurement, its bounds and its peer-vote log.
    pub measured: Measurement<Sha256Digest>,
}

/// The outcome of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The view of every honest vote the flooder received, in the order received.
    pub heard: Vec<View>,
    /// The bursts, in the order started.
    pub bursts: Vec<Burst>,
    /// Simulated time at which every honest node had finalized the required
    /// containers.
    pub finalized_at: Duration,
    /// Simulated time of the measurement.
    pub measured_at: Duration,
    /// The honest nodes, by participant index.
    pub nodes: Vec<Node>,
}

impl Report {
    /// Votes of each class the flooder handed to the network.
    pub fn sent(&self) -> ClassCounts {
        let mut sent = ClassCounts::default();
        for burst in &self.bursts {
            sent.add(burst.class, burst.votes.len() as u64);
        }
        sent
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sent = self.sent();
        write!(
            f,
            "bursts={} sent(far,repeat,sweep)=({},{},{})",
            self.bursts.len(),
            sent.far,
            sent.repeat,
            sent.sweep
        )?;
        for node in &self.nodes {
            write!(
                f,
                " | node {}: taken=({},{},{}) recorded=({},{},{}) peer_votes={} finalized={} g={} T={} A={} F2={} bound={}",
                node.index,
                node.taken.far,
                node.taken.repeat,
                node.taken.sweep,
                node.recorded.far,
                node.recorded.repeat,
                node.recorded.sweep,
                node.measured.peer_votes.len(),
                node.finalized,
                node.measured.current,
                node.measured.tracked,
                node.measured.admission,
                node.measured.second_finalization,
                node.measured.retained.unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}

/// One vote the flooder chose to send: what it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Choice {
    pub kind: VoteKind,
    pub view: View,
    /// The payload voted for; `None` for a nullify.
    pub payload: Option<Sha256Digest>,
}

impl Choice {
    /// The choice an encoded vote of the flooder was signed from.
    pub fn of(vote: &[u8]) -> Self {
        match Vote::<Scheme, Sha256Digest>::decode(Copying(vote))
            .expect("the flooder encoded the vote")
        {
            Vote::Notarize(vote) => Self {
                kind: VoteKind::Notarize,
                view: vote.view(),
                payload: Some(vote.proposal.payload),
            },
            Vote::Nullify(vote) => Self {
                kind: VoteKind::Nullify,
                view: vote.view(),
                payload: None,
            },
            Vote::Finalize(vote) => Self {
                kind: VoteKind::Finalize,
                view: vote.view(),
                payload: Some(vote.proposal.payload),
            },
        }
    }
}

/// Draws the votes of one burst of `class`, in send order, for a flooder whose
/// highest received view is `seen`.
///
/// The flooder calls this on its runtime context. Called on [`stream_at`] the
/// burst's [`Burst::sampled_at`], it returns the choices behind [`Burst::votes`].
pub fn sample_burst(rng: &mut impl Rng, class: FloodClass, seen: View) -> Vec<Choice> {
    let seen = seen.get();
    match class {
        FloodClass::Far => {
            let size = rng.random_range(MIN_BURST_VOTES..=MAX_BURST_VOTES);
            let lowest = seen.saturating_add(FAR_DISTANCE);
            (0..size)
                .map(|_| {
                    let view = View::new(rng.random_range(lowest..=u64::MAX));
                    let payload = Sha256Digest::from(rng.random::<[u8; 32]>());
                    let kind = KINDS[rng.random_range(0..KINDS.len())];
                    Choice {
                        kind,
                        view,
                        payload: (kind != VoteKind::Nullify).then_some(payload),
                    }
                })
                .collect()
        }
        FloodClass::Repeat => {
            let size = rng.random_range(MIN_BURST_VOTES..=MAX_BURST_VOTES);
            let lowest = seen.saturating_sub(REPEAT_BEHIND).max(1);
            let view = View::new(rng.random_range(lowest..=seen.saturating_add(REPEAT_AHEAD)));
            // The position in the last bytes keeps the payloads of one burst distinct.
            let seed = rng.random::<[u8; 32]>();
            let notarize = |position: usize| {
                let mut bytes = seed;
                let position = (position as u64).to_be_bytes();
                bytes[seed.len() - position.len()..].copy_from_slice(&position);
                Choice {
                    kind: VoteKind::Notarize,
                    view,
                    payload: Some(Sha256Digest::from(bytes)),
                }
            };
            (0..size)
                .map(|position| notarize(if position % 2 == 1 { position } else { 0 }))
                .collect()
        }
        FloodClass::Sweep => {
            let lowest = seen.saturating_sub(SWEEP_RADIUS).max(1);
            (lowest..=seen.saturating_add(SWEEP_RADIUS))
                .flat_map(|view| {
                    let view = View::new(view);
                    let payload = Some(Sha256Digest::from(rng.random::<[u8; 32]>()));
                    [
                        Choice {
                            kind: VoteKind::Notarize,
                            view,
                            payload,
                        },
                        Choice {
                            kind: VoteKind::Nullify,
                            view,
                            payload: None,
                        },
                        Choice {
                            kind: VoteKind::Finalize,
                            view,
                            payload,
                        },
                    ]
                })
                .collect()
        }
    }
}

/// Draws the start view and the class of the burst after one that waited for
/// `previous`. `after` more bursts follow the drawn one and no burst waits for a view
/// beyond `last_start`, so start views increase and each leaves a view for every
/// later burst.
///
/// The flooder calls this on its runtime context. Called on [`stream_at`] a burst's
/// [`Burst::scheduled_at`], it returns that burst's start view and class.
pub fn sample_next(
    rng: &mut impl Rng,
    previous: View,
    last_start: View,
    after: u64,
) -> (View, FloodClass) {
    let lowest = previous.get().saturating_add(1);
    let highest = last_start.get().saturating_sub(after).max(lowest);
    let start = View::new(rng.random_range(lowest..=highest));
    let class = FloodClass::ALL[rng.random_range(0..FloodClass::ALL.len())];
    (start, class)
}

/// The random stream of a run on `raw_bytes`, after `drawn` bytes were drawn from it.
///
/// The runtime of a run draws all its randomness from this one stream, the flooder's
/// choices included.
pub fn stream_at(raw_bytes: &[u8], drawn: u64) -> FuzzRng {
    let mut stream = FuzzRng::new(raw_bytes.to_vec());
    let mut skipped = [0; STREAM_SKIP];
    let mut left = drawn;
    while left > 0 {
        let step = left.min(STREAM_SKIP as u64) as usize;
        stream.fill_bytes(&mut skipped[..step]);
        left -= step as u64;
    }
    stream
}

/// The runtime's RNG: the [`FuzzRng`] stream of the input, counting the bytes drawn
/// from it.
pub(crate) struct Tape {
    stream: FuzzRng,
    drawn: Arc<AtomicU64>,
}

impl Tape {
    /// The stream of `raw_bytes`, adding every byte drawn from it to `drawn`.
    pub(crate) fn new(raw_bytes: &[u8], drawn: Arc<AtomicU64>) -> Self {
        Self {
            stream: FuzzRng::new(raw_bytes.to_vec()),
            drawn,
        }
    }

    fn count(&self, bytes: usize) {
        self.drawn.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

impl TryRng for Tape {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.count(size_of::<u32>());
        self.stream.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.count(size_of::<u64>());
        self.stream.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.count(dest.len());
        self.stream.try_fill_bytes(dest)
    }
}

impl TryCryptoRng for Tape {}

/// The class of every vote the flooder has sent, by its encoding. The taps read it.
type Sent = Arc<Mutex<BTreeMap<Vec<u8>, FloodClass>>>;

/// What the flooder heard and sent.
#[derive(Default)]
struct Trace {
    heard: Vec<View>,
    bursts: Vec<Burst>,
}

struct Flooder<S, R> {
    context: deterministic::Context,
    scheme: Scheme,
    sender: S,
    receiver: R,
    honest: usize,
    bursts: u8,
    /// The last view a burst may wait for: every run gets past it.
    last_start: u64,
    /// Bytes drawn from the runtime's RNG so far.
    drawn: Arc<AtomicU64>,
    sent: Sent,
    trace: Arc<Mutex<Trace>>,
}

impl<S, R> Flooder<S, R>
where
    S: LimitedSender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    fn sign(&self, choice: &Choice) -> Vec<u8> {
        let round = Round::new(Epoch::new(EPOCH), choice.view);
        let vote = match choice.kind {
            VoteKind::Nullify => Vote::<Scheme, Sha256Digest>::Nullify(
                Nullify::<Scheme>::sign::<Sha256Digest>(&self.scheme, round)
                    .expect("the flooder signs"),
            ),
            kind => {
                let proposal = Proposal::new(
                    round,
                    View::new(choice.view.get().saturating_sub(1)),
                    choice
                        .payload
                        .expect("a notarize or finalize choice has a payload"),
                );
                if kind == VoteKind::Notarize {
                    Vote::Notarize(
                        Notarize::sign(&self.scheme, proposal).expect("the flooder signs"),
                    )
                } else {
                    Vote::Finalize(
                        Finalize::sign(&self.scheme, proposal).expect("the flooder signs"),
                    )
                }
            }
        };
        vote.encode().to_vec()
    }

    /// Signs and encodes `choices`. A choice equal to the first one reuses its bytes,
    /// so a repeated vote is the same message, signature included.
    fn encode(&self, choices: &[Choice]) -> Vec<Vec<u8>> {
        let mut votes: Vec<Vec<u8>> = Vec::with_capacity(choices.len());
        for choice in choices {
            let vote = match votes.first() {
                Some(first) if *choice == choices[0] => first.clone(),
                _ => self.sign(choice),
            };
            votes.push(vote);
        }
        votes
    }

    /// Hands `vote` to the network for every honest node, waiting out the rate limit.
    async fn send(&mut self, vote: &[u8]) {
        loop {
            match self.sender.check(Recipients::All) {
                Ok(checked) => {
                    assert_eq!(
                        checked.recipients().len(),
                        self.honest,
                        "a flood vote goes to every honest node"
                    );
                    assert!(
                        checked.send(IoBuf::from(vote.to_vec()), true).accepted(),
                        "the network refused a flood vote"
                    );
                    return;
                }
                Err(retry) => self.context.sleep_until(retry).await,
            }
        }
    }

    async fn run(mut self) {
        let mut seen = 0;
        let mut next = Some((1, FloodClass::Far, None));
        loop {
            let Ok((_, message)) = self.receiver.recv().await else {
                return;
            };
            let Ok(vote) = Vote::<Scheme, Sha256Digest>::decode(message) else {
                continue;
            };
            let view = vote.view().get();
            seen = seen.max(view);
            let trigger = {
                let mut trace = self.trace.lock();
                trace.heard.push(View::new(view));
                trace.heard.len() - 1
            };
            let Some((start, class, scheduled_at)) = next else {
                continue;
            };
            if view < start {
                continue;
            }

            let sampled_at = self.drawn.load(Ordering::Relaxed);
            let choices = sample_burst(&mut self.context, class, View::new(seen));
            let votes = self.encode(&choices);
            {
                let mut sent = self.sent.lock();
                for vote in &votes {
                    sent.entry(vote.clone()).or_insert(class);
                }
            }
            let index = {
                let mut trace = self.trace.lock();
                trace.bursts.push(Burst {
                    class,
                    start: View::new(start),
                    trigger,
                    seen: View::new(seen),
                    scheduled_at,
                    sampled_at,
                    votes: Vec::with_capacity(votes.len()),
                });
                trace.bursts.len() - 1
            };
            for vote in votes {
                self.send(&vote).await;
                self.trace.lock().bursts[index].votes.push(vote);
            }

            let started = index as u64 + 1;
            next = (started < u64::from(self.bursts)).then(|| {
                let scheduled_at = self.drawn.load(Ordering::Relaxed);
                let (start, class) = sample_next(
                    &mut self.context,
                    View::new(start),
                    View::new(self.last_start),
                    u64::from(self.bursts) - started - 1,
                );
                (start.get(), class, Some(scheduled_at))
            });
        }
    }
}

/// What a [`Tap`] saw.
#[derive(Default)]
struct Taken {
    counts: ClassCounts,
    votes: Vec<Vec<u8>>,
}

/// Counts, by class, the flood votes an honest engine takes off its vote channel.
struct Tap<R> {
    inner: R,
    flooder: PublicKey,
    sent: Sent,
    taken: Arc<Mutex<Taken>>,
    uncounted_sweep: bool,
}

impl<R> fmt::Debug for Tap<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tap").finish()
    }
}

impl<R: Receiver<PublicKey = PublicKey>> Receiver for Tap<R> {
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let (sender, message) = self.inner.recv().await?;
        if sender == self.flooder
            && let Some(class) = self.sent.lock().get(message.as_ref()).copied()
        {
            let mut taken = self.taken.lock();
            taken.votes.push(message.as_ref().to_vec());
            if !(self.uncounted_sweep && class == FloodClass::Sweep) {
                taken.counts.add(class, 1);
            }
        }
        Ok((sender, message))
    }

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }
}

struct Honest {
    index: usize,
    validator: PublicKey,
    recorder: Recorder,
    taken: Arc<Mutex<Taken>>,
}

/// The Standard-driver input the flood runs on: one Byzantine participant of four on
/// a connected, lossless network, with every honest engine policy at its default.
fn base(input: &FuzzInput) -> BaseInput {
    BaseInput {
        raw_bytes: input.raw_bytes.clone(),
        required_containers: input.required_containers,
        term_length: input.term_length,
        optimistic_views: input.optimistic_views,
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration: N4F1C3,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        mailbox_size: input.mailbox_size,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

/// The flood votes in `peer_votes`, by the class of the burst that sent them.
fn recorded(bursts: &[Burst], peer_votes: &[PeerVote<Sha256Digest>]) -> ClassCounts {
    let mut classes = BTreeMap::new();
    for burst in bursts {
        for vote in &burst.votes {
            classes.entry(Choice::of(vote)).or_insert(burst.class);
        }
    }
    let mut recorded = ClassCounts::default();
    for vote in peer_votes {
        let choice = Choice {
            kind: vote.kind,
            view: vote.view,
            payload: vote.payload,
        };
        if usize::from(vote.signer) == FLOODER
            && let Some(class) = classes.get(&choice)
        {
            recorded.add(*class, 1);
        }
    }
    recorded
}

/// Runs the flood on `input` with `plant` and returns what happened.
///
/// # Panics
///
/// Panics with the id of the violated invariant first, or with the runtime's
/// timeout when the honest nodes stop finalizing.
pub fn run_planted(input: &FuzzInput, plant: Option<Plant>) -> Report {
    let base = base(input);
    let drawn = Arc::new(AtomicU64::new(0));
    let tape: deterministic::BoxDynRng = Box::new(Tape::new(&input.raw_bytes, drawn.clone()));
    let cfg = deterministic::Config::new()
        .with_rng(tape)
        .with_timeout(Some(fuzz_runtime_timeout(input.required_containers, 0)));
    let required = input.required_containers;
    let bursts = input.bursts;
    deterministic::Runner::new(cfg).start(move |mut context| async move {
        let config = base.configuration;
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &base).await;
        let honest = (config.faults as usize)..(config.n as usize);
        if let Some(Plant::Isolate { node }) = plant {
            for peer in honest.clone().filter(|peer| *peer != node) {
                for (from, to) in [(node, peer), (peer, node)] {
                    oracle
                        .remove_link(participants[from].clone(), participants[to].clone())
                        .await
                        .expect("honest participants are linked");
                }
            }
        }

        let flooder = participants[FLOODER].clone();
        let sent = Sent::default();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let ((vote_sender, vote_receiver), certificates, backfill) =
            registrations.remove(&flooder).unwrap();
        context
            .child("validator")
            .with_attribute("public_key", &flooder)
            .child("flooder")
            .spawn({
                let scheme = schemes[FLOODER].clone();
                let honest = honest.len();
                let sent = sent.clone();
                let trace = trace.clone();
                move |context| async move {
                    // The flooder stays registered on the channels it never uses.
                    let _unused = (certificates, backfill);
                    Flooder {
                        context,
                        scheme,
                        sender: Counting::new(vote_sender, ACTOR),
                        receiver: vote_receiver,
                        honest,
                        bursts,
                        last_start: required,
                        drawn,
                        sent,
                        trace,
                    }
                    .run()
                    .await;
                }
            });

        let relay = Arc::new(block_relay::Relay::new());
        let mut nodes = Vec::new();
        for index in honest {
            let validator = participants[index].clone();
            let ((vote_sender, vote_receiver), recovered, resolver) =
                registrations.remove(&validator).unwrap();
            let taken = Arc::new(Mutex::new(Taken::default()));
            let tap = Tap {
                inner: vote_receiver,
                flooder: flooder.clone(),
                sent: sent.clone(),
                taken: taken.clone(),
                uncounted_sweep: plant == Some(Plant::UncountedSweep),
            };
            let recorder = spawn_filtered_validator_with_reporter::<P, _, Recorder, _, _, _, _, _, _>(
                context
                    .child("validator")
                    .with_attribute("public_key", &validator),
                &oracle,
                &participants,
                schemes[index].clone(),
                validator.clone(),
                P::elector(base.term_length, base.optimistic_views),
                relay.clone(),
                LEADER_TIMEOUT,
                CERTIFICATION_TIMEOUT,
                base.mailbox_size,
                base.forwarding,
                (vote_sender, tap),
                recovered,
                resolver,
                base.certify,
                base.handoff,
                base.reporting,
            );
            nodes.push(Honest {
                index,
                validator,
                recorder,
                taken,
            });
        }

        let mut finalizers = Vec::new();
        for node in nodes.iter_mut() {
            let (_, mut monitor) = node.recorder.subscribe().await;
            let reporter = node.recorder.recording().inner().clone();
            finalizers.push(
                context
                    .child("finalizer")
                    .with_attribute("public_key", &node.validator)
                    .spawn(move |_| async move {
                        while (reporter.finalizations.lock().len() as u64) < required {
                            monitor.recv().await.expect("event missing");
                        }
                    }),
            );
        }
        join_all(finalizers).await;
        let finalized_at = context.current().epoch();
        context.sleep(SETTLE).await;

        let measured_at = context.current().epoch();
        let metrics = context.encode();
        let (heard, bursts) = {
            let trace = trace.lock();
            (trace.heard.clone(), trace.bursts.clone())
        };
        let mut report = Report {
            heard,
            bursts,
            finalized_at,
            measured_at,
            nodes: Vec::new(),
        };
        for node in &nodes {
            let label = state_bounds::Node::public_key(&node.validator);
            let recording = node.recorder.recording();
            let me = recording.me().expect("an honest engine signs");
            match plant {
                Some(Plant::FarVote { node: planted }) if planted == node.index => {
                    let current =
                        View::new(state_bounds::gauge(&metrics, state_bounds::CURRENT_VIEW, &label));
                    let bound = state_bounds::admission_bound(
                        current,
                        base.term_length,
                        base.optimistic_views,
                    );
                    let vote = Notarize::sign(
                        &schemes[FLOODER],
                        Proposal::new(
                            Round::new(
                                Epoch::new(EPOCH),
                                View::new(bound.get() + FAR_DISTANCE),
                            ),
                            current,
                            Sha256Digest::from([0; 32]),
                        ),
                    )
                    .expect("the flooder signs");
                    node.recorder.clone().report(Activity::Notarize(vote));
                }
                Some(Plant::DuplicateVotes { node: planted }) if planted == node.index => {
                    for recorded in recording.audit().events() {
                        let Event::Activity { activity, .. } = recorded.event else {
                            continue;
                        };
                        let signer = match &activity {
                            Activity::Notarize(vote) => vote.signer(),
                            Activity::Nullify(vote) => vote.signer(),
                            Activity::Finalize(vote) => vote.signer(),
                            _ => continue,
                        };
                        if signer != me {
                            node.recorder.clone().report(activity);
                        }
                    }
                }
                _ => {}
            }
            let measured = state_bounds::check(
                &metrics,
                &label,
                &recording.audit().events(),
                me,
                base.term_length,
                base.optimistic_views,
                config.can_finalize(),
            );
            let taken = node.taken.lock();
            report.nodes.push(Node {
                index: node.index,
                taken: taken.counts,
                received: taken.votes.clone(),
                recorded: recorded(&report.bursts, &measured.peer_votes),
                finalized: recording.inner().finalizations.lock().len() as u64,
                measured,
            });
        }

        let recordings: Vec<_> = nodes
            .iter()
            .map(|node| node.recorder.recording().clone())
            .collect();
        invariants::check_no_invalid_certificates(&recordings);
        invariants::check_recorded_vote_invariants(
            config.faults as usize,
            P::elector(base.term_length, base.optimistic_views),
            Epoch::new(EPOCH),
            base.term_length,
            base.optimistic_views,
            base.handoff,
            &recordings,
        );
        invariants::check::<P>(
            config,
            base.term_length,
            base.optimistic_views,
            invariants::extract(summaries(&recordings), config.n as usize),
        );
        report
    })
}

/// Runs the flood on `input` and returns what happened. See [`run_planted`].
pub fn run(input: &FuzzInput) -> Report {
    run_planted(input, None)
}

pub fn fuzz(input: FuzzInput) {
    run(&input);
}

/// The inputs [`check_floors`] is made for: every seed below [`FIXED_SEEDS`] (as
/// eight big-endian bytes) with a single-view and the longest term, each without
/// lookahead and with a lookahead of the term length.
pub fn fixed_corpus() -> Vec<FuzzInput> {
    let mut corpus = Vec::new();
    for seed in 0..FIXED_SEEDS {
        for term_length in [1, MAX_TERM_LENGTH] {
            for optimistic_views in [0, u64::from(term_length)] {
                corpus.push(FuzzInput {
                    raw_bytes: seed.to_be_bytes().to_vec(),
                    required_containers: FIXED_CONTAINERS,
                    term_length: TermLength::new(NZU32!(term_length)),
                    optimistic_views: ViewDelta::new(optimistic_views),
                    mailbox_size: DEFAULT_MAILBOX_SIZE,
                    bursts: FIXED_BURSTS,
                });
            }
        }
    }
    corpus
}

/// `C6-I5`: over `reports`, every honest node took at least [`FLOOR`] votes of each
/// class, and some node recorded a [`FloodClass::Sweep`] vote. Otherwise the runs
/// did not put the bounds under the load they are meant for.
pub fn check_floors(reports: &[Report]) -> Result<(), String> {
    let mut taken: BTreeMap<usize, ClassCounts> = BTreeMap::new();
    let mut swept = 0;
    for node in reports.iter().flat_map(|report| &report.nodes) {
        let total = taken.entry(node.index).or_default();
        for class in FloodClass::ALL {
            total.add(class, node.taken.of(class));
        }
        swept += node.recorded.sweep;
    }
    if taken.is_empty() {
        return Err("C6-I5 vacuous: no honest node was measured".into());
    }
    for (index, total) in &taken {
        for class in FloodClass::ALL {
            if total.of(class) < FLOOR {
                return Err(format!(
                    "C6-I5 vacuous: node {index} took {} {class:?} votes, below {FLOOR}",
                    total.of(class)
                ));
            }
        }
    }
    if swept == 0 {
        return Err("C6-I5 vacuous: no Sweep vote was recorded".into());
    }
    Ok(())
}
