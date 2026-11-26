//! Equivocation evidence: one Byzantine participant sends honest engines conflicting
//! pairs of votes, and the run checks that every pair an engine held in full is
//! exported as fault evidence, passes the export wrapper and gets the sender blocked.
//!
//! Four participants run on a connected, lossless network with the production
//! ed25519 scheme. Index 0 is the equivocator and runs no engine; the other three
//! run production engines with `track_historical_votes` as the input says. The
//! equivocator sends only votes it signs itself, for the run's epoch, on the vote
//! channel. When it first receives an honest vote for a view it draws the view's
//! plan with [`sample_plan`]: a [`PairKind`] and a delay in views. It sends the
//! pair's first vote when it first receives the honest vote the kind waits for. The
//! second vote follows once the first is sent and some honest vote received in the
//! run, before or after, is for a view at least the delay above the pair's: right
//! after the first vote, or at the first such honest vote later. Each draw reports
//! where on the input's random stream it began, so a test can repeat it on
//! [`stream_at`].
//!
//! Every honest node keeps three logs. A [`Tap`] on its vote receiver appends each
//! message of the equivocator together with the voter's view at that moment, the
//! [`Raw`] log appends each activity the engine exports, and one [`Sequence`] orders
//! both. Behind the raw log the documented export path, `AttributableReporter`,
//! forwards into the forwarded log.
//!
//! The run ends once every honest node has finalized `required_containers`
//! containers; a stall ends it in the runtime's timeout panic. After [`SETTLE`] it
//! reads the block list once and evaluates the logs with [`evaluate`]. A pair is an
//! obligation at a node when the node took both votes, recorded the first and was
//! certain to admit the second ([`obligations`]). Every obligation must have its
//! evidence in the raw log (`C4-I1`) and in the forwarded log (`C4-I2`), every node
//! with an obligation must have blocked the equivocator (`C4-I3`), and no evidence
//! may name another signer (`C4-I4`). The safety invariants of the Standard driver
//! run last.
//!
//! One run may hold no obligation. [`check_floors`] asserts over the reports of
//! [`fixed_corpus`] that every kind was measured, also after the certificate of its
//! first vote (`C4-I5`).
//!
//! Not asserted: a run without `track_historical_votes` (its late pairs without
//! evidence are counted), a pair no single node took in full, two different nullify
//! votes, and evidence across a restart.

pub use crate::flood::stream_at;
use crate::{flood::Tape, invariants};
use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::Feedback;
use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_consensus::{
    Handoff, Monitor, Reporter, Reporters, Viewable,
    simplex::{
        ForwardPolicy,
        mocks::{application, relay, reporter},
        scheme::reporter::AttributableReporter,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalize, Notarize,
            Nullify, NullifyFinalize, Proposal, Vote,
        },
    },
    types::{Epoch, Participant, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX, BlockFilterChoice, CertifyChoice, DEFAULT_MAILBOX_SIZE, EPOCH,
    FuzzInput as BaseInput, MAX_RAW_BYTES, MAX_TERM_LENGTH, N4F1C3, PublicKeyOf, ReporterWiring,
    bounded_fuzz_runtime_config,
    byzantine::Counting,
    reach, sample_optimistic_views, setup_network,
    simplex::{Simplex, SimplexEd25519},
    simplex_audit::{ActivityRecorder, summaries},
    start_validator_engine,
    state_bounds::{self, VIEW_RETENTION, term_end},
    strategy::StrategyChoice,
    utils::{Action, Partition, link_peers},
};
use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
use commonware_p2p::{
    BlockedSubscription, Blocker, CheckedSender, LimitedSender, Receiver, Recipients,
    simulated::Link,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, IoBuf, Metrics, Runner, Spawner, Supervisor as _, deterministic};
use commonware_utils::{NZU32, SystemTimeExt as _, TestRng, probability, sync::Mutex};
use futures::future::join_all;
use rand::{Rng, RngExt as _};
use std::{
    collections::BTreeMap,
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Fewest containers a run makes every honest node finalize.
pub const MIN_REQUIRED_CONTAINERS: u64 = 20;

/// Most containers a run makes every honest node finalize.
pub const MAX_REQUIRED_CONTAINERS: u64 = 40;

/// Shortest term of a run, in views.
pub const MIN_TERM_LENGTH: u32 = 1;

/// Lowest latency of every link, in milliseconds.
pub const MIN_LATENCY_MS: u64 = 1;

/// Highest latency of every link, in milliseconds.
pub const MAX_LATENCY_MS: u64 = 50;

/// Lowest jitter of every link, in milliseconds.
pub const MIN_JITTER_MS: u64 = 0;

/// Highest jitter of every link, in milliseconds.
pub const MAX_JITTER_MS: u64 = 50;

/// One decoded input in this many runs its engines without
/// `track_historical_votes`; an input too short to say runs them with it.
pub const DEFAULT_MODE_ONE_IN: u8 = 8;

/// Most views between the two votes of a pair.
pub const MAX_DELAY: u64 = 6;

/// Simulated time between the last required finalization and the measurement.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Seeds of [`fixed_corpus`]: `0..FIXED_SEEDS`.
pub const FIXED_SEEDS: u64 = 25;

/// Containers of every [`fixed_corpus`] input.
pub const FIXED_CONTAINERS: u64 = 30;

/// Link latency of every [`fixed_corpus`] input, in milliseconds.
pub const FIXED_LATENCY_MS: u64 = 10;

/// Link jitter of every [`fixed_corpus`] input, in milliseconds.
pub const FIXED_JITTER_MS: u64 = 10;

/// Label the equivocator's sends count under.
pub const ACTOR: &str = "equivocator";

/// Participant index of the equivocator.
pub const EQUIVOCATOR: usize = BYZANTINE_IDX;

/// The honest participant [`Picks::by_type`] looks at.
pub const PICK_NODE: usize = 1;

/// [`reach`] label: `C4-I1` was evaluated for one obligation.
pub const EXPORT_CHECKED: &str = "evidence_export_checked";

/// [`reach`] label: `C4-I2` was evaluated for one obligation.
pub const FORWARD_CHECKED: &str = "evidence_forward_checked";

/// [`reach`] label: `C4-I3` was evaluated for one honest node.
pub const BLOCK_CHECKED: &str = "evidence_block_checked";

/// [`reach`] label: `C4-I4` was evaluated for one honest node.
pub const SIGNER_CHECKED: &str = "evidence_signer_checked";

/// [`reach`] label: the safety invariants of the Standard driver passed for one run.
pub const SAFETY_CHECKED: &str = "evidence_safety_checked";

/// Mean and standard deviation, in milliseconds, of every latency of the mock
/// application, as `build_validator_with_reporter` sets them.
const APPLICATION_LATENCY: (f64, f64) = (10.0, 5.0);
const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

type P = SimplexEd25519;

/// The scheme every participant signs with.
pub type Scheme = <P as Simplex>::Scheme;

/// A participant's key.
pub type PublicKey = PublicKeyOf<P>;

/// An activity an engine exports.
pub type Exported = Activity<Scheme, Sha256Digest>;

type Ballot = Vote<Scheme, Sha256Digest>;
type Recorder =
    ActivityRecorder<deterministic::Context, Scheme, <P as Simplex>::Elector, Sha256Digest>;
type Export =
    AttributableReporter<TestRng, Scheme, Sha256Digest, Sequential, Planted<Log<Exported>>>;

/// What the equivocator does in one view. `P` is the proposal of the honest vote
/// that releases the first vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PairKind {
    /// Nothing.
    None,
    /// On an honest notarize of `P`: notarize `P`, then notarize `P'`, which has
    /// the round and parent of `P` and another payload.
    K1,
    /// On an honest finalize of `P`: finalize `P`, then finalize such a `P'`.
    K2,
    /// On an honest nullify of the view: nullify it, then finalize a proposal for
    /// its round.
    K3,
    /// On an honest finalize of `P`: finalize `P`, then nullify the view.
    K4,
}

impl PairKind {
    /// Every kind a plan is drawn from.
    pub const ALL: [Self; 5] = [Self::None, Self::K1, Self::K2, Self::K3, Self::K4];

    /// The kinds that send a pair.
    pub const PAIRS: [Self; 4] = [Self::K1, Self::K2, Self::K3, Self::K4];

    /// The evidence an engine that holds both votes of the pair must export.
    pub const fn evidence(self) -> Option<EvidenceType> {
        match self {
            Self::None => None,
            Self::K1 => Some(EvidenceType::ConflictingNotarize),
            Self::K2 => Some(EvidenceType::ConflictingFinalize),
            Self::K3 | Self::K4 => Some(EvidenceType::NullifyFinalize),
        }
    }
}

/// The three kinds of fault evidence an engine exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceType {
    ConflictingNotarize,
    ConflictingFinalize,
    NullifyFinalize,
}

impl EvidenceType {
    pub const ALL: [Self; 3] = [
        Self::ConflictingNotarize,
        Self::ConflictingFinalize,
        Self::NullifyFinalize,
    ];

    /// The evidence type of `activity`, with its signer; `None` for any other
    /// activity.
    pub fn of(activity: &Exported) -> Option<(Self, Participant)> {
        match activity {
            Activity::ConflictingNotarize(evidence) => {
                Some((Self::ConflictingNotarize, evidence.signer()))
            }
            Activity::ConflictingFinalize(evidence) => {
                Some((Self::ConflictingFinalize, evidence.signer()))
            }
            Activity::NullifyFinalize(evidence) => Some((Self::NullifyFinalize, evidence.signer())),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzInput {
    /// Seeds the runtime, whose context the equivocator draws its plans from.
    pub raw_bytes: Vec<u8>,
    /// Containers every honest node must finalize.
    pub required_containers: u64,
    pub term_length: TermLength,
    /// Optimistic lookahead of every honest engine.
    pub optimistic_views: ViewDelta,
    /// Latency of every link, in milliseconds.
    pub latency_ms: u64,
    /// Jitter of every link, in milliseconds.
    pub jitter_ms: u64,
    /// Whether the honest engines keep recorded votes after their certificate. The
    /// evidence invariants hold only with it.
    pub track_historical_votes: bool,
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
        let term_length =
            TermLength::new(NZU32!(u.int_in_range(MIN_TERM_LENGTH..=MAX_TERM_LENGTH)?));
        let optimistic_views = ViewDelta::new(sample_optimistic_views(u, term_length)?);
        let latency_ms = u.int_in_range(MIN_LATENCY_MS..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(MIN_JITTER_MS..=MAX_JITTER_MS)?;
        let default_mode = DEFAULT_MODE_ONE_IN - 1;
        let track_historical_votes = u.int_in_range(0..=default_mode)? != default_mode;
        Ok(Self {
            raw_bytes,
            required_containers,
            term_length,
            optimistic_views,
            latency_ms,
            jitter_ms,
            track_historical_votes,
        })
    }
}

/// A fault planted at an observation point of one run, for the negative controls of
/// the invariants. [`fuzz`] and [`run`] plant none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    /// Every `evidence` activity the engine of honest participant `node` exports is
    /// dropped before the raw log. `C4-I1` must fire.
    DropBeforeRaw { node: usize, evidence: EvidenceType },
    /// Every `evidence` activity the export wrapper of honest participant `node`
    /// forwards is dropped before the forwarded log. `C4-I2` must fire, alone.
    DropAfterExport { node: usize, evidence: EvidenceType },
    /// The engine of honest participant `node` cannot block the equivocator.
    /// `C4-I3` must fire.
    SwallowBlock { node: usize },
    /// Before the first activity the engine of honest participant `node` exports,
    /// its raw log is given one `ConflictingNotarize` made of two valid notarize
    /// votes of honest participant `signer` (another one than `node`). `C4-I4` must
    /// fire.
    FalseEvidence { node: usize, signer: usize },
}

/// The plan of one view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub kind: PairKind,
    /// The second vote waits until the equivocator has received an honest vote for
    /// a view this many views above the plan's view, or more.
    pub delay: u64,
}

/// Draws the plan of one view.
///
/// The equivocator calls this on its runtime context. Called on [`stream_at`] a
/// plan's [`Planned::drawn_at`], it returns that plan.
pub fn sample_plan(rng: &mut impl Rng) -> Plan {
    let kind = PairKind::ALL[rng.random_range(0..PairKind::ALL.len())];
    let delay = rng.random_range(0..=MAX_DELAY);
    Plan { kind, delay }
}

/// Draws a payload other than `taken`, drawing again while it is equal.
///
/// The equivocator calls this on its runtime context for the proposal of a second
/// vote. Called on [`stream_at`] the vote's [`Sent::drawn_at`], it returns that
/// proposal's payload.
pub fn sample_payload(rng: &mut impl Rng, taken: Option<&Sha256Digest>) -> Sha256Digest {
    loop {
        let payload = Sha256Digest::from(rng.random::<[u8; 32]>());
        if Some(&payload) != taken {
            return payload;
        }
    }
}

/// One honest vote the equivocator received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    /// Participant index of the sender.
    pub from: usize,
    /// The encoded vote.
    pub vote: Vec<u8>,
}

/// The plan the equivocator drew for one view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    pub view: View,
    pub plan: Plan,
    /// Position in [`Adversary::heard`] of the first honest vote for the view.
    pub trigger: usize,
    /// Bytes drawn from the run's random stream before the equivocator drew the plan
    /// with [`sample_plan`].
    pub drawn_at: u64,
}

/// One vote the equivocator handed to the network, for all three honest nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub view: View,
    pub kind: PairKind,
    /// Whether this is the second vote of the view's pair.
    pub second: bool,
    /// Position in [`Adversary::heard`] of the honest vote the equivocator had just
    /// received when it sent this one.
    pub trigger: usize,
    /// Bytes drawn from the run's random stream before the equivocator drew the
    /// payload of this vote's proposal with [`sample_payload`]; `None` for a vote
    /// whose proposal was not drawn.
    pub drawn_at: Option<u64>,
    /// The encoded vote.
    pub vote: Vec<u8>,
}

/// What the equivocator heard, planned and sent, each in the order it happened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Adversary {
    pub heard: Vec<Heard>,
    pub plans: Vec<Planned>,
    pub sent: Vec<Sent>,
}

/// Both votes of one view, as the equivocator sent them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub kind: PairKind,
    pub view: View,
    /// The encoded first vote.
    pub first: Vec<u8>,
    /// The encoded second vote.
    pub second: Vec<u8>,
}

/// The pairs in `sent`, in the order their second votes were sent.
pub fn pairs(sent: &[Sent]) -> Vec<Pair> {
    sent.iter()
        .filter(|second| second.second)
        .filter_map(|second| {
            let first = sent
                .iter()
                .find(|first| !first.second && first.view == second.view)?;
            Some(Pair {
                kind: second.kind,
                view: second.view,
                first: first.vote.clone(),
                second: second.vote.clone(),
            })
        })
        .collect()
}

/// How far a view's pair has got.
enum Stage {
    Waiting,
    First(Ballot),
    Done,
}

struct Equivocator<S, R> {
    context: deterministic::Context,
    scheme: Scheme,
    sender: S,
    receiver: R,
    participants: Vec<PublicKey>,
    /// Bytes drawn from the runtime's RNG so far.
    drawn: Arc<AtomicU64>,
    /// The highest view of any honest vote received so far.
    seen: View,
    slots: BTreeMap<View, (Plan, Stage)>,
    trace: Arc<Mutex<Adversary>>,
}

impl<S, R> Equivocator<S, R>
where
    S: LimitedSender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    /// The first vote of a `kind` pair, if `heard` is the honest vote the kind waits
    /// for.
    fn first(&self, kind: PairKind, heard: &Ballot) -> Option<Ballot> {
        let vote = match (kind, heard) {
            (PairKind::K1, Vote::Notarize(heard)) => {
                Vote::Notarize(Notarize::sign(&self.scheme, heard.proposal.clone())?)
            }
            (PairKind::K2 | PairKind::K4, Vote::Finalize(heard)) => {
                Vote::Finalize(Finalize::sign(&self.scheme, heard.proposal.clone())?)
            }
            (PairKind::K3, Vote::Nullify(heard)) => {
                Vote::Nullify(Nullify::sign::<Sha256Digest>(&self.scheme, heard.round)?)
            }
            _ => return None,
        };
        Some(vote)
    }

    /// The second vote of a `kind` pair whose first vote is `first`, and where on the
    /// random stream the payload of its proposal was drawn.
    fn second(&mut self, kind: PairKind, first: &Ballot) -> (Ballot, Option<u64>) {
        let drawn_at = self.drawn.load(Ordering::Relaxed);
        let another = |context: &mut deterministic::Context, proposal: &Proposal<Sha256Digest>| {
            Proposal::new(
                proposal.round,
                proposal.parent,
                sample_payload(context, Some(&proposal.payload)),
            )
        };
        let (vote, drawn_at) = match (kind, first) {
            (PairKind::K1, Vote::Notarize(first)) => {
                let proposal = another(&mut self.context, &first.proposal);
                (
                    Notarize::sign(&self.scheme, proposal).map(Vote::Notarize),
                    Some(drawn_at),
                )
            }
            (PairKind::K2, Vote::Finalize(first)) => {
                let proposal = another(&mut self.context, &first.proposal);
                (
                    Finalize::sign(&self.scheme, proposal).map(Vote::Finalize),
                    Some(drawn_at),
                )
            }
            (PairKind::K3, Vote::Nullify(first)) => {
                let view = first.round.view();
                let proposal = Proposal::new(
                    first.round,
                    View::new(view.get().saturating_sub(1)),
                    sample_payload(&mut self.context, None),
                );
                (
                    Finalize::sign(&self.scheme, proposal).map(Vote::Finalize),
                    Some(drawn_at),
                )
            }
            (PairKind::K4, Vote::Finalize(first)) => (
                Nullify::sign::<Sha256Digest>(&self.scheme, first.proposal.round)
                    .map(Vote::Nullify),
                None,
            ),
            _ => unreachable!("a first vote is the first vote of its kind"),
        };
        (vote.expect("the equivocator signs"), drawn_at)
    }

    /// Hands `vote` to the network for every honest node, waiting out the rate limit.
    async fn send(&mut self, vote: &[u8]) {
        loop {
            match self.sender.check(Recipients::All) {
                Ok(checked) => {
                    assert_eq!(
                        checked.recipients().len(),
                        self.participants.len() - 1,
                        "a vote of the equivocator goes to every honest node"
                    );
                    assert!(
                        checked.send(IoBuf::from(vote.to_vec()), true).accepted(),
                        "the network refused a vote of the equivocator"
                    );
                    return;
                }
                Err(retry) => self.context.sleep_until(retry).await,
            }
        }
    }

    async fn run(mut self) {
        loop {
            let Ok((from, message)) = self.receiver.recv().await else {
                return;
            };
            let from = self
                .participants
                .iter()
                .position(|participant| *participant == from)
                .expect("a participant sent the vote");
            let heard = Ballot::decode(Copying(message.as_ref())).expect("an honest vote decodes");
            let view = heard.view();
            self.seen = self.seen.max(view);
            let trigger = {
                let mut trace = self.trace.lock();
                trace.heard.push(Heard {
                    from,
                    vote: message.as_ref().to_vec(),
                });
                trace.heard.len() - 1
            };

            if !self.slots.contains_key(&view) {
                let drawn_at = self.drawn.load(Ordering::Relaxed);
                let plan = sample_plan(&mut self.context);
                self.slots.insert(view, (plan, Stage::Waiting));
                self.trace.lock().plans.push(Planned {
                    view,
                    plan,
                    trigger,
                    drawn_at,
                });
            }

            let (plan, stage) = &self.slots[&view];
            if matches!(stage, Stage::Waiting)
                && let Some(first) = self.first(plan.kind, &heard)
            {
                let kind = plan.kind;
                let vote = first.encode().to_vec();
                self.send(&vote).await;
                self.slots.get_mut(&view).expect("the view has a plan").1 = Stage::First(first);
                self.trace.lock().sent.push(Sent {
                    view,
                    kind,
                    second: false,
                    trigger,
                    drawn_at: None,
                    vote,
                });
            }

            let due: Vec<_> = self
                .slots
                .iter()
                .filter(|(planned, (plan, stage))| {
                    matches!(stage, Stage::First(_))
                        && self.seen.get() >= planned.get().saturating_add(plan.delay)
                })
                .map(|(planned, _)| *planned)
                .collect();
            for planned in due {
                let (plan, stage) = self.slots.get_mut(&planned).expect("the view has a plan");
                let kind = plan.kind;
                let Stage::First(first) = std::mem::replace(stage, Stage::Done) else {
                    unreachable!("only a view whose first vote is sent is due");
                };
                let (second, drawn_at) = self.second(kind, &first);
                let vote = second.encode().to_vec();
                self.send(&vote).await;
                self.trace.lock().sent.push(Sent {
                    view: planned,
                    kind,
                    second: true,
                    trigger,
                    drawn_at,
                    vote,
                });
            }
        }
    }
}

/// One counter per honest node: it orders the entries of the node's [`Tap`] and of
/// its [`Raw`] log.
#[derive(Clone, Debug, Default)]
pub struct Sequence(Arc<AtomicU64>);

impl Sequence {
    /// The next number: one above the last one handed out, from zero.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// An append-only log shared between its writer and the run that reads it.
#[derive(Debug)]
pub struct Log<T>(Arc<Mutex<Vec<T>>>);

impl<T> Clone for Log<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Default for Log<T> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<T: Clone> Log<T> {
    pub fn push(&self, entry: T) {
        self.0.lock().push(entry);
    }

    /// The entries so far, in the order appended.
    pub fn entries(&self) -> Vec<T> {
        self.0.lock().clone()
    }
}

/// The forwarded log: it keeps what the export wrapper hands it.
impl Reporter for Log<Exported> {
    type Activity = Exported;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.push(activity);
        Feedback::Ok
    }
}

/// One message of the equivocator, as an honest engine took it off its vote
/// channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    pub seq: u64,
    /// The message as received.
    pub bytes: Vec<u8>,
    /// The view the node's voter was in.
    pub gauge: u64,
}

/// One activity an honest engine exported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub seq: u64,
    pub activity: Exported,
}

/// Appends every message of the equivocator that an honest engine takes off its
/// vote channel, with the voter's view read from `gauge` at that moment, before the
/// engine gets the message.
pub struct Tap<R, G> {
    inner: R,
    equivocator: PublicKey,
    sequence: Sequence,
    log: Log<Taken>,
    gauge: G,
}

impl<R, G> Tap<R, G> {
    pub const fn new(
        inner: R,
        equivocator: PublicKey,
        sequence: Sequence,
        log: Log<Taken>,
        gauge: G,
    ) -> Self {
        Self {
            inner,
            equivocator,
            sequence,
            log,
            gauge,
        }
    }
}

impl<R, G> fmt::Debug for Tap<R, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tap").finish()
    }
}

impl<R, G> Receiver for Tap<R, G>
where
    R: Receiver<PublicKey = PublicKey>,
    G: FnMut() -> u64 + Send + 'static,
{
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let (sender, message) = self.inner.recv().await?;
        if sender == self.equivocator {
            let gauge = (self.gauge)();
            self.log.push(Taken {
                seq: self.sequence.next(),
                bytes: message.as_ref().to_vec(),
                gauge,
            });
        }
        Ok((sender, message))
    }

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }
}

/// The raw log: appends every activity it is given, numbered by `sequence`, and
/// hands it on to `next`.
#[derive(Clone)]
pub struct Raw<R> {
    sequence: Sequence,
    log: Log<Recorded>,
    next: R,
}

impl<R> Raw<R> {
    pub const fn new(sequence: Sequence, log: Log<Recorded>, next: R) -> Self {
        Self {
            sequence,
            log,
            next,
        }
    }
}

impl<R: Reporter<Activity = Exported>> Reporter for Raw<R> {
    type Activity = Exported;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.log.push(Recorded {
            seq: self.sequence.next(),
            activity: activity.clone(),
        });
        self.next.report(activity)
    }
}

/// Where a [`Plant`] changes what a reporter is given. Without a plant it hands
/// everything on.
#[derive(Clone)]
struct Planted<R> {
    dropped: Option<EvidenceType>,
    injected: Arc<Mutex<Option<Exported>>>,
    next: R,
}

impl<R> Planted<R> {
    fn new(dropped: Option<EvidenceType>, injected: Option<Exported>, next: R) -> Self {
        Self {
            dropped,
            injected: Arc::new(Mutex::new(injected)),
            next,
        }
    }
}

impl<R: Reporter<Activity = Exported>> Reporter for Planted<R> {
    type Activity = Exported;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let injected = self.injected.lock().take();
        if let Some(injected) = injected {
            self.next.report(injected);
        }
        let evidence = EvidenceType::of(&activity).map(|(evidence, _)| evidence);
        if evidence.is_some() && evidence == self.dropped {
            return Feedback::Ok;
        }
        self.next.report(activity)
    }
}

/// An engine's blocker. With [`Plant::SwallowBlock`] it never blocks `swallowed`.
#[derive(Clone)]
struct Blocking<B: Blocker> {
    inner: B,
    swallowed: Option<B::PublicKey>,
}

impl<B: Blocker> Blocker for Blocking<B> {
    type PublicKey = B::PublicKey;

    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        if self.swallowed.as_ref() == Some(&peer) {
            return Feedback::Ok;
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "hands the engine's own block on to the network"
        )]
        self.inner.block(peer)
    }

    fn blocked(&mut self) -> BlockedSubscription<Self::PublicKey> {
        self.inner.blocked()
    }
}

/// The voter's view of the engine of `node`, read from an encoded metrics text.
///
/// # Panics
///
/// Panics with the gauge's name unless exactly one sample matches: a renamed metric
/// must fail every run instead of leaving the pairs unmeasured.
pub fn current_view(metrics: &str, node: &state_bounds::Node) -> u64 {
    state_bounds::gauge(metrics, state_bounds::CURRENT_VIEW, node)
}

/// Whether an engine whose voter is in view `current` tracks a peer vote for
/// `pending`, for terms of `term_length` views and an optimistic lookahead of
/// `lookahead`: the admission rule of `Optimistic Validation` in
/// [commonware_consensus::simplex], restated.
///
/// A vote is admitted at or below `current`, at `current + 1`, at the first view of
/// the next term, in the admission window (the views of the current term up to
/// `2 * lookahead + 1` ahead) and in the next-term lane (the
/// `min(max(lookahead, 1), term_length) + 1` views after the first one of the next
/// term).
pub const fn admits(current: u64, pending: u64, term_length: u64, lookahead: u64) -> bool {
    let end = term_end(current, term_length);
    let next = end.saturating_add(1);
    if pending <= current.saturating_add(1) || pending == next {
        return true;
    }
    let reach = current
        .saturating_add(lookahead.saturating_mul(2))
        .saturating_add(1);
    let window = if end < reach { end } else { reach };
    if pending <= window {
        return true;
    }
    let lookahead = if lookahead == 0 { 1 } else { lookahead };
    let lane = if lookahead < term_length {
        lookahead
    } else {
        term_length
    };
    pending > next && pending <= next.saturating_add(lane).saturating_add(1)
}

/// Whether an engine that admitted a vote for `view` before certainly admits another
/// one when its voter is in view `gauge`: [`admits`] holds at every view from the
/// lowest one that admits `view` up to `gauge`.
///
/// The engine admits against its batcher's view, which is at most the voter's and
/// at least the view at which the first vote was admitted. With no lookahead and
/// terms of three views or more, a view can be admitted, then not, then again.
pub fn certainly_admits(view: u64, gauge: u64, term_length: u64, lookahead: u64) -> bool {
    // Every view from `view - 1` on admits `view`.
    let highest = gauge.min(view);
    let Some(lowest) = (0..=highest).find(|current| admits(*current, view, term_length, lookahead))
    else {
        return false;
    };
    (lowest..=highest).all(|current| admits(current, view, term_length, lookahead))
}

/// Whether an engine whose voter is in view `gauge` still holds the round of `view`:
/// rounds are kept down to `view_retention` views below the finalized view, which is
/// below the voter's view.
pub const fn retains(view: u64, gauge: u64) -> bool {
    view >= 1 && view.saturating_add(VIEW_RETENTION.get()).saturating_add(1) >= gauge
}

/// What the oracle is told about a run besides its logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Participant index of the equivocator.
    pub equivocator: usize,
    /// Whether the honest engines ran with `track_historical_votes`.
    pub track_historical_votes: bool,
    pub term_length: TermLength,
    /// Optimistic lookahead of every honest engine.
    pub optimistic_views: ViewDelta,
}

/// The three logs of one honest node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logs {
    /// Participant index of the node.
    pub node: usize,
    /// Every message of the equivocator the node's engine took, in order.
    pub tap: Vec<Taken>,
    /// Every activity the node's engine exported, in order.
    pub raw: Vec<Recorded>,
    /// Every activity the export wrapper forwarded, in order.
    pub forwarded: Vec<Exported>,
}

/// Why a pair is not measured at a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// `C4-O2`: the node's engine did not take the first vote.
    FirstNotTaken,
    /// `C4-O2`: the node's engine did not take the second vote.
    SecondNotTaken,
    /// `C4-O2`: the node's engine took the second vote before the first.
    OutOfOrder,
    /// `C4-O2`: the first vote does not decode.
    FirstUndecodable,
    /// `C4-O2`: the second vote does not decode.
    SecondUndecodable,
    /// `C4-O2`: a vote is not signed by the equivocator.
    ForeignSigner,
    /// `C4-O2`: a vote does not verify.
    InvalidSignature,
    /// `C4-O2`: the votes are not the two votes of the pair's kind for its view.
    NotAPair,
    /// `C4-O3`: the node's engine did not export the first vote before it took the
    /// equivocator's next message.
    FirstNotRecorded,
    /// `C4-O4`: the round may have been pruned when the second vote came.
    NotRetained,
    /// `C4-O4`: the node may not have admitted the second vote.
    NotAdmitted,
    /// `C4-O5`: a `K2` pair after a nullify vote of the equivocator for the view.
    EarlierCrossVote,
}

impl Reason {
    /// The condition of an obligation the reason fails.
    pub const fn condition(self) -> &'static str {
        match self {
            Self::FirstNotTaken
            | Self::SecondNotTaken
            | Self::OutOfOrder
            | Self::FirstUndecodable
            | Self::SecondUndecodable
            | Self::ForeignSigner
            | Self::InvalidSignature
            | Self::NotAPair => "C4-O2",
            Self::FirstNotRecorded => "C4-O3",
            Self::NotRetained | Self::NotAdmitted => "C4-O4",
            Self::EarlierCrossVote => "C4-O5",
        }
    }
}

/// A pair one honest node must have exported evidence for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// Participant index of the node.
    pub node: usize,
    pub kind: PairKind,
    pub view: View,
    /// Sequence number of the tap entry of the first vote.
    pub first_seq: u64,
    /// Sequence number of the tap entry of the second vote.
    pub second_seq: u64,
    /// Sequence number of the tap entry after the second vote's, if there is one.
    pub next_seq: Option<u64>,
    /// The evidence: its type, signer, view and two votes.
    pub evidence: Exported,
    /// Whether the node had exported the certificate of the first vote's phase for
    /// the view before it took the second vote.
    pub late: bool,
}

/// A pair that is not measured at one honest node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unmeasured {
    /// Participant index of the node.
    pub node: usize,
    pub kind: PairKind,
    pub view: View,
    pub reason: Reason,
}

/// A pair that would be an obligation with `track_historical_votes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Untracked {
    pub pair: Obligation,
    /// Whether the node exported the pair's evidence all the same.
    pub reported: bool,
}

/// The pairs of a run as one honest node saw them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    /// Participant index of the node.
    pub node: usize,
    pub obligations: Vec<Obligation>,
    pub unmeasured: Vec<Unmeasured>,
    /// The pairs of a run without `track_historical_votes` that meet `C4-O2` to
    /// `C4-O5`. Such a run has no obligation and no unmeasured pair.
    pub untracked: Vec<Untracked>,
}

fn activity(vote: &Ballot) -> Exported {
    match vote {
        Vote::Notarize(vote) => Activity::Notarize(vote.clone()),
        Vote::Nullify(vote) => Activity::Nullify(vote.clone()),
        Vote::Finalize(vote) => Activity::Finalize(vote.clone()),
    }
}

fn signer(vote: &Ballot) -> Participant {
    match vote {
        Vote::Notarize(vote) => vote.signer(),
        Vote::Nullify(vote) => vote.signer(),
        Vote::Finalize(vote) => vote.signer(),
    }
}

fn verifies(verifier: &Scheme, vote: &Ballot) -> bool {
    // A verifier of its own, as the audit recorder has: it draws nothing from a run.
    let mut rng = TestRng::new(0);
    match vote {
        Vote::Notarize(vote) => vote.verify(&mut rng, verifier, &Sequential),
        Vote::Nullify(vote) => vote.verify::<_, Sha256Digest>(&mut rng, verifier, &Sequential),
        Vote::Finalize(vote) => vote.verify(&mut rng, verifier, &Sequential),
    }
}

/// The evidence of a `kind` pair for `view` made of `first` and `second`, both
/// signed by one participant; `None` if they are not such a pair.
fn evidence(kind: PairKind, view: View, first: &Ballot, second: &Ballot) -> Option<Exported> {
    if first.view() != view || second.view() != view {
        return None;
    }
    match (kind, first, second) {
        (PairKind::K1, Vote::Notarize(first), Vote::Notarize(second))
            if first.proposal.round == second.proposal.round
                && first.proposal != second.proposal =>
        {
            Some(Activity::ConflictingNotarize(ConflictingNotarize::new(
                first.clone(),
                second.clone(),
            )))
        }
        (PairKind::K2, Vote::Finalize(first), Vote::Finalize(second))
            if first.proposal.round == second.proposal.round
                && first.proposal != second.proposal =>
        {
            Some(Activity::ConflictingFinalize(ConflictingFinalize::new(
                first.clone(),
                second.clone(),
            )))
        }
        (PairKind::K3, Vote::Nullify(nullify), Vote::Finalize(finalize))
        | (PairKind::K4, Vote::Finalize(finalize), Vote::Nullify(nullify))
            if nullify.round == finalize.proposal.round =>
        {
            Some(Activity::NullifyFinalize(NullifyFinalize::new(
                nullify.clone(),
                finalize.clone(),
            )))
        }
        _ => None,
    }
}

/// Whether `raw` holds, below sequence number `before`, the certificate of the phase
/// of a `kind` pair's first vote for `view`: a notarization for `K1`, a finalization
/// for `K2` and `K4`, a nullification for `K3`.
pub fn late(kind: PairKind, view: View, before: u64, raw: &[Recorded]) -> bool {
    raw.iter().any(|recorded| {
        recorded.seq < before
            && recorded.activity.view() == view
            && matches!(
                (kind, &recorded.activity),
                (PairKind::K1, Activity::Notarization(_))
                    | (PairKind::K2 | PairKind::K4, Activity::Finalization(_))
                    | (PairKind::K3, Activity::Nullification(_))
            )
    })
}

/// The sequence number of the tap entry after the one numbered `seq`.
fn next_taken(tap: &[Taken], seq: u64) -> Option<u64> {
    tap.iter()
        .map(|taken| taken.seq)
        .filter(|next| *next > seq)
        .min()
}

/// Whether `raw` holds `activity` above sequence number `after` and below `before`.
fn recorded_between(
    raw: &[Recorded],
    activity: &Exported,
    after: u64,
    before: Option<u64>,
) -> bool {
    raw.iter().any(|recorded| {
        recorded.seq > after
            && before.is_none_or(|before| recorded.seq < before)
            && recorded.activity == *activity
    })
}

/// `C4-O2` to `C4-O5` for one pair at one node.
fn measure(
    verifier: &Scheme,
    rules: &Rules,
    pair: &Pair,
    logs: &Logs,
) -> Result<Obligation, Reason> {
    let taken = |bytes: &[u8]| logs.tap.iter().find(|taken| taken.bytes == bytes);
    let first_taken = taken(&pair.first).ok_or(Reason::FirstNotTaken)?;
    let second_taken = taken(&pair.second).ok_or(Reason::SecondNotTaken)?;
    if first_taken.seq >= second_taken.seq {
        return Err(Reason::OutOfOrder);
    }
    let first =
        Ballot::decode(Copying(&first_taken.bytes)).map_err(|_| Reason::FirstUndecodable)?;
    let second =
        Ballot::decode(Copying(&second_taken.bytes)).map_err(|_| Reason::SecondUndecodable)?;
    let equivocator = Participant::from_usize(rules.equivocator);
    if signer(&first) != equivocator || signer(&second) != equivocator {
        return Err(Reason::ForeignSigner);
    }
    if !verifies(verifier, &first) || !verifies(verifier, &second) {
        return Err(Reason::InvalidSignature);
    }
    let evidence = evidence(pair.kind, pair.view, &first, &second).ok_or(Reason::NotAPair)?;

    if !recorded_between(
        &logs.raw,
        &activity(&first),
        first_taken.seq,
        next_taken(&logs.tap, first_taken.seq),
    ) {
        return Err(Reason::FirstNotRecorded);
    }

    let view = pair.view.get();
    if !retains(view, second_taken.gauge) {
        return Err(Reason::NotRetained);
    }
    if !certainly_admits(
        view,
        second_taken.gauge,
        rules.term_length.get(),
        rules.optimistic_views.get(),
    ) {
        return Err(Reason::NotAdmitted);
    }

    if pair.kind == PairKind::K2
        && logs.raw.iter().any(|recorded| {
            recorded.seq < second_taken.seq
                && matches!(
                    &recorded.activity,
                    Activity::Nullify(nullify)
                        if nullify.signer() == equivocator && nullify.view() == pair.view
                )
        })
    {
        return Err(Reason::EarlierCrossVote);
    }

    Ok(Obligation {
        node: logs.node,
        kind: pair.kind,
        view: pair.view,
        first_seq: first_taken.seq,
        second_seq: second_taken.seq,
        next_seq: next_taken(&logs.tap, second_taken.seq),
        evidence,
        late: late(pair.kind, pair.view, second_taken.seq, &logs.raw),
    })
}

/// Sorts `pairs` by what the honest node of `logs` must have done with them.
///
/// `verifier` is any participant's scheme of the run. A pair is found in the node's
/// tap by its two encoded votes.
pub fn obligations(verifier: &Scheme, rules: &Rules, pairs: &[Pair], logs: &Logs) -> Classified {
    let mut classified = Classified {
        node: logs.node,
        obligations: Vec::new(),
        unmeasured: Vec::new(),
        untracked: Vec::new(),
    };
    for pair in pairs {
        match measure(verifier, rules, pair, logs) {
            Ok(obligation) if rules.track_historical_votes => {
                classified.obligations.push(obligation);
            }
            Ok(pair) => {
                let reported = check_exported(&pair, &logs.raw).is_ok();
                classified.untracked.push(Untracked { pair, reported });
            }
            Err(reason) if rules.track_historical_votes => {
                classified.unmeasured.push(Unmeasured {
                    node: logs.node,
                    kind: pair.kind,
                    view: pair.view,
                    reason,
                });
            }
            Err(_) => {}
        }
    }
    classified
}

/// `C4-I1`: `raw`, the raw log of the obligation's node, holds the obligation's
/// evidence after the second vote and before the equivocator's next message.
pub fn check_exported(obligation: &Obligation, raw: &[Recorded]) -> Result<(), String> {
    if recorded_between(
        raw,
        &obligation.evidence,
        obligation.second_seq,
        obligation.next_seq,
    ) {
        return Ok(());
    }
    let (evidence, signer) =
        EvidenceType::of(&obligation.evidence).expect("an obligation's evidence is a fault");
    Err(format!(
        "C4-I1: node {} took both votes of the {:?} pair of participant {} for view {} and \
         exported no {evidence:?} for them after sequence {}",
        obligation.node,
        obligation.kind,
        signer.get(),
        obligation.view,
        obligation.second_seq,
    ))
}

/// `C4-I2`: `forwarded`, the forwarded log of the obligation's node, holds the
/// obligation's evidence.
pub fn check_forwarded(obligation: &Obligation, forwarded: &[Exported]) -> Result<(), String> {
    if forwarded.contains(&obligation.evidence) {
        return Ok(());
    }
    let (evidence, signer) =
        EvidenceType::of(&obligation.evidence).expect("an obligation's evidence is a fault");
    Err(format!(
        "C4-I2: node {} exported {evidence:?} for the {:?} pair of participant {} for view {} \
         and the export wrapper did not forward it",
        obligation.node,
        obligation.kind,
        signer.get(),
        obligation.view,
    ))
}

/// `C4-I3`: `blocked`, the block list as pairs of participant indices (who blocks
/// whom), holds `node` blocking `equivocator`. It is checked for a node with an
/// obligation.
pub fn check_blocked(
    node: usize,
    equivocator: usize,
    blocked: &[(usize, usize)],
) -> Result<(), String> {
    if blocked.contains(&(node, equivocator)) {
        return Ok(());
    }
    Err(format!(
        "C4-I3: node {node} holds both votes of a pair of participant {equivocator} and has \
         not blocked it"
    ))
}

/// `C4-I4`: neither log of a node holds fault evidence against a signer other than
/// `equivocator`.
pub fn check_honest_signers(logs: &Logs, equivocator: usize) -> Result<(), String> {
    let raw = logs.raw.iter().map(|recorded| ("raw", &recorded.activity));
    let forwarded = logs
        .forwarded
        .iter()
        .map(|activity| ("forwarded", activity));
    for (log, activity) in raw.chain(forwarded) {
        if let Some((evidence, signer)) = EvidenceType::of(activity)
            && usize::from(signer) != equivocator
        {
            return Err(format!(
                "C4-I4: the {log} log of node {} holds {evidence:?} against signer {} for view {}",
                logs.node,
                signer.get(),
                activity.view(),
            ));
        }
    }
    Ok(())
}

/// The counts of one pair kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KindReport {
    /// Obligations by the participant index of the honest node.
    pub obligations: BTreeMap<usize, u64>,
    /// Obligations whose second vote came after the certificate of the first
    /// vote's phase, over all nodes.
    pub late: u64,
    /// Unmeasured pairs by reason, over all nodes.
    pub unmeasured: BTreeMap<Reason, u64>,
    /// In a run without `track_historical_votes`: pairs that would be late
    /// obligations and got no evidence, over all nodes.
    pub unreported_late: u64,
}

/// The counts of one run, or of several runs added up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The counts of each kind in [`PairKind::PAIRS`].
    pub kinds: BTreeMap<PairKind, KindReport>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            kinds: PairKind::PAIRS
                .into_iter()
                .map(|kind| (kind, KindReport::default()))
                .collect(),
        }
    }
}

impl Report {
    /// Counts what `classified` holds, one entry per honest node.
    pub fn new(classified: &[Classified]) -> Self {
        let mut report = Self::default();
        for node in classified {
            for counts in report.kinds.values_mut() {
                counts.obligations.entry(node.node).or_default();
            }
            for obligation in &node.obligations {
                let counts = report.kinds.entry(obligation.kind).or_default();
                *counts.obligations.entry(node.node).or_default() += 1;
                counts.late += u64::from(obligation.late);
            }
            for unmeasured in &node.unmeasured {
                let counts = report.kinds.entry(unmeasured.kind).or_default();
                *counts.unmeasured.entry(unmeasured.reason).or_default() += 1;
            }
            for untracked in &node.untracked {
                let counts = report.kinds.entry(untracked.pair.kind).or_default();
                counts.unreported_late += u64::from(untracked.pair.late && !untracked.reported);
            }
        }
        report
    }

    /// Obligations of `kind` at the honest node with participant index `node`.
    pub fn at(&self, kind: PairKind, node: usize) -> u64 {
        self.kinds
            .get(&kind)
            .and_then(|counts| counts.obligations.get(&node))
            .copied()
            .unwrap_or_default()
    }

    /// Obligations of `kind` over all nodes.
    pub fn obligations(&self, kind: PairKind) -> u64 {
        self.kinds
            .get(&kind)
            .map_or(0, |counts| counts.obligations.values().sum())
    }

    /// Late obligations of `kind` over all nodes.
    pub fn late(&self, kind: PairKind) -> u64 {
        self.kinds.get(&kind).map_or(0, |counts| counts.late)
    }

    /// Adds the counts of `other`.
    pub fn add(&mut self, other: &Self) {
        for (kind, theirs) in &other.kinds {
            let ours = self.kinds.entry(*kind).or_default();
            for (node, count) in &theirs.obligations {
                *ours.obligations.entry(*node).or_default() += count;
            }
            ours.late += theirs.late;
            for (reason, count) in &theirs.unmeasured {
                *ours.unmeasured.entry(*reason).or_default() += count;
            }
            ours.unreported_late += theirs.unreported_late;
        }
    }

    /// The counts of `reports` added up.
    pub fn sum<'a>(reports: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut sum = Self::default();
        for report in reports {
            sum.add(report);
        }
        sum
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, (kind, counts)) in self.kinds.iter().enumerate() {
            if position > 0 {
                write!(f, " | ")?;
            }
            write!(f, "{kind:?}: obligations")?;
            for (node, count) in &counts.obligations {
                write!(f, " node{node}={count}")?;
            }
            write!(f, " late={} unmeasured", counts.late)?;
            if counts.unmeasured.is_empty() {
                write!(f, "=0")?;
            }
            for (reason, count) in &counts.unmeasured {
                write!(f, " {reason:?}={count}")?;
            }
            write!(f, " unreported_late={}", counts.unreported_late)?;
        }
        Ok(())
    }
}

/// What [`evaluate`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The pairs as each honest node saw them, in the order of the logs given.
    pub classified: Vec<Classified>,
    pub report: Report,
    /// Every violated invariant, `C4-I1` first. Each text starts with the id.
    pub violations: Vec<String>,
}

/// The oracle: sorts `pairs` at every node of `logs` ([`obligations`]) and checks
/// `C4-I1` to `C4-I4` on the logs and on `blocked`, the block list as pairs of
/// participant indices. It sees nothing of the engines.
///
/// `C4-I2` is checked for an obligation that passed `C4-I1`. Every evaluation counts
/// under its label in [`reach`].
pub fn evaluate(
    verifier: &Scheme,
    rules: &Rules,
    pairs: &[Pair],
    logs: &[Logs],
    blocked: &[(usize, usize)],
) -> Evaluation {
    let classified: Vec<_> = logs
        .iter()
        .map(|logs| obligations(verifier, rules, pairs, logs))
        .collect();
    let mut violations = Vec::new();
    let mut exported = Vec::new();
    for (logs, node) in logs.iter().zip(&classified) {
        for obligation in &node.obligations {
            reach::record(EXPORT_CHECKED);
            match check_exported(obligation, &logs.raw) {
                Ok(()) => exported.push((logs, obligation)),
                Err(violation) => violations.push(violation),
            }
        }
    }
    for (logs, obligation) in exported {
        reach::record(FORWARD_CHECKED);
        violations.extend(check_forwarded(obligation, &logs.forwarded).err());
    }
    for node in classified
        .iter()
        .filter(|node| !node.obligations.is_empty())
    {
        reach::record(BLOCK_CHECKED);
        violations.extend(check_blocked(node.node, rules.equivocator, blocked).err());
    }
    for logs in logs {
        reach::record(SIGNER_CHECKED);
        violations.extend(check_honest_signers(logs, rules.equivocator).err());
    }
    Evaluation {
        report: Report::new(&classified),
        classified,
        violations,
    }
}

/// One honest node of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub logs: Logs,
    /// Containers the node finalized.
    pub finalized: u64,
    /// Times the node's tap read the voter's view from the metrics.
    pub gauge_reads: u64,
}

/// The outcome of one run.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub report: Report,
    /// What the oracle was told.
    pub rules: Rules,
    /// A scheme of the run that verifies every participant's votes.
    pub verifier: Scheme,
    /// The participants, by index.
    pub participants: Vec<PublicKey>,
    pub adversary: Adversary,
    /// The pairs the equivocator sent in full.
    pub pairs: Vec<Pair>,
    /// The honest nodes, by participant index.
    pub nodes: Vec<Node>,
    /// The block list at the measurement, as sorted pairs of participant indices:
    /// who blocks whom.
    pub blocked: Vec<(usize, usize)>,
    /// The pairs as each honest node saw them, in the order of `nodes`.
    pub classified: Vec<Classified>,
    /// Simulated time at which every honest node had finalized the required
    /// containers.
    pub finalized_at: Duration,
    /// Simulated time of the measurement: the one read of the block list, and the
    /// end of every log.
    pub measured_at: Duration,
    /// The encoded metrics at the measurement, with the lines sorted so that two runs
    /// of one input give the same text.
    pub metrics: String,
}

struct Honest {
    index: usize,
    validator: PublicKey,
    recorder: Recorder,
    tap: Log<Taken>,
    raw: Log<Recorded>,
    forwarded: Log<Exported>,
    gauge_reads: Arc<AtomicU64>,
}

/// The Standard-driver input the scenario runs on: one Byzantine participant of four
/// on a connected network, with every honest engine policy at its default.
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
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

/// Two valid notarize votes of `scheme`'s participant for two payloads of one round.
fn false_evidence(scheme: &Scheme) -> Exported {
    let round = Round::new(Epoch::new(EPOCH), View::new(1));
    let vote = |payload: u8| {
        Notarize::sign(
            scheme,
            Proposal::new(round, View::zero(), Sha256Digest::from([payload; 32])),
        )
        .expect("an honest participant signs")
    };
    Activity::ConflictingNotarize(ConflictingNotarize::new(vote(0), vote(1)))
}

/// Runs the scenario on `input` with `plant` and returns what happened.
///
/// # Panics
///
/// Panics with every violated invariant, one per line and each with its id first,
/// or with the runtime's timeout when the honest nodes stop finalizing.
pub fn run_planted(input: &FuzzInput, plant: Option<Plant>) -> Outcome {
    let base = base(input);
    let drawn = Arc::new(AtomicU64::new(0));
    let tape: deterministic::BoxDynRng = Box::new(Tape::new(&input.raw_bytes, drawn.clone()));
    let cfg =
        bounded_fuzz_runtime_config(&input.raw_bytes, input.required_containers, 0).with_rng(tape);
    let required = input.required_containers;
    let link = Link {
        latency: Duration::from_millis(input.latency_ms),
        jitter: Duration::from_millis(input.jitter_ms),
        success_rate: probability!(1.0),
    };
    let rules = Rules {
        equivocator: EQUIVOCATOR,
        track_historical_votes: input.track_historical_votes,
        term_length: input.term_length,
        optimistic_views: input.optimistic_views,
    };
    deterministic::Runner::new(cfg).start(move |mut context| async move {
        let config = base.configuration;
        let (mut oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &base).await;
        link_peers(&mut oracle, &participants, Action::Update(link), None).await;

        let equivocator = participants[EQUIVOCATOR].clone();
        let trace = Arc::new(Mutex::new(Adversary::default()));
        let ((vote_sender, vote_receiver), certificates, backfill) =
            registrations.remove(&equivocator).unwrap();
        context
            .child("validator")
            .with_attribute("public_key", &equivocator)
            .child("equivocator")
            .spawn({
                let scheme = schemes[EQUIVOCATOR].clone();
                let participants = participants.clone();
                let trace = trace.clone();
                move |context| async move {
                    // The equivocator stays registered on the channels it never uses.
                    let _unused = (certificates, backfill);
                    Equivocator {
                        context,
                        scheme,
                        sender: Counting::new(vote_sender, ACTOR),
                        receiver: vote_receiver,
                        participants,
                        drawn,
                        seen: View::zero(),
                        slots: BTreeMap::new(),
                        trace,
                    }
                    .run()
                    .await;
                }
            });

        let relay = Arc::new(relay::Relay::new());
        let mut nodes = Vec::new();
        for index in (config.faults as usize)..(config.n as usize) {
            let validator = participants[index].clone();
            let scheme = schemes[index].clone();
            let elector = P::elector(base.term_length, base.optimistic_views);
            let context = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let ((vote_sender, vote_receiver), recovered, resolver) =
                registrations.remove(&validator).unwrap();

            let (dropped_before_raw, dropped_after_export, swallowed, injected) = match plant {
                Some(Plant::DropBeforeRaw { node, evidence }) if node == index => {
                    (Some(evidence), None, None, None)
                }
                Some(Plant::DropAfterExport { node, evidence }) if node == index => {
                    (None, Some(evidence), None, None)
                }
                Some(Plant::SwallowBlock { node }) if node == index => {
                    (None, None, Some(equivocator.clone()), None)
                }
                Some(Plant::FalseEvidence { node, signer }) if node == index => {
                    (None, None, None, Some(false_evidence(&schemes[signer])))
                }
                _ => (None, None, None, None),
            };

            let recorder = Recorder::new(
                context.child("reporter"),
                validator.clone(),
                reporter::Config {
                    participants: participants
                        .as_slice()
                        .try_into()
                        .expect("public keys are unique"),
                    scheme: scheme.clone(),
                    elector: elector.clone(),
                },
            );
            let forwarded = Log::default();
            // The wrapper verifies with an RNG of its own, as the audit recorder
            // does, so it draws nothing from the run.
            let export: Export = AttributableReporter::new(
                TestRng::new(0),
                scheme.clone(),
                Planted::new(dropped_after_export, None, forwarded.clone()),
                Sequential,
                true,
            );
            let sequence = Sequence::default();
            let raw = Log::default();
            let reporter = Planted::new(
                dropped_before_raw,
                injected,
                Raw::new(
                    sequence.clone(),
                    raw.clone(),
                    Reporters::<Recorder, Export>::from((recorder.clone(), export)),
                ),
            );

            let tap = Log::default();
            let gauge_reads = Arc::new(AtomicU64::new(0));
            let gauge = {
                let context = context.child("tap");
                let node = state_bounds::Node::public_key(&validator);
                let gauge_reads = gauge_reads.clone();
                move || {
                    gauge_reads.fetch_add(1, Ordering::Relaxed);
                    current_view(&context.encode(), &node)
                }
            };

            let (actor, application) = application::Application::new(
                context.child("application"),
                application::Config::<Sha256, _> {
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: APPLICATION_LATENCY,
                    verify_latency: APPLICATION_LATENCY,
                    certify_latency: APPLICATION_LATENCY,
                    should_certify: base.certify.into_certifier(index),
                },
            );
            actor.start();
            start_validator_engine::<P, _, _, _, _, _, _, _, _, _, _, _>(
                &context,
                Blocking {
                    inner: oracle.control(validator.clone()),
                    swallowed,
                },
                scheme,
                elector,
                application.clone(),
                application,
                reporter,
                validator.to_string(),
                LEADER_TIMEOUT,
                CERTIFICATION_TIMEOUT,
                base.mailbox_size,
                base.forwarding,
                (
                    vote_sender,
                    Tap::new(
                        vote_receiver,
                        equivocator.clone(),
                        sequence,
                        tap.clone(),
                        gauge,
                    ),
                ),
                recovered,
                resolver,
                rules.track_historical_votes,
            );
            nodes.push(Honest {
                index,
                validator,
                recorder,
                tap,
                raw,
                forwarded,
                gauge_reads,
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
        let mut blocked: Vec<_> = oracle
            .blocked()
            .await
            .expect("the network answers")
            .into_iter()
            .map(|(from, to)| {
                let index = |key: &PublicKey| {
                    participants
                        .iter()
                        .position(|participant| participant == key)
                        .expect("a participant blocks a participant")
                };
                (index(&from), index(&to))
            })
            .collect();
        blocked.sort_unstable();
        // The registry encodes its families in no fixed order.
        let mut metrics: Vec<_> = context.encode().lines().map(str::to_owned).collect();
        metrics.sort_unstable();
        let metrics = metrics.join("\n");
        let adversary = trace.lock().clone();
        let pairs = pairs(&adversary.sent);
        let logs: Vec<_> = nodes
            .iter()
            .map(|node| Logs {
                node: node.index,
                tap: node.tap.entries(),
                raw: node.raw.entries(),
                forwarded: node.forwarded.entries(),
            })
            .collect();
        let verifier = schemes[EQUIVOCATOR].clone();
        let evaluation = evaluate(&verifier, &rules, &pairs, &logs, &blocked);
        assert!(
            evaluation.violations.is_empty(),
            "{}",
            evaluation.violations.join("\n")
        );

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
        reach::record(SAFETY_CHECKED);

        Outcome {
            report: evaluation.report,
            rules,
            verifier,
            participants,
            adversary,
            pairs,
            nodes: nodes
                .iter()
                .zip(logs)
                .map(|(node, logs)| Node {
                    logs,
                    finalized: node.recorder.recording().inner().finalizations.lock().len() as u64,
                    gauge_reads: node.gauge_reads.load(Ordering::Relaxed),
                })
                .collect(),
            blocked,
            classified: evaluation.classified,
            finalized_at,
            measured_at,
            metrics,
        }
    })
}

/// Runs the scenario on `input` and returns what happened. See [`run_planted`].
pub fn run(input: &FuzzInput) -> Outcome {
    run_planted(input, None)
}

pub fn fuzz(input: FuzzInput) {
    run(&input);
}

/// The inputs [`check_floors`] is made for: every seed below [`FIXED_SEEDS`] (as
/// eight big-endian bytes) with a single-view and the longest term, each without
/// lookahead and with a lookahead of the term length. The input of seed `s`, term
/// choice `a` and lookahead choice `b` is at `4 * s + 2 * a + b`.
pub fn fixed_corpus() -> Vec<FuzzInput> {
    let mut corpus = Vec::new();
    for seed in 0..FIXED_SEEDS {
        for term_length in [MIN_TERM_LENGTH, MAX_TERM_LENGTH] {
            for optimistic_views in [0, u64::from(term_length)] {
                corpus.push(FuzzInput {
                    raw_bytes: seed.to_be_bytes().to_vec(),
                    required_containers: FIXED_CONTAINERS,
                    term_length: TermLength::new(NZU32!(term_length)),
                    optimistic_views: ViewDelta::new(optimistic_views),
                    latency_ms: FIXED_LATENCY_MS,
                    jitter_ms: FIXED_JITTER_MS,
                    track_historical_votes: true,
                });
            }
        }
    }
    corpus
}

/// `C4-I5`: over `reports`, every kind of pair has an obligation and a late
/// obligation. Otherwise the runs did not measure what the invariants are for.
pub fn check_floors(reports: &[Report]) -> Result<(), String> {
    let sum = Report::sum(reports);
    for kind in PairKind::PAIRS {
        if sum.obligations(kind) == 0 {
            return Err(format!(
                "C4-I5 vacuous: no {kind:?} obligation in {} runs",
                reports.len()
            ));
        }
        if sum.late(kind) == 0 {
            return Err(format!(
                "C4-I5 vacuous: no late {kind:?} obligation in {} runs",
                reports.len()
            ));
        }
    }
    Ok(())
}

/// The first of `reports` with an obligation at honest participant `node` of a kind
/// whose evidence is `evidence`.
pub fn pick_type(reports: &[Report], evidence: EvidenceType, node: usize) -> Option<usize> {
    reports.iter().position(|report| {
        PairKind::PAIRS
            .into_iter()
            .any(|kind| kind.evidence() == Some(evidence) && report.at(kind, node) > 0)
    })
}

/// The first of `reports` with an obligation of any kind at honest participant
/// `node`.
pub fn pick_node(reports: &[Report], node: usize) -> Option<usize> {
    reports.iter().position(|report| {
        PairKind::PAIRS
            .into_iter()
            .any(|kind| report.at(kind, node) > 0)
    })
}

/// The inputs the negative controls run on, as positions in the reports given to
/// [`picks`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Picks {
    /// [`pick_type`] at [`PICK_NODE`], for each evidence type.
    pub by_type: BTreeMap<EvidenceType, usize>,
    /// [`pick_node`], for each honest participant.
    pub by_node: BTreeMap<usize, usize>,
}

impl fmt::Display for Picks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (evidence, position) in &self.by_type {
            write!(f, "pick({evidence:?}, {PICK_NODE})={position} ")?;
        }
        for (position, (node, pick)) in self.by_node.iter().enumerate() {
            if position > 0 {
                write!(f, " ")?;
            }
            write!(f, "pick({node})={pick}")?;
        }
        Ok(())
    }
}

/// The picks over `reports`, which must each count the same honest nodes. Fails
/// with `C4-I5 vacuous` when one is missing.
pub fn picks(reports: &[Report]) -> Result<Picks, String> {
    let mut by_type = BTreeMap::new();
    for evidence in EvidenceType::ALL {
        let Some(position) = pick_type(reports, evidence, PICK_NODE) else {
            return Err(format!(
                "C4-I5 vacuous: no run has a {evidence:?} obligation at node {PICK_NODE}"
            ));
        };
        by_type.insert(evidence, position);
    }
    let nodes: Vec<_> = reports
        .first()
        .and_then(|report| report.kinds.values().next())
        .map(|counts| counts.obligations.keys().copied().collect())
        .unwrap_or_default();
    if nodes.is_empty() {
        return Err("C4-I5 vacuous: no honest node was measured".into());
    }
    let mut by_node = BTreeMap::new();
    for node in nodes {
        let Some(position) = pick_node(reports, node) else {
            return Err(format!(
                "C4-I5 vacuous: no run has an obligation at node {node}"
            ));
        };
        by_node.insert(node, position);
    }
    Ok(Picks { by_type, by_node })
}
