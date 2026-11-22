//! Honest blame: one scripted Byzantine participant attacks three honest engines, and
//! the run checks that no honest engine blocks another honest participant.
//!
//! Four participants run on the production ed25519 scheme. Index 0 is the Byzantine
//! participant, `B`. It runs no engine: it holds its ends of the vote, certificate
//! and resolver channels and a handle of the mock relay, and follows a script. The
//! other three run production engines without `track_historical_votes`. The links of
//! `B` are faster than the links between honest nodes ([`link`]), so a vote of `B`
//! sits in an honest batch before the honest votes arrive and a certificate of `B`
//! reaches a node before the node builds its own.
//!
//! `B` handles one received message at a time. Its base behaviour is that of a
//! correct participant without a timer: it echoes every honest vote once and proposes
//! one block when it leads a view. An [`Attack`] changes what it does in a view
//! ([`attack_at`]): it floods all three channels, sends votes with broken signatures,
//! replays honest votes and forges their signer, sends junk, withholds its votes and
//! rushes certificates it assembled to the one node that did not vote, sends broken
//! copies of honest certificates, proposes two blocks, names a stale parent and
//! answers resolver requests with lies.
//!
//! Three times in a run the harness cuts, for [`WINDOW`], the links from the other
//! two honest nodes into one honest node. The node then misses certificates and
//! fetches them, so honest nodes check resolver answers of honest nodes.
//!
//! The run waits until every honest node has finalized [`CONTAINERS`] containers; a
//! stall ends it in the runtime's timeout panic. After [`SETTLE`] it reads the block
//! list once. No pair in it may name an honest participant as the blocked one
//! (`C7-I1`, [`check_blocks`]). The certificate-state invariants of the Standard
//! driver run last.
//!
//! An [`Outcome`] also holds every message `B` received and sent ([`Adversary`]) and
//! the windows as they happened ([`Window`]), so a test can check the script itself.
//!
//! One run does not show that its attack reached the engine. [`check_floors`] does,
//! over the outcomes of the twelve [`fixed_scenarios`] of one attack (`C7-I2`): from
//! the calls of every honest engine to its blocker ([`Recording`]), the counters of
//! `B` ([`Trace`]) and two metrics of every honest engine ([`fallbacks`],
//! [`fetched`]).
//!
//! Not asserted: what a block does to the connection, that `B` is blocked whenever it
//! should be, signatures built from curve edge cases, other schemes,
//! `track_historical_votes`, more than one Byzantine participant, a restart and an
//! epoch change.

use crate::{
    evidence::Log,
    flood::{FloodClass, sample_burst},
    invariants,
};
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::{Copying, Decode, DecodeExt, Encode};
use commonware_consensus::{
    Handoff, Monitor, Viewable,
    simplex::{
        ForwardPolicy,
        elector::{Config as ElectorConfig, Elector as _},
        mocks::{application, relay, reporter},
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
    },
    types::{Epoch, Participant, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX, BlockFilterChoice, CertifyChoice, DEFAULT_MAILBOX_SIZE, EPOCH,
    FuzzInput as BaseInput, N4F1C3, PublicKeyOf, ReporterWiring, bounded_fuzz_runtime_config,
    byzantine::Counting,
    setup_network,
    simplex::{Simplex, SimplexEd25519},
    simplex_audit::{ActivityRecorder, summaries},
    start_validator_engine,
    state_bounds::{self, VoteKind},
    strategy::StrategyChoice,
    utils::Partition,
};
use commonware_cryptography::{
    Hasher as _, Sha256, certificate::Verifier as _, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    BlockedSubscription, Blocker, CheckedSender, LimitedSender, Receiver as _, Recipients,
    simulated::{Link, Receiver as NetReceiver, Sender as NetSender},
};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{
    Clock, IoBuf, IoBufs, Metrics, Runner, Spawner, Supervisor as _, deterministic,
};
use commonware_utils::{
    NZU32, iter::NonEmpty, ordered::Set, probability, sequence::U64, sync::Mutex,
};
use futures::future::join_all;
use rand::{Rng as _, RngExt as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

/// Participant index of the Byzantine participant.
pub const BYZANTINE: usize = BYZANTINE_IDX;

/// Participant indices of the honest nodes.
pub const HONEST: [usize; 3] = [1, 2, 3];

/// Containers every honest node must finalize.
pub const CONTAINERS: u64 = 60;

/// Latency of every link to and from the Byzantine participant. These links have no
/// jitter.
pub const BYZANTINE_LATENCY: Duration = Duration::from_millis(1);

/// Latency of every link between two honest nodes.
pub const HONEST_LATENCY: Duration = Duration::from_millis(20);

/// Jitter of every link between two honest nodes.
pub const HONEST_JITTER: Duration = Duration::from_millis(10);

/// Cut-off windows of one run.
pub const WINDOWS: usize = 3;

/// How long a cut-off window lasts.
pub const WINDOW: Duration = Duration::from_millis(1_500);

/// Simulated time from the start of the run to the first window, and from the end of
/// a window to the next one.
pub const WINDOW_GAP: Duration = Duration::from_secs(3);

/// Simulated time between the last required finalization and the measurement.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Term length and optimistic lookahead of the [`fixed_scenarios`].
pub const CONFIGURATIONS: [(u32, u64); 4] = [(1, 0), (5, 0), (5, 5), (3, 1)];

/// Seeds of the [`fixed_scenarios`]: `0..SEEDS`.
pub const SEEDS: u64 = 3;

/// Scenarios of one attack in [`fixed_scenarios`].
pub const RUNS: usize = CONFIGURATIONS.len() * SEEDS as usize;

/// A run of [`Attack::Flood`] floods the views divisible by this number, and the
/// class of a burst changes every this many views.
pub const FLOOD_EVERY: u64 = 8;

/// One of a flood's resolver requests is for the view this many views below.
pub const FLOOD_BEHIND: u64 = 5;

/// One of a flood's resolver requests is for the view this many views above, and a
/// far copy of a certificate is this many views above the certificate.
pub const FAR_VIEWS: u64 = 1_000;

/// The first request id of the Byzantine participant's own resolver requests is one
/// above this number.
pub const FLOOD_REQUEST_IDS: u64 = 1 << 40;

/// Random bytes sent as junk on the vote channel.
pub const JUNK_VOTE_BYTES: usize = 40;

/// Random bytes sent as junk on the certificate channel, as a random copy of a
/// certificate and as a random resolver answer.
pub const JUNK_CERTIFICATE_BYTES: usize = 64;

/// Random bytes sent as junk on the resolver channel.
pub const JUNK_RESOLVER_BYTES: usize = 16;

/// The payload of the copy of a certificate that names another payload.
pub const OTHER_PAYLOAD: [u8; 32] = [7; 32];

/// The response sent under a guessed request id.
pub const GUESS: [u8; 16] = [0xab; 16];

/// Responses sent under guessed request ids before each answer.
pub const GUESSES: u64 = 3;

/// The answer when the Byzantine participant holds no certificate below the
/// requested view.
pub const NOTHING_BELOW: [u8; 8] = [0xff; 8];

/// The answer when the Byzantine participant holds no certificate at or above the
/// requested view.
pub const NOTHING_ABOVE: [u8; 8] = [0xfe; 8];

/// Votes [`Plant::CorruptVotes`] leaves unchanged.
pub const CLEAN_VOTES: u64 = 20;

/// Certificates [`Plant::CorruptCertificates`] leaves unchanged.
pub const CLEAN_CERTIFICATES: u64 = 5;

/// Flood votes a run that floods must send.
pub const FLOOR_FLOOD_VOTES: u64 = 64;

/// Flood requests a run that floods must send.
pub const FLOOR_FLOOD_REQUESTS: u64 = 5;

/// Junk messages a run that sends junk must send.
pub const FLOOR_JUNK: u64 = 4;

/// Equivocations a run of an equivocation attack must make.
pub const FLOOR_EQUIVOCATIONS: u64 = 3;

/// Label the Byzantine participant's sends count under.
pub const ACTOR: &str = "blame_byzantine";

/// Suffix of the counter of an engine's fallbacks from a failed batch verification.
pub const FALLBACKS: &str = "engine_batcher_construct_fallback_total";

/// Suffix of the counter of an engine's resolver fetches, by status.
pub const FETCHES: &str = "engine_resolver_resolver_fetch_total";

/// The label of a fetch whose answer the engine accepted.
pub const FETCH_SUCCESS: &str = "status=\"Success\"";

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

type Ballot = Vote<Scheme, Sha256Digest>;
type Proof = Certificate<Scheme, Sha256Digest>;
type Leaders = <<P as Simplex>::Elector as ElectorConfig<Scheme>>::Elector;
type Recorder =
    ActivityRecorder<deterministic::Context, Scheme, <P as Simplex>::Elector, Sha256Digest>;
type Outbound = Counting<NetSender<PublicKey, deterministic::Context>>;
type Inbound = NetReceiver<PublicKey>;

/// What the Byzantine participant does in a view, besides or in place of its base
/// behaviour: it echoes every honest vote once and proposes when it leads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attack {
    /// Nothing more.
    Correct,
    /// Sends nothing on any channel.
    Silent,
    /// On the first honest vote for the view, one burst of votes it signs. On the
    /// first honest certificate of a kind, the same bytes back, and once per view
    /// five resolver requests.
    Flood,
    /// Every echo and every notarize of its own proposal carries a signature that
    /// does not verify.
    BadSignature,
    /// After the echo, the honest vote unchanged and a vote it signs under the
    /// honest signer's index.
    Replay,
    /// On the first honest vote for the view: random bytes on all three channels and
    /// a nullify for another epoch.
    Junk,
    /// No echo and no proposal. Once it holds two honest votes for one subject it
    /// adds its own, assembles the certificate and sends it only to the honest node
    /// whose vote is not in it.
    RushCertificates,
    /// On the first honest certificate of a kind for the view: broken copies of it.
    BadCertificates,
    /// When it leads: two blocks on one parent, one for one honest node and the
    /// other for the other two.
    Equivocate,
    /// As [`Attack::Equivocate`], with a broken signature on the notarize the one
    /// node gets.
    EquivocateUnsigned,
    /// When it leads: a proposal on the parent before the latest one, so honest
    /// nodes ask it for the ancestry. It answers every resolver request with an
    /// invalid response, after responses under guessed request ids.
    ResolverLies,
    /// The attack [`Attack::CYCLE`] gives the view.
    Mixed,
}

impl Attack {
    /// Every attack, in the order of [`fixed_scenarios`].
    pub const ALL: [Self; 12] = [
        Self::Correct,
        Self::Silent,
        Self::Flood,
        Self::BadSignature,
        Self::Replay,
        Self::Junk,
        Self::RushCertificates,
        Self::BadCertificates,
        Self::Equivocate,
        Self::EquivocateUnsigned,
        Self::ResolverLies,
        Self::Mixed,
    ];

    /// The attacks of a [`Attack::Mixed`] run: view `v` gets `CYCLE[v mod 9]`.
    pub const CYCLE: [Self; 9] = [
        Self::Flood,
        Self::BadSignature,
        Self::Replay,
        Self::Junk,
        Self::RushCertificates,
        Self::BadCertificates,
        Self::Equivocate,
        Self::EquivocateUnsigned,
        Self::ResolverLies,
    ];
}

/// The attack the Byzantine participant applies to `view` in a run of `attack`.
///
/// `view` is the view of the vote or certificate it is handling, or the view it
/// proposes in. Whether it answers resolver requests depends on the run's attack
/// alone.
pub fn attack_at(attack: Attack, view: View) -> Attack {
    match attack {
        Attack::Mixed => Attack::CYCLE[(view.get() % Attack::CYCLE.len() as u64) as usize],
        Attack::Flood if !view.get().is_multiple_of(FLOOD_EVERY) => Attack::Correct,
        attack => attack,
    }
}

/// One run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    pub attack: Attack,
    /// Seeds the runtime with its eight big-endian bytes.
    pub seed: u64,
    pub term_length: TermLength,
    /// Optimistic lookahead of every honest engine.
    pub optimistic_views: ViewDelta,
}

/// The 144 scenarios the floors are made for: every attack of [`Attack::ALL`] on
/// every configuration of [`CONFIGURATIONS`] with every seed below [`SEEDS`]. The
/// scenario of attack `a`, configuration `c` and seed `s` is at `12 * a + 3 * c + s`.
pub fn fixed_scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::with_capacity(Attack::ALL.len() * RUNS);
    for attack in Attack::ALL {
        for (term_length, optimistic_views) in CONFIGURATIONS {
            for seed in 0..SEEDS {
                scenarios.push(Scenario {
                    attack,
                    seed,
                    term_length: TermLength::new(NZU32!(term_length)),
                    optimistic_views: ViewDelta::new(optimistic_views),
                });
            }
        }
    }
    scenarios
}

/// A fault planted at an observation point of one run, for the negative controls.
/// [`run`] plants none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    /// The harness blocks `to` in the name of `from`, through the network's control
    /// of `from`, after [`SETTLE`] and before the block list is read.
    DirectBlock { from: usize, to: usize },
    /// The vote sender of honest `node` flips the last byte of every vote after its
    /// first [`CLEAN_VOTES`].
    CorruptVotes { node: usize },
    /// The certificate sender of honest `node` flips the last byte of every
    /// certificate after its first [`CLEAN_CERTIFICATES`].
    CorruptCertificates { node: usize },
    /// The resolver sender of every honest node flips the last byte of every message
    /// that decodes as a response. Requests and errors pass unchanged.
    CorruptResponses,
    /// The blocker of honest `node` drops every call: no log entry, nothing to the
    /// network.
    SwallowBlocks { node: usize },
    /// No link is ever cut.
    NoWindows,
}

impl Plant {
    /// # Panics
    ///
    /// Panics unless every node the plant names as acting is honest and every node
    /// it names as blocked is a participant.
    fn validate(self) {
        let honest = |node: usize| {
            assert!(
                HONEST.contains(&node),
                "{self:?} names participant {node}, which is not an honest node"
            );
        };
        match self {
            Self::DirectBlock { from, to } => {
                honest(from);
                assert!(
                    to == BYZANTINE || HONEST.contains(&to),
                    "{self:?} names participant {to}, which is not a participant"
                );
            }
            Self::CorruptVotes { node }
            | Self::CorruptCertificates { node }
            | Self::SwallowBlocks { node } => honest(node),
            Self::CorruptResponses | Self::NoWindows => {}
        }
    }
}

/// One call of an honest engine to its blocker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Participant index of the engine.
    pub blocker: usize,
    /// Participant index of the peer it blocked.
    pub blocked: usize,
    /// Simulated time since the start of the run.
    pub at: Duration,
}

/// What the Byzantine participant did. Every counter but [`Trace::requests_heard`]
/// and [`Trace::relayed`] counts messages it handed to the network, one per message
/// whatever the number of recipients.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    /// Echoes of an honest vote, also those with a broken signature.
    pub echoes: u64,
    /// Views it proposed in.
    pub proposals: u64,
    /// Votes of a flood burst.
    pub flood_votes: u64,
    /// Honest certificates sent back in a flooded view.
    pub flood_certificates: u64,
    /// Resolver requests of its own.
    pub flood_requests: u64,
    /// Echoes and notarizes of its own proposal sent with a broken signature in a
    /// view of [`Attack::BadSignature`].
    pub bad_signatures: u64,
    /// Honest votes sent on unchanged.
    pub replayed: u64,
    /// Votes it signed under an honest signer's index.
    pub forged_signers: u64,
    /// Junk messages.
    pub junk: u64,
    /// Certificates it assembled and sent to one honest node.
    pub rushed: u64,
    /// Certificates received from an honest node whose bytes equal a certificate it
    /// rushed.
    pub relayed: u64,
    /// Broken copies of an honest certificate.
    pub bad_certificates: u64,
    /// Views it proposed two blocks in.
    pub equivocations: u64,
    /// Proposals on the parent before the latest one.
    pub stale_parents: u64,
    /// Resolver requests received from an honest node.
    pub requests_heard: u64,
    /// Responses under the id of a request it received.
    pub answers: u64,
    /// Responses under a guessed request id.
    pub guesses: u64,
}

impl Trace {
    /// Every counter with its name, in the order of the fields.
    pub const fn counters(&self) -> [(&'static str, u64); 17] {
        [
            ("echoes", self.echoes),
            ("proposals", self.proposals),
            ("flood_votes", self.flood_votes),
            ("flood_certificates", self.flood_certificates),
            ("flood_requests", self.flood_requests),
            ("bad_signatures", self.bad_signatures),
            ("replayed", self.replayed),
            ("forged_signers", self.forged_signers),
            ("junk", self.junk),
            ("rushed", self.rushed),
            ("relayed", self.relayed),
            ("bad_certificates", self.bad_certificates),
            ("equivocations", self.equivocations),
            ("stale_parents", self.stale_parents),
            ("requests_heard", self.requests_heard),
            ("answers", self.answers),
            ("guesses", self.guesses),
        ]
    }
}

/// A channel of the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Channel {
    Vote,
    Certificate,
    Resolver,
}

/// The rule of the script that made the Byzantine participant send a message. The
/// counter of the same name in [`Trace`] counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// The echo of an honest vote ([`Trace::echoes`]).
    Echo,
    /// The notarize of a block it proposed ([`Trace::proposals`] counts the view).
    Proposal,
    FloodVote,
    FloodCertificate,
    FloodRequest,
    Replay,
    ForgedSigner,
    Junk,
    Rush,
    BadCertificate,
    Guess,
    Answer,
}

/// One message the Byzantine participant received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub channel: Channel,
    /// Participant index of the sender.
    pub from: usize,
    /// The message as received.
    pub bytes: Vec<u8>,
}

/// One message the Byzantine participant handed to the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub channel: Channel,
    /// Participant indices of the nodes the network took the message for, sorted.
    pub to: Vec<usize>,
    /// The message as sent.
    pub bytes: Vec<u8>,
    pub rule: Rule,
    /// Position in [`Adversary::heard`] of the message the Byzantine participant was
    /// handling; `None` for a proposal at the start of the run.
    pub trigger: Option<usize>,
}

/// One block the Byzantine participant gave to the relay for all participants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The proposal it signs for the block. Its payload is the SHA-256 digest of the
    /// block's contents: the round, the parent's payload and `nonce`, in the mock
    /// application's encoding.
    pub proposal: Proposal<Sha256Digest>,
    /// The payload of the parent.
    pub parent: Sha256Digest,
    /// The number it drew for the block.
    pub nonce: u64,
    /// Whether the parent is the one before the latest it knows.
    pub stale: bool,
    /// Position in [`Adversary::heard`] of the certificate that made it propose;
    /// `None` at the start of the run.
    pub trigger: Option<usize>,
}

/// What the Byzantine participant received, sent and proposed, each in the order it
/// happened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Adversary {
    pub heard: Vec<Heard>,
    pub sent: Vec<Sent>,
    pub blocks: Vec<Block>,
}

/// One cut-off window, as it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// Participant index of the honest node that was cut off.
    pub node: usize,
    /// Participant indices of the nodes whose links into `node` were removed.
    pub from: Vec<usize>,
    /// Simulated time since the start of the run at which the harness began to
    /// remove the links.
    pub cut_at: Duration,
    /// Simulated time since the start of the run at which the harness began to add
    /// them back.
    pub restored_at: Duration,
}

/// One honest node at the measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Participant index.
    pub index: usize,
    /// Containers the node finalized.
    pub finalized: u64,
    /// [`fallbacks`] of the node's engine.
    pub fallbacks: u64,
    /// [`fetched`] of the node's engine.
    pub fetched: u64,
}

/// The outcome of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub scenario: Scenario,
    /// The participants, by index. With the namespace of the fuzz network they give
    /// a scheme that verifies every participant's votes.
    pub participants: Vec<PublicKey>,
    /// The block list at the measurement, as sorted pairs of participant indices:
    /// who blocks whom.
    pub blocked: Vec<(usize, usize)>,
    /// Every call of an honest engine to its blocker, in the order made.
    pub calls: Vec<Call>,
    pub trace: Trace,
    /// The honest nodes, by participant index.
    pub nodes: Vec<Node>,
    /// Simulated time since the start of the run at which the last honest node had
    /// finalized [`CONTAINERS`] containers.
    pub finalized_at: Duration,
    /// Simulated time since the start of the run of the measurement: the one read
    /// of the block list.
    pub measured_at: Duration,
    /// The cut-off windows, in the order they happened.
    pub windows: Vec<Window>,
    pub adversary: Adversary,
}

/// The link from participant `from` to participant `to`: lossless, and faster when
/// one end is the Byzantine participant.
pub fn link(from: usize, to: usize) -> Link {
    if from == BYZANTINE || to == BYZANTINE {
        Link {
            latency: BYZANTINE_LATENCY,
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        }
    } else {
        Link {
            latency: HONEST_LATENCY,
            jitter: HONEST_JITTER,
            success_rate: probability!(1.0),
        }
    }
}

/// An engine's blocker: appends every call to `calls` and then hands it to `inner`.
#[derive(Clone)]
pub struct Recording<B: Blocker> {
    inner: B,
    blocker: usize,
    participants: Vec<B::PublicKey>,
    calls: Log<Call>,
    clock: Arc<deterministic::Context>,
    started: SystemTime,
    swallow: bool,
}

impl<B: Blocker> Recording<B> {
    /// The blocker of the engine of participant `blocker`. `clock` gives the
    /// simulated time and `started` is the time the run started at.
    pub const fn new(
        inner: B,
        blocker: usize,
        participants: Vec<B::PublicKey>,
        calls: Log<Call>,
        clock: Arc<deterministic::Context>,
        started: SystemTime,
    ) -> Self {
        Self {
            inner,
            blocker,
            participants,
            calls,
            clock,
            started,
            swallow: false,
        }
    }
}

impl<B: Blocker> Blocker for Recording<B> {
    type PublicKey = B::PublicKey;

    /// # Panics
    ///
    /// Panics when `peer` is not a participant.
    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        let blocked = self
            .participants
            .iter()
            .position(|participant| *participant == peer)
            .unwrap_or_else(|| {
                panic!(
                    "participant {} blocked {peer}, which is not a participant",
                    self.blocker
                )
            });
        if self.swallow {
            return Feedback::Ok;
        }
        self.calls.push(Call {
            blocker: self.blocker,
            blocked,
            at: since(&*self.clock, self.started),
        });
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

/// What a [`Corrupting`] sender does to the messages it is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corruption {
    /// Nothing.
    None,
    /// Flips the last byte of every message after the first so many.
    After(u64),
    /// Flips the last byte of every message that decodes as a resolver response.
    Responses,
}

/// An honest engine's sender with a [`Corruption`].
#[derive(Clone)]
pub struct Corrupting<S> {
    inner: S,
    corruption: Corruption,
    sent: Arc<AtomicU64>,
}

impl<S> Corrupting<S> {
    pub fn new(inner: S, corruption: Corruption) -> Self {
        Self {
            inner,
            corruption,
            sent: Arc::default(),
        }
    }
}

impl<S: LimitedSender> LimitedSender for Corrupting<S> {
    type PublicKey = S::PublicKey;
    type Checked<'a>
        = CorruptingChecked<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let corruption = self.corruption;
        let sent = self.sent.clone();
        self.inner.check(recipients).map(|inner| CorruptingChecked {
            inner,
            corruption,
            sent,
        })
    }
}

/// The checked sender of a [`Corrupting`] sender.
pub struct CorruptingChecked<C> {
    inner: C,
    corruption: Corruption,
    sent: Arc<AtomicU64>,
}

impl<C: CheckedSender> CheckedSender for CorruptingChecked<C> {
    type PublicKey = C::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        if self.corruption == Corruption::None {
            return self.inner.send(message, priority);
        }
        let message: IoBufs = message.into();
        let mut bytes = message.coalesce().as_ref().to_vec();
        let corrupt = match self.corruption {
            Corruption::None => false,
            Corruption::After(clean) => self.sent.fetch_add(1, Ordering::Relaxed) >= clean,
            Corruption::Responses => ResolverMessage::<U64>::decode(Copying(bytes.as_slice()))
                .is_ok_and(|message| matches!(message.payload, ResolverPayload::Response(_))),
        };
        if corrupt {
            flip_last(&mut bytes);
        }
        self.inner.send(IoBuf::from(bytes), priority)
    }
}

/// The block list as sorted pairs of participant indices: who blocks whom.
///
/// # Panics
///
/// Panics when the list could not be read or names a key that is not a participant.
pub fn block_list<E: fmt::Debug>(
    read: Result<Vec<(PublicKey, PublicKey)>, E>,
    participants: &[PublicKey],
) -> Vec<(usize, usize)> {
    let pairs = read.unwrap_or_else(|error| panic!("the block list could not be read: {error:?}"));
    let index = |key: &PublicKey| {
        participants
            .iter()
            .position(|participant| participant == key)
            .unwrap_or_else(|| panic!("the block list names {key}, which is not a participant"))
    };
    let mut blocked: Vec<_> = pairs
        .iter()
        .map(|(blocker, blocked)| (index(blocker), index(blocked)))
        .collect();
    blocked.sort_unstable();
    blocked
}

/// Times the engine of `node` fell back to verifying every vote after a batch
/// failed, read from an encoded metrics text.
///
/// # Panics
///
/// Panics with the counter's name unless exactly one sample matches: the engine
/// encodes the counter also at zero, so a renamed metric fails every run.
pub fn fallbacks(metrics: &str, node: &state_bounds::Node) -> u64 {
    state_bounds::gauge(metrics, FALLBACKS, node)
}

/// Resolver answers the engine of `node` fetched and accepted, read from an encoded
/// metrics text; zero when the text has no such sample, because the engine encodes
/// the series only once it is above zero.
///
/// # Panics
///
/// Panics with the counter's name when more than one sample matches or the value is
/// not a number.
pub fn fetched(metrics: &str, node: &state_bounds::Node) -> u64 {
    let label = node.to_string();
    let mut samples = metrics.lines().filter_map(|line| {
        let (series, value) = line.rsplit_once(' ')?;
        let (name, labels) = series.split_once('{')?;
        let labels = labels.strip_suffix('}')?;
        let named = name == FETCHES
            || name
                .strip_suffix(FETCHES)
                .is_some_and(|prefix| prefix.ends_with('_'));
        let labeled = |wanted: &str| labels.split(',').any(|pair| pair == wanted);
        (named && labeled(&label) && labeled(FETCH_SUCCESS)).then_some(value)
    });
    let Some(value) = samples.next() else {
        return 0;
    };
    assert!(
        samples.next().is_none(),
        "counter {FETCHES}{{{label},{FETCH_SUCCESS}}} is ambiguous"
    );
    value.parse().unwrap_or_else(|_| {
        panic!("counter {FETCHES}{{{label},{FETCH_SUCCESS}}} has the value {value}")
    })
}

/// `C7-I1`: no pair of `blocked`, the block list as pairs of participant indices
/// (who blocks whom), names an honest participant as the blocked one.
pub fn check_blocks(blocked: &[(usize, usize)]) -> Result<(), String> {
    honest_blocked(blocked).map_or(Ok(()), |(blocker, blocked)| {
        Err(format!(
            "C7-I1 violated: participant {blocker} blocked honest participant {blocked}"
        ))
    })
}

/// The first pair of `blocked` whose blocked participant is honest.
fn honest_blocked(blocked: &[(usize, usize)]) -> Option<(usize, usize)> {
    blocked
        .iter()
        .copied()
        .find(|(_, blocked)| HONEST.contains(blocked))
}

/// Block calls of honest participant `node` on the Byzantine participant.
pub fn calls_on_byzantine(outcome: &Outcome, node: usize) -> usize {
    outcome
        .calls
        .iter()
        .filter(|call| call.blocker == node && call.blocked == BYZANTINE)
        .count()
}

/// One row of the floors of an attack, for the run at `scenario` in
/// [`fixed_scenarios`].
struct Floor<'a> {
    id: &'static str,
    scenario: usize,
    outcome: &'a Outcome,
}

impl Floor<'_> {
    fn miss(&self, node: Option<usize>, what: fmt::Arguments<'_>) -> String {
        let Self { id, scenario, .. } = self;
        match node {
            Some(node) => format!("C7-I2 vacuous: {id}: scenario {scenario}, node {node}: {what}"),
            None => format!("C7-I2 vacuous: {id}: scenario {scenario}: {what}"),
        }
    }

    /// The counter `name` of the trace is at least `least`.
    fn counter(&self, name: &str, least: u64) -> Result<(), String> {
        let value = self
            .outcome
            .trace
            .counters()
            .into_iter()
            .find(|(counter, _)| *counter == name)
            .map(|(_, value)| value)
            .expect("the trace has the counter");
        if value >= least {
            return Ok(());
        }
        Err(self.miss(None, format_args!("{name} is {value}, below {least}")))
    }

    /// No honest engine called its blocker.
    fn no_calls(&self) -> Result<(), String> {
        let Some(call) = self.outcome.calls.first() else {
            return Ok(());
        };
        Err(self.miss(
            None,
            format_args!(
                "participant {} blocked participant {} at {:?}",
                call.blocker, call.blocked, call.at
            ),
        ))
    }

    /// Every honest engine called its blocker on the Byzantine participant.
    fn every_node_blocked(&self) -> Result<(), String> {
        for node in HONEST {
            if calls_on_byzantine(self.outcome, node) == 0 {
                return Err(self.miss(
                    Some(node),
                    format_args!("no block call on participant {BYZANTINE}"),
                ));
            }
        }
        Ok(())
    }

    /// Every honest engine called its blocker on the Byzantine participant and fell
    /// back from a failed batch verification.
    fn every_node_blocked_after_fallback(&self) -> Result<(), String> {
        for node in &self.outcome.nodes {
            if calls_on_byzantine(self.outcome, node.index) == 0 {
                return Err(self.miss(
                    Some(node.index),
                    format_args!("no block call on participant {BYZANTINE}"),
                ));
            }
            if node.fallbacks == 0 {
                return Err(self.miss(Some(node.index), format_args!("fallbacks is 0")));
            }
        }
        Ok(())
    }

    /// Some honest engine called its blocker on the Byzantine participant.
    fn some_node_blocked(&self) -> Result<(), String> {
        if HONEST
            .into_iter()
            .any(|node| calls_on_byzantine(self.outcome, node) > 0)
        {
            return Ok(());
        }
        Err(self.miss(
            None,
            format_args!("no honest node has a block call on participant {BYZANTINE}"),
        ))
    }

    /// Every counter of the trace but `requests_heard` is zero.
    fn silent(&self) -> Result<(), String> {
        for (name, value) in self.outcome.trace.counters() {
            if name != "requests_heard" && value != 0 {
                return Err(self.miss(None, format_args!("{name} is {value}, not 0")));
            }
        }
        Ok(())
    }
}

/// `C7-I2`: the attack of every run reached the engine code it aims at.
///
/// `outcomes` are the outcomes of the twelve scenarios of `attack`, in the order of
/// [`fixed_scenarios`]; anything else is an error that starts with `C7-I2 input:`. A
/// missed floor is an error that starts with `C7-I2 vacuous: ` and the floor's id,
/// and names the scenario by its position in [`fixed_scenarios`] and, where the
/// floor is per node, the node.
///
/// | Floor | Attack | Required in every run, unless "sum" |
/// |---|---|---|
/// | `F-0a` | `Correct` | no block call; `echoes >= 1`; `proposals >= 1` |
/// | `F-0b` | `Correct` | sum over the runs and the honest nodes of `fetched >= 1` |
/// | `F-1` | `Silent` | no block call; every counter but `requests_heard` is 0 |
/// | `F-2` | `Flood` | `flood_votes >= 64`; `flood_certificates >= 1`; `flood_requests >= 5`; every honest node blocked `B` |
/// | `F-3` | `BadSignature` | `bad_signatures >= 1`; every honest node blocked `B` and has `fallbacks >= 1` |
/// | `F-4` | `Replay` | `replayed >= 1`; `forged_signers >= 1`; every honest node blocked `B` |
/// | `F-5` | `Junk` | `junk >= 4`; every honest node blocked `B` |
/// | `F-6` | `RushCertificates` | `rushed >= 1`; `relayed >= 1`; no block call |
/// | `F-7` | `BadCertificates` | `bad_certificates >= 1`; every honest node blocked `B` |
/// | `F-8` | `Equivocate` | `equivocations >= 3`; some honest node blocked `B`; sum: every honest node blocked `B` in some run |
/// | `F-9` | `EquivocateUnsigned` | as `F-8` |
/// | `F-10` | `ResolverLies` | `stale_parents >= 1`; `answers >= 1`; `guesses >= 3`; every honest node blocked `B` |
/// | `F-11` | `Mixed` | `flood_votes >= 64`; `bad_signatures >= 1`; `replayed >= 1`; `junk >= 4`; `rushed >= 1`; `relayed >= 1`; `bad_certificates >= 1`; `equivocations >= 1`; every honest node blocked `B` and has `fallbacks >= 1` |
///
/// "Blocked `B`" means a call in [`Outcome::calls`], not a pair of the block list.
pub fn check_floors(attack: Attack, outcomes: &[Outcome]) -> Result<(), String> {
    let position = Attack::ALL
        .iter()
        .position(|listed| *listed == attack)
        .expect("every attack is listed");
    let first = position * RUNS;
    let last = first + RUNS - 1;
    let scenarios = fixed_scenarios();
    if outcomes.len() != RUNS {
        return Err(format!(
            "C7-I2 input: {attack:?} has {RUNS} scenarios and {} outcomes were given",
            outcomes.len()
        ));
    }
    for (offset, outcome) in outcomes.iter().enumerate() {
        let scenario = first + offset;
        if outcome.scenario != scenarios[scenario] {
            return Err(format!(
                "C7-I2 input: outcome {offset} is of {:?}, not of scenario {scenario}, {:?}",
                outcome.scenario, scenarios[scenario]
            ));
        }
        if !outcome.nodes.iter().map(|node| node.index).eq(HONEST) {
            return Err(format!(
                "C7-I2 input: outcome {offset} does not hold the honest nodes {HONEST:?} in order"
            ));
        }
    }

    let floor = |id: &'static str, offset: usize| Floor {
        id,
        scenario: first + offset,
        outcome: &outcomes[offset],
    };
    let every_run = |id: &'static str, check: &dyn Fn(&Floor<'_>) -> Result<(), String>| {
        (0..RUNS).try_for_each(|offset| check(&floor(id, offset)))
    };
    // Every honest node has a block call on the Byzantine participant in some run.
    let every_node_in_some_run = |id: &'static str| {
        for node in HONEST {
            if outcomes
                .iter()
                .all(|outcome| calls_on_byzantine(outcome, node) == 0)
            {
                return Err(format!(
                    "C7-I2 vacuous: {id}: scenarios {first} to {last}, node {node}: no block call \
                     on participant {BYZANTINE} in any run"
                ));
            }
        }
        Ok(())
    };
    let equivocation = |id: &'static str| {
        every_run(id, &|floor| {
            floor.counter("equivocations", FLOOR_EQUIVOCATIONS)?;
            floor.some_node_blocked()
        })?;
        every_node_in_some_run(id)
    };

    match attack {
        Attack::Correct => {
            every_run("F-0a", &|floor| {
                floor.no_calls()?;
                floor.counter("echoes", 1)?;
                floor.counter("proposals", 1)
            })?;
            let fetched: u64 = outcomes
                .iter()
                .flat_map(|outcome| &outcome.nodes)
                .map(|node| node.fetched)
                .sum();
            if fetched == 0 {
                return Err(format!(
                    "C7-I2 vacuous: F-0b: scenarios {first} to {last}: no honest node fetched a \
                     resolver answer"
                ));
            }
            Ok(())
        }
        Attack::Silent => every_run("F-1", &|floor| {
            floor.no_calls()?;
            floor.silent()
        }),
        Attack::Flood => every_run("F-2", &|floor| {
            floor.counter("flood_votes", FLOOR_FLOOD_VOTES)?;
            floor.counter("flood_certificates", 1)?;
            floor.counter("flood_requests", FLOOR_FLOOD_REQUESTS)?;
            floor.every_node_blocked()
        }),
        Attack::BadSignature => every_run("F-3", &|floor| {
            floor.counter("bad_signatures", 1)?;
            floor.every_node_blocked_after_fallback()
        }),
        Attack::Replay => every_run("F-4", &|floor| {
            floor.counter("replayed", 1)?;
            floor.counter("forged_signers", 1)?;
            floor.every_node_blocked()
        }),
        Attack::Junk => every_run("F-5", &|floor| {
            floor.counter("junk", FLOOR_JUNK)?;
            floor.every_node_blocked()
        }),
        Attack::RushCertificates => every_run("F-6", &|floor| {
            floor.counter("rushed", 1)?;
            floor.counter("relayed", 1)?;
            floor.no_calls()
        }),
        Attack::BadCertificates => every_run("F-7", &|floor| {
            floor.counter("bad_certificates", 1)?;
            floor.every_node_blocked()
        }),
        Attack::Equivocate => equivocation("F-8"),
        Attack::EquivocateUnsigned => equivocation("F-9"),
        Attack::ResolverLies => every_run("F-10", &|floor| {
            floor.counter("stale_parents", 1)?;
            floor.counter("answers", 1)?;
            floor.counter("guesses", GUESSES)?;
            floor.every_node_blocked()
        }),
        Attack::Mixed => every_run("F-11", &|floor| {
            floor.counter("flood_votes", FLOOR_FLOOD_VOTES)?;
            floor.counter("bad_signatures", 1)?;
            floor.counter("replayed", 1)?;
            floor.counter("junk", FLOOR_JUNK)?;
            floor.counter("rushed", 1)?;
            floor.counter("relayed", 1)?;
            floor.counter("bad_certificates", 1)?;
            floor.counter("equivocations", 1)?;
            floor.every_node_blocked_after_fallback()
        }),
    }
}

/// Simulated time since `started`.
fn since(clock: &impl Clock, started: SystemTime) -> Duration {
    clock
        .current()
        .duration_since(started)
        .expect("simulated time does not go back")
}

fn flip_last(bytes: &mut [u8]) {
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
}

const fn kind(vote: &Ballot) -> VoteKind {
    match vote {
        Vote::Notarize(_) => VoteKind::Notarize,
        Vote::Nullify(_) => VoteKind::Nullify,
        Vote::Finalize(_) => VoteKind::Finalize,
    }
}

/// Whether two votes of one kind are for one subject: the proposal, or the round of
/// a nullify.
fn same_subject(a: &Ballot, b: &Ballot) -> bool {
    match (a, b) {
        (Vote::Notarize(a), Vote::Notarize(b)) => a.proposal == b.proposal,
        (Vote::Nullify(a), Vote::Nullify(b)) => a.round == b.round,
        (Vote::Finalize(a), Vote::Finalize(b)) => a.proposal == b.proposal,
        _ => false,
    }
}

/// The scripted Byzantine participant.
struct Byzantine {
    context: deterministic::Context,
    scheme: Scheme,
    /// The attack of the run.
    attack: Attack,
    participants: Vec<PublicKey>,
    leaders: Leaders,
    relay: Arc<relay::Relay<Sha256Digest, PublicKey>>,
    votes: Outbound,
    certificates: Outbound,
    resolver: Outbound,
    trace: Arc<Mutex<Trace>>,
    log: Arc<Mutex<Adversary>>,
    /// Position in the log of the received message being handled.
    handling: Option<usize>,

    /// The highest view it has seen the certificate of the view before.
    entered: View,
    /// The proposal of the first notarization or finalization received for a view.
    parents: BTreeMap<View, Proposal<Sha256Digest>>,
    /// Every honest vote received, with its sender, in the order received: one per
    /// view, kind, subject and sender.
    heard: BTreeMap<(View, VoteKind), Vec<(usize, Ballot)>>,
    /// The bytes of the first certificate of each view and kind received.
    proofs: BTreeMap<(View, VoteKind), Vec<u8>>,
    /// The views it has received an honest vote for.
    voted: BTreeSet<View>,
    /// The votes it has echoed, and a notarize for every view it proposed in.
    echoed: BTreeSet<(View, VoteKind)>,
    /// The certificates it has rushed.
    rushed: BTreeSet<(View, VoteKind)>,
    rushed_bytes: BTreeSet<Vec<u8>>,
    /// The views it has sent resolver requests of its own for.
    asked: BTreeSet<View>,
    /// The id of its last resolver request.
    request_id: u64,
    /// Requests it has answered.
    answered: u64,
}

impl Byzantine {
    fn index(&self, key: &PublicKey) -> usize {
        self.participants
            .iter()
            .position(|participant| participant == key)
            .expect("a participant sent the message")
    }

    fn leads(&self, view: View) -> bool {
        let leader = self.leaders.elect(Round::new(Epoch::new(EPOCH), view), ());
        leader == Participant::from_usize(BYZANTINE)
    }

    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.context.fill_bytes(&mut bytes);
        bytes
    }

    /// Appends a received message to the log and makes it the one being handled.
    fn hear(&mut self, channel: Channel, from: &PublicKey, bytes: &[u8]) {
        let from = self.index(from);
        let mut log = self.log.lock();
        self.handling = Some(log.heard.len());
        log.heard.push(Heard {
            channel,
            from,
            bytes: bytes.to_vec(),
        });
    }

    /// Hands `bytes` to the network for `to`, waiting out the rate limit, and appends
    /// the message to the log.
    async fn send(
        &mut self,
        channel: Channel,
        to: Recipients<PublicKey>,
        bytes: Vec<u8>,
        rule: Rule,
    ) {
        let sender = match channel {
            Channel::Vote => &mut self.votes,
            Channel::Certificate => &mut self.certificates,
            Channel::Resolver => &mut self.resolver,
        };
        let recipients = loop {
            match sender.check(to.clone()) {
                Ok(checked) => {
                    let recipients = checked.recipients();
                    assert!(
                        checked.send(IoBuf::from(bytes.clone()), true).accepted(),
                        "the network refused a message of the Byzantine participant"
                    );
                    break recipients;
                }
                Err(retry) => self.context.sleep_until(retry).await,
            }
        };
        let mut to: Vec<_> = recipients.iter().map(|key| self.index(key)).collect();
        to.sort_unstable();
        self.log.lock().sent.push(Sent {
            channel,
            to,
            bytes,
            rule,
            trigger: self.handling,
        });
    }

    async fn vote_all(&mut self, bytes: Vec<u8>, rule: Rule) {
        self.send(Channel::Vote, Recipients::All, bytes, rule).await;
    }

    /// Its own vote for the subject of `heard`.
    fn sign(&self, heard: &Ballot) -> Ballot {
        match heard {
            Vote::Notarize(heard) => {
                Notarize::sign(&self.scheme, heard.proposal.clone()).map(Vote::Notarize)
            }
            Vote::Nullify(heard) => {
                Nullify::sign::<Sha256Digest>(&self.scheme, heard.round).map(Vote::Nullify)
            }
            Vote::Finalize(heard) => {
                Finalize::sign(&self.scheme, heard.proposal.clone()).map(Vote::Finalize)
            }
        }
        .expect("the Byzantine participant signs")
    }

    /// `vote`, which it signed, with a signature that does not verify: the last byte
    /// flipped (`form` 0), its signature over another subject (1), or zeroes (2).
    fn bad_signature(&self, vote: &Ballot, form: u64) -> Vec<u8> {
        let mut bytes = vote.encode().to_vec();
        match form {
            0 => flip_last(&mut bytes),
            1 => {
                let other: Ballot = match vote {
                    Vote::Notarize(vote) => {
                        let mut forged = vote.clone();
                        forged.attestation = Finalize::sign(&self.scheme, vote.proposal.clone())
                            .expect("the Byzantine participant signs")
                            .attestation;
                        Vote::Notarize(forged)
                    }
                    Vote::Nullify(vote) => {
                        let mut forged = vote.clone();
                        let next = Round::new(vote.round.epoch(), vote.round.view().next());
                        forged.attestation = Nullify::sign::<Sha256Digest>(&self.scheme, next)
                            .expect("the Byzantine participant signs")
                            .attestation;
                        Vote::Nullify(forged)
                    }
                    Vote::Finalize(vote) => {
                        let mut forged = vote.clone();
                        forged.attestation = Notarize::sign(&self.scheme, vote.proposal.clone())
                            .expect("the Byzantine participant signs")
                            .attestation;
                        Vote::Finalize(forged)
                    }
                };
                bytes = other.encode().to_vec();
            }
            _ => {
                // An encoded vote ends in its ed25519 signature.
                let signature = bytes.len() - 64;
                bytes[signature..].fill(0);
            }
        }
        bytes
    }

    /// Echoes `heard` once per view and kind, unless it crosses an echo it sent or
    /// its own proposal.
    async fn echo(&mut self, heard: &Ballot) {
        let view = heard.view();
        let kind = kind(heard);
        let crossed = match kind {
            VoteKind::Notarize => false,
            VoteKind::Nullify => self.echoed.contains(&(view, VoteKind::Finalize)),
            VoteKind::Finalize => self.echoed.contains(&(view, VoteKind::Nullify)),
        };
        if crossed || !self.echoed.insert((view, kind)) {
            return;
        }
        let own = self.sign(heard);
        let bytes = if attack_at(self.attack, view) == Attack::BadSignature {
            self.trace.lock().bad_signatures += 1;
            self.bad_signature(&own, view.get() % 3)
        } else {
            own.encode().to_vec()
        };
        self.trace.lock().echoes += 1;
        self.vote_all(bytes, Rule::Echo).await;
    }

    /// One burst of votes it signs for the run's epoch.
    async fn flood(&mut self, view: View) {
        let class = FloodClass::ALL[((view.get() / FLOOD_EVERY) % 3) as usize];
        for choice in sample_burst(&mut self.context, class, view) {
            let round = Round::new(Epoch::new(EPOCH), choice.view);
            let proposal = |payload: Option<Sha256Digest>| {
                Proposal::new(
                    round,
                    View::new(choice.view.get().saturating_sub(1)),
                    payload.expect("a notarize or finalize choice has a payload"),
                )
            };
            let vote: Option<Ballot> = match choice.kind {
                VoteKind::Notarize => {
                    Notarize::sign(&self.scheme, proposal(choice.payload)).map(Vote::Notarize)
                }
                VoteKind::Nullify => {
                    Nullify::sign::<Sha256Digest>(&self.scheme, round).map(Vote::Nullify)
                }
                VoteKind::Finalize => {
                    Finalize::sign(&self.scheme, proposal(choice.payload)).map(Vote::Finalize)
                }
            };
            let vote = vote.expect("the Byzantine participant signs");
            self.trace.lock().flood_votes += 1;
            self.vote_all(vote.encode().to_vec(), Rule::FloodVote).await;
        }
    }

    /// Random bytes on all three channels and a nullify for another epoch.
    async fn junk(&mut self, view: View) {
        let bytes = self.random_bytes(JUNK_VOTE_BYTES);
        self.trace.lock().junk += 1;
        self.vote_all(bytes, Rule::Junk).await;

        let round = Round::new(Epoch::new(EPOCH + 1), view);
        let nullify = Nullify::sign::<Sha256Digest>(&self.scheme, round)
            .expect("the Byzantine participant signs");
        self.trace.lock().junk += 1;
        self.vote_all(Ballot::Nullify(nullify).encode().to_vec(), Rule::Junk)
            .await;

        let bytes = self.random_bytes(JUNK_CERTIFICATE_BYTES);
        self.trace.lock().junk += 1;
        self.send(Channel::Certificate, Recipients::All, bytes, Rule::Junk)
            .await;

        let bytes = self.random_bytes(JUNK_RESOLVER_BYTES);
        self.trace.lock().junk += 1;
        self.send(Channel::Resolver, Recipients::All, bytes, Rule::Junk)
            .await;
    }

    /// The honest vote unchanged, and a vote it signs under the honest signer's
    /// index.
    async fn replay(&mut self, heard: &Ballot, bytes: Vec<u8>) {
        self.trace.lock().replayed += 1;
        self.vote_all(bytes, Rule::Replay).await;

        let forged = match (self.sign(heard), heard) {
            (Vote::Notarize(mut forged), Vote::Notarize(heard)) => {
                forged.attestation.signer = heard.attestation.signer;
                Vote::Notarize(forged)
            }
            (Vote::Nullify(mut forged), Vote::Nullify(heard)) => {
                forged.attestation.signer = heard.attestation.signer;
                Vote::Nullify(forged)
            }
            (Vote::Finalize(mut forged), Vote::Finalize(heard)) => {
                forged.attestation.signer = heard.attestation.signer;
                Vote::Finalize(forged)
            }
            _ => unreachable!("its own vote is of the kind of the vote it heard"),
        };
        self.trace.lock().forged_signers += 1;
        self.vote_all(forged.encode().to_vec(), Rule::ForgedSigner)
            .await;
    }

    /// Once it holds two honest votes for the subject of `heard`: the certificate of
    /// the two and its own vote, sent to the honest node whose vote is not in it.
    async fn rush(&mut self, heard: &Ballot) {
        let view = heard.view();
        let kind = kind(heard);
        if self.rushed.contains(&(view, kind)) {
            return;
        }
        let mut held: Vec<_> = self.heard[&(view, kind)]
            .iter()
            .filter(|(_, vote)| same_subject(vote, heard))
            .collect();
        held.sort_by_key(|(signer, _)| *signer);
        let [(first, _), (second, _), ..] = held[..] else {
            return;
        };
        let (first, second) = (*first, *second);
        self.rushed.insert((view, kind));

        let own = self.sign(heard);
        let votes = held[..2].iter().map(|(_, vote)| vote).chain([&own]);
        let proof: Option<Proof> = match heard {
            Vote::Notarize(_) => {
                let votes: Vec<_> = votes
                    .filter_map(|vote| match vote {
                        Vote::Notarize(vote) => Some(vote),
                        _ => None,
                    })
                    .collect();
                Notarization::from_notarizes(
                    &self.scheme,
                    NonEmpty::try_new(votes.into_iter()).expect("three votes"),
                    &Sequential,
                )
                .ok()
                .map(Certificate::Notarization)
            }
            Vote::Nullify(_) => {
                let votes: Vec<_> = votes
                    .filter_map(|vote| match vote {
                        Vote::Nullify(vote) => Some(vote),
                        _ => None,
                    })
                    .collect();
                Nullification::from_nullifies(
                    &self.scheme,
                    NonEmpty::try_new(votes.into_iter()).expect("three votes"),
                    &Sequential,
                )
                .ok()
                .map(Certificate::Nullification)
            }
            Vote::Finalize(_) => {
                let votes: Vec<_> = votes
                    .filter_map(|vote| match vote {
                        Vote::Finalize(vote) => Some(vote),
                        _ => None,
                    })
                    .collect();
                Finalization::from_finalizes(
                    &self.scheme,
                    NonEmpty::try_new(votes.into_iter()).expect("three votes"),
                    &Sequential,
                )
                .ok()
                .map(Certificate::Finalization)
            }
        };
        let bytes = proof
            .expect("three votes for one subject make a certificate")
            .encode()
            .to_vec();
        let absent = HONEST
            .into_iter()
            .find(|node| *node != first && *node != second)
            .expect("two of three honest nodes voted");
        self.rushed_bytes.insert(bytes.clone());
        self.trace.lock().rushed += 1;
        let to = Recipients::One(self.participants[absent].clone());
        self.send(Channel::Certificate, to, bytes, Rule::Rush).await;
    }

    async fn on_vote(&mut self, from: PublicKey, bytes: Vec<u8>) {
        self.hear(Channel::Vote, &from, &bytes);
        let Ok(heard) = Ballot::decode(Copying(bytes.as_slice())) else {
            return;
        };
        let from = self.index(&from);
        let view = heard.view();
        let first = self.voted.insert(view);
        let held = self.heard.entry((view, kind(&heard))).or_default();
        if !held
            .iter()
            .any(|(signer, vote)| *signer == from && same_subject(vote, &heard))
        {
            held.push((from, heard.clone()));
        }

        match attack_at(self.attack, view) {
            Attack::Silent => {}
            Attack::RushCertificates => self.rush(&heard).await,
            Attack::Replay => {
                self.echo(&heard).await;
                self.replay(&heard, bytes).await;
            }
            Attack::Junk => {
                self.echo(&heard).await;
                if first {
                    self.junk(view).await;
                }
            }
            Attack::Flood => {
                self.echo(&heard).await;
                if first {
                    self.flood(view).await;
                }
            }
            _ => self.echo(&heard).await,
        }
    }

    /// The broken copies of `proof`, whose encoding is `bytes`.
    fn bad_certificates(&mut self, proof: &Proof, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut flipped = bytes.to_vec();
        flip_last(&mut flipped);
        let half = bytes[..bytes.len() / 2].to_vec();
        let random = self.random_bytes(JUNK_CERTIFICATE_BYTES);
        let other_epoch = |round: Round| Round::new(Epoch::new(EPOCH + 1), round.view());
        let far = |round: Round| {
            Round::new(
                round.epoch(),
                View::new(round.view().get().saturating_add(FAR_VIEWS)),
            )
        };
        let mut copies = vec![flipped, half, random];
        match proof {
            Certificate::Notarization(proof) => {
                for round in [other_epoch(proof.proposal.round), far(proof.proposal.round)] {
                    let mut copy = proof.clone();
                    copy.proposal.round = round;
                    copies.push(Proof::Notarization(copy).encode().to_vec());
                }
                let mut copy = proof.clone();
                copy.proposal.payload = Sha256Digest::from(OTHER_PAYLOAD);
                copies.push(Proof::Notarization(copy).encode().to_vec());
            }
            Certificate::Nullification(proof) => {
                for round in [other_epoch(proof.round), far(proof.round)] {
                    let mut copy = proof.clone();
                    copy.round = round;
                    copies.push(Proof::Nullification(copy).encode().to_vec());
                }
            }
            Certificate::Finalization(proof) => {
                for round in [other_epoch(proof.proposal.round), far(proof.proposal.round)] {
                    let mut copy = proof.clone();
                    copy.proposal.round = round;
                    copies.push(Proof::Finalization(copy).encode().to_vec());
                }
                let mut copy = proof.clone();
                copy.proposal.payload = Sha256Digest::from(OTHER_PAYLOAD);
                copies.push(Proof::Finalization(copy).encode().to_vec());
            }
        }
        copies
    }

    async fn on_certificate(&mut self, from: PublicKey, bytes: Vec<u8>) {
        self.hear(Channel::Certificate, &from, &bytes);
        let Ok(proof) = Proof::decode_cfg(
            Copying(bytes.as_slice()),
            &self.scheme.certificate_codec_config(),
        ) else {
            return;
        };
        if self.rushed_bytes.contains(&bytes) {
            self.trace.lock().relayed += 1;
        }
        let view = proof.view();
        let kind = match &proof {
            Certificate::Notarization(proof) => {
                self.parents
                    .entry(view)
                    .or_insert_with(|| proof.proposal.clone());
                VoteKind::Notarize
            }
            Certificate::Nullification(_) => VoteKind::Nullify,
            Certificate::Finalization(proof) => {
                self.parents
                    .entry(view)
                    .or_insert_with(|| proof.proposal.clone());
                VoteKind::Finalize
            }
        };
        let first = !self.proofs.contains_key(&(view, kind));
        if first {
            self.proofs.insert((view, kind), bytes.clone());
        }

        let attack = attack_at(self.attack, view);
        if attack == Attack::Flood && first {
            self.trace.lock().flood_certificates += 1;
            self.send(
                Channel::Certificate,
                Recipients::All,
                bytes.clone(),
                Rule::FloodCertificate,
            )
            .await;
        }
        if attack == Attack::BadCertificates && first {
            for copy in self.bad_certificates(&proof, &bytes) {
                self.trace.lock().bad_certificates += 1;
                self.send(
                    Channel::Certificate,
                    Recipients::All,
                    copy,
                    Rule::BadCertificate,
                )
                .await;
            }
        }
        if attack == Attack::Flood && self.asked.insert(view) {
            let view = view.get();
            for requested in [
                view,
                view.saturating_sub(FLOOD_BEHIND),
                view.saturating_add(FAR_VIEWS),
                0,
                u64::MAX,
            ] {
                self.request_id += 1;
                let request = ResolverMessage::<U64> {
                    id: self.request_id,
                    payload: ResolverPayload::Request(U64::from(requested)),
                };
                self.trace.lock().flood_requests += 1;
                self.send(
                    Channel::Resolver,
                    Recipients::All,
                    request.encode().to_vec(),
                    Rule::FloodRequest,
                )
                .await;
            }
        }

        let next = view.next();
        if next > self.entered {
            self.entered = next;
            if self.leads(next) {
                self.propose(next).await;
            }
        }
    }

    /// Builds a block for `view` on `parent` and gives it to the relay for all
    /// participants.
    fn block(
        &mut self,
        view: View,
        parent: (View, Sha256Digest),
        stale: bool,
    ) -> Proposal<Sha256Digest> {
        let round = Round::new(Epoch::new(EPOCH), view);
        let nonce = self.context.random::<u64>();
        let contents = (round, parent.1, nonce).encode();
        let payload = Sha256::hash(&[contents.as_ref()]);
        self.relay.broadcast(
            &self.participants[BYZANTINE],
            Recipients::All,
            (payload, contents),
        );
        let proposal = Proposal::new(round, parent.0, payload);
        self.log.lock().blocks.push(Block {
            proposal: proposal.clone(),
            parent: parent.1,
            nonce,
            stale,
            trigger: self.handling,
        });
        proposal
    }

    fn notarize(&self, proposal: Proposal<Sha256Digest>) -> Ballot {
        Vote::Notarize(
            Notarize::sign(&self.scheme, proposal).expect("the Byzantine participant signs"),
        )
    }

    async fn propose(&mut self, view: View) {
        let attack = attack_at(self.attack, view);
        if matches!(attack, Attack::Silent | Attack::RushCertificates) {
            return;
        }
        let stale = attack == Attack::ResolverLies && self.parents.range(..view).count() > 1;
        let parent = self
            .parents
            .range(..view)
            .rev()
            .nth(usize::from(stale))
            .map_or_else(
                || {
                    (
                        View::zero(),
                        application::genesis::<Sha256>(Epoch::new(EPOCH)),
                    )
                },
                |(view, proposal)| (*view, proposal.payload),
            );
        let proposal = self.block(view, parent, stale);
        self.echoed.insert((view, VoteKind::Notarize));
        {
            let mut trace = self.trace.lock();
            trace.proposals += 1;
            trace.stale_parents += u64::from(stale);
        }
        let vote = self.notarize(proposal);
        match attack {
            Attack::Equivocate | Attack::EquivocateUnsigned => {
                let other = self.block(view, parent, stale);
                let other = self.notarize(other).encode().to_vec();
                let vote = if attack == Attack::EquivocateUnsigned {
                    self.bad_signature(&vote, 0)
                } else {
                    vote.encode().to_vec()
                };
                let odd = {
                    let mut trace = self.trace.lock();
                    trace.equivocations += 1;
                    HONEST[((trace.equivocations - 1) % HONEST.len() as u64) as usize]
                };
                let one = Recipients::One(self.participants[odd].clone());
                self.send(Channel::Vote, one, vote, Rule::Proposal).await;
                let rest = Recipients::Some(
                    HONEST
                        .into_iter()
                        .filter(|node| *node != odd)
                        .map(|node| self.participants[node].clone())
                        .collect(),
                );
                self.send(Channel::Vote, rest, other, Rule::Proposal).await;
            }
            Attack::BadSignature => {
                self.trace.lock().bad_signatures += 1;
                let vote = self.bad_signature(&vote, 0);
                self.vote_all(vote, Rule::Proposal).await;
            }
            _ => self.vote_all(vote.encode().to_vec(), Rule::Proposal).await,
        }
    }

    /// The bytes of the notarization it holds for `view`, or else of the
    /// finalization.
    fn held(&self, view: View) -> Option<&Vec<u8>> {
        self.proofs
            .get(&(view, VoteKind::Notarize))
            .or_else(|| self.proofs.get(&(view, VoteKind::Finalize)))
    }

    /// The payload of its answer number `number` to a request for `requested`. None
    /// is a valid answer.
    fn answer(&mut self, number: u64, requested: View) -> Vec<u8> {
        let mut views = self
            .proofs
            .keys()
            .filter(|(_, kind)| *kind != VoteKind::Nullify)
            .map(|(view, _)| *view);
        match number % 4 {
            0 => self.random_bytes(JUNK_CERTIFICATE_BYTES),
            1 => views
                .rfind(|view| *view < requested)
                .and_then(|view| self.held(view))
                .map_or_else(|| NOTHING_BELOW.to_vec(), Clone::clone),
            2 => views
                .find(|view| *view >= requested)
                .and_then(|view| self.held(view))
                .map_or_else(
                    || NOTHING_ABOVE.to_vec(),
                    |bytes| {
                        let mut bytes = bytes.clone();
                        flip_last(&mut bytes);
                        bytes
                    },
                ),
            _ => Vec::new(),
        }
    }

    async fn on_resolver(&mut self, from: PublicKey, bytes: Vec<u8>) {
        self.hear(Channel::Resolver, &from, &bytes);
        let Ok(message) = ResolverMessage::<U64>::decode(Copying(bytes.as_slice())) else {
            return;
        };
        let ResolverPayload::Request(requested) = message.payload else {
            return;
        };
        self.trace.lock().requests_heard += 1;
        if !matches!(self.attack, Attack::ResolverLies | Attack::Mixed) {
            return;
        }
        self.answered += 1;
        let answer = self.answer(self.answered, View::new(u64::from(&requested)));
        let to = Recipients::One(from);
        for guess in [
            message.id.wrapping_add(1),
            message.id.wrapping_add(2),
            message.id.wrapping_sub(1),
        ] {
            let response = ResolverMessage::<U64> {
                id: guess,
                payload: ResolverPayload::Response(GUESS.to_vec().into()),
            };
            self.trace.lock().guesses += 1;
            self.send(
                Channel::Resolver,
                to.clone(),
                response.encode().to_vec(),
                Rule::Guess,
            )
            .await;
        }
        let response = ResolverMessage::<U64> {
            id: message.id,
            payload: ResolverPayload::Response(answer.into()),
        };
        self.trace.lock().answers += 1;
        self.send(
            Channel::Resolver,
            to,
            response.encode().to_vec(),
            Rule::Answer,
        )
        .await;
    }

    async fn run(mut self, mut votes: Inbound, mut certificates: Inbound, mut resolver: Inbound) {
        if self.leads(self.entered) {
            self.propose(self.entered).await;
        }
        loop {
            select! {
                message = votes.recv() => {
                    let Ok((from, bytes)) = message else { return };
                    self.on_vote(from, bytes.as_ref().to_vec()).await;
                },
                message = certificates.recv() => {
                    let Ok((from, bytes)) = message else { return };
                    self.on_certificate(from, bytes.as_ref().to_vec()).await;
                },
                message = resolver.recv() => {
                    let Ok((from, bytes)) = message else { return };
                    self.on_resolver(from, bytes.as_ref().to_vec()).await;
                },
            }
        }
    }
}

/// The Standard-driver input the scenario runs on: one Byzantine participant of four
/// on a connected network, with every honest engine policy at its default.
fn base(scenario: &Scenario, raw_bytes: Vec<u8>) -> BaseInput {
    BaseInput {
        raw_bytes,
        required_containers: CONTAINERS,
        term_length: scenario.term_length,
        optimistic_views: scenario.optimistic_views,
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

/// Runs `scenario` with `plant` and returns what happened.
///
/// # Panics
///
/// Panics with a text that starts with `C7-I1` when the block list at the measurement
/// names an honest participant as blocked, with the runtime's timeout when the honest
/// nodes stop finalizing, and when `plant` names a node it cannot act on.
pub fn run_planted(scenario: &Scenario, plant: Option<Plant>) -> Outcome {
    if let Some(plant) = plant {
        plant.validate();
    }
    let raw_bytes = scenario.seed.to_be_bytes().to_vec();
    let base = base(scenario, raw_bytes.clone());
    let cfg = bounded_fuzz_runtime_config(&raw_bytes, CONTAINERS, 0);
    let scenario = scenario.clone();
    deterministic::Runner::new(cfg).start(move |mut context| async move {
        let started = context.current();
        let config = base.configuration;
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &base).await;
        for (from, sender) in participants.iter().enumerate() {
            for (to, receiver) in participants.iter().enumerate() {
                if from == to {
                    continue;
                }
                oracle
                    .remove_link(sender.clone(), receiver.clone())
                    .await
                    .expect("the network is connected");
                oracle
                    .add_link(sender.clone(), receiver.clone(), link(from, to))
                    .await
                    .expect("the link was removed");
            }
        }

        let relay = Arc::new(relay::Relay::new());
        let trace = Arc::new(Mutex::new(Trace::default()));
        let log = Arc::new(Mutex::new(Adversary::default()));
        let byzantine = participants[BYZANTINE].clone();
        let (
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        ) = registrations.remove(&byzantine).unwrap();
        let set: Set<PublicKey> = participants
            .as_slice()
            .try_into()
            .expect("public keys are unique");
        let leaders = P::elector(base.term_length, base.optimistic_views).build(&set);
        let payloads = relay.register(byzantine.clone());
        context
            .child("validator")
            .with_attribute("public_key", &byzantine)
            .child("byzantine")
            .spawn({
                let scheme = schemes[BYZANTINE].clone();
                let participants = participants.clone();
                let relay = relay.clone();
                let trace = trace.clone();
                let log = log.clone();
                let attack = scenario.attack;
                move |context| async move {
                    // The Byzantine participant stays registered with the relay and
                    // reads nothing from it.
                    let _payloads = payloads;
                    Byzantine {
                        context,
                        scheme,
                        attack,
                        participants,
                        leaders,
                        relay,
                        votes: Counting::new(vote_sender, ACTOR),
                        certificates: Counting::new(certificate_sender, ACTOR),
                        resolver: Counting::new(resolver_sender, ACTOR),
                        trace,
                        log,
                        handling: None,
                        entered: View::new(1),
                        parents: BTreeMap::new(),
                        heard: BTreeMap::new(),
                        proofs: BTreeMap::new(),
                        voted: BTreeSet::new(),
                        echoed: BTreeSet::new(),
                        rushed: BTreeSet::new(),
                        rushed_bytes: BTreeSet::new(),
                        asked: BTreeSet::new(),
                        request_id: FLOOD_REQUEST_IDS,
                        answered: 0,
                    }
                    .run(vote_receiver, certificate_receiver, resolver_receiver)
                    .await;
                }
            });

        let calls = Log::default();
        let mut recorders = Vec::new();
        for index in HONEST {
            let validator = participants[index].clone();
            let scheme = schemes[index].clone();
            let elector = P::elector(base.term_length, base.optimistic_views);
            let context = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let (
                (vote_sender, vote_receiver),
                (certificate_sender, certificate_receiver),
                (resolver_sender, resolver_receiver),
            ) = registrations.remove(&validator).unwrap();
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

            let mut blocker = Recording::new(
                oracle.control(validator.clone()),
                index,
                participants.clone(),
                calls.clone(),
                Arc::new(context.child("blocker")),
                started,
            );
            blocker.swallow = plant == Some(Plant::SwallowBlocks { node: index });
            let votes = if plant == Some(Plant::CorruptVotes { node: index }) {
                Corruption::After(CLEAN_VOTES)
            } else {
                Corruption::None
            };
            let certificates = if plant == Some(Plant::CorruptCertificates { node: index }) {
                Corruption::After(CLEAN_CERTIFICATES)
            } else {
                Corruption::None
            };
            let responses = if plant == Some(Plant::CorruptResponses) {
                Corruption::Responses
            } else {
                Corruption::None
            };
            start_validator_engine::<P, _, _, _, _, _, _, _, _, _, _, _>(
                &context,
                blocker,
                scheme,
                elector,
                application.clone(),
                application,
                recorder.clone(),
                validator.to_string(),
                LEADER_TIMEOUT,
                CERTIFICATION_TIMEOUT,
                base.mailbox_size,
                base.forwarding,
                (Corrupting::new(vote_sender, votes), vote_receiver),
                (
                    Corrupting::new(certificate_sender, certificates),
                    certificate_receiver,
                ),
                (
                    Corrupting::new(resolver_sender, responses),
                    resolver_receiver,
                ),
                false,
            );
            recorders.push((index, validator, recorder));
        }

        let mut finalizers = Vec::new();
        for (_, validator, recorder) in recorders.iter_mut() {
            let (_, mut monitor) = recorder.subscribe().await;
            let reporter = recorder.recording().inner().clone();
            finalizers.push(
                context
                    .child("finalizer")
                    .with_attribute("public_key", &*validator)
                    .spawn(move |context| async move {
                        while (reporter.finalizations.lock().len() as u64) < CONTAINERS {
                            monitor.recv().await.expect("event missing");
                        }
                        since(&context, started)
                    }),
            );
        }

        let mut windows = Vec::new();
        if plant != Some(Plant::NoWindows) {
            let mut cut_at = started;
            for window in 0..WINDOWS {
                cut_at += WINDOW_GAP;
                context.sleep_until(cut_at).await;
                let node = HONEST[HONEST.len() - 1 - window];
                let from: Vec<_> = HONEST.into_iter().filter(|other| *other != node).collect();
                let cut = since(&context, started);
                for other in &from {
                    oracle
                        .remove_link(participants[*other].clone(), participants[node].clone())
                        .await
                        .expect("the link is up");
                }
                cut_at += WINDOW;
                context.sleep_until(cut_at).await;
                let restored = since(&context, started);
                for other in &from {
                    oracle
                        .add_link(
                            participants[*other].clone(),
                            participants[node].clone(),
                            link(*other, node),
                        )
                        .await
                        .expect("the link was removed");
                }
                windows.push(Window {
                    node,
                    from,
                    cut_at: cut,
                    restored_at: restored,
                });
            }
        }

        let finalized_at = join_all(finalizers)
            .await
            .into_iter()
            .map(|finalized| finalized.expect("the finalizer ran to its end"))
            .max()
            .expect("there are honest nodes");
        context.sleep(SETTLE).await;
        if let Some(Plant::DirectBlock { from, to }) = plant {
            #[allow(
                clippy::disallowed_methods,
                reason = "the plant blocks in the name of an honest node"
            )]
            let _ = oracle
                .control(participants[from].clone())
                .block(participants[to].clone());
        }

        let measured_at = since(&context, started);
        let blocked = block_list(oracle.blocked().await, &participants);
        let calls = calls.entries();
        let trace = trace.lock().clone();
        let adversary = log.lock().clone();
        let metrics = context.encode();
        let nodes: Vec<_> = recorders
            .iter()
            .map(|(index, validator, recorder)| {
                let node = state_bounds::Node::public_key(validator);
                Node {
                    index: *index,
                    finalized: recorder.recording().inner().finalizations.lock().len() as u64,
                    fallbacks: fallbacks(&metrics, &node),
                    fetched: fetched(&metrics, &node),
                }
            })
            .collect();

        if let Err(violation) = check_blocks(&blocked) {
            let first = honest_blocked(&blocked).and_then(|(blocker, blocked)| {
                calls
                    .iter()
                    .find(|call| call.blocker == blocker && call.blocked == blocked)
            });
            match first {
                Some(call) => panic!("{violation}, first at {:?}", call.at),
                None => panic!("{violation}"),
            }
        }

        let recordings: Vec<_> = recorders
            .iter()
            .map(|(_, _, recorder)| recorder.recording().clone())
            .collect();
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

        Outcome {
            scenario,
            participants,
            blocked,
            calls,
            trace,
            nodes,
            finalized_at,
            measured_at,
            windows,
            adversary,
        }
    })
}

/// Runs `scenario` and returns what happened. See [`run_planted`].
pub fn run(scenario: &Scenario) -> Outcome {
    run_planted(scenario, None)
}
