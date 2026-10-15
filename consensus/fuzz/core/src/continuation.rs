//! Trusted continuation: a hook point inside the base drivers that runs a state-building
//! prefix after the network, the reporters and the honest engines exist, and before the
//! base's Byzantine actors, fault scheduler and oracles start.
//!
//! A [Prefix] drives the system through the restricted [PrefixContext] only. The runner
//! owns everything else: it spawns the honest replicas with the recording wrappers and
//! gates of a [ReplicaTap], keeps the compromised identity's channels while the prefix
//! signs and sends as it, ends the prefix at its budget if it has not returned, and at
//! the handoff revokes the context. After the release delay it reverts the changes the
//! prefix made, starts exactly the base's actors for the compromised identity, records
//! them in an [ActorRegistry], and lets the base's own code continue in the same runtime.
//!
//! A continuation checks safety only: the base runs its fault scheduler and Byzantine
//! actors for a fixed window and then its safety oracles, and never waits for progress.
//! A prefix can leave the system in any state a fault can (crashed or slow replicas,
//! cut links, held messages), so nothing after the release depends on the release
//! reverting everything. Drivers called without a prefix run unchanged.
//!
//! A marshal base also hands B its marshal channels ([MarshalChannel]), gates the honest
//! replicas' marshal channels apart from their engine channels, and answers bounded,
//! read-only queries of their marshal ([MarshalReads]). It has no block relay, and its
//! replicas cannot be crashed. A recorder that no wrapper of the base feeds reads as cut
//! from the read on ([Observer::dropped]).

use crate::{
    CertifyChoice, Configuration, FAULT_PHASE, FuzzInput, HarnessReporter, N4F0C4, N4F1C3,
    NetworkChannels, PublicKeyOf, ReporterWiring, block_relay, simplex::Simplex,
    start_validator_engine, utils,
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Handoff, Reporter, Viewable,
    simplex::{
        ForwardPolicy,
        elector::{Config as ElectorConfig, Elector, Input, Mode as _, Terms},
        types::{Activity, Context as SimplexContext},
    },
    types::{Epoch, Round, TermLength, View, ViewDelta},
};
use commonware_cryptography::{Digest, sha256::Digest as Sha256Digest};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver as _, Recipients, simulated::Link};
use commonware_runtime::{Clock, Handle, IoBuf, Spawner, Supervisor as _, deterministic};
use commonware_utils::{
    SystemTimeExt as _,
    channel::{
        fallible::{FallibleExt as _, OneshotExt as _},
        mpsc, oneshot,
    },
    ordered::Set,
    sync::{AsyncMutex, Mutex},
};
use futures::FutureExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};

/// How long the release check waits for the actors it just started to run.
const RELEASE_SETTLE: Duration = Duration::from_millis(100);
const RELEASE_POLL: Duration = Duration::from_millis(1);

/// Most entries a recorder log, B's inbox, a replica's held messages, or the held blocks
/// keep. Past it a recorder records nothing more and a gate drops what it would hold, so
/// a prefix that polls a log costs bounded memory however long it runs.
pub const LOG_CAP: usize = 1 << 12;

/// Most simulated time a prefix may ask for; the runner ends one that has not returned
/// by then. A longer budget is cut to it, and a longer release delay to [FAULT_PHASE].
pub const MAX_PREFIX_BUDGET: Duration = Duration::from_secs(60);

/// Most simulated time a marshal read waits for its answer.
pub const MARSHAL_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// What a marshal read that cannot be answered, or a refused crash, restart or link change,
/// costs, so a loop of them advances time.
const NO_ANSWER: Duration = Duration::from_millis(1);

/// The harness networks' largest message: B sends nothing larger.
pub const MAX_MESSAGE: u32 = 1 << 20;

/// Most bytes B's sends deliver in a run, each message counted once per recipient (at
/// least one) and at no less than [MIN_CHARGE] bytes, so what the network, the recorders
/// and the gates keep of them stays bounded.
pub const MAX_SENT: u64 = 64 << 20;

/// Fewest bytes a message B sends counts toward [MAX_SENT] per recipient, so a loop of
/// empty or tiny sends ends within MAX_SENT / MIN_CHARGE deliveries.
pub const MIN_CHARGE: u64 = 256;

/// Longest term a marshal base that honors a term-length pin runs (the block
/// dissemination decoder's bound).
pub const MARSHAL_MAX_TERM_LENGTH: u32 = 4;

// A continuation ends within the prefix budget, the release delay, the release check
// and the base's fixed window, so the base's runtime deadline never needs extending.
const _: () = assert!(
    MAX_PREFIX_BUDGET.as_millis()
        + FAULT_PHASE.as_millis()
        + RELEASE_SETTLE.as_millis()
        + crate::MAX_SLEEP_DURATION.as_millis()
        < crate::FUZZ_RUNTIME_TIMEOUT_FLOOR.as_millis()
);

/// The future of a [Prefix]'s online part.
pub type PrefixFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A consensus channel of a replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Channel {
    Vote,
    Certificate,
    Resolver,
}

impl Channel {
    const ALL: [Self; 3] = [Self::Vote, Self::Certificate, Self::Resolver];

    const fn index(self) -> usize {
        match self {
            Self::Vote => 0,
            Self::Certificate => 1,
            Self::Resolver => 2,
        }
    }
}

/// A marshal channel of a replica: backfill (channel 1), or broadcast (channel 2),
/// which carries blocks on the standard stack and shards on the coding stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MarshalChannel {
    Backfill,
    Broadcast,
}

impl MarshalChannel {
    const ALL: [Self; 2] = [Self::Backfill, Self::Broadcast];

    const fn index(self) -> usize {
        match self {
            Self::Backfill => 0,
            Self::Broadcast => 1,
        }
    }
}

/// Most channels of one kind a gate serves.
const LANES: usize = 3;

/// A kind of gated channel: the engine's ([Channel]) or marshal's ([MarshalChannel]).
/// Each kind has its own gate and deliveries log on a [ReplicaTap].
trait Lane: Copy + fmt::Debug + Send + Sync + 'static {
    /// What a filter and the deliveries log see of a message on this kind of channel.
    type Inbound: Clone + Send + Sync + 'static;

    const ALL: &'static [Self];

    /// The recorder a wrapper of this kind of channel feeds.
    const RECORDER: Recorder;

    /// The channel's index among its kind, below [LANES].
    fn index(self) -> usize;

    fn inbound(self, from: Option<usize>, payload: IoBuf) -> Self::Inbound;

    fn gate<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Gate<PublicKeyOf<P>, Self>>;

    fn deliveries<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Log<Recorded<Self::Inbound>>>;
}

impl Lane for Channel {
    type Inbound = Inbound;

    const ALL: &'static [Self] = &Self::ALL;
    const RECORDER: Recorder = Recorder::Gate;

    fn index(self) -> usize {
        Self::index(self)
    }

    fn inbound(self, from: Option<usize>, payload: IoBuf) -> Inbound {
        Inbound {
            from,
            channel: self,
            payload,
        }
    }

    fn gate<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Gate<PublicKeyOf<P>, Self>> {
        &tap.gate
    }

    fn deliveries<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Log<Recorded<Inbound>>> {
        &tap.deliveries
    }
}

impl Lane for MarshalChannel {
    type Inbound = MarshalInbound;

    const ALL: &'static [Self] = &Self::ALL;
    const RECORDER: Recorder = Recorder::MarshalGate;

    fn index(self) -> usize {
        Self::index(self)
    }

    fn inbound(self, from: Option<usize>, payload: IoBuf) -> MarshalInbound {
        MarshalInbound {
            from,
            channel: self,
            payload,
        }
    }

    fn gate<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Gate<PublicKeyOf<P>, Self>> {
        &tap.marshal_gate
    }

    fn deliveries<P: Simplex>(tap: &ReplicaTap<P>) -> &Mutex<Log<Recorded<MarshalInbound>>> {
        &tap.marshal_deliveries
    }
}

/// The position a trusted recorder stamped an entry with, from the [Observer], at the
/// moment it recorded it. Only the runner makes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    seq: u64,
    run: u32,
}

impl Stamp {
    /// The position `observer` gives now: a query's, never an earlier one.
    pub fn now(observer: &dyn Observer) -> Self {
        let (seq, run) = observer.position();
        Self { seq, run }
    }

    /// The entry's position; 0 when nothing watched.
    pub const fn seq(self) -> u64 {
        self.seq
    }

    /// The runtime instance the entry was recorded in.
    pub const fn run(self) -> u32 {
        self.run
    }
}

/// One entry of a trusted recorder.
#[derive(Clone, Debug)]
pub struct Recorded<T> {
    pub value: T,
    pub stamp: Stamp,
}

/// A trusted recorder's log, or a snapshot of it, which reads as a slice. A snapshot
/// shares the log, so taking one copies nothing; the recorder copies the log only to
/// append while a snapshot of it is alive. Iterating a snapshot by value clones it. A
/// log keeps at most [LOG_CAP] entries and remembers the position of the first one it
/// dropped.
#[derive(Debug)]
pub struct Log<T> {
    entries: Arc<Vec<T>>,
    dropped: Option<u64>,
}

impl<T: Clone> Log<T> {
    /// Appends `value`, recorded at position `seq`, or drops it once the log holds
    /// [LOG_CAP] entries. Position 0 is an entry recorded while nothing watched.
    fn push(&mut self, value: T, seq: u64) {
        if self.entries.len() >= LOG_CAP {
            if seq != 0 {
                self.dropped.get_or_insert(seq);
            }
            return;
        }
        Arc::make_mut(&mut self.entries).push(value);
    }
}

impl<T> Log<T> {
    /// The position of the first entry the log dropped at its cap, if any: from it
    /// on, the log misses entries, so what it lacks proves nothing.
    pub const fn dropped(&self) -> Option<u64> {
        self.dropped
    }
}

impl<T> Clone for Log<T> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            dropped: self.dropped,
        }
    }
}

impl<T> Default for Log<T> {
    fn default() -> Self {
        Self {
            entries: Arc::default(),
            dropped: None,
        }
    }
}

impl<T> std::ops::Deref for Log<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.entries
    }
}

impl<'a, T> IntoIterator for &'a Log<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<T: Clone> IntoIterator for Log<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        Arc::unwrap_or_clone(self.entries).into_iter()
    }
}

/// A message a replica received, or held, on one of its channels.
#[derive(Clone, Debug)]
pub struct Inbound {
    /// The sender's index among the participants, `None` for an unknown key.
    pub from: Option<usize>,
    pub channel: Channel,
    pub payload: IoBuf,
}

/// A message a replica received, or held, on one of its marshal channels.
#[derive(Clone, Debug)]
pub struct MarshalInbound {
    /// The sender's index among the participants, `None` for an unknown key.
    pub from: Option<usize>,
    pub channel: MarshalChannel,
    pub payload: IoBuf,
}

/// B's marshal channels as the base registered them: (backfill, broadcast).
pub type MarshalChannels<K> = (
    (
        commonware_p2p::simulated::Sender<K, deterministic::Context>,
        commonware_p2p::simulated::Receiver<K>,
    ),
    (
        commonware_p2p::simulated::Sender<K, deterministic::Context>,
        commonware_p2p::simulated::Receiver<K>,
    ),
);

/// Read-only queries of an honest replica's marshal, which a marshal base installs on
/// its tap ([ReplicaTap::set_reads]). Each future asks the replica's marshal actor
/// through its mailbox and resolves to marshal's answer, `None` when marshal has none;
/// these bases never set a floor or prune, so a request reaches the actor and is
/// answered, or is dropped before the future is first polled. An implementation
/// answers only through the actor: an answer ready at the first poll counts as none.
pub trait MarshalReads: Send + Sync + 'static {
    /// The digest of the block marshal finalized at `height`.
    fn finalized(&self, height: u64) -> Pin<Box<dyn Future<Output = Option<Sha256Digest>> + Send>>;

    /// The height of the last block marshal's application acknowledged.
    fn processed(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>>;
}

/// How an automaton request ended: answered, closed by the automaton, or canceled by
/// consensus, which dropped its receiver first (the audit recorder's outcomes).
pub use crate::simplex_audit::Completion;

/// What an honest replica's automaton was asked and answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutomatonEvent {
    Prepare {
        round: Round,
        parent: (View, Sha256Digest),
    },
    Prepared {
        round: Round,
        decision: Completion<Handoff<Sha256Digest>>,
    },
    Propose {
        round: Round,
        parent: (View, Sha256Digest),
    },
    Proposed {
        round: Round,
        payload: Completion<Sha256Digest>,
    },
    Verify {
        round: Round,
        leader: Option<usize>,
        parent: (View, Sha256Digest),
        payload: Sha256Digest,
    },
    Verified {
        round: Round,
        payload: Sha256Digest,
        valid: Completion<bool>,
    },
    Certify {
        round: Round,
        payload: Sha256Digest,
    },
    Certified {
        round: Round,
        payload: Sha256Digest,
        certified: Completion<bool>,
    },
}

/// The role an actor plays for the compromised identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// The core vote, certificate and resolver mutator.
    Disrupter,
    /// The primary engine of a twin pair.
    Primary,
    /// The secondary engine of a twin pair.
    Secondary,
}

impl Role {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Disrupter => "disrupter",
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }
}

/// Whether a required actor runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorState {
    /// Its task has not finished, and the task polled a receiver it was started with.
    Running,
    /// Its task has not finished, but never polled a receiver it was started with.
    Unpolled,
    /// Every task registered for it has finished.
    Finished,
    /// No task was registered for it.
    Absent,
}

impl ActorState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Unpolled => "unpolled",
            Self::Finished => "finished",
            Self::Absent => "absent",
        }
    }
}

/// An actor's execution marker: set by the actor's own task, the first time it polls the
/// receiver that [MarkedReceiver] wraps.
#[derive(Clone, Default)]
pub struct Marker(Arc<AtomicBool>);

impl Marker {
    fn set(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// A receiver an actor is started with, which sets the actor's [Marker] when the actor's
/// task first polls it; without a marker it only forwards. Any task that executes polls
/// its receivers, whether or not a message ever arrives.
pub struct MarkedReceiver<R> {
    inner: R,
    marker: Option<Marker>,
}

impl<R> MarkedReceiver<R> {
    pub const fn new(inner: R, marker: Option<Marker>) -> Self {
        Self { inner, marker }
    }
}

impl<R: fmt::Debug> fmt::Debug for MarkedReceiver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<R: commonware_p2p::Receiver> commonware_p2p::Receiver for MarkedReceiver<R> {
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        if let Some(marker) = &self.marker {
            marker.set();
        }
        self.inner.recv().await
    }
}

/// One required actor and its state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorStatus {
    pub identity: usize,
    pub role: Role,
    pub state: ActorState,
}

/// The actor check at one point of a continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorCheck {
    /// `release` (the handoff plus the release delay) or `end` (after the base's fixed window).
    pub at: &'static str,
    pub actors: Vec<ActorStatus>,
    /// Why the base's own fault model did not run, as one token without whitespace, or
    /// `None` when it did.
    pub base: Option<&'static str>,
}

impl ActorCheck {
    /// Whether every required actor runs and the base's fault model ran.
    pub fn ok(&self) -> bool {
        self.base.is_none()
            && self
                .actors
                .iter()
                .all(|actor| actor.state == ActorState::Running)
    }
}

impl fmt::Display for ActorCheck {
    /// `<at> ok|failed <identity>:<role>=<state> ...`, or `-` when nothing is required,
    /// then ` base=<reason>` when the base's fault model did not run.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.at, if self.ok() { "ok" } else { "failed" })?;
        if self.actors.is_empty() {
            write!(f, " -")?;
        }
        for actor in &self.actors {
            write!(
                f,
                " {}:{}={}",
                actor.identity,
                actor.role.name(),
                actor.state.name()
            )?;
        }
        if let Some(reason) = self.base {
            write!(f, " base={reason}")?;
        }
        Ok(())
    }
}

/// One registered actor: its identity, role and task, `None` once it finished.
type Actor = (usize, Role, Option<Pin<Box<Handle<()>>>>);

/// The actor tasks the runner started for the compromised identities, and their execution
/// markers, keyed by identity and role.
#[derive(Clone, Default)]
pub struct ActorRegistry {
    actors: Arc<Mutex<Vec<Actor>>>,
    markers: Arc<Mutex<BTreeMap<(usize, Role), Marker>>>,
}

impl ActorRegistry {
    /// The execution marker of the actor of `identity` in `role`: the trusted code that
    /// starts the actor wraps one of its receivers with it ([MarkedReceiver]).
    pub fn marker(&self, identity: usize, role: Role) -> Marker {
        self.markers
            .lock()
            .entry((identity, role))
            .or_default()
            .clone()
    }

    /// Registers the task of an actor started for `identity` in `role`.
    pub fn register(&self, identity: usize, role: Role, handle: Handle<()>) {
        self.actors
            .lock()
            .push((identity, role, Some(Box::pin(handle))));
    }

    /// Whether every one of `required` has executed: its marker is set.
    fn executed(&self, required: &[(usize, Role)]) -> bool {
        let markers = self.markers.lock();
        required
            .iter()
            .all(|key| markers.get(key).is_some_and(Marker::is_set))
    }

    /// Checks that every one of `required` runs: a task that has not finished, and whose
    /// execution marker its task set.
    pub fn check(&self, at: &'static str, required: &[(usize, Role)]) -> ActorCheck {
        let mut actors = self.actors.lock();
        // Polling a finished task's handle yields its result; it is dropped once seen.
        for (_, _, handle) in actors.iter_mut() {
            if handle
                .as_mut()
                .is_some_and(|task| task.as_mut().now_or_never().is_some())
            {
                *handle = None;
            }
        }
        let markers = self.markers.lock();
        let actors = required
            .iter()
            .map(|&(identity, role)| {
                let mut found = actors
                    .iter()
                    .filter(|(id, r, _)| *id == identity && *r == role)
                    .peekable();
                let executed = markers.get(&(identity, role)).is_some_and(Marker::is_set);
                let state = if found.peek().is_none() {
                    ActorState::Absent
                } else if !found.any(|(_, _, handle)| handle.is_some()) {
                    ActorState::Finished
                } else if executed {
                    ActorState::Running
                } else {
                    ActorState::Unpolled
                };
                ActorStatus {
                    identity,
                    role,
                    state,
                }
            })
            .collect();
        ActorCheck {
            at,
            actors,
            base: None,
        }
    }
}

/// The trusted code that watches a continuation (StateLens' helper). Generated prefix
/// code never implements it.
pub trait Observer: Send + Sync + 'static {
    /// The position and runtime instance a recorder stamps an entry with now.
    fn position(&self) -> (u64, u32);

    /// Publishes the compromised identities, before any engine starts.
    fn compromised(&self, identities: &[usize]);

    /// Reports an actor check.
    fn actors(&self, check: &ActorCheck);

    /// Reports what the release reverted.
    fn released(&self, _release: &Release) {}

    /// Called after the base's last oracle.
    fn done(&self) {}

    /// Reports, when the prefix reads a recorder log, B's inbox, or a replica's held
    /// messages, the position of the first entry it dropped at its cap. From that
    /// position on what the prefix read misses entries, so a check over it, in
    /// particular one for the absence of an entry, decides nothing. A recorder or gate
    /// the base does not feed reports the position of the read itself, which it takes
    /// from [Self::position]: what was read before it stands.
    fn dropped(&self, _seq: u64) {}
}

/// What the prefix asks of the runtime: the sum of its stage deadlines, and the release
/// delay `d` from the handoff to the release. The runner ends a prefix that has not
/// returned once `prefix` has passed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub prefix: Duration,
    pub release: Duration,
}

/// The decoder whose domain a [Pins] keeps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Simplex,
    Twins,
    /// The notarize-omission base: N4F0C4 and single-view terms only.
    Omission,
    /// A marshal base: N4F1C3 and a zero lookahead only, and a term length only when
    /// the base honors one.
    Marshal {
        term: bool,
    },
}

/// The decoded input fields a prefix may pin before the runtime starts. Each setter
/// keeps the fields that depend on it as the decoder sets them.
pub struct Pins<'a> {
    input: &'a mut FuzzInput,
    domain: Domain,
}

impl<'a> Pins<'a> {
    const fn new(input: &'a mut FuzzInput, domain: Domain) -> Self {
        Self { input, domain }
    }

    /// The input as decoded so far.
    pub fn input(&self) -> &FuzzInput {
        self.input
    }

    /// The bytes the prefix takes its knobs from; the rest seeds the runtime.
    pub fn raw_bytes(&mut self) -> &mut Vec<u8> {
        &mut self.input.raw_bytes
    }

    /// Pins the term length; a lookahead beyond what the decoder samples for it is cut.
    /// A marshal base that honors a term length pins one up to
    /// [MARSHAL_MAX_TERM_LENGTH]; another marshal base and the notarize-omission base
    /// pin nothing.
    pub fn term_length(&mut self, term_length: TermLength) {
        if self.domain == Domain::Omission {
            return;
        }
        if let Domain::Marshal { term } = self.domain {
            if term && term_length.get() <= u64::from(MARSHAL_MAX_TERM_LENGTH) {
                self.input.term_length = term_length;
            }
            return;
        }
        self.input.term_length = term_length;
        let most = term_length.get() + 2;
        if self.input.optimistic_views.get() > most {
            self.input.optimistic_views = ViewDelta::new(most);
        }
    }

    /// Pins the optimistic lookahead; returns false, and pins nothing, beyond the
    /// decoder's domain (the term length plus two; zero on a marshal base).
    pub fn lookahead(&mut self, views: ViewDelta) -> bool {
        let most = match self.domain {
            Domain::Marshal { .. } => 0,
            Domain::Simplex | Domain::Twins | Domain::Omission => self.input.term_length.get() + 2,
        };
        if views.get() > most {
            return false;
        }
        self.input.optimistic_views = views;
        true
    }

    /// Pins N4F1C3 or N4F0C4; returns false, and pins nothing, for another
    /// configuration, for N4F0C4 under Twins and on a marshal base, which run N4F1C3
    /// only, and for N4F1C3 on the notarize-omission base, which runs N4F0C4 only.
    pub fn configuration(&mut self, configuration: Configuration) -> bool {
        if configuration != N4F1C3 && configuration != N4F0C4 {
            return false;
        }
        if self.domain == Domain::Omission {
            return configuration == N4F0C4;
        }
        if self.domain != Domain::Simplex && configuration != N4F1C3 {
            return false;
        }
        if matches!(self.domain, Domain::Marshal { .. }) {
            return true;
        }
        self.input.configuration = configuration;
        if configuration == N4F1C3 {
            // Single-target certifiers are drawn only under N4F0C4.
            if matches!(
                self.input.certify,
                CertifyChoice::SingleCancel { .. } | CertifyChoice::SinglePending { .. }
            ) {
                self.input.certify = CertifyChoice::Always;
            }
        } else {
            // A degraded network and a dropped block are drawn only under N4F1C3.
            self.input.degraded_network = false;
            self.input.block_filter = crate::BlockFilterChoice::None;
        }
        true
    }
}

/// Generated state-building code: the only part of a scaffold that is not trusted.
pub trait Prefix<P: Simplex>: Send + 'static {
    /// Before the runtime starts: splits the knobs off `pins.raw_bytes()`, pins fields,
    /// and returns the budget.
    fn plan(&mut self, pins: &mut Pins<'_>) -> Budget;

    /// The online prefix: drives the system through `cx` and returns at the handoff.
    fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture;
}

/// A prefix bound to the trusted code that watches it, as a trusted entry receives it.
pub struct Hook<P: Simplex> {
    prefix: Box<dyn Prefix<P>>,
    observer: Arc<dyn Observer>,
    budget: Budget,
}

impl<P: Simplex> Hook<P> {
    /// Plans `prefix` against `input` and binds it to `observer`. The budget is cut to
    /// [MAX_PREFIX_BUDGET] and the release delay to [FAULT_PHASE].
    pub fn plan(
        prefix: Box<dyn Prefix<P>>,
        observer: Arc<dyn Observer>,
        input: &mut FuzzInput,
        twins: bool,
    ) -> Self {
        let domain = if twins {
            Domain::Twins
        } else {
            Domain::Simplex
        };
        Self::plan_in(prefix, observer, input, domain)
    }

    /// [Self::plan] for a marshal base, whose scratch `input` mirrors the base's own: a
    /// pin keeps to N4F1C3 and a zero lookahead, and pins a term length only when the
    /// base honors one (`term`).
    pub fn plan_marshal(
        prefix: Box<dyn Prefix<P>>,
        observer: Arc<dyn Observer>,
        input: &mut FuzzInput,
        term: bool,
    ) -> Self {
        Self::plan_in(prefix, observer, input, Domain::Marshal { term })
    }

    /// [Self::plan] for the notarize-omission base, whose `input` already carries the
    /// base's forced fields: a pin keeps to N4F0C4 and pins no term length.
    pub fn plan_omission(
        prefix: Box<dyn Prefix<P>>,
        observer: Arc<dyn Observer>,
        input: &mut FuzzInput,
    ) -> Self {
        Self::plan_in(prefix, observer, input, Domain::Omission)
    }

    fn plan_in(
        mut prefix: Box<dyn Prefix<P>>,
        observer: Arc<dyn Observer>,
        input: &mut FuzzInput,
        domain: Domain,
    ) -> Self {
        let asked = prefix.plan(&mut Pins::new(input, domain));
        let budget = Budget {
            prefix: asked.prefix.min(MAX_PREFIX_BUDGET),
            release: asked.release.min(FAULT_PHASE),
        };
        Self {
            prefix,
            observer,
            budget,
        }
    }

    /// The budget the runner applies.
    pub const fn budget(&self) -> Budget {
        self.budget
    }
}

/// Per-replica application latencies, `(mean ms, deviation ms)` as the mock application
/// takes them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Latencies {
    pub propose: (f64, f64),
    pub verify: (f64, f64),
    pub certify: (f64, f64),
}

/// What a release reverted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Release {
    /// Whether the prefix had not returned when its budget ran out, so the runner ended
    /// it there.
    pub overran: bool,
    /// The replicas whose gates were opened.
    pub gates: Vec<usize>,
    /// The held messages delivered, in arrival order, at the release.
    pub delivered: usize,
    /// The held blocks delivered at the release, counted by the applications that took
    /// them.
    pub blocks: usize,
    /// The directed links restored to the base's.
    pub links: Vec<(usize, usize)>,
    /// The replicas whose latency override was removed.
    pub latencies: Vec<usize>,
    /// The replicas restarted from their journal.
    pub restarted: Vec<usize>,
    /// The highest view any honest replica finalized at the release; the base's
    /// view-indexed faults are re-based on it.
    pub base: u64,
    /// The highest view any honest replica's elector was asked for by the release.
    pub view: u64,
}

type HoldFilter<L> = Arc<dyn Fn(&<L as Lane>::Inbound) -> bool + Send + Sync>;
type ActivityOf<P> = Activity<<P as Simplex>::Scheme, Sha256Digest>;
type BlockFilter = Arc<dyn Fn(Option<View>, &Sha256Digest) -> bool + Send + Sync>;

/// The gate on one kind of an honest replica's receivers.
struct Gate<K, L: Lane> {
    hold: Option<HoldFilter<L>>,
    held: VecDeque<(L, K, IoBuf)>,
    /// The position of the first message the full gate dropped.
    dropped: Option<u64>,
    ready: [VecDeque<(K, IoBuf)>; LANES],
    wake: [Option<mpsc::UnboundedSender<()>>; LANES],
}

impl<K, L: Lane> Gate<K, L> {
    const fn new() -> Self {
        Self {
            hold: None,
            held: VecDeque::new(),
            dropped: None,
            ready: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            wake: [None, None, None],
        }
    }

    /// Moves the held messages `select` accepts to their channels, in arrival order,
    /// and wakes those channels. Returns how many moved.
    fn pass(&mut self, mut select: impl FnMut(L, &K, &IoBuf) -> bool) -> usize {
        let mut moved = 0;
        let mut kept = VecDeque::with_capacity(self.held.len());
        let mut woken = [false; LANES];
        for (channel, sender, payload) in self.held.drain(..) {
            if select(channel, &sender, &payload) {
                self.ready[channel.index()].push_back((sender, payload));
                woken[channel.index()] = true;
                moved += 1;
            } else {
                kept.push_back((channel, sender, payload));
            }
        }
        self.held = kept;
        for channel in L::ALL {
            if woken[channel.index()]
                && let Some(wake) = &self.wake[channel.index()]
            {
                wake.send_lossy(());
            }
        }
        moved
    }

    /// Stops holding and delivers what the gate holds, in arrival order.
    fn open(&mut self) -> usize {
        self.hold = None;
        self.pass(|_, _, _| true)
    }

    /// Whether the release has anything to open: a filter or held messages.
    fn engaged(&self) -> bool {
        self.hold.is_some() || !self.held.is_empty()
    }
}

/// A recorder of a [ReplicaTap], as a bit of the set the base's wrappers feed.
#[derive(Clone, Copy, Debug)]
enum Recorder {
    /// The engine gate: its held messages and the deliveries log.
    Gate = 1,
    /// The marshal gate: its held messages and the marshal deliveries log.
    MarshalGate = 1 << 1,
    Activities = 1 << 2,
    Automaton = 1 << 3,
    Elections = 1 << 4,
    Blocks = 1 << 5,
}

/// The tasks of one incarnation of an honest replica, and how to build the next one.
struct Incarnation<P: Simplex> {
    app: Option<Handle<()>>,
    engine: Option<Handle<()>>,
    respawn: Option<Respawn<P>>,
}

type Respawn<P> =
    Box<dyn FnMut(NetworkChannels<PublicKeyOf<P>>) -> (Handle<()>, Handle<()>) + Send>;

/// The runner's view of one honest replica: the gates on its receivers and the
/// recorders wrapped around its reporter, automaton, elector and blocker at spawn.
pub struct ReplicaTap<P: Simplex> {
    index: usize,
    participants: Arc<[PublicKeyOf<P>]>,
    observer: Arc<dyn Observer>,
    recording: Arc<AtomicBool>,
    gate: Mutex<Gate<PublicKeyOf<P>, Channel>>,
    deliveries: Mutex<Log<Recorded<Inbound>>>,
    marshal_gate: Mutex<Gate<PublicKeyOf<P>, MarshalChannel>>,
    marshal_deliveries: Mutex<Log<Recorded<MarshalInbound>>>,
    activities: Mutex<Log<Recorded<ActivityOf<P>>>>,
    automaton: Mutex<Log<Recorded<AutomatonEvent>>>,
    elections: Mutex<Log<Recorded<(View, usize)>>>,
    blocks: Mutex<Log<Recorded<usize>>>,
    /// The [Recorder]s a wrapper feeds.
    fed: AtomicU8,
    /// The highest view this replica reported a finalization of, kept past the logs' cap.
    finalized: AtomicU64,
    /// The highest view this replica's elector was asked for, kept past the logs' cap.
    elected: AtomicU64,
    reads: Mutex<Option<Arc<dyn MarshalReads>>>,
    incarnation: Mutex<Incarnation<P>>,
    /// Whether this replica was ever crashed: a restarted incarnation runs without the
    /// wrappers the base gave it at spawn.
    crashed_once: AtomicBool,
    /// Held while this replica crashes or restarts: a concurrent crash or restart of it
    /// returns false, so two incarnations never run on its partition at once.
    busy: AsyncMutex<()>,
}

impl<P: Simplex> ReplicaTap<P> {
    fn new(
        index: usize,
        participants: Arc<[PublicKeyOf<P>]>,
        observer: Arc<dyn Observer>,
        recording: Arc<AtomicBool>,
    ) -> Self {
        Self {
            index,
            participants,
            observer,
            recording,
            gate: Mutex::new(Gate::new()),
            deliveries: Mutex::default(),
            marshal_gate: Mutex::new(Gate::new()),
            marshal_deliveries: Mutex::default(),
            activities: Mutex::default(),
            automaton: Mutex::default(),
            elections: Mutex::default(),
            blocks: Mutex::default(),
            fed: AtomicU8::new(0),
            finalized: AtomicU64::new(0),
            elected: AtomicU64::new(0),
            reads: Mutex::new(None),
            incarnation: Mutex::new(Incarnation {
                app: None,
                engine: None,
                respawn: None,
            }),
            crashed_once: AtomicBool::new(false),
            busy: AsyncMutex::new(()),
        }
    }

    /// Installs the queries of this replica's marshal the prefix reads through.
    pub fn set_reads(&self, reads: Arc<dyn MarshalReads>) {
        *self.reads.lock() = Some(reads);
    }

    fn reads(&self) -> Option<Arc<dyn MarshalReads>> {
        self.reads.lock().clone()
    }

    /// Marks `recorder` as fed by a wrapper of the base.
    fn feed(&self, recorder: Recorder) {
        self.fed.fetch_or(recorder as u8, Ordering::Relaxed);
    }

    fn fed(&self, recorder: Recorder) -> bool {
        self.fed.load(Ordering::Relaxed) & recorder as u8 != 0
    }

    fn recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }

    fn record<T: Clone>(&self, log: &Mutex<Log<Recorded<T>>>, value: T) {
        if self.recording() {
            let stamp = Stamp::now(&*self.observer);
            log.lock().push(Recorded { value, stamp }, stamp.seq());
        }
    }

    fn position(&self, key: &PublicKeyOf<P>) -> Option<usize> {
        self.participants.iter().position(|known| known == key)
    }

    /// The next message ready for `lane`, as its gate passed or released it.
    fn take_ready<L: Lane>(&self, lane: L) -> Option<(PublicKeyOf<P>, IoBuf)> {
        L::gate(self).lock().ready[lane.index()].pop_front()
    }

    /// Whether the gate of `lane` holds `message`, which it then keeps.
    fn hold<L: Lane>(&self, lane: L, sender: &PublicKeyOf<P>, payload: &IoBuf) -> bool {
        let gate = L::gate(self);
        // The filter runs with the gate unlocked, so it may call the context.
        let Some(hold) = gate.lock().hold.clone() else {
            return false;
        };
        let inbound = lane.inbound(self.position(sender), payload.clone());
        if !hold(&inbound) {
            return false;
        }
        let full = {
            let mut gate = gate.lock();
            let full = gate.held.len() >= LOG_CAP;
            if !full {
                gate.held.push_back((lane, sender.clone(), payload.clone()));
            }
            full
        };
        // A full gate drops the message, as a lossy link would, and remembers where.
        if full {
            let seq = Stamp::now(&*self.observer).seq();
            if seq != 0 {
                gate.lock().dropped.get_or_insert(seq);
            }
        }
        true
    }

    fn delivered<L: Lane>(&self, lane: L, sender: &PublicKeyOf<P>, payload: &IoBuf) {
        if self.recording() {
            let inbound = lane.inbound(self.position(sender), payload.clone());
            self.record(L::deliveries(self), inbound);
        }
    }

    fn wake<L: Lane>(&self, lane: L) -> mpsc::UnboundedReceiver<()> {
        let (sender, receiver) = mpsc::unbounded_channel();
        L::gate(self).lock().wake[lane.index()] = Some(sender);
        receiver
    }

    /// Opens both gates: every held message goes to its channel, in arrival order.
    fn open(&self) -> usize {
        self.gate.lock().open() + self.marshal_gate.lock().open()
    }

    fn crashed(&self) -> bool {
        let incarnation = self.incarnation.lock();
        incarnation.engine.is_none() && incarnation.respawn.is_some()
    }
}

/// A receiver behind the gate of an honest replica's channel `L`: it holds what the
/// gate's filter accepts, delivers what the prefix passes, and records every delivery.
/// Without a tap it only forwards.
pub struct GateReceiver<P: Simplex, R, L = Channel> {
    inner: R,
    tap: Option<Arc<ReplicaTap<P>>>,
    lane: L,
    /// Wakes the receiver when the prefix passes a message to its channel; `None`
    /// without a tap, or once a newer receiver of the channel took the wake-ups.
    wake: Option<mpsc::UnboundedReceiver<()>>,
}

/// A receiver of honest replica `tap`'s engine `channel`, behind its engine gate.
pub fn gate<P: Simplex, R>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: R,
    channel: Channel,
) -> GateReceiver<P, R> {
    gated(tap, inner, channel)
}

/// A receiver of honest replica `tap`'s marshal `channel`, behind its marshal gate.
pub fn marshal_gate<P: Simplex, R>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: R,
    channel: MarshalChannel,
) -> GateReceiver<P, R, MarshalChannel> {
    gated(tap, inner, channel)
}

fn gated<P: Simplex, R, L: Lane>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: R,
    lane: L,
) -> GateReceiver<P, R, L> {
    let tap = fed(tap, L::RECORDER);
    let wake = tap.as_ref().map(|tap| tap.wake(lane));
    GateReceiver {
        inner,
        tap,
        lane,
        wake,
    }
}

/// `tap`, marked as feeding `recorder`.
fn fed<P: Simplex>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    recorder: Recorder,
) -> Option<Arc<ReplicaTap<P>>> {
    tap.map(|tap| {
        tap.feed(recorder);
        tap.clone()
    })
}

impl<P: Simplex, R, L: fmt::Debug> fmt::Debug for GateReceiver<P, R, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateReceiver")
            .field("replica", &self.tap.as_ref().map(|tap| tap.index))
            .field("channel", &self.lane)
            .finish()
    }
}

impl<P, R> commonware_p2p::Receiver for GateReceiver<P, R>
where
    P: Simplex,
    R: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    type Error = R::Error;
    type PublicKey = PublicKeyOf<P>;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        gated_recv(self).await
    }
}

impl<P, R> commonware_p2p::Receiver for GateReceiver<P, R, MarshalChannel>
where
    P: Simplex,
    R: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    type Error = R::Error;
    type PublicKey = PublicKeyOf<P>;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        gated_recv(self).await
    }
}

/// The next message `receiver` delivers: one the prefix passed, or one its gate's
/// filter does not hold.
async fn gated_recv<P, R, L>(
    receiver: &mut GateReceiver<P, R, L>,
) -> Result<commonware_p2p::Message<PublicKeyOf<P>>, R::Error>
where
    P: Simplex,
    R: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    L: Lane,
{
    let GateReceiver {
        inner,
        tap,
        lane,
        wake,
    } = receiver;
    let Some(tap) = tap.as_ref() else {
        return inner.recv().await;
    };
    loop {
        if let Some((sender, payload)) = tap.take_ready(*lane) {
            tap.delivered(*lane, &sender, &payload);
            return Ok((sender, payload));
        }
        let message = match wake.as_mut() {
            Some(signal) => select! {
                message = inner.recv() => message,
                woken = signal.recv() => {
                    // A closed wake channel means a newer receiver of this channel
                    // took its wake-ups: this one waits for its own messages only.
                    if woken.is_none() {
                        *wake = None;
                    }
                    continue;
                },
            },
            None => inner.recv().await,
        };
        let (sender, payload) = message?;
        if tap.hold(*lane, &sender, &payload) {
            continue;
        }
        tap.delivered(*lane, &sender, &payload);
        return Ok((sender, payload));
    }
}

/// Records every activity an honest replica's engine reports; without a tap it only
/// forwards.
pub struct TapReporter<P: Simplex, R> {
    inner: R,
    tap: Option<Arc<ReplicaTap<P>>>,
}

/// A reporter that records into honest replica `tap`'s activities log.
pub fn tap_reporter<P: Simplex, R>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: R,
) -> TapReporter<P, R> {
    TapReporter {
        inner,
        tap: fed(tap, Recorder::Activities),
    }
}

impl<P: Simplex, R: Clone> Clone for TapReporter<P, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
        }
    }
}

impl<P, R> Reporter for TapReporter<P, R>
where
    P: Simplex,
    R: Reporter<Activity = Activity<P::Scheme, Sha256Digest>>,
{
    type Activity = R::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Some(tap) = &self.tap {
            if let Activity::Finalization(finalization) = &activity {
                tap.finalized
                    .fetch_max(finalization.view().get(), Ordering::Relaxed);
            }
            if tap.recording() {
                tap.record(&tap.activities, activity.clone());
            }
        }
        self.inner.report(activity)
    }
}

/// Raises the release's base with every finalization an honest replica's engine
/// reports, whatever its payload, and records nothing; without a tap it only forwards.
pub struct TapFinalized<P: Simplex, R> {
    inner: R,
    tap: Option<Arc<ReplicaTap<P>>>,
}

/// A reporter that raises honest replica `tap`'s finalized view.
pub fn tap_finalized<P: Simplex, R>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: R,
) -> TapFinalized<P, R> {
    TapFinalized {
        inner,
        tap: tap.cloned(),
    }
}

impl<P: Simplex, R: Clone> Clone for TapFinalized<P, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
        }
    }
}

impl<P, R, D> Reporter for TapFinalized<P, R>
where
    P: Simplex,
    D: Digest,
    R: Reporter<Activity = Activity<P::Scheme, D>>,
{
    type Activity = R::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let (Some(tap), Activity::Finalization(finalization)) = (&self.tap, &activity) {
            tap.finalized
                .fetch_max(finalization.view().get(), Ordering::Relaxed);
        }
        self.inner.report(activity)
    }
}

/// Records every leader an honest replica's voter elects; without a tap it only
/// forwards.
pub struct TapElector<P: Simplex, C> {
    inner: C,
    tap: Option<Arc<ReplicaTap<P>>>,
}

/// An elector config whose elector records into honest replica `tap`'s elections log.
pub fn tap_elector<P: Simplex, C>(tap: Option<&Arc<ReplicaTap<P>>>, inner: C) -> TapElector<P, C> {
    TapElector {
        inner,
        tap: fed(tap, Recorder::Elections),
    }
}

impl<P: Simplex, C: Clone> Clone for TapElector<P, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
        }
    }
}

/// The elector [TapElector] builds.
pub struct TapElectorState<P: Simplex, E> {
    inner: E,
    tap: Option<Arc<ReplicaTap<P>>>,
}

impl<P: Simplex, E: Clone> Clone for TapElectorState<P, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
        }
    }
}

impl<P, C> ElectorConfig<P::Scheme> for TapElector<P, C>
where
    P: Simplex,
    C: ElectorConfig<P::Scheme>,
{
    type Elector = TapElectorState<P, C::Elector>;

    fn build(self, participants: &Set<PublicKeyOf<P>>) -> Self::Elector {
        TapElectorState {
            inner: self.inner.build(participants),
            tap: self.tap,
        }
    }
}

impl<P, E> Elector<P::Scheme> for TapElectorState<P, E>
where
    P: Simplex,
    E: Elector<P::Scheme>,
{
    type Mode = E::Mode;

    fn terms(&self) -> Terms {
        self.inner.terms()
    }

    fn elect(
        &self,
        round: Round,
        input: Input<'_, P::Scheme, Self>,
    ) -> commonware_consensus::types::Participant {
        let leader = self.inner.elect(round, input);
        if let Some(tap) = &self.tap {
            tap.elected.fetch_max(round.view().get(), Ordering::Relaxed);
            tap.record(&tap.elections, (round.view(), leader.get() as usize));
        }
        leader
    }
}

/// Records every peer an honest replica blocks; without a tap it only forwards.
pub struct TapBlocker<P: Simplex, B> {
    inner: B,
    tap: Option<Arc<ReplicaTap<P>>>,
}

/// A blocker that records into honest replica `tap`'s blocks log.
pub fn tap_blocker<P: Simplex, B>(tap: Option<&Arc<ReplicaTap<P>>>, inner: B) -> TapBlocker<P, B> {
    TapBlocker {
        inner,
        tap: fed(tap, Recorder::Blocks),
    }
}

impl<P: Simplex, B: Clone> Clone for TapBlocker<P, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
        }
    }
}

impl<P, B> Blocker for TapBlocker<P, B>
where
    P: Simplex,
    B: Blocker<PublicKey = PublicKeyOf<P>>,
{
    type PublicKey = PublicKeyOf<P>;

    #[allow(
        clippy::disallowed_methods,
        reason = "a recording blocker forwards the engine's block, which logged it"
    )]
    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        if let Some(tap) = &self.tap
            && let Some(index) = tap.position(&peer)
        {
            tap.record(&tap.blocks, index);
        }
        self.inner.block(peer)
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        self.inner.blocked()
    }
}

/// Records what an honest replica's automaton is asked, and what it answers; without
/// a tap it only forwards.
pub struct TapAutomaton<P: Simplex, A> {
    inner: A,
    tap: Option<Arc<ReplicaTap<P>>>,
    context: Option<Arc<Mutex<deterministic::Context>>>,
}

/// An automaton that records into honest replica `tap`'s automaton log, with a child
/// of `context` for the tasks that watch the answers.
pub fn tap_automaton<P: Simplex, A>(
    tap: Option<&Arc<ReplicaTap<P>>>,
    inner: A,
    context: &deterministic::Context,
) -> TapAutomaton<P, A> {
    let tap = fed(tap, Recorder::Automaton);
    let context = tap
        .as_ref()
        .map(|_| Arc::new(Mutex::new(context.child("tap"))));
    TapAutomaton {
        inner,
        tap,
        context,
    }
}

impl<P: Simplex, A: Clone> Clone for TapAutomaton<P, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tap: self.tap.clone(),
            context: self.context.clone(),
        }
    }
}

impl<P: Simplex, A> TapAutomaton<P, A> {
    /// Records the event `event` builds for the tap.
    fn record(&self, event: impl FnOnce(&ReplicaTap<P>) -> AutomatonEvent) {
        if let Some(tap) = &self.tap {
            tap.record(&tap.automaton, event(tap));
        }
    }

    /// Forwards `receiver`'s answer and records how the request ended with `done`. When
    /// consensus drops the receiver it was given, the proxy drops `receiver` too, so the
    /// automaton sees the cancellation as it would without the recorder.
    fn proxy<T: Clone + Send + 'static>(
        &self,
        receiver: oneshot::Receiver<T>,
        done: impl FnOnce(Completion<T>) -> AutomatonEvent + Send + 'static,
    ) -> oneshot::Receiver<T> {
        let (Some(tap), Some(context)) = (&self.tap, &self.context) else {
            return receiver;
        };
        if !tap.recording() {
            return receiver;
        }
        let (mut sender, output) = oneshot::channel();
        let tap = tap.clone();
        context
            .lock()
            .child("tap_automaton")
            .spawn(move |_| async move {
                let completion = select! {
                    answer = receiver => match answer {
                        Ok(value) => {
                            if sender.send_lossy(value.clone()) {
                                Completion::Returned(value)
                            } else {
                                Completion::Canceled
                            }
                        }
                        Err(_) if sender.is_closed() => Completion::Canceled,
                        Err(_) => Completion::Closed,
                    },
                    _ = sender.closed() => Completion::Canceled,
                };
                tap.record(&tap.automaton, done(completion));
            });
        output
    }
}

impl<P, A> Automaton for TapAutomaton<P, A>
where
    P: Simplex,
    A: CertifiableAutomaton<
            Context = SimplexContext<Sha256Digest, PublicKeyOf<P>>,
            Digest = Sha256Digest,
        >,
{
    type Context = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
    type Digest = Sha256Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let round = context.round;
        self.record(|_| AutomatonEvent::Propose {
            round,
            parent: context.parent,
        });
        let receiver = self.inner.propose(context).await;
        self.proxy(receiver, move |payload| AutomatonEvent::Proposed {
            round,
            payload,
        })
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let round = context.round;
        self.record(|tap| AutomatonEvent::Verify {
            round,
            leader: tap.position(&context.leader),
            parent: context.parent,
            payload,
        });
        let receiver = self.inner.verify(context, payload).await;
        self.proxy(receiver, move |valid| AutomatonEvent::Verified {
            round,
            payload,
            valid,
        })
    }
}

impl<P, A> CertifiableAutomaton for TapAutomaton<P, A>
where
    P: Simplex,
    A: CertifiableAutomaton<
            Context = SimplexContext<Sha256Digest, PublicKeyOf<P>>,
            Digest = Sha256Digest,
        >,
{
    async fn prepare(
        &mut self,
        context: Self::Context,
    ) -> oneshot::Receiver<Handoff<Self::Digest>> {
        let round = context.round;
        self.record(|_| AutomatonEvent::Prepare {
            round,
            parent: context.parent,
        });
        let receiver = self.inner.prepare(context).await;
        self.proxy(receiver, move |decision| AutomatonEvent::Prepared {
            round,
            decision,
        })
    }

    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        self.record(|_| AutomatonEvent::Certify { round, payload });
        let receiver = self.inner.certify(round, payload).await;
        self.proxy(receiver, move |certified| AutomatonEvent::Certified {
            round,
            payload,
            certified,
        })
    }
}

/// Spawns an honest validator on the fuzz-local block relay: with `tap`, behind its
/// gate and recorders, with its tasks retained so the prefix may crash and restart it;
/// without, exactly as [crate::spawn_filtered_validator_with_reporter] does.
#[allow(clippy::too_many_arguments)]
pub fn spawn_validator<
    P,
    EC,
    R,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    tap: Option<Arc<ReplicaTap<P>>>,
    context: deterministic::Context,
    oracle: &commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    handoff: Handoff<()>,
    wiring: ReporterWiring,
) -> R
where
    P: Simplex,
    EC: ElectorConfig<P::Scheme>,
    R: HarnessReporter<P, EC, block_relay::Mailbox<PublicKeyOf<P>>>,
    PendingSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    PendingReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    RecoveredSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    RecoveredReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ResolverSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    ResolverReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    let Some(tap) = tap else {
        return crate::spawn_filtered_validator_with_reporter::<P, EC, R, _, _, _, _, _, _>(
            context,
            oracle,
            participants,
            scheme,
            validator,
            elector,
            relay,
            leader_timeout,
            certification_timeout,
            mailbox_size,
            forwarding,
            pending,
            recovered,
            resolver,
            certify,
            handoff,
            wiring,
        );
    };
    let reporter_cfg = commonware_consensus::simplex::mocks::reporter::Config {
        participants: participants.try_into().expect("public keys are unique"),
        scheme: scheme.clone(),
        elector: elector.clone(),
    };
    let reporter = R::create(context.child("reporter"), validator.clone(), reporter_cfg);
    let build = Build {
        context,
        oracle: oracle.clone(),
        participants: participants.to_vec(),
        scheme,
        validator,
        elector,
        relay,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        forwarding,
        certify,
        handoff,
        wiring,
        reporter: reporter.clone(),
    };
    let (app, engine) = build.incarnation(&tap, pending, recovered, resolver);
    let weak = Arc::downgrade(&tap);
    let mut generation = 0u32;
    let respawn: Respawn<P> = Box::new(move |(pending, recovered, resolver)| {
        let tap = Weak::upgrade(&weak).expect("a respawned replica keeps its tap");
        // The restarted engine replays its journal into the retained reporter: a new
        // generation keeps its votes apart from the previous incarnation's.
        generation += 1;
        build.reporter.new_incarnation(generation);
        build.incarnation(&tap, pending, recovered, resolver)
    });
    let mut incarnation = tap.incarnation.lock();
    incarnation.app = Some(app);
    incarnation.engine = Some(engine);
    incarnation.respawn = Some(respawn);
    reporter
}

/// Everything one incarnation of a tapped honest validator is built from.
struct Build<P: Simplex, EC, R> {
    context: deterministic::Context,
    oracle: commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: Vec<PublicKeyOf<P>>,
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
    certify: CertifyChoice,
    handoff: Handoff<()>,
    wiring: ReporterWiring,
    reporter: R,
}

impl<P, EC, R> Build<P, EC, R>
where
    P: Simplex,
    EC: ElectorConfig<P::Scheme>,
    R: HarnessReporter<P, EC, block_relay::Mailbox<PublicKeyOf<P>>>,
{
    /// Starts an incarnation on the validator's partition with its retained reporter,
    /// behind `tap`; returns its application and engine tasks.
    #[allow(clippy::type_complexity)]
    fn incarnation<VS, VR, CS, CR, XS, XR>(
        &self,
        tap: &Arc<ReplicaTap<P>>,
        (vote_sender, vote_receiver): (VS, VR),
        (certificate_sender, certificate_receiver): (CS, CR),
        (resolver_sender, resolver_receiver): (XS, XR),
    ) -> (Handle<()>, Handle<()>)
    where
        VS: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        VR: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        CS: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        CR: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        XS: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        XR: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    {
        let index = self
            .participants
            .iter()
            .position(|key| key == &self.validator)
            .expect("validator must be in participants");
        let app_cfg = block_relay::Config::<_> {
            relay: self.relay.clone(),
            me: self.validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: self.certify.into_certifier(index),
        };
        let (mut actor, application) =
            block_relay::Application::new(self.context.child("application"), app_cfg);
        actor.set_handoff(self.handoff);
        let app = actor.start();
        let tap = Some(tap);
        let automaton = tap_automaton(
            tap,
            self.reporter.automaton(&self.context, application.clone()),
            &self.context,
        );
        let reporter = tap_reporter(tap, self.reporter.clone());
        let elector = tap_elector(tap, self.elector.clone());
        let blocker = tap_blocker(tap, self.oracle.control(self.validator.clone()));
        let engine = start_validator_engine::<P, _, _, _, _, _, _, _, _, _, _, _>(
            &self.context,
            blocker,
            self.scheme.clone(),
            elector,
            automaton,
            application,
            self.wiring.wire(reporter),
            self.validator.to_string(),
            self.leader_timeout,
            self.certification_timeout,
            self.mailbox_size,
            self.forwarding,
            (vote_sender, gate(tap, vote_receiver, Channel::Vote)),
            (
                certificate_sender,
                gate(tap, certificate_receiver, Channel::Certificate),
            ),
            (
                resolver_sender,
                gate(tap, resolver_receiver, Channel::Resolver),
            ),
        );
        (app, engine)
    }
}

/// Held blocks and the per-recipient filters that hold them.
struct BlockGate<K> {
    filters: BTreeMap<usize, BlockFilter>,
    held: Vec<(K, Option<u64>, K, Sha256Digest, Bytes)>,
}

/// The compromised identity's channels while the prefix acts as it.
type Senders<K> = (
    commonware_p2p::simulated::Sender<K, deterministic::Context>,
    commonware_p2p::simulated::Sender<K, deterministic::Context>,
    commonware_p2p::simulated::Sender<K, deterministic::Context>,
);
type Receivers<K> = (
    commonware_p2p::simulated::Receiver<K>,
    commonware_p2p::simulated::Receiver<K>,
    commonware_p2p::simulated::Receiver<K>,
);

/// The compromised identity's marshal channels while the prefix acts as it.
type MarshalSenders<K> = (
    commonware_p2p::simulated::Sender<K, deterministic::Context>,
    commonware_p2p::simulated::Sender<K, deterministic::Context>,
);
type MarshalReceivers<K> = (
    commonware_p2p::simulated::Receiver<K>,
    commonware_p2p::simulated::Receiver<K>,
);

/// The runner's state, which the [PrefixContext] reaches only while it is valid.
struct Shared<P: Simplex> {
    observer: Arc<dyn Observer>,
    participants: Arc<[PublicKeyOf<P>]>,
    byzantine: Option<usize>,
    term_length: TermLength,
    optimistic_views: ViewDelta,
    scripted_views: u64,
    epoch: Epoch,
    leader: Box<dyn Fn(View) -> usize + Send + Sync>,
    oracle: commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
    taps: Vec<Option<Arc<ReplicaTap<P>>>>,
    revoked: AtomicBool,
    scheme: Option<P::Scheme>,
    senders: Mutex<Option<Senders<PublicKeyOf<P>>>>,
    inbox: Mutex<Log<Recorded<Inbound>>>,
    /// Whether the base handed the runner B's marshal channels.
    lanes: AtomicBool,
    marshal_senders: Mutex<Option<MarshalSenders<PublicKeyOf<P>>>>,
    marshal_inbox: Mutex<Log<Recorded<MarshalInbound>>>,
    made: Mutex<BTreeMap<Sha256Digest, Bytes>>,
    nonce: AtomicU64,
    /// The bytes B's sends delivered so far, toward [MAX_SENT].
    sent: AtomicU64,
    links: Mutex<BTreeSet<(usize, usize)>>,
    latencies: Mutex<BTreeSet<usize>>,
    block_gate: Arc<Mutex<BlockGate<PublicKeyOf<P>>>>,
}

impl<P: Simplex> Shared<P> {
    /// The tap a capability that changes the system takes: none past the handoff.
    fn tap(&self, replica: usize) -> Option<&Arc<ReplicaTap<P>>> {
        if self.revoked.load(Ordering::Relaxed) {
            return None;
        }
        self.read(replica)
    }

    /// The tap a read takes: valid past the handoff, since a filter runs until the release.
    fn read(&self, replica: usize) -> Option<&Arc<ReplicaTap<P>>> {
        self.taps.get(replica).and_then(Option::as_ref)
    }

    fn key(&self, index: usize) -> Option<PublicKeyOf<P>> {
        self.participants.get(index).cloned()
    }

    /// Charges a send of `len` bytes, at least [MIN_CHARGE], to `recipients`, at least
    /// one, against [MAX_SENT]; false, and nothing charged, past it.
    fn charge(&self, len: usize, recipients: usize) -> bool {
        let cost = (len as u64)
            .max(MIN_CHARGE)
            .saturating_mul(recipients.max(1) as u64);
        let sent = self.sent.load(Ordering::Relaxed);
        if sent.saturating_add(cost) > MAX_SENT {
            return false;
        }
        self.sent.store(sent + cost, Ordering::Relaxed);
        true
    }
}

/// The base driver's handle on a continuation: it hands out the taps of the honest
/// replicas, keeps the compromised identity's channels, runs the prefix, and performs
/// the release.
pub struct Runner<P: Simplex> {
    context: deterministic::Context,
    prefix: Option<Box<dyn Prefix<P>>>,
    budget: Budget,
    shared: Arc<Shared<P>>,
    recording: Arc<AtomicBool>,
    registry: ActorRegistry,
    required: Vec<(usize, Role)>,
    receivers: Option<Receivers<PublicKeyOf<P>>>,
    marshal_receivers: Option<MarshalReceivers<PublicKeyOf<P>>>,
    /// B's marshal channels, returned once the release took them back.
    marshal: Option<MarshalChannels<PublicKeyOf<P>>>,
    base_link: Box<dyn Fn(usize, usize) -> Option<Link> + Send>,
}

/// What a base driver tells the runner when it starts it.
pub struct Topology<P: Simplex> {
    pub participants: Vec<PublicKeyOf<P>>,
    pub schemes: Vec<P::Scheme>,
    /// The compromised identity, if the base runs one.
    pub byzantine: Option<usize>,
    /// The actors the base starts for it: they must run from the release on.
    pub required: Vec<Role>,
    pub term_length: TermLength,
    pub optimistic_views: ViewDelta,
    /// The last view of a scripted Twins prefix, 0 outside Twins.
    pub scripted_views: u64,
    /// The epoch the honest engines run.
    pub epoch: Epoch,
    /// The base's block relay; `None` for a base without one (marshal), which leaves
    /// the block and latency capabilities inert.
    pub relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
    pub oracle: commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    /// The link the base set up between two participants, `None` for no link.
    pub base_link: Box<dyn Fn(usize, usize) -> Option<Link> + Send>,
}

impl<P: Simplex> Runner<P> {
    /// Starts a continuation over `topology` with the elector the honest engines run,
    /// and publishes the compromised identity, before any engine starts.
    pub fn start<EC: ElectorConfig<P::Scheme>>(
        hook: Hook<P>,
        context: &deterministic::Context,
        topology: Topology<P>,
        elector: EC,
    ) -> Self {
        let Hook {
            prefix,
            observer,
            budget,
        } = hook;
        observer.compromised(&topology.byzantine.into_iter().collect::<Vec<_>>());
        let participants: Arc<[PublicKeyOf<P>]> = topology.participants.clone().into();
        let set: Set<PublicKeyOf<P>> = topology
            .participants
            .as_slice()
            .try_into()
            .expect("public keys are unique");
        let leaders = Mutex::new(elector.build(&set));
        let epoch = topology.epoch;
        let leader: Box<dyn Fn(View) -> usize + Send + Sync> = Box::new(move |view| {
            leaders
                .lock()
                .elect(
                    Round::new(epoch, view),
                    <EC::Elector as Elector<P::Scheme>>::Mode::input(None),
                )
                .get() as usize
        });
        let recording = Arc::new(AtomicBool::new(true));
        let taps = (0..participants.len())
            .map(|index| {
                (Some(index) != topology.byzantine).then(|| {
                    Arc::new(ReplicaTap::new(
                        index,
                        participants.clone(),
                        observer.clone(),
                        recording.clone(),
                    ))
                })
            })
            .collect();
        let required = topology
            .byzantine
            .map(|identity| {
                topology
                    .required
                    .iter()
                    .map(|role| (identity, *role))
                    .collect()
            })
            .unwrap_or_default();
        let scheme = topology
            .byzantine
            .and_then(|index| topology.schemes.get(index).cloned());
        let shared = Arc::new(Shared {
            observer,
            participants,
            byzantine: topology.byzantine,
            term_length: topology.term_length,
            optimistic_views: topology.optimistic_views,
            scripted_views: topology.scripted_views,
            epoch,
            leader,
            oracle: topology.oracle,
            relay: topology.relay,
            taps,
            revoked: AtomicBool::new(false),
            scheme,
            senders: Mutex::new(None),
            inbox: Mutex::default(),
            lanes: AtomicBool::new(false),
            marshal_senders: Mutex::new(None),
            marshal_inbox: Mutex::default(),
            made: Mutex::new(BTreeMap::new()),
            nonce: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            links: Mutex::new(BTreeSet::new()),
            latencies: Mutex::new(BTreeSet::new()),
            block_gate: Arc::new(Mutex::new(BlockGate {
                filters: BTreeMap::new(),
                held: Vec::new(),
            })),
        });
        Self {
            context: context.child("continuation"),
            prefix: Some(prefix),
            budget,
            shared,
            recording,
            registry: ActorRegistry::default(),
            required,
            receivers: None,
            marshal_receivers: None,
            marshal: None,
            base_link: topology.base_link,
        }
    }

    /// The tap of honest replica `index`; `None` for the compromised identity.
    pub fn tap(&self, index: usize) -> Option<Arc<ReplicaTap<P>>> {
        self.shared.taps.get(index).cloned().flatten()
    }

    /// Whether honest replica `index` was ever crashed.
    pub fn was_crashed(&self, index: usize) -> bool {
        self.tap(index)
            .is_some_and(|tap| tap.crashed_once.load(Ordering::Relaxed))
    }

    /// The compromised identity, if the base runs one.
    pub fn byzantine(&self) -> Option<usize> {
        self.shared.byzantine
    }

    /// The registry of the compromised identity's actors.
    pub fn registry(&self) -> ActorRegistry {
        self.registry.clone()
    }

    /// Keeps the compromised identity's registered channels: the prefix sends as it,
    /// and the runner records what it receives, until the release.
    pub fn adopt(&mut self, channels: NetworkChannels<PublicKeyOf<P>>) {
        let (
            (vote_sender, vote_receiver),
            (cert_sender, cert_receiver),
            (res_sender, res_receiver),
        ) = channels;
        *self.shared.senders.lock() = Some((vote_sender, cert_sender, res_sender));
        self.receivers = Some((vote_receiver, cert_receiver, res_receiver));
    }

    /// Keeps the compromised identity's registered marshal channels as [Self::adopt]
    /// keeps its engine channels; [Self::marshal_channels] returns them after the
    /// release.
    pub fn adopt_marshal(&mut self, channels: MarshalChannels<PublicKeyOf<P>>) {
        let ((backfill_sender, backfill_receiver), (broadcast_sender, broadcast_receiver)) =
            channels;
        *self.shared.marshal_senders.lock() = Some((backfill_sender, broadcast_sender));
        self.marshal_receivers = Some((backfill_receiver, broadcast_receiver));
        self.shared.lanes.store(true, Ordering::Relaxed);
    }

    /// The compromised identity's marshal channels, once [Self::run] stopped recording
    /// them; `None` before, after the first call, and when the base adopted none.
    pub fn marshal_channels(&mut self) -> Option<MarshalChannels<PublicKeyOf<P>>> {
        self.marshal.take()
    }

    /// Runs the prefix, ending it once its budget has passed, then performs the
    /// release: revokes the prefix's capabilities, waits the release delay, reverts the
    /// changes the prefix made, and returns the compromised identity's channels with
    /// what was reverted; its marshal channels wait in [Self::marshal_channels]. The
    /// caller then starts the base's actors for it.
    pub async fn run(&mut self) -> (Option<NetworkChannels<PublicKeyOf<P>>>, Release) {
        // The compromised identity's inbox: recorded until the release, then returned.
        let (stop, stopped) = oneshot::channel::<()>();
        let inbox = self.receivers.take().map(|receivers| {
            let shared = self.shared.clone();
            self.context
                .child("inbox")
                .spawn(move |_| inbox_task::<P>(receivers, shared, stopped))
        });
        let (stop_marshal, stopped_marshal) = oneshot::channel::<()>();
        let marshal_inbox = self.marshal_receivers.take().map(|receivers| {
            let shared = self.shared.clone();
            self.context
                .child("marshal_inbox")
                .spawn(move |_| marshal_inbox_task::<P>(receivers, shared, stopped_marshal))
        });
        self.install_block_gate();
        let mut overran = false;
        if let Some(prefix) = self.prefix.take() {
            let cx = PrefixContext {
                context: self.context.child("prefix"),
                shared: self.shared.clone(),
            };
            // A prefix that has not returned by its budget is dropped there: every
            // capability either completes synchronously or leaves a state the release
            // reverts or the continuation tolerates.
            select! {
                _ = prefix.run(cx) => {},
                _ = self.context.sleep(self.budget.prefix) => {
                    overran = true;
                },
            }
        }
        // The handoff: the context no longer changes anything.
        self.shared.revoked.store(true, Ordering::Relaxed);
        if !self.budget.release.is_zero() {
            self.context.sleep(self.budget.release).await;
        }
        let mut release = self.revert().await;
        release.overran = overran;
        self.recording.store(false, Ordering::Relaxed);
        stop.send_lossy(());
        stop_marshal.send_lossy(());
        let receivers = match inbox {
            Some(handle) => handle.await.ok(),
            None => None,
        };
        let marshal_receivers = match marshal_inbox {
            Some(handle) => handle.await.ok(),
            None => None,
        };
        let senders = self.shared.senders.lock().take();
        let channels = match (senders, receivers) {
            (Some((vs, cs, rs)), Some((vr, cr, rr))) => Some(((vs, vr), (cs, cr), (rs, rr))),
            _ => None,
        };
        let marshal_senders = self.shared.marshal_senders.lock().take();
        self.marshal = match (marshal_senders, marshal_receivers) {
            (Some((bs, ss)), Some((br, sr))) => Some(((bs, br), (ss, sr))),
            _ => None,
        };
        release.base = self.finalized();
        release.view = self.elected();
        self.shared.observer.released(&release);
        (channels, release)
    }

    /// Checks that the compromised identity's required actors run, and reports it.
    pub fn check(&self, at: &'static str) -> ActorCheck {
        self.check_with(at, None)
    }

    /// [Self::check], failed by `base` when it names why the base's own fault model did
    /// not run (one token without whitespace).
    pub fn check_with(&self, at: &'static str, base: Option<&'static str>) -> ActorCheck {
        let mut check = self.registry.check(at, &self.required);
        check.base = base;
        self.shared.observer.actors(&check);
        check
    }

    /// The check at the release: first gives the actors just started up to
    /// `RELEASE_SETTLE` of simulated time to run, so a task that executes sets its marker.
    pub async fn check_release(&self) -> ActorCheck {
        let mut waited = Duration::ZERO;
        while !self.registry.executed(&self.required) && waited < RELEASE_SETTLE {
            self.context.sleep(RELEASE_POLL).await;
            waited += RELEASE_POLL;
        }
        self.check("release")
    }

    /// The highest view any honest replica reported a finalization of.
    fn finalized(&self) -> u64 {
        self.shared
            .taps
            .iter()
            .flatten()
            .map(|tap| tap.finalized.load(Ordering::Relaxed))
            .max()
            .unwrap_or(0)
    }

    /// The highest view any honest replica's elector was asked for.
    fn elected(&self) -> u64 {
        self.shared
            .taps
            .iter()
            .flatten()
            .map(|tap| tap.elected.load(Ordering::Relaxed))
            .max()
            .unwrap_or(0)
    }

    fn install_block_gate(&self) {
        let Some(relay) = &self.shared.relay else {
            return;
        };
        let gate = self.shared.block_gate.clone();
        let participants = self.shared.participants.clone();
        // Set while a filter runs: a block the filter sends is delivered, not filtered,
        // so a filter that sends a block it accepts cannot recurse.
        let filtering = AtomicBool::new(false);
        relay.set_gate(
            move |sender, sender_tag, recipient, _tag, payload, contents| {
                let Some(index) = participants.iter().position(|key| key == recipient) else {
                    return false;
                };
                // The filter runs with the gate unlocked, so it may call the context.
                let Some(filter) = gate.lock().filters.get(&index).cloned() else {
                    return false;
                };
                if filtering.swap(true, Ordering::Relaxed) {
                    return false;
                }
                let hold = filter(block_relay::mock_block_view(contents), payload);
                filtering.store(false, Ordering::Relaxed);
                if !hold {
                    return false;
                }
                let mut gate = gate.lock();
                // A full gate drops the block, as a lossy link would.
                if gate.held.len() >= LOG_CAP {
                    return true;
                }
                gate.held.push((
                    sender.clone(),
                    sender_tag,
                    recipient.clone(),
                    *payload,
                    contents.clone(),
                ));
                true
            },
        );
    }

    /// Reverts the changes of the prefix: latency overrides removed, links restored to
    /// the base's, crashed replicas restarted, and only then gates opened and held blocks
    /// delivered, so a restarted replica's new receivers and application get what was held
    /// for it. An application request already sleeping on an override keeps the latency it
    /// drew. Nothing here can fail the run: a link the network refuses stays as it is.
    async fn revert(&mut self) -> Release {
        let mut release = Release::default();
        let latencies = std::mem::take(&mut *self.shared.latencies.lock());
        for replica in latencies {
            if let (Some(relay), Some(key)) = (&self.shared.relay, self.shared.key(replica)) {
                relay.set_latency(&key, None);
            }
            release.latencies.push(replica);
        }
        let links = std::mem::take(&mut *self.shared.links.lock());
        for (from, to) in links {
            let (Some(sender), Some(receiver)) = (self.shared.key(from), self.shared.key(to))
            else {
                continue;
            };
            self.shared
                .oracle
                .remove_link(sender.clone(), receiver.clone())
                .await
                .ok();
            if let Some(link) = (self.base_link)(from, to) {
                self.shared
                    .oracle
                    .add_link(sender, receiver, link)
                    .await
                    .ok();
            }
            release.links.push((from, to));
        }
        let crashed: Vec<_> = self
            .shared
            .taps
            .iter()
            .flatten()
            .filter(|tap| tap.crashed())
            .cloned()
            .collect();
        for tap in crashed {
            restart(&self.shared, &tap).await;
            release.restarted.push(tap.index);
        }
        for tap in self.shared.taps.iter().flatten() {
            let engaged = tap.gate.lock().engaged();
            if engaged || tap.marshal_gate.lock().engaged() {
                release.gates.push(tap.index);
            }
            release.delivered += tap.open();
        }
        let held = {
            let mut gate = self.shared.block_gate.lock();
            gate.filters.clear();
            std::mem::take(&mut gate.held)
        };
        if let Some(relay) = &self.shared.relay {
            relay.clear_gate();
            for (sender, tag, recipient, payload, contents) in held {
                release.blocks += relay.redeliver(&sender, tag, recipient, (payload, contents));
            }
        }
        release
    }
}

/// Records what the compromised identity receives until `stop`, then returns its
/// receivers.
async fn inbox_task<P: Simplex>(
    (mut votes, mut certificates, mut resolver): Receivers<PublicKeyOf<P>>,
    shared: Arc<Shared<P>>,
    mut stop: oneshot::Receiver<()>,
) -> Receivers<PublicKeyOf<P>> {
    loop {
        let (channel, message) = select! {
            _ = &mut stop => break,
            message = votes.recv() => (Channel::Vote, message),
            message = certificates.recv() => (Channel::Certificate, message),
            message = resolver.recv() => (Channel::Resolver, message),
        };
        let Ok((sender, payload)) = message else {
            break;
        };
        let stamp = Stamp::now(&*shared.observer);
        let from = shared.participants.iter().position(|key| key == &sender);
        shared.inbox.lock().push(
            Recorded {
                value: Inbound {
                    from,
                    channel,
                    payload,
                },
                stamp,
            },
            stamp.seq(),
        );
    }
    (votes, certificates, resolver)
}

/// Records what the compromised identity receives on its marshal channels until
/// `stop`, then returns its receivers.
async fn marshal_inbox_task<P: Simplex>(
    (mut backfill, mut broadcast): MarshalReceivers<PublicKeyOf<P>>,
    shared: Arc<Shared<P>>,
    mut stop: oneshot::Receiver<()>,
) -> MarshalReceivers<PublicKeyOf<P>> {
    loop {
        let (channel, message) = select! {
            _ = &mut stop => break,
            message = backfill.recv() => (MarshalChannel::Backfill, message),
            message = broadcast.recv() => (MarshalChannel::Broadcast, message),
        };
        let Ok((sender, payload)) = message else {
            break;
        };
        let stamp = Stamp::now(&*shared.observer);
        let from = shared.participants.iter().position(|key| key == &sender);
        shared.marshal_inbox.lock().push(
            Recorded {
                value: MarshalInbound {
                    from,
                    channel,
                    payload,
                },
                stamp,
            },
            stamp.seq(),
        );
    }
    (backfill, broadcast)
}

/// Crash-stops honest replica `tap`: aborts and awaits its tasks.
async fn crash<P: Simplex>(tap: &ReplicaTap<P>) -> bool {
    let Ok(_busy) = tap.busy.try_lock() else {
        return false;
    };
    let (app, engine) = {
        let mut incarnation = tap.incarnation.lock();
        if incarnation.respawn.is_none() {
            return false;
        }
        (incarnation.app.take(), incarnation.engine.take())
    };
    let crashed = engine.is_some();
    if crashed {
        tap.crashed_once.store(true, Ordering::Relaxed);
    }
    // Both tasks are aborted before either is awaited, so a caller dropped while
    // awaiting leaves no half of the replica running.
    let handles: Vec<_> = [engine, app].into_iter().flatten().collect();
    for handle in &handles {
        handle.abort();
    }
    for handle in handles {
        let _ = handle.await;
    }
    crashed
}

/// Restarts a crashed honest replica from its journal, on its partition, with its
/// retained reporter, behind its gate and recorders.
async fn restart<P: Simplex>(shared: &Shared<P>, tap: &Arc<ReplicaTap<P>>) -> bool {
    let Ok(_busy) = tap.busy.try_lock() else {
        return false;
    };
    if !tap.crashed() {
        return false;
    }
    let Some(key) = shared.key(tap.index) else {
        return false;
    };
    let mut oracle = shared.oracle.clone();
    let mut fresh = utils::register(&mut oracle, std::slice::from_ref(&key)).await;
    let Some(channels) = fresh.remove(&key) else {
        return false;
    };
    let Some(mut respawn) = tap.incarnation.lock().respawn.take() else {
        return false;
    };
    // The aborted application's relay registration is closed; the new one replaces it.
    if let Some(relay) = &shared.relay {
        relay.forget_closed(&key);
    }
    let (app, engine) = respawn(channels);
    let mut incarnation = tap.incarnation.lock();
    incarnation.app = Some(app);
    incarnation.engine = Some(engine);
    incarnation.respawn = Some(respawn);
    true
}

/// The restricted capabilities a [Prefix] drives the system with. Every capability
/// that changes the system ends at the handoff, while the reads keep answering, so a
/// filter sees the same context until the release: the runner then takes back the
/// compromised identity's channels and reverts what it can of the changes made through
/// this context.
pub struct PrefixContext<P: Simplex> {
    context: deterministic::Context,
    shared: Arc<Shared<P>>,
}

impl<P: Simplex> PrefixContext<P> {
    /// The participants, in index order.
    pub fn participants(&self) -> &[PublicKeyOf<P>] {
        &self.shared.participants
    }

    /// The compromised identity, `B`, if the base runs one.
    pub fn byzantine(&self) -> Option<usize> {
        self.shared.byzantine
    }

    /// The honest replicas, in index order.
    pub fn honest(&self) -> Vec<usize> {
        (0..self.shared.participants.len())
            .filter(|index| Some(*index) != self.shared.byzantine)
            .collect()
    }

    /// The term length the engines run.
    pub fn term_length(&self) -> TermLength {
        self.shared.term_length
    }

    /// The optimistic lookahead the engines run.
    pub fn optimistic_views(&self) -> ViewDelta {
        self.shared.optimistic_views
    }

    /// The last view of the base's scripted Twins prefix, 0 outside Twins.
    pub fn scripted_views(&self) -> u64 {
        self.shared.scripted_views
    }

    /// The epoch the honest engines run.
    pub fn epoch(&self) -> Epoch {
        self.shared.epoch
    }

    /// The leader of `view` under the honest engines' elector.
    pub fn leader(&self, view: View) -> usize {
        (self.shared.leader)(view)
    }

    /// Sleeps `duration` of simulated time, at least 1 ms and at most
    /// [MAX_PREFIX_BUDGET], so every sleep yields and the runner can end the prefix at
    /// its budget.
    pub async fn sleep(&self, duration: Duration) {
        self.context
            .sleep(duration.clamp(Duration::from_millis(1), MAX_PREFIX_BUDGET))
            .await;
    }

    /// The simulated time since the start of the run.
    pub fn now(&self) -> Duration {
        self.context.current().epoch()
    }

    /// The position a query takes now, for a witness that names a moment.
    pub fn stamp(&self) -> Stamp {
        Stamp::now(&*self.shared.observer)
    }

    /// B's signing scheme.
    pub fn scheme(&self) -> Option<&P::Scheme> {
        self.shared.scheme.as_ref()
    }

    /// Sends `message` as B on its own `channel` to the participants `recipients`;
    /// returns how many it went to. Nothing goes out after the handoff, over
    /// [MAX_MESSAGE], or past [MAX_SENT], where each message counts at least
    /// [MIN_CHARGE] bytes per recipient.
    pub fn send(&self, channel: Channel, recipients: &[usize], message: impl Into<IoBuf>) -> usize {
        if self.shared.revoked.load(Ordering::Relaxed) {
            return 0;
        }
        let message = message.into();
        if message.len() > MAX_MESSAGE as usize {
            return 0;
        }
        let keys: Vec<_> = recipients
            .iter()
            .filter_map(|index| self.shared.key(*index))
            .collect();
        let mut senders = self.shared.senders.lock();
        let Some((votes, certificates, resolver)) = senders.as_mut() else {
            return 0;
        };
        if !self.shared.charge(message.len(), keys.len()) {
            return 0;
        }
        let sender = match channel {
            Channel::Vote => votes,
            Channel::Certificate => certificates,
            Channel::Resolver => resolver,
        };
        commonware_p2p::Sender::send(sender, Recipients::Some(keys), message, true).len()
    }

    /// Everything B received so far, stamped.
    pub fn inbox(&self) -> Log<Recorded<Inbound>> {
        self.snapshot(&self.shared.inbox)
    }

    /// Whether B holds its marshal channels: only a marshal base hands them over.
    pub fn marshal_lanes(&self) -> bool {
        self.shared.lanes.load(Ordering::Relaxed)
    }

    /// Sends `message` as B on its own marshal `channel` to the participants
    /// `recipients`; returns how many it went to. Nothing goes out without B's marshal
    /// channels, after the handoff, over [MAX_MESSAGE], or past [MAX_SENT], where each
    /// message counts at least [MIN_CHARGE] bytes per recipient.
    pub fn send_marshal(
        &self,
        channel: MarshalChannel,
        recipients: &[usize],
        message: impl Into<IoBuf>,
    ) -> usize {
        if self.shared.revoked.load(Ordering::Relaxed) {
            return 0;
        }
        let message = message.into();
        if message.len() > MAX_MESSAGE as usize {
            return 0;
        }
        let keys: Vec<_> = recipients
            .iter()
            .filter_map(|index| self.shared.key(*index))
            .collect();
        let mut senders = self.shared.marshal_senders.lock();
        let Some((backfill, broadcast)) = senders.as_mut() else {
            return 0;
        };
        if !self.shared.charge(message.len(), keys.len()) {
            return 0;
        }
        let sender = match channel {
            MarshalChannel::Backfill => backfill,
            MarshalChannel::Broadcast => broadcast,
        };
        commonware_p2p::Sender::send(sender, Recipients::Some(keys), message, false).len()
    }

    /// Everything B received on its marshal channels so far, stamped. Without B's
    /// marshal channels the read is cut ([Observer::dropped]).
    pub fn marshal_inbox(&self) -> Log<Recorded<MarshalInbound>> {
        if !self.marshal_lanes() {
            self.cut();
        }
        self.snapshot(&self.shared.marshal_inbox)
    }

    /// A snapshot of `log`; reports the position of the first entry it dropped.
    fn snapshot<T>(&self, log: &Mutex<Log<T>>) -> Log<T> {
        let log = log.lock().clone();
        self.report(log.dropped());
        log
    }

    /// Reports a drop at `dropped`, if any, to the observer.
    fn report(&self, dropped: Option<u64>) {
        if let Some(seq) = dropped {
            self.shared.observer.dropped(seq);
        }
    }

    /// Reports a cut at this read, for a recorder or gate no wrapper of the base feeds:
    /// from here on what the prefix reads decides nothing.
    fn cut(&self) {
        let seq = self.stamp().seq();
        if seq != 0 {
            self.shared.observer.dropped(seq);
        }
    }

    /// A snapshot of the log of honest `replica`'s `recorder`; cut at this read when no
    /// wrapper of the base feeds it.
    fn recorded<T>(
        &self,
        replica: usize,
        recorder: Recorder,
        log: impl FnOnce(&ReplicaTap<P>) -> &Mutex<Log<T>>,
    ) -> Log<T> {
        let Some(tap) = self.shared.read(replica) else {
            return Log::default();
        };
        if !tap.fed(recorder) {
            self.cut();
        }
        self.snapshot(log(tap))
    }

    /// Builds a mock block for `round` on `parent` as B would, without sending it;
    /// returns its digest. B keeps at most [LOG_CAP] blocks: past that, the block is
    /// not kept and [Self::send_block] refuses it.
    pub fn block(&self, round: Round, parent: Sha256Digest) -> Sha256Digest {
        let nonce = self.shared.nonce.fetch_add(1, Ordering::Relaxed);
        let (digest, contents) = block_relay::mock_block(round, parent, nonce);
        let mut made = self.shared.made.lock();
        if made.len() < LOG_CAP {
            made.insert(digest, contents);
        }
        digest
    }

    /// Sends the block B built with [Self::block] to `recipients`, through the base's
    /// block relay; false for a block B did not build, and after the handoff.
    pub fn send_block(&self, digest: Sha256Digest, recipients: &[usize]) -> bool {
        if self.shared.revoked.load(Ordering::Relaxed) {
            return false;
        }
        let Some(relay) = &self.shared.relay else {
            return false;
        };
        let (Some(byzantine), Some(contents)) = (
            self.shared
                .byzantine
                .and_then(|index| self.shared.key(index)),
            self.shared.made.lock().get(&digest).cloned(),
        ) else {
            return false;
        };
        let keys: Vec<_> = recipients
            .iter()
            .filter_map(|index| self.shared.key(*index))
            .collect();
        relay.broadcast(&byzantine, Recipients::Some(keys), (digest, contents));
        true
    }

    /// Holds, from now on, every message to honest `replica` that `hold` accepts, until
    /// it is passed or the release; replaces an earlier filter. Past [LOG_CAP] held
    /// messages the gate drops what it would hold. `hold` may call the context.
    pub fn hold(&self, replica: usize, hold: impl Fn(&Inbound) -> bool + Send + Sync + 'static) {
        self.hold_in::<Channel>(replica, Arc::new(hold));
    }

    /// Delivers to honest `replica` the held messages `select` accepts, in arrival
    /// order; returns how many. `select` may call the context; while it runs,
    /// [Self::held] for `replica` is empty.
    pub fn pass(&self, replica: usize, select: impl Fn(&Inbound) -> bool) -> usize {
        self.pass_in::<Channel>(replica, select)
    }

    /// The messages held for honest `replica`, in arrival order.
    pub fn held(&self, replica: usize) -> Vec<Inbound> {
        self.held_in::<Channel>(replica)
    }

    /// Stops holding for honest `replica`, on its engine and marshal channels, and
    /// delivers what it holds.
    pub fn open(&self, replica: usize) -> usize {
        self.shared.tap(replica).map_or(0, |tap| tap.open())
    }

    /// [Self::hold] on honest `replica`'s marshal channels, which have their own gate,
    /// filter and cap. False, and holds nothing, when the base does not gate them, and
    /// after the handoff.
    pub fn hold_marshal(
        &self,
        replica: usize,
        hold: impl Fn(&MarshalInbound) -> bool + Send + Sync + 'static,
    ) -> bool {
        self.hold_in::<MarshalChannel>(replica, Arc::new(hold))
    }

    /// [Self::pass] on honest `replica`'s marshal gate.
    pub fn pass_marshal(&self, replica: usize, select: impl Fn(&MarshalInbound) -> bool) -> usize {
        self.pass_in::<MarshalChannel>(replica, select)
    }

    /// The messages held for honest `replica` on its marshal channels, in arrival
    /// order. Without a marshal gate the read is cut ([Observer::dropped]).
    pub fn held_marshal(&self, replica: usize) -> Vec<MarshalInbound> {
        self.held_in::<MarshalChannel>(replica)
    }

    fn hold_in<L: Lane>(&self, replica: usize, hold: HoldFilter<L>) -> bool {
        let Some(tap) = self.shared.tap(replica) else {
            return false;
        };
        if !tap.fed(L::RECORDER) {
            return false;
        }
        L::gate(tap).lock().hold = Some(hold);
        true
    }

    fn pass_in<L: Lane>(&self, replica: usize, select: impl Fn(&L::Inbound) -> bool) -> usize {
        let Some(tap) = self.shared.tap(replica) else {
            return 0;
        };
        let gate = L::gate(tap);
        // The selector runs with the gate unlocked; what is held meanwhile stays held.
        let held = std::mem::take(&mut gate.lock().held);
        let mut selected = held
            .iter()
            .map(|(lane, sender, payload)| {
                select(&lane.inbound(tap.position(sender), payload.clone()))
            })
            .collect::<Vec<_>>()
            .into_iter();
        let mut gate = gate.lock();
        let added = std::mem::replace(&mut gate.held, held);
        gate.held.extend(added);
        gate.pass(|_, _, _| selected.next().unwrap_or(false))
    }

    fn held_in<L: Lane>(&self, replica: usize) -> Vec<L::Inbound> {
        let Some(tap) = self.shared.read(replica) else {
            return Vec::new();
        };
        if !tap.fed(L::RECORDER) {
            self.cut();
            return Vec::new();
        }
        let (held, dropped) = {
            let gate = L::gate(tap).lock();
            let held = gate
                .held
                .iter()
                .map(|(lane, sender, payload)| lane.inbound(tap.position(sender), payload.clone()))
                .collect();
            (held, gate.dropped)
        };
        self.report(dropped);
        held
    }

    fn deliveries_in<L: Lane>(&self, replica: usize) -> Log<Recorded<L::Inbound>> {
        let Some(tap) = self.shared.read(replica) else {
            return Log::default();
        };
        if !tap.fed(L::RECORDER) {
            self.cut();
        } else {
            // What the full gate dropped never reaches the deliveries either.
            let dropped = L::gate(tap).lock().dropped;
            self.report(dropped);
        }
        self.snapshot(L::deliveries(tap))
    }

    /// Holds, from now on, every block to honest `replica` whose view and digest `hold`
    /// accepts, until passed or the release. Past [LOG_CAP] held blocks, for all
    /// replicas together, the gate drops what it would hold. `hold` may call the context;
    /// a block it sends is delivered without filtering. Holds nothing on a base without a
    /// block relay.
    pub fn hold_blocks(
        &self,
        replica: usize,
        hold: impl Fn(Option<View>, &Sha256Digest) -> bool + Send + Sync + 'static,
    ) {
        if self.shared.relay.is_some() && self.shared.tap(replica).is_some() {
            self.shared
                .block_gate
                .lock()
                .filters
                .insert(replica, Arc::new(hold));
        }
    }

    /// Delivers to honest `replica` the held blocks `select` accepts; returns how many its
    /// application took (none while it is crashed: the block is then lost, as on a link).
    /// `select` may call the context; while it runs, no block is held.
    pub fn pass_blocks(
        &self,
        replica: usize,
        select: impl Fn(Option<View>, &Sha256Digest) -> bool,
    ) -> usize {
        let Some(relay) = &self.shared.relay else {
            return 0;
        };
        let Some(key) = self.shared.tap(replica).and(self.shared.key(replica)) else {
            return 0;
        };
        // The selector runs with the gate unlocked; what is held meanwhile stays held.
        let held = std::mem::take(&mut self.shared.block_gate.lock().held);
        let (passed, kept): (Vec<_>, Vec<_>) =
            held.into_iter()
                .partition(|(_, _, recipient, payload, contents)| {
                    recipient == &key && select(block_relay::mock_block_view(contents), payload)
                });
        {
            let mut gate = self.shared.block_gate.lock();
            let added = std::mem::replace(&mut gate.held, kept);
            gate.held.extend(added);
        }
        passed
            .into_iter()
            .map(|(sender, tag, recipient, payload, contents)| {
                relay.redeliver(&sender, tag, recipient, (payload, contents))
            })
            .sum()
    }

    /// What honest `replica`'s engine received through its gate, stamped.
    pub fn deliveries(&self, replica: usize) -> Log<Recorded<Inbound>> {
        self.deliveries_in::<Channel>(replica)
    }

    /// What honest `replica`'s marshal received through its marshal gate, stamped.
    /// Without a marshal gate the read is cut ([Observer::dropped]).
    pub fn marshal_deliveries(&self, replica: usize) -> Log<Recorded<MarshalInbound>> {
        self.deliveries_in::<MarshalChannel>(replica)
    }

    /// What honest `replica`'s engine reported, stamped. A base that does not record
    /// it (coding marshal) cuts the read ([Observer::dropped]).
    pub fn activities(&self, replica: usize) -> Log<Recorded<ActivityOf<P>>> {
        self.recorded(replica, Recorder::Activities, |tap| &tap.activities)
    }

    /// What honest `replica`'s automaton was asked and answered, stamped. A base that
    /// does not record it (coding marshal) cuts the read ([Observer::dropped]).
    pub fn automaton(&self, replica: usize) -> Log<Recorded<AutomatonEvent>> {
        self.recorded(replica, Recorder::Automaton, |tap| &tap.automaton)
    }

    /// Every election honest `replica`'s voter ran, by view, stamped. The voter
    /// also elects the next term's leader ahead of entering it, so a view can
    /// appear early and more than once.
    pub fn elections(&self, replica: usize) -> Log<Recorded<(View, usize)>> {
        self.recorded(replica, Recorder::Elections, |tap| &tap.elections)
    }

    /// The peers honest `replica` blocked, stamped. A base that does not record every
    /// blocker of the replica (marshal Twins) cuts the read ([Observer::dropped]):
    /// [Self::blocked] answers there.
    pub fn blocks(&self, replica: usize) -> Log<Recorded<usize>> {
        self.recorded(replica, Recorder::Blocks, |tap| &tap.blocks)
    }

    /// The digest of the block honest `replica`'s marshal finalized at `height`, as
    /// marshal answers (`Some(None)`: none). `None` when the base has no marshal reads,
    /// when the request could not reach the replica's marshal (after a 1 ms sleep), or
    /// when marshal did not answer within [MARSHAL_READ_TIMEOUT]. Changes nothing.
    pub async fn finalized_block(
        &self,
        replica: usize,
        height: u64,
    ) -> Option<Option<Sha256Digest>> {
        let read = self
            .shared
            .read(replica)
            .and_then(|tap| tap.reads())
            .map(|reads| reads.finalized(height));
        self.bounded(read).await
    }

    /// The height of the last block honest `replica`'s application acknowledged to its
    /// marshal, as marshal answers; `None` as for [Self::finalized_block].
    pub async fn processed_height(&self, replica: usize) -> Option<Option<u64>> {
        let read = self
            .shared
            .read(replica)
            .and_then(|tap| tap.reads())
            .map(|reads| reads.processed());
        self.bounded(read).await
    }

    /// Waits for `read`'s answer, at most [MARSHAL_READ_TIMEOUT]. A read ready at its
    /// first poll never reached a live actor, which answers from its own task, so it is
    /// no answer; it and a missing read sleep [NO_ANSWER], so a loop of reads advances
    /// time. A read dropped before its answer leaves a closed responder behind.
    async fn bounded<T>(
        &self,
        read: Option<Pin<Box<dyn Future<Output = Option<T>> + Send>>>,
    ) -> Option<Option<T>> {
        let Some(mut read) = read else {
            self.context.sleep(NO_ANSWER).await;
            return None;
        };
        if poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_ready())).await {
            self.context.sleep(NO_ANSWER).await;
            return None;
        }
        select! {
            answer = read => Some(answer),
            _ = self.context.sleep(MARSHAL_READ_TIMEOUT) => None,
        }
    }

    /// The network's blocked pairs, (blocker, blocked), now.
    pub async fn blocked(&self) -> Vec<(usize, usize)> {
        if self.shared.revoked.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let pairs = self.shared.oracle.blocked().await.unwrap_or_default();
        pairs
            .into_iter()
            .filter_map(|(blocker, blocked)| {
                let index = |key| self.shared.participants.iter().position(|k| k == &key);
                Some((index(blocker)?, index(blocked)?))
            })
            .collect()
    }

    /// Sets the directed link `from` -> `to`, or removes it with `None`, until the
    /// release, which restores the base's. False for a self link, an unknown index and
    /// after the handoff; a refusal costs [NO_ANSWER], so a loop of them advances time.
    pub async fn set_link(&self, from: usize, to: usize, link: Option<Link>) -> bool {
        let keys = match (self.shared.key(from), self.shared.key(to)) {
            (Some(sender), Some(receiver))
                if from != to && !self.shared.revoked.load(Ordering::Relaxed) =>
            {
                Some((sender, receiver))
            }
            _ => None,
        };
        let Some((sender, receiver)) = keys else {
            self.context.sleep(NO_ANSWER).await;
            return false;
        };
        self.shared.links.lock().insert((from, to));
        self.shared
            .oracle
            .remove_link(sender.clone(), receiver.clone())
            .await
            .ok();
        match link {
            Some(link) => self
                .shared
                .oracle
                .add_link(sender, receiver, link)
                .await
                .is_ok(),
            None => true,
        }
    }

    /// Overrides honest `replica`'s application latencies until the release; `None`
    /// restores the base's. A request already sleeping keeps the latency it drew. False
    /// on a base without a block relay.
    pub fn set_latency(&self, replica: usize, latencies: Option<Latencies>) -> bool {
        let Some(relay) = &self.shared.relay else {
            return false;
        };
        let Some(key) = self.shared.tap(replica).and(self.shared.key(replica)) else {
            return false;
        };
        relay.set_latency(&key, latencies);
        self.shared.latencies.lock().insert(replica);
        true
    }

    /// Crash-stops honest `replica`: its engine and application tasks are aborted and
    /// awaited. The release restarts it if the prefix did not. False if it is crashed,
    /// while another crash or restart of it runs, and on a base whose replicas cannot
    /// restart (marshal); a refusal costs [NO_ANSWER], so a loop of them advances time.
    pub async fn crash(&self, replica: usize) -> bool {
        let crashed = match self.shared.tap(replica) {
            Some(tap) => crash(tap).await,
            None => false,
        };
        if !crashed {
            self.context.sleep(NO_ANSWER).await;
        }
        crashed
    }

    /// Restarts crashed honest `replica` from its journal, on its partition, with its
    /// retained reporter. False if it is not crashed, or while another crash or restart
    /// of it runs; a refusal costs [NO_ANSWER], so a loop of them advances time.
    pub async fn restart(&self, replica: usize) -> bool {
        let restarted = match self.shared.tap(replica).cloned() {
            Some(tap) => restart(&self.shared, &tap).await,
            None => false,
        };
        if !restarted {
            self.context.sleep(NO_ANSWER).await;
        }
        restarted
    }

    /// Whether honest `replica` is crashed.
    pub fn crashed(&self, replica: usize) -> bool {
        self.shared.read(replica).is_some_and(|tap| tap.crashed())
    }
}

/// The link [crate::setup_network] gives the directed edge `from` -> `to` of a
/// Standard run over `n` participants, `None` where a static partition cuts it.
pub fn standard_link(input: &FuzzInput, n: usize, from: usize, to: usize) -> Option<Link> {
    if let Some(partition) = input.partition.set_partition()
        && !partition.connected(from, to)
    {
        return None;
    }
    let last = n.checked_sub(1);
    if input.partition.is_connected()
        && input.configuration == N4F1C3
        && input.degraded_network
        && (Some(from) == last || Some(to) == last)
    {
        return Some(crate::degraded_link());
    }
    Some(crate::default_link())
}

/// Starts the base's Disrupter for a compromised identity at a continuation's
/// release, signing in `epoch`, with its sampled faulty views moved `view_offset` views
/// later; returns its task. `marker` is set when the Disrupter's task first polls its
/// vote receiver.
#[allow(clippy::too_many_arguments)]
pub fn start_disrupter<P: Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    strategy: &crate::strategy::StrategyChoice,
    required_containers: u64,
    channels: NetworkChannels<PublicKeyOf<P>>,
    relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
    view_offset: u64,
    marker: Marker,
    epoch: Epoch,
) -> Handle<()> {
    let ((vote_sender, vote_receiver), certificate, resolver) = channels;
    let vote = (
        vote_sender,
        MarkedReceiver::new(vote_receiver, Some(marker)),
    );
    crate::start_disrupter_with_epoch_relay_and_tag::<P>(
        context,
        scheme,
        strategy,
        required_containers,
        epoch,
        vote,
        certificate,
        resolver,
        relay,
        None,
        view_offset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EPOCH;
    use commonware_runtime::Runner as _;

    /// An observer that stamps nothing: positions are 0.
    struct Unobserved;

    impl Observer for Unobserved {
        fn position(&self) -> (u64, u32) {
            (0, 0)
        }

        fn compromised(&self, _identities: &[usize]) {}

        fn actors(&self, _check: &ActorCheck) {}
    }

    /// A [Prefix] that does nothing.
    struct NoPrefix;

    impl<P: Simplex> Prefix<P> for NoPrefix {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            Budget::default()
        }

        fn run(self: Box<Self>, _cx: PrefixContext<P>) -> PrefixFuture {
            Box::pin(async {})
        }
    }

    #[test]
    fn registry_reports_running_unpolled_finished_and_absent_actors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let registry = ActorRegistry::default();
            // An actor whose task polls the receiver it was started with.
            let marker = registry.marker(0, Role::Primary);
            let (_sender, receiver) = mpsc::unbounded_channel::<()>();
            let running = context.child("running").spawn(move |_| async move {
                let mut receiver = MarkedReceiver::new(Receiving(receiver), Some(marker));
                let _ = commonware_p2p::Receiver::recv(&mut receiver).await;
            });
            // A task that has not run: it waits before it touches its receiver.
            let idle_marker = registry.marker(0, Role::Disrupter);
            let (_idle_sender, idle_receiver) = mpsc::unbounded_channel::<()>();
            let idle = context.child("idle").spawn(move |context| async move {
                context.sleep(Duration::from_secs(3600)).await;
                let mut receiver = MarkedReceiver::new(Receiving(idle_receiver), Some(idle_marker));
                let _ = commonware_p2p::Receiver::recv(&mut receiver).await;
            });
            let finished = context.child("finished").spawn(|_| async move {});
            registry.register(0, Role::Primary, running);
            registry.register(0, Role::Disrupter, idle);
            registry.register(0, Role::Secondary, finished);
            // Tasks woken in one round of the executor run in a shuffled order: two rounds
            // let every ready task run.
            context.sleep(Duration::from_millis(1)).await;
            context.sleep(Duration::from_millis(1)).await;
            let check = registry.check(
                "release",
                &[
                    (0, Role::Primary),
                    (0, Role::Secondary),
                    (0, Role::Disrupter),
                    (1, Role::Primary),
                ],
            );
            assert!(!check.ok());
            assert_eq!(
                check
                    .actors
                    .iter()
                    .map(|actor| actor.state)
                    .collect::<Vec<_>>(),
                vec![
                    ActorState::Running,
                    ActorState::Finished,
                    ActorState::Unpolled,
                    ActorState::Absent
                ]
            );
            assert_eq!(
                check.to_string(),
                "release failed 0:primary=running 0:secondary=finished 0:disrupter=unpolled \
                 1:primary=absent"
            );
            let only = registry.check("end", &[(0, Role::Primary)]);
            assert!(only.ok());
            assert_eq!(only.to_string(), "end ok 0:primary=running");
            assert_eq!(registry.check("end", &[]).to_string(), "end ok -");
        });
    }

    #[test]
    fn a_failed_base_check_fails_the_actor_check() {
        let running = ActorStatus {
            identity: 0,
            role: Role::Disrupter,
            state: ActorState::Running,
        };
        for (actors, line) in [
            (Vec::new(), "end failed - base=omission-incomplete"),
            (
                vec![running],
                "end failed 0:disrupter=running base=omission-incomplete",
            ),
        ] {
            let mut check = ActorCheck {
                at: "end",
                actors,
                base: None,
            };
            assert!(check.ok());
            check.base = Some("omission-incomplete");
            assert!(!check.ok());
            assert_eq!(check.to_string(), line);
        }
    }

    /// A receiver over a channel, for the marker test.
    #[derive(Debug)]
    struct Receiving(mpsc::UnboundedReceiver<()>);

    #[derive(Debug)]
    struct Closed;

    impl fmt::Display for Closed {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "closed")
        }
    }

    impl std::error::Error for Closed {}

    impl commonware_p2p::Receiver for Receiving {
        type Error = Closed;
        type PublicKey = commonware_cryptography::ed25519::PublicKey;

        async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Closed> {
            self.0.recv().await;
            Err(Closed)
        }
    }

    /// An automaton whose answers never come: a request stays open until it is dropped.
    #[derive(Clone)]
    struct Silent {
        open: Arc<Mutex<Vec<oneshot::Sender<bool>>>>,
        prepares: Arc<Mutex<Vec<oneshot::Sender<Handoff<Sha256Digest>>>>>,
    }

    impl Automaton for Silent {
        type Context = SimplexContext<Sha256Digest, PublicKeyOf<crate::SimplexCertificateMock>>;
        type Digest = Sha256Digest;

        async fn propose(&mut self, _context: Self::Context) -> oneshot::Receiver<Sha256Digest> {
            oneshot::channel().1
        }

        async fn verify(
            &mut self,
            _context: Self::Context,
            _payload: Sha256Digest,
        ) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            self.open.lock().push(sender);
            receiver
        }
    }

    impl CertifiableAutomaton for Silent {
        async fn prepare(
            &mut self,
            _context: Self::Context,
        ) -> oneshot::Receiver<Handoff<Sha256Digest>> {
            let (sender, receiver) = oneshot::channel();
            self.prepares.lock().push(sender);
            receiver
        }
    }

    #[test]
    fn the_automaton_recorder_passes_a_cancellation_on() {
        type P = crate::SimplexCertificateMock;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let (participants, _schemes) = <P as Simplex>::setup(&mut context, crate::NAMESPACE, 4);
            let observer: Arc<dyn Observer> = Arc::new(Unobserved);
            let tap = Arc::new(ReplicaTap::<P>::new(
                1,
                participants.clone().into(),
                observer,
                Arc::new(AtomicBool::new(true)),
            ));
            let silent = Silent {
                open: Arc::new(Mutex::new(Vec::new())),
                prepares: Arc::new(Mutex::new(Vec::new())),
            };
            let mut automaton = tap_automaton(Some(&tap), silent.clone(), &context);
            let round = Round::new(Epoch::new(EPOCH), View::new(1));
            let request = SimplexContext {
                round,
                leader: participants[0].clone(),
                parent: (View::zero(), Sha256Digest([0; 32])),
            };
            let payload = Sha256Digest([1; 32]);
            let receiver = automaton.verify(request, payload).await;
            context.sleep(Duration::from_millis(1)).await;
            // Consensus abandons the request: the automaton's channel closes too.
            drop(receiver);
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                silent.open.lock().iter().all(oneshot::Sender::is_closed),
                "the recorder kept the automaton's request open"
            );
            let events: Vec<_> = tap
                .automaton
                .lock()
                .iter()
                .map(|entry| entry.value.clone())
                .collect();
            assert_eq!(
                events.last(),
                Some(&AutomatonEvent::Verified {
                    round,
                    payload,
                    valid: Completion::Canceled,
                })
            );
        });
    }

    #[test]
    fn the_automaton_recorder_passes_a_prepare_cancellation_on() {
        type P = crate::SimplexCertificateMock;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let (participants, _schemes) = <P as Simplex>::setup(&mut context, crate::NAMESPACE, 4);
            let observer: Arc<dyn Observer> = Arc::new(Unobserved);
            let tap = Arc::new(ReplicaTap::<P>::new(
                1,
                participants.clone().into(),
                observer,
                Arc::new(AtomicBool::new(true)),
            ));
            let silent = Silent {
                open: Arc::new(Mutex::new(Vec::new())),
                prepares: Arc::new(Mutex::new(Vec::new())),
            };
            let mut automaton = tap_automaton(Some(&tap), silent.clone(), &context);
            let round = Round::new(Epoch::new(EPOCH), View::new(1));
            let request = SimplexContext {
                round,
                leader: participants[0].clone(),
                parent: (View::zero(), Sha256Digest([0; 32])),
            };
            let receiver = automaton.prepare(request).await;
            context.sleep(Duration::from_millis(1)).await;
            // Consensus abandons the request: the automaton's channel closes too.
            drop(receiver);
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                silent
                    .prepares
                    .lock()
                    .iter()
                    .all(oneshot::Sender::is_closed),
                "the recorder kept the automaton's request open"
            );
            let events: Vec<_> = tap
                .automaton
                .lock()
                .iter()
                .map(|entry| entry.value.clone())
                .collect();
            assert_eq!(
                events.last(),
                Some(&AutomatonEvent::Prepared {
                    round,
                    decision: Completion::Canceled,
                })
            );
        });
    }

    fn test_input() -> FuzzInput {
        FuzzInput {
            raw_bytes: vec![1, 2, 3],
            required_containers: 3,
            term_length: TermLength::new(commonware_utils::NZU32!(5)),
            optimistic_views: ViewDelta::new(7),
            heterogeneous_optimism: false,
            handoff: Handoff::Wait,
            degraded_network: false,
            configuration: N4F0C4,
            partition: crate::utils::Partition::Connected,
            strategy: crate::strategy::StrategyChoice::AnyScope,
            mailbox_size: crate::DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardPolicy::Disabled,
            certify: CertifyChoice::SingleCancel { target_idx: 1 },
            block_filter: crate::BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    #[test]
    fn runner_reports_a_missing_actor_and_returns_the_channels() {
        type P = crate::SimplexCertificateMock;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut input = test_input();
            input.configuration = N4F1C3;
            input.certify = CertifyChoice::Always;
            let (oracle, participants, schemes, mut registrations) =
                crate::setup_network::<P>(&mut context, &input).await;
            let relay = Arc::new(block_relay::Relay::new());
            let hook = Hook::<P>::plan(Box::new(NoPrefix), Arc::new(Unobserved), &mut input, false);
            let links = input.clone();
            let mut runner = Runner::start(
                hook,
                &context,
                Topology {
                    participants: participants.clone(),
                    schemes: schemes.clone(),
                    byzantine: Some(0),
                    required: vec![Role::Disrupter],
                    term_length: TermLength::ONE,
                    optimistic_views: ViewDelta::zero(),
                    scripted_views: 0,
                    epoch: Epoch::new(EPOCH),
                    relay: Some(relay.clone()),
                    oracle,
                    base_link: Box::new(move |from, to| standard_link(&links, 4, from, to)),
                },
                <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero()),
            );
            assert!(runner.tap(0).is_none(), "B has no tap");
            assert!(runner.tap(1).is_some());
            runner.adopt(
                registrations
                    .remove(&participants[0])
                    .expect("B is registered"),
            );
            let (channels, release) = runner.run().await;
            assert_eq!(release, Release::default());
            // Nothing started for B: the check fails.
            let check = runner.check_release().await;
            assert!(!check.ok());
            assert_eq!(check.to_string(), "release failed 0:disrupter=absent");
            let registry = runner.registry();
            let handle = start_disrupter::<P>(
                context.child("disrupter"),
                schemes[0].clone(),
                &crate::strategy::StrategyChoice::AnyScope,
                1,
                channels.expect("the release returns B's channels"),
                Some(relay),
                0,
                registry.marker(0, Role::Disrupter),
                Epoch::new(EPOCH),
            );
            registry.register(0, Role::Disrupter, handle);
            // Checked at once, the Disrupter has not run yet; the release check waits for it.
            assert_eq!(
                runner.check("early").to_string(),
                "early failed 0:disrupter=unpolled"
            );
            assert_eq!(
                runner.check_release().await.to_string(),
                "release ok 0:disrupter=running"
            );
        });
    }

    #[test]
    fn pins_keep_dependent_fields_as_the_decoder_sets_them() {
        let mut input = FuzzInput {
            raw_bytes: vec![1, 2, 3],
            required_containers: 3,
            term_length: TermLength::new(commonware_utils::NZU32!(5)),
            optimistic_views: ViewDelta::new(7),
            heterogeneous_optimism: false,
            handoff: Handoff::Wait,
            degraded_network: false,
            configuration: N4F0C4,
            partition: crate::utils::Partition::Connected,
            strategy: crate::strategy::StrategyChoice::AnyScope,
            mailbox_size: crate::DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardPolicy::Disabled,
            certify: CertifyChoice::SingleCancel { target_idx: 1 },
            block_filter: crate::BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        };
        let mut pins = Pins::new(&mut input, Domain::Simplex);
        pins.term_length(TermLength::ONE);
        assert_eq!(pins.input().optimistic_views, ViewDelta::new(3));
        assert!(!pins.lookahead(ViewDelta::new(4)));
        assert!(pins.lookahead(ViewDelta::zero()));
        assert!(pins.configuration(N4F1C3));
        assert_eq!(pins.input().certify, CertifyChoice::Always);
        assert!(!pins.configuration(crate::N4F3C1));
        let mut twins = Pins::new(&mut input, Domain::Twins);
        assert!(!twins.configuration(N4F0C4));
        assert_eq!(input.configuration, N4F1C3);
    }

    #[test]
    fn a_log_snapshot_shares_the_log_until_the_next_record_and_the_log_stops_at_its_cap() {
        let mut log = Log::<u64>::default();
        log.push(1, 1);
        let snapshot = log.clone();
        assert!(
            Arc::ptr_eq(&snapshot.entries, &log.entries),
            "taking a snapshot copied"
        );
        let again = log.clone();
        assert!(Arc::ptr_eq(&again.entries, &log.entries));
        drop(again);
        // Appending while a snapshot is alive leaves the snapshot as it was.
        log.push(2, 2);
        assert_eq!(&*snapshot, &[1]);
        assert_eq!(&*log, &[1, 2]);
        drop(snapshot);
        for value in 2..LOG_CAP as u64 {
            log.push(value, value);
        }
        assert_eq!(log.len(), LOG_CAP);
        assert_eq!(log.dropped(), None);
        // An entry recorded while nothing watched has no position to report.
        log.push(0, 0);
        assert_eq!(log.dropped(), None);
        let first = LOG_CAP as u64 + 5;
        log.push(0, first);
        log.push(0, first + 1);
        assert_eq!(log.len(), LOG_CAP, "a full log drops the entry");
        assert_eq!(
            log.dropped(),
            Some(first),
            "the first drop's position is kept"
        );
        assert_eq!(log.clone().dropped(), Some(first), "a snapshot carries it");
    }

    #[test]
    fn a_full_gate_drops_what_it_would_hold() {
        type P = crate::SimplexCertificateMock;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let input = test_input();
            let (_oracle, participants, _schemes, _registrations) =
                crate::setup_network::<P>(&mut context, &input).await;
            /// Hands out positions 1, 2, ...
            struct Count(AtomicU64);

            impl Observer for Count {
                fn position(&self) -> (u64, u32) {
                    (self.0.fetch_add(1, Ordering::Relaxed) + 1, 1)
                }

                fn compromised(&self, _identities: &[usize]) {}

                fn actors(&self, _check: &ActorCheck) {}
            }

            let tap = ReplicaTap::<P>::new(
                1,
                participants.clone().into(),
                Arc::new(Count(AtomicU64::new(0))),
                Arc::new(AtomicBool::new(true)),
            );
            tap.gate.lock().hold = Some(Arc::new(|_| true));
            let payload = IoBuf::from(vec![0u8; 8]);
            for _ in 0..LOG_CAP + 10 {
                assert!(tap.hold(Channel::Vote, &participants[2], &payload));
            }
            assert_eq!(tap.gate.lock().held.len(), LOG_CAP);
            // Holding takes no position; the first drop takes position 1.
            assert_eq!(tap.gate.lock().dropped, Some(1));
            assert_eq!(tap.open(), LOG_CAP);
        });
    }

    type P = crate::SimplexCertificateMock;
    type Key = PublicKeyOf<P>;
    type SchemeOf = <P as Simplex>::Scheme;
    type ElectorOf = <<P as Simplex>::Elector as ElectorConfig<SchemeOf>>::Elector;

    /// Long enough for every task a pass woke to run: tasks woken in one round of the
    /// executor run in a shuffled order.
    const SETTLE: Duration = Duration::from_millis(10);

    /// Hands out positions 1, 2, ... and keeps the drops and releases it hears of.
    #[derive(Clone, Default)]
    struct Watch {
        position: Arc<AtomicU64>,
        dropped: Arc<Mutex<Vec<u64>>>,
        releases: Arc<Mutex<Vec<Release>>>,
    }

    impl Observer for Watch {
        fn position(&self) -> (u64, u32) {
            (self.position.fetch_add(1, Ordering::Relaxed) + 1, 1)
        }

        fn compromised(&self, _identities: &[usize]) {}

        fn actors(&self, _check: &ActorCheck) {}

        fn released(&self, release: &Release) {
            self.releases.lock().push(release.clone());
        }

        fn dropped(&self, seq: u64) {
            self.dropped.lock().push(seq);
        }
    }

    /// A prefix that asks for its budget and runs its closure.
    struct Script<F>(Budget, F);

    impl<F> Prefix<P> for Script<F>
    where
        F: FnOnce(PrefixContext<P>) -> PrefixFuture + Send + 'static,
    {
        fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
            self.0
        }

        fn run(self: Box<Self>, cx: PrefixContext<P>) -> PrefixFuture {
            (self.1)(cx)
        }
    }

    fn script<F>(prefix: Duration, run: F) -> Script<F>
    where
        F: FnOnce(PrefixContext<P>) -> PrefixFuture + Send + 'static,
    {
        Script(
            Budget {
                prefix,
                release: Duration::from_millis(500),
            },
            run,
        )
    }

    const QUOTA: commonware_runtime::Quota =
        commonware_runtime::Quota::per_second(std::num::NonZeroU32::MAX);

    /// A connected N4F1C3 network whose participants also hold two marshal channels.
    struct Net {
        oracle: commonware_p2p::simulated::Oracle<Key, deterministic::Context>,
        participants: Vec<Key>,
        schemes: Vec<SchemeOf>,
        engine: std::collections::HashMap<Key, NetworkChannels<Key>>,
        marshal: std::collections::HashMap<Key, MarshalChannels<Key>>,
    }

    impl Net {
        async fn new(context: &mut deterministic::Context) -> Self {
            let mut input = test_input();
            input.configuration = N4F1C3;
            input.certify = CertifyChoice::Always;
            let (oracle, participants, schemes, engine) =
                crate::setup_network::<P>(context, &input).await;
            let mut marshal = std::collections::HashMap::new();
            for key in &participants {
                let control = oracle.control(key.clone());
                let backfill = control.register(3, QUOTA).await.unwrap();
                let broadcast = control.register(4, QUOTA).await.unwrap();
                marshal.insert(key.clone(), (backfill, broadcast));
            }
            Self {
                oracle,
                participants,
                schemes,
                engine,
                marshal,
            }
        }

        fn engine(&mut self, index: usize) -> NetworkChannels<Key> {
            self.engine.remove(&self.participants[index]).unwrap()
        }

        fn marshal(&mut self, index: usize) -> MarshalChannels<Key> {
            self.marshal.remove(&self.participants[index]).unwrap()
        }

        /// A runner over the network with B = 0, no block relay, and `prefix`.
        fn runner(
            &self,
            context: &deterministic::Context,
            watch: &Watch,
            epoch: Epoch,
            prefix: impl Prefix<P>,
        ) -> Runner<P> {
            let mut input = test_input();
            let hook = Hook::plan(Box::new(prefix), Arc::new(watch.clone()), &mut input, false);
            Runner::start(
                hook,
                context,
                Topology {
                    participants: self.participants.clone(),
                    schemes: self.schemes.clone(),
                    byzantine: Some(0),
                    required: Vec::new(),
                    term_length: TermLength::ONE,
                    optimistic_views: ViewDelta::zero(),
                    scripted_views: 0,
                    epoch,
                    relay: None,
                    oracle: self.oracle.clone(),
                    base_link: Box::new(|_, _| Some(crate::default_link())),
                },
                <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero()),
            )
        }
    }

    /// The first payload byte each honest replica's gated receivers delivered.
    type Got = Arc<Mutex<Vec<(usize, u8)>>>;

    /// Runs `receiver` as an honest replica's engine or marshal would, into `got`.
    fn drain<R>(context: &deterministic::Context, replica: usize, mut receiver: R, got: &Got)
    where
        R: commonware_p2p::Receiver<PublicKey = Key> + Send + 'static,
    {
        let got = got.clone();
        context.child("drain").spawn(move |_| async move {
            while let Ok((_, payload)) = receiver.recv().await {
                got.lock()
                    .push((replica, payload.as_ref().first().copied().unwrap_or(0)));
            }
        });
    }

    fn got(got: &Got) -> Vec<u8> {
        let mut bytes: Vec<_> = got.lock().iter().map(|(_, byte)| *byte).collect();
        bytes.sort_unstable();
        bytes
    }

    /// Holds a clone of the prefix's context past the handoff.
    type Leak = Arc<Mutex<Option<PrefixContext<P>>>>;

    impl Clone for PrefixContext<P> {
        fn clone(&self) -> Self {
            Self {
                context: self.context.child("leaked"),
                shared: self.shared.clone(),
            }
        }
    }

    #[test]
    fn runner_without_a_block_relay_reverts_links_and_gates() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let delivered: Got = Arc::default();
            let prefix = script(Duration::from_secs(10), |cx| {
                Box::pin(async move {
                    // The block, latency and crash capabilities are inert on a base
                    // without a block relay and without restartable replicas.
                    let round = Round::new(cx.epoch(), View::new(1));
                    let digest = cx.block(round, Sha256Digest([0; 32]));
                    assert!(!cx.send_block(digest, &[1]));
                    cx.hold_blocks(1, |_, _| true);
                    assert_eq!(cx.pass_blocks(1, |_, _| true), 0);
                    let slow = (2_000.0, 0.0);
                    assert!(!cx.set_latency(
                        1,
                        Some(Latencies {
                            propose: slow,
                            verify: slow,
                            certify: slow,
                        })
                    ));
                    assert!(!cx.crash(1).await);
                    assert!(!cx.crashed(1));
                    assert!(cx.set_link(2, 3, None).await);
                    cx.hold(1, |_| true);
                    assert!(cx.hold_marshal(1, |_| true));
                    assert_eq!(cx.send(Channel::Vote, &[1], vec![7u8]), 1);
                    assert_eq!(
                        cx.send_marshal(MarshalChannel::Backfill, &[1], vec![8u8]),
                        1
                    );
                    cx.sleep(Duration::from_secs(1)).await;
                    assert_eq!(cx.held(1).len(), 1);
                    assert_eq!(cx.held_marshal(1).len(), 1);
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let tap = runner.tap(1);
            let ((_, vote), _, _) = net.engine(1);
            let ((_, backfill), _) = net.marshal(1);
            drain(
                &context,
                1,
                gate(tap.as_ref(), vote, Channel::Vote),
                &delivered,
            );
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), backfill, MarshalChannel::Backfill),
                &delivered,
            );
            runner.adopt(net.engine(0));
            runner.adopt_marshal(net.marshal(0));
            let (channels, release) = runner.run().await;
            assert!(channels.is_some());
            assert!(runner.marshal_channels().is_some());
            assert!(!release.overran);
            assert_eq!(release.gates, vec![1]);
            assert_eq!(release.delivered, 2);
            assert_eq!(release.links, vec![(2, 3)]);
            assert!(release.latencies.is_empty());
            assert!(release.restarted.is_empty());
            assert_eq!(release.blocks, 0);
            assert_eq!(watch.releases.lock().as_slice(), &[release]);
            context.sleep(Duration::from_secs(1)).await;
            assert_eq!(got(&delivered), vec![7, 8]);
            // The cut link is back: 2 reaches 3.
            let (_, (mut sender, _)) = net.marshal(2);
            let (_, (_, mut receiver)) = net.marshal(3);
            commonware_p2p::Sender::send(
                &mut sender,
                Recipients::Some(vec![net.participants[3].clone()]),
                IoBuf::from(vec![9u8]),
                false,
            );
            select! {
                message = receiver.recv() => assert_eq!(message.unwrap().1.as_ref(), &[9]),
                _ = context.sleep(Duration::from_secs(1)) => panic!("the link was not restored"),
            }
        });
    }

    #[test]
    fn the_leader_follows_the_topology_epoch() {
        let mut leaders = Vec::new();
        for epoch in [Epoch::zero(), Epoch::new(EPOCH)] {
            let seen = deterministic::Runner::default().start(|mut context| async move {
                let net = Net::new(&mut context).await;
                let set: Set<Key> = net.participants.as_slice().try_into().unwrap();
                let elector: ElectorOf =
                    <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero()).build(&set);
                let expected: Vec<usize> = (1..=8)
                    .map(|view| {
                        elector.elect(Round::new(epoch, View::new(view)), ()).get() as usize
                    })
                    .collect();
                let seen = Arc::new(Mutex::new(Vec::new()));
                let record = seen.clone();
                let prefix = script(Duration::from_secs(1), move |cx| {
                    Box::pin(async move {
                        assert_eq!(cx.epoch(), epoch);
                        *record.lock() = (1..=8).map(|view| cx.leader(View::new(view))).collect();
                    })
                });
                let mut runner = net.runner(&context, &Watch::default(), epoch, prefix);
                runner.run().await;
                let seen = seen.lock().clone();
                assert_eq!(seen, expected);
                seen
            });
            leaders.push(seen);
        }
        assert_ne!(leaders[0], leaders[1], "the epoch moves the rotation");
    }

    #[test]
    fn marshal_lanes_hold_pass_and_open() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let delivered: Got = Arc::default();
            let seen = delivered.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    assert!(cx.marshal_lanes());
                    assert!(cx.hold_marshal(1, |message| {
                        message.channel == MarshalChannel::Backfill
                    }));
                    cx.send_marshal(MarshalChannel::Backfill, &[1], vec![1u8]);
                    cx.send_marshal(MarshalChannel::Broadcast, &[1], vec![2u8]);
                    cx.sleep(Duration::from_secs(1)).await;
                    assert_eq!(got(&seen), vec![2]);
                    let held = cx.held_marshal(1);
                    assert_eq!(held.len(), 1);
                    assert_eq!(held[0].from, Some(0));
                    assert_eq!(held[0].channel, MarshalChannel::Backfill);
                    assert_eq!(held[0].payload.as_ref(), &[1]);
                    let deliveries = cx.marshal_deliveries(1);
                    assert_eq!(deliveries.len(), 1);
                    assert_eq!(deliveries[0].value.channel, MarshalChannel::Broadcast);
                    assert_eq!(
                        cx.pass_marshal(1, |message| message.payload.as_ref() == [1]),
                        1
                    );
                    cx.sleep(SETTLE).await;
                    assert_eq!(got(&seen), vec![1, 2]);
                    assert_eq!(cx.marshal_deliveries(1).len(), 2);
                    // Opened, the gate delivers what it held and holds nothing more.
                    cx.send_marshal(MarshalChannel::Backfill, &[1], vec![3u8]);
                    cx.sleep(Duration::from_secs(1)).await;
                    assert_eq!(cx.held_marshal(1).len(), 1);
                    assert_eq!(cx.open(1), 1);
                    cx.send_marshal(MarshalChannel::Backfill, &[1], vec![4u8]);
                    cx.sleep(Duration::from_secs(1)).await;
                    assert_eq!(got(&seen), vec![1, 2, 3, 4]);
                    assert!(cx.held_marshal(1).is_empty());
                    // Held again until the release opens the gate.
                    assert!(cx.hold_marshal(1, |_| true));
                    cx.send_marshal(MarshalChannel::Broadcast, &[1], vec![5u8]);
                    cx.sleep(Duration::from_secs(1)).await;
                    assert_eq!(cx.held_marshal(1).len(), 1);
                })
            });
            let watch = Watch::default();
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let tap = runner.tap(1);
            let ((_, backfill), (_, broadcast)) = net.marshal(1);
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), backfill, MarshalChannel::Backfill),
                &delivered,
            );
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), broadcast, MarshalChannel::Broadcast),
                &delivered,
            );
            runner.adopt_marshal(net.marshal(0));
            let (_, release) = runner.run().await;
            assert_eq!(release.gates, vec![1]);
            assert_eq!(release.delivered, 1);
            context.sleep(SETTLE).await;
            assert_eq!(got(&delivered), vec![1, 2, 3, 4, 5]);
            assert!(watch.dropped.lock().is_empty());
        });
    }

    #[test]
    fn each_gate_drops_at_its_own_cap() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let watch = Watch::default();
            let tap = ReplicaTap::<P>::new(
                1,
                net.participants.clone().into(),
                Arc::new(watch),
                Arc::new(AtomicBool::new(true)),
            );
            tap.gate.lock().hold = Some(Arc::new(|_| true));
            tap.marshal_gate.lock().hold = Some(Arc::new(|_| true));
            let payload = IoBuf::from(vec![0u8; 8]);
            let sender = &net.participants[2];
            for _ in 0..LOG_CAP + 10 {
                assert!(tap.hold(MarshalChannel::Broadcast, sender, &payload));
            }
            assert_eq!(tap.marshal_gate.lock().held.len(), LOG_CAP);
            assert_eq!(tap.marshal_gate.lock().dropped, Some(1));
            // The engine gate keeps its own room and its own first drop.
            assert!(tap.gate.lock().held.is_empty());
            assert_eq!(tap.gate.lock().dropped, None);
            for _ in 0..LOG_CAP + 1 {
                assert!(tap.hold(Channel::Vote, sender, &payload));
            }
            assert_eq!(tap.gate.lock().held.len(), LOG_CAP);
            assert_eq!(tap.gate.lock().dropped, Some(11));
            assert_eq!(tap.open(), 2 * LOG_CAP);
        });
    }

    #[test]
    fn b_sends_stop_at_the_byte_budget() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let prefix = script(Duration::from_secs(30), |cx| {
                Box::pin(async move {
                    let largest = vec![0u8; MAX_MESSAGE as usize];
                    let size = u64::from(MAX_MESSAGE);
                    // A message counts once per recipient.
                    assert_eq!(cx.send(Channel::Resolver, &[1, 2], largest.clone()), 2);
                    let fit = MAX_SENT / size - 2;
                    for sent in 0..fit + 40 {
                        let went = if sent % 2 == 0 {
                            cx.send(Channel::Resolver, &[1], largest.clone())
                        } else {
                            cx.send_marshal(MarshalChannel::Backfill, &[1], largest.clone())
                        };
                        assert_eq!(went, usize::from(sent < fit), "{sent}");
                        cx.sleep(Duration::from_millis(10)).await;
                    }
                    assert_eq!(cx.send(Channel::Vote, &[1], vec![1u8]), 0);
                    assert_eq!(
                        cx.send_marshal(MarshalChannel::Broadcast, &[1], vec![1u8]),
                        0
                    );
                    cx.sleep(Duration::from_secs(1)).await;
                    let engine: usize = cx
                        .deliveries(1)
                        .iter()
                        .map(|entry| entry.value.payload.len())
                        .sum();
                    let marshal: usize = cx
                        .marshal_deliveries(1)
                        .iter()
                        .map(|entry| entry.value.payload.len())
                        .sum();
                    let kept = (engine + marshal) as u64;
                    assert!(kept > 0 && kept <= MAX_SENT, "{kept}");
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let tap = runner.tap(1);
            let delivered: Got = Arc::default();
            let (_, _, (_, resolver)) = net.engine(1);
            let ((_, backfill), _) = net.marshal(1);
            drain(
                &context,
                1,
                gate(tap.as_ref(), resolver, Channel::Resolver),
                &delivered,
            );
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), backfill, MarshalChannel::Backfill),
                &delivered,
            );
            runner.adopt(net.engine(0));
            runner.adopt_marshal(net.marshal(0));
            let (_, release) = runner.run().await;
            assert!(!release.overran);
        });
    }

    #[test]
    fn b_sends_of_tiny_messages_stop_at_the_byte_budget() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let accepted = Arc::new(AtomicU64::new(0));
            let counted = accepted.clone();
            let prefix = script(Duration::from_secs(1), move |cx| {
                Box::pin(async move {
                    // A send to nobody goes nowhere and still costs MIN_CHARGE.
                    assert_eq!(cx.send(Channel::Vote, &[], Vec::<u8>::new()), 0);
                    // Empty and one-byte messages on both kinds of channel, with no
                    // yield: only the byte budget ends the loop.
                    let mut sends = 0u64;
                    loop {
                        let message = if sends.is_multiple_of(2) {
                            Vec::new()
                        } else {
                            vec![1u8]
                        };
                        let went = if sends.is_multiple_of(3) {
                            cx.send_marshal(MarshalChannel::Backfill, &[1, 2, 3], message)
                        } else {
                            cx.send(Channel::Vote, &[1, 2, 3], message)
                        };
                        if went == 0 {
                            break;
                        }
                        assert_eq!(went, 3);
                        sends += 1;
                    }
                    counted.store(sends, Ordering::Relaxed);
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            runner.adopt(net.engine(0));
            runner.adopt_marshal(net.marshal(0));
            let (_, release) = runner.run().await;
            assert!(!release.overran);
            let accepted = accepted.load(Ordering::Relaxed);
            assert!(accepted * 3 <= MAX_SENT / MIN_CHARGE, "{accepted}");
            assert_eq!(accepted, (MAX_SENT / MIN_CHARGE - 1) / 3);
        });
    }

    #[test]
    fn a_refused_link_change_costs_time() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let prefix = script(Duration::from_secs(1), |cx| {
                Box::pin(async move {
                    let start = cx.now();
                    assert!(!cx.set_link(1, 99, None).await);
                    assert!(cx.now() - start >= NO_ANSWER);
                    // A loop of refusals advances time, so the runner ends it at its budget.
                    while !cx.set_link(1, 1, None).await {}
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            runner.adopt(net.engine(0));
            let (_, release) = runner.run().await;
            assert!(release.overran);
            assert!(release.links.is_empty());
        });
    }

    #[test]
    fn engine_pass_is_unchanged_with_marshal_traffic_held() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let delivered: Got = Arc::default();
            let seen = delivered.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    cx.hold(1, |_| true);
                    assert!(cx.hold_marshal(1, |_| true));
                    cx.send(Channel::Vote, &[1], vec![1u8]);
                    cx.send_marshal(MarshalChannel::Backfill, &[1], vec![2u8]);
                    cx.send(Channel::Certificate, &[1], vec![3u8]);
                    cx.send_marshal(MarshalChannel::Broadcast, &[1], vec![4u8]);
                    cx.sleep(Duration::from_secs(1)).await;
                    let engine: Vec<_> = cx.held(1).iter().map(|m| m.channel).collect();
                    let mut sorted = engine.clone();
                    sorted.sort();
                    assert_eq!(sorted, vec![Channel::Vote, Channel::Certificate]);
                    assert_eq!(cx.held_marshal(1).len(), 2);
                    // An engine selector sees engine messages only, by index.
                    let asked = Mutex::new(Vec::new());
                    let passed = cx.pass(1, |message| {
                        asked.lock().push(message.channel);
                        message.channel == Channel::Certificate
                    });
                    assert_eq!(passed, 1);
                    assert_eq!(asked.into_inner(), engine);
                    cx.sleep(SETTLE).await;
                    assert_eq!(got(&seen), vec![3]);
                    assert_eq!(cx.held(1).len(), 1);
                    assert_eq!(cx.held_marshal(1).len(), 2);
                    assert_eq!(cx.pass(1, |_| true), 1);
                    assert_eq!(cx.pass_marshal(1, |_| true), 2);
                    cx.sleep(SETTLE).await;
                    assert_eq!(got(&seen), vec![1, 2, 3, 4]);
                    assert_eq!(cx.deliveries(1).len(), 2);
                    assert_eq!(cx.marshal_deliveries(1).len(), 2);
                })
            });
            let mut runner = net.runner(&context, &Watch::default(), Epoch::zero(), prefix);
            let tap = runner.tap(1);
            let ((_, vote), (_, certificate), _) = net.engine(1);
            let ((_, backfill), (_, broadcast)) = net.marshal(1);
            drain(
                &context,
                1,
                gate(tap.as_ref(), vote, Channel::Vote),
                &delivered,
            );
            drain(
                &context,
                1,
                gate(tap.as_ref(), certificate, Channel::Certificate),
                &delivered,
            );
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), backfill, MarshalChannel::Backfill),
                &delivered,
            );
            drain(
                &context,
                1,
                marshal_gate(tap.as_ref(), broadcast, MarshalChannel::Broadcast),
                &delivered,
            );
            runner.adopt(net.engine(0));
            runner.adopt_marshal(net.marshal(0));
            let (_, release) = runner.run().await;
            // Both filters were still installed at the release, with nothing held.
            assert_eq!(release.gates, vec![1]);
            assert_eq!(release.delivered, 0);
        });
    }

    #[test]
    fn hold_marshal_without_a_marshal_gate_is_false() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let leak: Leak = Arc::default();
            let leaked = leak.clone();
            let dropped = watch.dropped.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    // Replica 1 has no marshal gate, replica 2 has one.
                    assert!(!cx.hold_marshal(1, |_| true));
                    assert_eq!(cx.pass_marshal(1, |_| true), 0);
                    assert!(cx.held_marshal(1).is_empty());
                    assert!(cx.marshal_deliveries(1).is_empty());
                    assert_eq!(
                        dropped.lock().len(),
                        2,
                        "each read of a missing gate is cut"
                    );
                    assert!(cx.hold_marshal(2, |_| true));
                    assert!(cx.held_marshal(2).is_empty());
                    assert_eq!(dropped.lock().len(), 2);
                    *leaked.lock() = Some(cx.clone());
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let ((_, backfill), _) = net.marshal(2);
            drain(
                &context,
                2,
                marshal_gate(runner.tap(2).as_ref(), backfill, MarshalChannel::Backfill),
                &Got::default(),
            );
            let (_, release) = runner.run().await;
            assert_eq!(release.gates, vec![2]);
            // Past the handoff a gated replica refuses a filter too.
            let cx = leak.lock().take().unwrap();
            assert!(!cx.hold_marshal(2, |_| true));
            assert_eq!(cx.pass_marshal(2, |_| true), 0);
        });
    }

    #[test]
    fn send_marshal_without_lanes_sends_nothing() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let dropped = watch.dropped.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    assert!(!cx.marshal_lanes());
                    assert_eq!(
                        cx.send_marshal(MarshalChannel::Backfill, &[1, 2, 3], vec![1u8]),
                        0
                    );
                    let at = cx.stamp().seq();
                    assert!(cx.marshal_inbox().is_empty());
                    assert_eq!(dropped.lock().as_slice(), &[at + 1]);
                    // B's engine channels are unaffected.
                    assert_eq!(cx.send(Channel::Vote, &[1], vec![1u8]), 1);
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            runner.adopt(net.engine(0));
            let (channels, _) = runner.run().await;
            assert!(channels.is_some());
            assert!(runner.marshal_channels().is_none());
        });
    }

    #[test]
    fn b_marshal_lanes_record_until_the_release_and_return() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let watch = Watch::default();
            let leak: Leak = Arc::default();
            let leaked = leak.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    cx.sleep(Duration::from_secs(1)).await;
                    let inbox = cx.marshal_inbox();
                    assert_eq!(inbox.len(), 2);
                    let mut seen: Vec<_> = inbox
                        .iter()
                        .map(|entry| (entry.value.from, entry.value.channel, entry.value.payload.as_ref()[0]))
                        .collect();
                    seen.sort();
                    assert_eq!(
                        seen,
                        vec![
                            (Some(2), MarshalChannel::Backfill, 5),
                            (Some(3), MarshalChannel::Broadcast, 6),
                        ]
                    );
                    *leaked.lock() = Some(cx.clone());
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let b = net.participants[0].clone();
            let ((mut backfill, _), _) = net.marshal(2);
            let (_, (mut broadcast, _)) = net.marshal(3);
            commonware_p2p::Sender::send(
                &mut backfill,
                Recipients::Some(vec![b.clone()]),
                IoBuf::from(vec![5u8]),
                false,
            );
            commonware_p2p::Sender::send(
                &mut broadcast,
                Recipients::Some(vec![b.clone()]),
                IoBuf::from(vec![6u8]),
                false,
            );
            runner.adopt_marshal(net.marshal(0));
            let (channels, _) = runner.run().await;
            assert!(channels.is_none(), "B's engine channels were never adopted");
            let ((mut b_backfill, mut b_backfill_receiver), _) =
                runner.marshal_channels().expect("the release returns B's lanes");
            assert!(runner.marshal_channels().is_none());
            // The lanes returned are B's live ones, no longer recorded.
            commonware_p2p::Sender::send(
                &mut backfill,
                Recipients::Some(vec![b.clone()]),
                IoBuf::from(vec![7u8]),
                false,
            );
            select! {
                message = b_backfill_receiver.recv() => assert_eq!(message.unwrap().1.as_ref(), &[7]),
                _ = context.sleep(Duration::from_secs(1)) => panic!("B's backfill lane is dead"),
            }
            let cx = leak.lock().take().unwrap();
            assert_eq!(cx.marshal_inbox().len(), 2);
            assert_eq!(cx.send_marshal(MarshalChannel::Backfill, &[2], vec![1u8]), 0);
            let sent = commonware_p2p::Sender::send(
                &mut b_backfill,
                Recipients::Some(vec![net.participants[2].clone()]),
                IoBuf::from(vec![1u8]),
                false,
            );
            assert_eq!(sent.len(), 1, "the base sends on B's returned lane");
        });
    }

    #[test]
    fn an_unfed_recorder_cuts_at_the_read() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let watch = Watch::default();
            let dropped = watch.dropped.clone();
            let prefix = script(Duration::from_secs(10), move |cx| {
                Box::pin(async move {
                    type Read = Box<dyn Fn(&PrefixContext<P>) -> usize + Send>;
                    let reads: [(&str, Read); 9] = [
                        ("deliveries", Box::new(|cx| cx.deliveries(1).len())),
                        ("held", Box::new(|cx| cx.held(1).len())),
                        (
                            "marshal_deliveries",
                            Box::new(|cx| cx.marshal_deliveries(1).len()),
                        ),
                        ("held_marshal", Box::new(|cx| cx.held_marshal(1).len())),
                        ("marshal_inbox", Box::new(|cx| cx.marshal_inbox().len())),
                        ("activities", Box::new(|cx| cx.activities(1).len())),
                        ("automaton", Box::new(|cx| cx.automaton(1).len())),
                        ("elections", Box::new(|cx| cx.elections(2).len())),
                        ("blocks", Box::new(|cx| cx.blocks(1).len())),
                    ];
                    for (name, read) in reads {
                        // A stage read before the cut keeps its position; the cut is the
                        // read's own, after it.
                        let before = cx.stamp().seq();
                        assert_eq!(read(&cx), 0, "{name}");
                        assert_eq!(dropped.lock().last(), Some(&(before + 1)), "{name}");
                        dropped.lock().clear();
                    }
                    // A fed recorder, and a replica without a tap, cut nothing.
                    let _ = cx.elections(1);
                    let _ = cx.activities(0);
                    assert!(dropped.lock().is_empty());
                })
            });
            let runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let set: Set<Key> = net.participants.as_slice().try_into().unwrap();
            let _ = tap_elector(
                runner.tap(1).as_ref(),
                <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero()),
            )
            .build(&set);
            let mut runner = runner;
            runner.run().await;
        });
    }

    /// A reporter that counts what reaches it.
    struct Sink<D>(Arc<AtomicU64>, std::marker::PhantomData<fn() -> D>);

    impl<D> Clone for Sink<D> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), std::marker::PhantomData)
        }
    }

    impl<D: Digest> Reporter for Sink<D> {
        type Activity = Activity<SchemeOf, D>;

        fn report(&mut self, _activity: Self::Activity) -> Feedback {
            self.0.fetch_add(1, Ordering::Relaxed);
            Feedback::Ok
        }
    }

    /// A queue of messages, then a closed receiver.
    #[derive(Debug)]
    struct Queue(VecDeque<(Key, IoBuf)>);

    impl commonware_p2p::Receiver for Queue {
        type Error = Closed;
        type PublicKey = Key;

        async fn recv(&mut self) -> Result<commonware_p2p::Message<Key>, Closed> {
            self.0.pop_front().ok_or(Closed)
        }
    }

    /// A finalization of `view` over `payload` by a quorum of `schemes`.
    fn finalization<D: Digest>(
        schemes: &[SchemeOf],
        view: u64,
        payload: D,
    ) -> Activity<SchemeOf, D> {
        use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(view)),
            View::new(view - 1),
            payload,
        );
        let finalizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Activity::Finalization(
            Finalization::from_finalizes(
                &schemes[0],
                commonware_utils::iter::NonEmpty::try_new(finalizes.iter()).unwrap(),
                &commonware_parallel::Sequential,
            )
            .unwrap(),
        )
    }

    #[test]
    fn wrappers_without_a_tap_only_forward() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let key = net.participants[1].clone();
            let message = IoBuf::from(vec![1u8, 2, 3]);
            let mut engine = gate::<P, _>(
                None,
                Queue(VecDeque::from([(key.clone(), message.clone())])),
                Channel::Vote,
            );
            assert!(engine.tap.is_none() && engine.wake.is_none());
            let (from, payload) = engine.recv().await.unwrap();
            assert_eq!((&from, payload.as_ref()), (&key, message.as_ref()));
            assert!(engine.recv().await.is_err());
            let mut marshal = marshal_gate::<P, _>(
                None,
                Queue(VecDeque::from([(key.clone(), message.clone())])),
                MarshalChannel::Broadcast,
            );
            assert!(marshal.tap.is_none() && marshal.wake.is_none());
            assert_eq!(marshal.recv().await.unwrap().1.as_ref(), message.as_ref());

            let count = Arc::new(AtomicU64::new(0));
            let mut reporter = tap_reporter::<P, _>(
                None,
                Sink::<Sha256Digest>(count.clone(), Default::default()),
            );
            assert!(reporter.tap.is_none());
            reporter.report(finalization(&net.schemes, 3, Sha256Digest([3; 32])));
            let mut finalized = tap_finalized::<P, _>(
                None,
                Sink::<commonware_cryptography::blake3::Digest>(count.clone(), Default::default()),
            );
            finalized.report(finalization(
                &net.schemes,
                4,
                commonware_cryptography::blake3::Digest([4; 32]),
            ));
            assert_eq!(count.load(Ordering::Relaxed), 2);

            let set: Set<Key> = net.participants.as_slice().try_into().unwrap();
            let config = <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero());
            let inner: ElectorOf = config.clone().build(&set);
            let elector = tap_elector::<P, _>(None, config).build(&set);
            assert!(elector.tap.is_none());
            for view in 1..=8 {
                let round = Round::new(Epoch::zero(), View::new(view));
                assert_eq!(elector.elect(round, ()), inner.elect(round, ()));
            }

            let mut blocker = tap_blocker::<P, _>(None, net.oracle.control(key.clone()));
            assert!(blocker.tap.is_none());
            #[allow(
                clippy::disallowed_methods,
                reason = "the test checks the block is forwarded"
            )]
            let _ = blocker.block(net.participants[2].clone());
            context.sleep(SETTLE).await;
            assert!(
                net.oracle
                    .blocked()
                    .await
                    .unwrap()
                    .contains(&(key.clone(), net.participants[2].clone())),
                "the block was not forwarded"
            );

            let silent = Silent {
                open: Arc::new(Mutex::new(Vec::new())),
                prepares: Arc::new(Mutex::new(Vec::new())),
            };
            let mut automaton = tap_automaton::<P, _>(None, silent.clone(), &context);
            assert!(automaton.tap.is_none() && automaton.context.is_none());
            let request = SimplexContext {
                round: Round::new(Epoch::new(EPOCH), View::new(1)),
                leader: key,
                parent: (View::zero(), Sha256Digest([0; 32])),
            };
            let _receiver = automaton.verify(request, Sha256Digest([1; 32])).await;
            assert_eq!(silent.open.lock().len(), 1);
        });
    }

    #[test]
    fn tap_finalized_raises_the_release_base_for_any_digest() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let watch = Watch::default();
            let dropped = watch.dropped.clone();
            let prefix = script(Duration::from_secs(1), move |cx| {
                Box::pin(async move {
                    // It records nothing: the activities log stays unfed.
                    assert!(cx.activities(1).is_empty());
                    assert_eq!(dropped.lock().len(), 1);
                })
            });
            let mut runner = net.runner(&context, &watch, Epoch::zero(), prefix);
            let count = Arc::new(AtomicU64::new(0));
            let mut reporter = tap_finalized(
                runner.tap(1).as_ref(),
                Sink::<commonware_cryptography::blake3::Digest>(count.clone(), Default::default()),
            );
            for view in [7, 3] {
                reporter.report(finalization(
                    &net.schemes,
                    view,
                    commonware_cryptography::blake3::Digest([view as u8; 32]),
                ));
            }
            assert_eq!(count.load(Ordering::Relaxed), 2);
            let (_, release) = runner.run().await;
            assert_eq!(release.base, 7);
        });
    }

    #[test]
    fn release_view_is_the_highest_elected_view() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let watch = Watch::default();
            let mut runner = net.runner(
                &context,
                &watch,
                Epoch::zero(),
                script(Duration::from_secs(1), |_| Box::pin(async {})),
            );
            let set: Set<Key> = net.participants.as_slice().try_into().unwrap();
            let electors: Vec<_> = (1..=3)
                .map(|replica| {
                    tap_elector(
                        runner.tap(replica).as_ref(),
                        <P as Simplex>::elector(TermLength::ONE, ViewDelta::zero()),
                    )
                    .build(&set)
                })
                .collect();
            let elect = |replica: usize, view: u64| {
                electors[replica - 1].elect(Round::new(Epoch::zero(), View::new(view)), ());
            };
            elect(1, 5);
            elect(2, 9);
            elect(1, 6);
            let (_, release) = runner.run().await;
            assert_eq!(release.view, 9);
            assert_eq!(release.base, 0);
            // Past the release the counter still follows the elector, unrecorded.
            let tap = runner.tap(3).unwrap();
            let recorded = tap.elections.lock().len();
            elect(3, 20);
            assert_eq!(tap.elected.load(Ordering::Relaxed), 20);
            assert_eq!(tap.elections.lock().len(), recorded);
        });
    }

    /// How a fake marshal read answers.
    #[derive(Clone, Copy)]
    enum Answer {
        Never,
        /// Ready at the first poll, as an answer from a closed mailbox would be.
        Immediate,
        /// The request was dropped before the first poll.
        Dropped,
        /// Answered by another task after 10 ms.
        Later,
    }

    /// Marshal reads whose answer follows the height asked for.
    struct FakeReads {
        context: Mutex<deterministic::Context>,
    }

    impl FakeReads {
        fn read<T: Send + 'static>(
            &self,
            answer: Answer,
            value: Option<T>,
        ) -> Pin<Box<dyn Future<Output = Option<T>> + Send>> {
            match answer {
                Answer::Never => Box::pin(futures::future::pending()),
                Answer::Immediate => Box::pin(async move { value }),
                Answer::Dropped => {
                    let (sender, receiver) = oneshot::channel::<Option<T>>();
                    drop(sender);
                    Box::pin(async move { receiver.await.ok().flatten() })
                }
                Answer::Later => {
                    let (sender, receiver) = oneshot::channel();
                    self.context
                        .lock()
                        .child("answer")
                        .spawn(move |context| async move {
                            context.sleep(Duration::from_millis(10)).await;
                            sender.send_lossy(value);
                        });
                    Box::pin(async move { receiver.await.ok().flatten() })
                }
            }
        }
    }

    impl MarshalReads for FakeReads {
        /// Height 0 never answers, 1 answers at once, 2 is dropped, 3 is finalized and 4
        /// is not.
        fn finalized(
            &self,
            height: u64,
        ) -> Pin<Box<dyn Future<Output = Option<Sha256Digest>> + Send>> {
            match height {
                0 => self.read(Answer::Never, None),
                1 => self.read(Answer::Immediate, Some(Sha256Digest([1; 32]))),
                2 => self.read(Answer::Dropped, None),
                3 => self.read(Answer::Later, Some(Sha256Digest([3; 32]))),
                _ => self.read(Answer::Later, None),
            }
        }

        fn processed(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
            self.read(Answer::Later, Some(9))
        }
    }

    #[test]
    fn marshal_reads_answer_time_out_or_refuse_immediately() {
        deterministic::Runner::default().start(|mut context| async move {
            let net = Net::new(&mut context).await;
            let prefix = script(Duration::from_secs(10), |cx| {
                Box::pin(async move {
                    // The time a read took, in whole milliseconds of the executor's rounds.
                    let took = |cx: &PrefixContext<P>, start: Duration| cx.now() - start;
                    let within =
                        |took: Duration, least: Duration| took >= least && took < least + SETTLE;
                    let start = cx.now();
                    assert_eq!(cx.finalized_block(1, 0).await, None);
                    assert!(within(took(&cx, start), MARSHAL_READ_TIMEOUT));
                    for height in [1, 2] {
                        let start = cx.now();
                        assert_eq!(cx.finalized_block(1, height).await, None, "{height}");
                        assert!(within(took(&cx, start), NO_ANSWER), "{height}");
                    }
                    let start = cx.now();
                    assert_eq!(
                        cx.finalized_block(1, 3).await,
                        Some(Some(Sha256Digest([3; 32])))
                    );
                    assert!(within(took(&cx, start), Duration::from_millis(10)));
                    assert_eq!(cx.finalized_block(1, 4).await, Some(None));
                    assert_eq!(cx.processed_height(1).await, Some(Some(9)));
                    // Without reads, and for B, there is no answer, after 1 ms.
                    for replica in [0, 2, 9] {
                        let start = cx.now();
                        assert_eq!(cx.processed_height(replica).await, None);
                        assert!(within(took(&cx, start), NO_ANSWER));
                    }
                })
            });
            let mut runner = net.runner(&context, &Watch::default(), Epoch::zero(), prefix);
            runner.tap(1).unwrap().set_reads(Arc::new(FakeReads {
                context: Mutex::new(context.child("reads")),
            }));
            let (_, release) = runner.run().await;
            assert!(!release.overran);

            // A prefix ended at its budget inside a read releases on time.
            let reads = Arc::new(FakeReads {
                context: Mutex::new(context.child("reads")),
            });
            let prefix = Script(
                Budget {
                    prefix: Duration::from_millis(300),
                    release: Duration::ZERO,
                },
                |cx: PrefixContext<P>| -> PrefixFuture {
                    Box::pin(async move {
                        let _ = cx.finalized_block(1, 0).await;
                        unreachable!("the read outlived the budget");
                    })
                },
            );
            let mut runner = net.runner(&context, &Watch::default(), Epoch::zero(), prefix);
            runner.tap(1).unwrap().set_reads(reads);
            let start = context.current();
            let (_, release) = runner.run().await;
            assert!(release.overran);
            let took = context.current().duration_since(start).unwrap();
            assert!(took >= Duration::from_millis(300) && took < MARSHAL_READ_TIMEOUT);
        });
    }

    #[test]
    fn marshal_pins_honor_only_their_domain() {
        let mut input = test_input();
        input.configuration = N4F1C3;
        input.certify = CertifyChoice::Always;
        input.term_length = TermLength::ONE;
        input.optimistic_views = ViewDelta::zero();
        let mut pins = Pins::new(&mut input, Domain::Marshal { term: true });
        assert!(pins.configuration(N4F1C3));
        assert!(!pins.configuration(N4F0C4));
        assert!(!pins.configuration(crate::N4F3C1));
        assert!(pins.lookahead(ViewDelta::zero()));
        assert!(!pins.lookahead(ViewDelta::new(1)));
        pins.term_length(TermLength::new(commonware_utils::NZU32!(3)));
        assert_eq!(pins.input().term_length.get(), 3);
        pins.term_length(TermLength::new(commonware_utils::NZU32!(
            MARSHAL_MAX_TERM_LENGTH + 1
        )));
        assert_eq!(
            pins.input().term_length.get(),
            3,
            "past the decoder's bound"
        );
        assert_eq!(pins.input().optimistic_views, ViewDelta::zero());
        let mut pins = Pins::new(&mut input, Domain::Marshal { term: false });
        pins.term_length(TermLength::ONE);
        assert_eq!(
            pins.input().term_length.get(),
            3,
            "a base without terms pins none"
        );
        assert_eq!(input.configuration, N4F1C3);

        // The plan cuts a marshal budget as any other.
        let mut input = test_input();
        let hook = Hook::<P>::plan_marshal(
            Box::new(Script(
                Budget {
                    prefix: Duration::from_secs(3600),
                    release: Duration::from_secs(3600),
                },
                |_: PrefixContext<P>| -> PrefixFuture { Box::pin(async {}) },
            )),
            Arc::new(Unobserved),
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
    }

    #[test]
    fn start_disrupter_signs_in_the_given_epoch() {
        use commonware_codec::DecodeExt as _;
        use commonware_consensus::{Epochable as _, simplex::types::Vote};
        deterministic::Runner::default().start(|mut context| async move {
            let mut net = Net::new(&mut context).await;
            let epoch = Epoch::new(7);
            let registry = ActorRegistry::default();
            let handle = start_disrupter::<P>(
                context.child("disrupter"),
                net.schemes[0].clone(),
                &crate::strategy::StrategyChoice::AnyScope,
                1,
                net.engine(0),
                None,
                0,
                registry.marker(0, Role::Disrupter),
                epoch,
            );
            let ((_, mut votes), _, _) = net.engine(1);
            let mut epochs = BTreeSet::new();
            let deadline = context.current() + Duration::from_secs(5);
            while context.current() < deadline {
                select! {
                    message = votes.recv() => {
                        let (_, payload) = message.unwrap();
                        if let Ok(vote) = Vote::<SchemeOf, Sha256Digest>::decode(payload) {
                            epochs.insert(vote.epoch());
                        }
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {},
                }
            }
            handle.abort();
            assert_eq!(
                epochs,
                BTreeSet::from([epoch]),
                "the Disrupter signed in {epochs:?}"
            );
        });
    }
}
