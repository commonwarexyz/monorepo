//! Trusted continuation: a hook point inside the base drivers that runs a state-building
//! prefix after the network, the reporters and the honest engines exist, and before the
//! base's Byzantine actors, fault scheduler, liveness wait and oracles start.
//!
//! A [Prefix] drives the system through the restricted [PrefixContext] only. The runner
//! owns everything else: it spawns the honest replicas with the recording wrappers and
//! gates of a [ReplicaTap], keeps the compromised identity's channels while the prefix
//! signs and sends as it, and at the handoff revokes the context. After the release
//! delay it reverts every change the prefix made, starts exactly the base's actors for
//! the compromised identity, records them in an [ActorRegistry], and lets the base's
//! own code continue in the same runtime. Drivers called without a prefix run unchanged.

use crate::{
    CertifyChoice, Configuration, EPOCH, FuzzInput, HarnessReporter, MAX_REQUIRED_CONTAINERS,
    N4F0C4, N4F1C3, NetworkChannels, PublicKeyOf, ReporterWiring, block_relay, simplex::Simplex,
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
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver as _, Recipients, simulated::Link};
use commonware_runtime::{Clock, Handle, IoBuf, Spawner, Supervisor as _, deterministic};
use commonware_utils::{
    channel::{
        fallible::{FallibleExt as _, OneshotExt as _},
        mpsc, oneshot,
    },
    ordered::Set,
    sync::Mutex,
};
use futures::FutureExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

/// How long the release check waits for the actors it just started to run.
const RELEASE_SETTLE: Duration = Duration::from_millis(100);
const RELEASE_POLL: Duration = Duration::from_millis(1);

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

/// A message a replica received, or held, on one of its channels.
#[derive(Clone, Debug)]
pub struct Inbound {
    /// The sender's index among the participants, `None` for an unknown key.
    pub from: Option<usize>,
    pub channel: Channel,
    pub payload: IoBuf,
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
    /// `release` (the handoff plus the release delay) or `end` (after the liveness wait).
    pub at: &'static str,
    pub actors: Vec<ActorStatus>,
}

impl ActorCheck {
    /// Whether every required actor runs.
    pub fn ok(&self) -> bool {
        self.actors
            .iter()
            .all(|actor| actor.state == ActorState::Running)
    }
}

impl fmt::Display for ActorCheck {
    /// `<at> ok|failed <identity>:<role>=<state> ...`, or `-` when nothing is required.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.at, if self.ok() { "ok" } else { "failed" })?;
        if self.actors.is_empty() {
            return write!(f, " -");
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
        ActorCheck { at, actors }
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

    /// Whether to run the base's largest progress budget (a reach replay of StateLens).
    fn largest(&self) -> bool {
        false
    }
}

/// An observer that stamps nothing: positions are 0.
pub struct Unobserved;

impl Observer for Unobserved {
    fn position(&self) -> (u64, u32) {
        (0, 0)
    }

    fn compromised(&self, _identities: &[usize]) {}

    fn actors(&self, _check: &ActorCheck) {}
}

/// What the prefix asks of the runtime: the sum of its stage deadlines, and the release
/// delay `d` from the handoff to the release.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub prefix: Duration,
    pub release: Duration,
}

impl Budget {
    /// The runtime deadline of a continuation: the base's plus this budget.
    pub fn deadline(self, base: Duration) -> Duration {
        base.saturating_add(self.prefix)
            .saturating_add(self.release)
    }
}

/// The decoded input fields a prefix may pin before the runtime starts. Each setter
/// keeps the fields that depend on it as the decoder sets them.
pub struct Pins<'a> {
    input: &'a mut FuzzInput,
    twins: bool,
}

impl<'a> Pins<'a> {
    pub(crate) const fn new(input: &'a mut FuzzInput, twins: bool) -> Self {
        Self { input, twins }
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
    pub fn term_length(&mut self, term_length: TermLength) {
        self.input.term_length = term_length;
        let most = term_length.get() + 2;
        if self.input.optimistic_views.get() > most {
            self.input.optimistic_views = ViewDelta::new(most);
        }
    }

    /// Pins the optimistic lookahead; returns false, and pins nothing, beyond the
    /// decoder's domain (the term length plus two).
    pub fn lookahead(&mut self, views: ViewDelta) -> bool {
        if views.get() > self.input.term_length.get() + 2 {
            return false;
        }
        self.input.optimistic_views = views;
        true
    }

    /// Pins N4F1C3 or N4F0C4; returns false, and pins nothing, for another
    /// configuration, and for N4F0C4 under Twins, which runs N4F1C3 only.
    pub fn configuration(&mut self, configuration: Configuration) -> bool {
        if configuration != N4F1C3 && configuration != N4F0C4 {
            return false;
        }
        if self.twins && configuration != N4F1C3 {
            return false;
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
    /// Plans `prefix` against `input` and binds it to `observer`. The largest budget
    /// the observer asks for is applied after the prefix's pins.
    pub fn plan(
        mut prefix: Box<dyn Prefix<P>>,
        observer: Arc<dyn Observer>,
        input: &mut FuzzInput,
        twins: bool,
    ) -> Self {
        let budget = prefix.plan(&mut Pins::new(input, twins));
        if observer.largest() {
            input.required_containers = MAX_REQUIRED_CONTAINERS;
        }
        Self {
            prefix,
            observer,
            budget,
        }
    }

    pub const fn budget(&self) -> Budget {
        self.budget
    }

    pub fn observer(&self) -> Arc<dyn Observer> {
        self.observer.clone()
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
    /// view-indexed faults and progress targets are re-based on it.
    pub base: u64,
}

type HoldFilter = Arc<dyn Fn(&Inbound) -> bool + Send + Sync>;
type ActivityOf<P> = Activity<<P as Simplex>::Scheme, Sha256Digest>;
type BlockFilter = Arc<dyn Fn(Option<View>, &Sha256Digest) -> bool + Send + Sync>;

/// The gate on an honest replica's receivers.
struct Gate<K> {
    hold: Option<HoldFilter>,
    held: VecDeque<(Channel, K, IoBuf)>,
    ready: [VecDeque<(K, IoBuf)>; 3],
    wake: [Option<mpsc::UnboundedSender<()>>; 3],
}

impl<K> Gate<K> {
    const fn new() -> Self {
        Self {
            hold: None,
            held: VecDeque::new(),
            ready: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            wake: [None, None, None],
        }
    }

    /// Moves the held messages `select` accepts to their channels, in arrival order,
    /// and wakes those channels. Returns how many moved.
    fn pass(&mut self, mut select: impl FnMut(Channel, &K, &IoBuf) -> bool) -> usize {
        let mut moved = 0;
        let mut kept = VecDeque::with_capacity(self.held.len());
        let mut woken = [false; 3];
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
        for channel in Channel::ALL {
            if woken[channel.index()]
                && let Some(wake) = &self.wake[channel.index()]
            {
                wake.send_lossy(());
            }
        }
        moved
    }
}

/// The tasks of one incarnation of an honest replica, and how to build the next one.
struct Incarnation<P: Simplex> {
    app: Option<Handle<()>>,
    engine: Option<Handle<()>>,
    respawn: Option<Respawn<P>>,
}

type Respawn<P> =
    Box<dyn FnMut(NetworkChannels<PublicKeyOf<P>>) -> (Handle<()>, Handle<()>) + Send>;

/// The runner's view of one honest replica: the gate on its receivers and the
/// recorders wrapped around its reporter, automaton, elector and blocker at spawn.
pub struct ReplicaTap<P: Simplex> {
    index: usize,
    participants: Arc<[PublicKeyOf<P>]>,
    observer: Arc<dyn Observer>,
    recording: Arc<AtomicBool>,
    gate: Mutex<Gate<PublicKeyOf<P>>>,
    deliveries: Mutex<Vec<Recorded<Inbound>>>,
    activities: Mutex<Vec<Recorded<ActivityOf<P>>>>,
    automaton: Mutex<Vec<Recorded<AutomatonEvent>>>,
    elections: Mutex<Vec<Recorded<(View, usize)>>>,
    blocks: Mutex<Vec<Recorded<usize>>>,
    incarnation: Mutex<Incarnation<P>>,
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
            deliveries: Mutex::new(Vec::new()),
            activities: Mutex::new(Vec::new()),
            automaton: Mutex::new(Vec::new()),
            elections: Mutex::new(Vec::new()),
            blocks: Mutex::new(Vec::new()),
            incarnation: Mutex::new(Incarnation {
                app: None,
                engine: None,
                respawn: None,
            }),
        }
    }

    /// This replica's index among the participants.
    pub const fn index(&self) -> usize {
        self.index
    }

    fn recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }

    fn stamp(&self) -> Stamp {
        let (seq, run) = self.observer.position();
        Stamp { seq, run }
    }

    fn record<T>(&self, log: &Mutex<Vec<Recorded<T>>>, value: T) {
        if self.recording() {
            let stamp = self.stamp();
            log.lock().push(Recorded { value, stamp });
        }
    }

    fn position(&self, key: &PublicKeyOf<P>) -> Option<usize> {
        self.participants.iter().position(|known| known == key)
    }

    /// The next message ready for `channel`, as the gate passed or released it.
    fn take_ready(&self, channel: Channel) -> Option<(PublicKeyOf<P>, IoBuf)> {
        self.gate.lock().ready[channel.index()].pop_front()
    }

    /// Whether the gate holds `message`, which it then keeps.
    fn hold(&self, channel: Channel, sender: &PublicKeyOf<P>, payload: &IoBuf) -> bool {
        let mut gate = self.gate.lock();
        let Some(hold) = gate.hold.clone() else {
            return false;
        };
        let inbound = Inbound {
            from: self.position(sender),
            channel,
            payload: payload.clone(),
        };
        if !hold(&inbound) {
            return false;
        }
        gate.held
            .push_back((channel, sender.clone(), payload.clone()));
        true
    }

    fn delivered(&self, channel: Channel, sender: &PublicKeyOf<P>, payload: &IoBuf) {
        if self.recording() {
            let inbound = Inbound {
                from: self.position(sender),
                channel,
                payload: payload.clone(),
            };
            self.record(&self.deliveries, inbound);
        }
    }

    fn wake(&self, channel: Channel) -> mpsc::UnboundedReceiver<()> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.gate.lock().wake[channel.index()] = Some(sender);
        receiver
    }

    /// Opens the gate: every held message goes to its channel, in arrival order.
    fn open(&self) -> usize {
        let mut gate = self.gate.lock();
        gate.hold = None;
        gate.pass(|_, _, _| true)
    }

    fn crashed(&self) -> bool {
        let incarnation = self.incarnation.lock();
        incarnation.engine.is_none() && incarnation.respawn.is_some()
    }
}

/// A receiver behind an honest replica's gate: it holds what the gate's filter
/// accepts, delivers what the prefix passes, and records every delivery.
pub struct GateReceiver<P: Simplex, R> {
    inner: R,
    tap: Arc<ReplicaTap<P>>,
    channel: Channel,
    wake: mpsc::UnboundedReceiver<()>,
}

impl<P: Simplex, R> GateReceiver<P, R> {
    fn new(inner: R, tap: Arc<ReplicaTap<P>>, channel: Channel) -> Self {
        let wake = tap.wake(channel);
        Self {
            inner,
            tap,
            channel,
            wake,
        }
    }
}

impl<P: Simplex, R> fmt::Debug for GateReceiver<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateReceiver")
            .field("replica", &self.tap.index)
            .field("channel", &self.channel)
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
        loop {
            if let Some((sender, payload)) = self.tap.take_ready(self.channel) {
                self.tap.delivered(self.channel, &sender, &payload);
                return Ok((sender, payload));
            }
            select! {
                message = self.inner.recv() => {
                    let (sender, payload) = message?;
                    if self.tap.hold(self.channel, &sender, &payload) {
                        continue;
                    }
                    self.tap.delivered(self.channel, &sender, &payload);
                    return Ok((sender, payload));
                },
                _ = self.wake.recv() => {},
            }
        }
    }
}

/// Records every activity an honest replica's engine reports.
pub struct TapReporter<P: Simplex, R> {
    inner: R,
    tap: Arc<ReplicaTap<P>>,
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
        if self.tap.recording() {
            self.tap.record(&self.tap.activities, activity.clone());
        }
        self.inner.report(activity)
    }
}

/// Records every leader an honest replica's voter elects.
pub struct TapElector<P: Simplex, C> {
    inner: C,
    tap: Arc<ReplicaTap<P>>,
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
    tap: Arc<ReplicaTap<P>>,
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
        self.tap
            .record(&self.tap.elections, (round.view(), leader.get() as usize));
        leader
    }
}

/// Records every peer an honest replica blocks.
pub struct TapBlocker<P: Simplex, B> {
    inner: B,
    tap: Arc<ReplicaTap<P>>,
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
        if let Some(index) = self.tap.position(&peer) {
            self.tap.record(&self.tap.blocks, index);
        }
        self.inner.block(peer)
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        self.inner.blocked()
    }
}

/// Records what an honest replica's automaton is asked, and what it answers.
pub struct TapAutomaton<P: Simplex, A> {
    inner: A,
    tap: Arc<ReplicaTap<P>>,
    context: Arc<Mutex<deterministic::Context>>,
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
    /// Forwards `receiver`'s answer and records how the request ended with `done`. When
    /// consensus drops the receiver it was given, the proxy drops `receiver` too, so the
    /// automaton sees the cancellation as it would without the recorder.
    fn proxy<T: Clone + Send + 'static>(
        &self,
        receiver: oneshot::Receiver<T>,
        done: impl FnOnce(Completion<T>) -> AutomatonEvent + Send + 'static,
    ) -> oneshot::Receiver<T> {
        if !self.tap.recording() {
            return receiver;
        }
        let (mut sender, output) = oneshot::channel();
        let tap = self.tap.clone();
        self.context
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
        self.tap.record(
            &self.tap.automaton,
            AutomatonEvent::Propose {
                round,
                parent: context.parent,
            },
        );
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
        self.tap.record(
            &self.tap.automaton,
            AutomatonEvent::Verify {
                round,
                leader: self.tap.position(&context.leader),
                parent: context.parent,
                payload,
            },
        );
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
        self.tap.record(
            &self.tap.automaton,
            AutomatonEvent::Prepare {
                round,
                parent: context.parent,
            },
        );
        let receiver = self.inner.prepare(context).await;
        self.proxy(receiver, move |decision| AutomatonEvent::Prepared {
            round,
            decision,
        })
    }

    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        self.tap.record(
            &self.tap.automaton,
            AutomatonEvent::Certify { round, payload },
        );
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
    let respawn: Respawn<P> = Box::new(move |(pending, recovered, resolver)| {
        let tap = Weak::upgrade(&weak).expect("a respawned replica keeps its tap");
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
        let automaton = TapAutomaton {
            inner: self.reporter.automaton(&self.context, application.clone()),
            tap: tap.clone(),
            context: Arc::new(Mutex::new(self.context.child("tap"))),
        };
        let reporter = TapReporter {
            inner: self.reporter.clone(),
            tap: tap.clone(),
        };
        let elector = TapElector {
            inner: self.elector.clone(),
            tap: tap.clone(),
        };
        let blocker = TapBlocker {
            inner: self.oracle.control(self.validator.clone()),
            tap: tap.clone(),
        };
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
            (
                vote_sender,
                GateReceiver::new(vote_receiver, tap.clone(), Channel::Vote),
            ),
            (
                certificate_sender,
                GateReceiver::new(certificate_receiver, tap.clone(), Channel::Certificate),
            ),
            (
                resolver_sender,
                GateReceiver::new(resolver_receiver, tap.clone(), Channel::Resolver),
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

/// The runner's state, which the [PrefixContext] reaches only while it is valid.
struct Shared<P: Simplex> {
    observer: Arc<dyn Observer>,
    participants: Arc<[PublicKeyOf<P>]>,
    byzantine: Option<usize>,
    term_length: TermLength,
    optimistic_views: ViewDelta,
    scripted_views: u64,
    leader: Box<dyn Fn(View) -> usize + Send + Sync>,
    oracle: commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    taps: Vec<Option<Arc<ReplicaTap<P>>>>,
    revoked: AtomicBool,
    scheme: Option<P::Scheme>,
    senders: Mutex<Option<Senders<PublicKeyOf<P>>>>,
    inbox: Arc<Mutex<Vec<Recorded<Inbound>>>>,
    made: Mutex<BTreeMap<Sha256Digest, Bytes>>,
    nonce: AtomicU64,
    links: Mutex<BTreeSet<(usize, usize)>>,
    latencies: Mutex<BTreeSet<usize>>,
    block_gate: Arc<Mutex<BlockGate<PublicKeyOf<P>>>>,
}

impl<P: Simplex> Shared<P> {
    fn tap(&self, replica: usize) -> Option<&Arc<ReplicaTap<P>>> {
        if self.revoked.load(Ordering::Relaxed) {
            return None;
        }
        self.taps.get(replica).and_then(Option::as_ref)
    }

    fn key(&self, index: usize) -> Option<PublicKeyOf<P>> {
        self.participants.get(index).cloned()
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
    pub relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
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
        let leader: Box<dyn Fn(View) -> usize + Send + Sync> = Box::new(move |view| {
            leaders
                .lock()
                .elect(
                    Round::new(Epoch::new(EPOCH), view),
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
            leader,
            oracle: topology.oracle,
            relay: topology.relay,
            taps,
            revoked: AtomicBool::new(false),
            scheme,
            senders: Mutex::new(None),
            inbox: Arc::new(Mutex::new(Vec::new())),
            made: Mutex::new(BTreeMap::new()),
            nonce: AtomicU64::new(0),
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
            base_link: topology.base_link,
        }
    }

    /// The tap of honest replica `index`; `None` for the compromised identity.
    pub fn tap(&self, index: usize) -> Option<Arc<ReplicaTap<P>>> {
        self.shared.taps.get(index).cloned().flatten()
    }

    /// The compromised identity, if the base runs one.
    pub fn byzantine(&self) -> Option<usize> {
        self.shared.byzantine
    }

    /// The registry of the compromised identity's actors.
    pub fn registry(&self) -> ActorRegistry {
        self.registry.clone()
    }

    /// The budget the prefix asked for.
    pub const fn budget(&self) -> Budget {
        self.budget
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

    /// Runs the prefix, then performs the release: revokes the prefix's capabilities,
    /// waits the release delay, reverts every change the prefix made, and returns the
    /// compromised identity's channels with what was reverted. The caller then starts
    /// the base's actors for it.
    pub async fn run(&mut self) -> (Option<NetworkChannels<PublicKeyOf<P>>>, Release) {
        // The compromised identity's inbox: recorded until the release, then returned.
        let (stop, stopped) = oneshot::channel::<()>();
        let inbox = self.receivers.take().map(|receivers| {
            let log = self.shared.inbox.clone();
            let shared = self.shared.clone();
            self.context
                .child("inbox")
                .spawn(move |_| inbox_task::<P>(receivers, log, shared, stopped))
        });
        self.install_block_gate();
        if let Some(prefix) = self.prefix.take() {
            let cx = PrefixContext {
                context: self.context.child("prefix"),
                shared: self.shared.clone(),
            };
            prefix.run(cx).await;
        }
        // The handoff: the context no longer reaches anything.
        self.shared.revoked.store(true, Ordering::Relaxed);
        if !self.budget.release.is_zero() {
            self.context.sleep(self.budget.release).await;
        }
        let mut release = self.revert().await;
        self.recording.store(false, Ordering::Relaxed);
        stop.send_lossy(());
        let receivers = match inbox {
            Some(handle) => handle.await.ok(),
            None => None,
        };
        let senders = self.shared.senders.lock().take();
        let channels = match (senders, receivers) {
            (Some((vs, cs, rs)), Some((vr, cr, rr))) => Some(((vs, vr), (cs, cr), (rs, rr))),
            _ => None,
        };
        release.base = self.finalized();
        self.shared.observer.released(&release);
        (channels, release)
    }

    /// Checks that the compromised identity's required actors run, and reports it.
    pub fn check(&self, at: &'static str) -> ActorCheck {
        let check = self.registry.check(at, &self.required);
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
            .filter_map(|tap| {
                tap.activities
                    .lock()
                    .iter()
                    .filter(|entry| matches!(entry.value, Activity::Finalization(_)))
                    .map(|entry| entry.value.view().get())
                    .max()
            })
            .max()
            .unwrap_or(0)
    }

    fn install_block_gate(&self) {
        let gate = self.shared.block_gate.clone();
        let participants = self.shared.participants.clone();
        self.shared.relay.set_gate(
            move |sender, sender_tag, recipient, _tag, payload, contents| {
                let mut gate = gate.lock();
                let Some(index) = participants.iter().position(|key| key == recipient) else {
                    return false;
                };
                let Some(filter) = gate.filters.get(&index).cloned() else {
                    return false;
                };
                if !filter(block_relay::mock_block_view(contents), payload) {
                    return false;
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

    /// Reverts every change of the prefix: latency overrides removed, links restored to
    /// the base's, crashed replicas restarted, and only then gates opened and held blocks
    /// delivered, so a restarted replica's new receivers and application get what was held
    /// for it.
    async fn revert(&mut self) -> Release {
        let mut release = Release::default();
        let latencies = std::mem::take(&mut *self.shared.latencies.lock());
        for replica in latencies {
            if let Some(key) = self.shared.key(replica) {
                self.shared.relay.set_latency(&key, None);
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
                    .expect("the base's link is restored");
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
            let held = tap.gate.lock().held.len();
            let has_filter = tap.gate.lock().hold.is_some();
            if held > 0 || has_filter {
                release.gates.push(tap.index);
            }
            release.delivered += tap.open();
        }
        self.shared.relay.clear_gate();
        let held = {
            let mut gate = self.shared.block_gate.lock();
            gate.filters.clear();
            std::mem::take(&mut gate.held)
        };
        for (sender, tag, recipient, payload, contents) in held {
            release.blocks +=
                self.shared
                    .relay
                    .redeliver(&sender, tag, recipient, (payload, contents));
        }
        release
    }
}

/// Records what the compromised identity receives until `stop`, then returns its
/// receivers.
async fn inbox_task<P: Simplex>(
    (mut votes, mut certificates, mut resolver): Receivers<PublicKeyOf<P>>,
    log: Arc<Mutex<Vec<Recorded<Inbound>>>>,
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
        let (seq, run) = shared.observer.position();
        let from = shared.participants.iter().position(|key| key == &sender);
        log.lock().push(Recorded {
            value: Inbound {
                from,
                channel,
                payload,
            },
            stamp: Stamp { seq, run },
        });
    }
    (votes, certificates, resolver)
}

/// Crash-stops honest replica `tap`: aborts and awaits its tasks.
async fn crash<P: Simplex>(tap: &ReplicaTap<P>) -> bool {
    let (app, engine) = {
        let mut incarnation = tap.incarnation.lock();
        if incarnation.respawn.is_none() {
            return false;
        }
        (incarnation.app.take(), incarnation.engine.take())
    };
    let crashed = engine.is_some();
    for handle in [engine, app].into_iter().flatten() {
        handle.abort();
        let _ = handle.await;
    }
    crashed
}

/// Restarts a crashed honest replica from its journal, on its partition, with its
/// retained reporter, behind its gate and recorders.
async fn restart<P: Simplex>(shared: &Shared<P>, tap: &Arc<ReplicaTap<P>>) -> bool {
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
    shared.relay.forget_closed(&key);
    let (app, engine) = respawn(channels);
    let mut incarnation = tap.incarnation.lock();
    incarnation.app = Some(app);
    incarnation.engine = Some(engine);
    incarnation.respawn = Some(respawn);
    true
}

/// The restricted capabilities a [Prefix] drives the system with. Every capability
/// ends at the handoff: the runner then takes back the compromised identity's
/// channels and reverts every change made through this context.
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

    /// The leader of `view` under the honest engines' elector.
    pub fn leader(&self, view: View) -> usize {
        (self.shared.leader)(view)
    }

    /// Sleeps `duration` of simulated time.
    pub async fn sleep(&self, duration: Duration) {
        self.context.sleep(duration).await;
    }

    /// The simulated time since the start of the run.
    pub fn now(&self) -> Duration {
        self.context
            .current()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
    }

    /// The position a query takes now, for a witness that names a moment.
    pub fn stamp(&self) -> Stamp {
        let (seq, run) = self.shared.observer.position();
        Stamp { seq, run }
    }

    /// B's signing scheme.
    pub fn scheme(&self) -> Option<&P::Scheme> {
        self.shared.scheme.as_ref()
    }

    /// Sends `message` as B on its own `channel` to the participants `recipients`;
    /// returns how many it went to. Nothing goes out after the handoff.
    pub fn send(&self, channel: Channel, recipients: &[usize], message: impl Into<IoBuf>) -> usize {
        if self.shared.revoked.load(Ordering::Relaxed) {
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
        let sender = match channel {
            Channel::Vote => votes,
            Channel::Certificate => certificates,
            Channel::Resolver => resolver,
        };
        commonware_p2p::Sender::send(sender, Recipients::Some(keys), message.into(), true).len()
    }

    /// Everything B received so far, stamped.
    pub fn inbox(&self) -> Vec<Recorded<Inbound>> {
        self.shared.inbox.lock().clone()
    }

    /// Builds a mock block for `round` on `parent` as B would, without sending it;
    /// returns its digest.
    pub fn block(&self, round: Round, parent: Sha256Digest) -> Sha256Digest {
        let nonce = self.shared.nonce.fetch_add(1, Ordering::Relaxed);
        let (digest, contents) = block_relay::mock_block(round, parent, nonce);
        self.shared.made.lock().insert(digest, contents);
        digest
    }

    /// Sends the block B built with [Self::block] to `recipients`, through the base's
    /// block relay; false for a block B did not build, and after the handoff.
    pub fn send_block(&self, digest: Sha256Digest, recipients: &[usize]) -> bool {
        if self.shared.revoked.load(Ordering::Relaxed) {
            return false;
        }
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
        self.shared
            .relay
            .broadcast(&byzantine, Recipients::Some(keys), (digest, contents));
        true
    }

    /// Holds, from now on, every message to honest `replica` that `hold` accepts, until
    /// it is passed or the release; replaces an earlier filter.
    pub fn hold(&self, replica: usize, hold: impl Fn(&Inbound) -> bool + Send + Sync + 'static) {
        if let Some(tap) = self.shared.tap(replica) {
            tap.gate.lock().hold = Some(Arc::new(hold));
        }
    }

    /// Delivers to honest `replica` the held messages `select` accepts, in arrival
    /// order; returns how many.
    pub fn pass(&self, replica: usize, select: impl Fn(&Inbound) -> bool) -> usize {
        let Some(tap) = self.shared.tap(replica) else {
            return 0;
        };
        let participants = self.shared.participants.clone();
        tap.gate.lock().pass(|channel, sender, payload| {
            select(&Inbound {
                from: participants.iter().position(|key| key == sender),
                channel,
                payload: payload.clone(),
            })
        })
    }

    /// The messages held for honest `replica`, in arrival order.
    pub fn held(&self, replica: usize) -> Vec<Inbound> {
        let Some(tap) = self.shared.tap(replica) else {
            return Vec::new();
        };
        tap.gate
            .lock()
            .held
            .iter()
            .map(|(channel, sender, payload)| Inbound {
                from: tap.position(sender),
                channel: *channel,
                payload: payload.clone(),
            })
            .collect()
    }

    /// Stops holding for honest `replica` and delivers what it holds.
    pub fn open(&self, replica: usize) -> usize {
        self.shared.tap(replica).map_or(0, |tap| tap.open())
    }

    /// Holds, from now on, every block to honest `replica` whose view and digest `hold`
    /// accepts, until passed or the release.
    pub fn hold_blocks(
        &self,
        replica: usize,
        hold: impl Fn(Option<View>, &Sha256Digest) -> bool + Send + Sync + 'static,
    ) {
        if self.shared.tap(replica).is_some() {
            self.shared
                .block_gate
                .lock()
                .filters
                .insert(replica, Arc::new(hold));
        }
    }

    /// Delivers to honest `replica` the held blocks `select` accepts; returns how many its
    /// application took (none while it is crashed: the block is then lost, as on a link).
    pub fn pass_blocks(
        &self,
        replica: usize,
        select: impl Fn(Option<View>, &Sha256Digest) -> bool,
    ) -> usize {
        let Some(key) = self.shared.tap(replica).and(self.shared.key(replica)) else {
            return 0;
        };
        let passed: Vec<_> = {
            let mut gate = self.shared.block_gate.lock();
            let (passed, kept) = std::mem::take(&mut gate.held).into_iter().partition(
                |(_, _, recipient, payload, contents)| {
                    recipient == &key && select(block_relay::mock_block_view(contents), payload)
                },
            );
            gate.held = kept;
            passed
        };
        passed
            .into_iter()
            .map(|(sender, tag, recipient, payload, contents)| {
                self.shared
                    .relay
                    .redeliver(&sender, tag, recipient, (payload, contents))
            })
            .sum()
    }

    /// What honest `replica`'s engine received through its gate, stamped.
    pub fn deliveries(&self, replica: usize) -> Vec<Recorded<Inbound>> {
        self.shared
            .tap(replica)
            .map_or_else(Vec::new, |tap| tap.deliveries.lock().clone())
    }

    /// What honest `replica`'s engine reported, stamped.
    pub fn activities(&self, replica: usize) -> Vec<Recorded<ActivityOf<P>>> {
        self.shared
            .tap(replica)
            .map_or_else(Vec::new, |tap| tap.activities.lock().clone())
    }

    /// What honest `replica`'s automaton was asked and answered, stamped.
    pub fn automaton(&self, replica: usize) -> Vec<Recorded<AutomatonEvent>> {
        self.shared
            .tap(replica)
            .map_or_else(Vec::new, |tap| tap.automaton.lock().clone())
    }

    /// Every election honest `replica`'s voter ran, by view, stamped. The voter
    /// also elects the next term's leader ahead of entering it, so a view can
    /// appear early and more than once.
    pub fn elections(&self, replica: usize) -> Vec<Recorded<(View, usize)>> {
        self.shared
            .tap(replica)
            .map_or_else(Vec::new, |tap| tap.elections.lock().clone())
    }

    /// The peers honest `replica` blocked, stamped.
    pub fn blocks(&self, replica: usize) -> Vec<Recorded<usize>> {
        self.shared
            .tap(replica)
            .map_or_else(Vec::new, |tap| tap.blocks.lock().clone())
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
    /// release, which restores the base's.
    pub async fn set_link(&self, from: usize, to: usize, link: Option<Link>) -> bool {
        if self.shared.revoked.load(Ordering::Relaxed) || from == to {
            return false;
        }
        let (Some(sender), Some(receiver)) = (self.shared.key(from), self.shared.key(to)) else {
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
    /// restores the base's.
    pub fn set_latency(&self, replica: usize, latencies: Option<Latencies>) -> bool {
        let Some(key) = self.shared.tap(replica).and(self.shared.key(replica)) else {
            return false;
        };
        self.shared.relay.set_latency(&key, latencies);
        self.shared.latencies.lock().insert(replica);
        true
    }

    /// Crash-stops honest `replica`: its engine and application tasks are aborted and
    /// awaited. The release restarts it if the prefix did not.
    pub async fn crash(&self, replica: usize) -> bool {
        match self.shared.tap(replica) {
            Some(tap) => crash(tap).await,
            None => false,
        }
    }

    /// Restarts crashed honest `replica` from its journal, on its partition, with its
    /// retained reporter.
    pub async fn restart(&self, replica: usize) -> bool {
        match self.shared.tap(replica).cloned() {
            Some(tap) => restart(&self.shared, &tap).await,
            None => false,
        }
    }

    /// Whether honest `replica` is crashed.
    pub fn crashed(&self, replica: usize) -> bool {
        self.shared.tap(replica).is_some_and(|tap| tap.crashed())
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
/// release, with its sampled faulty views moved `view_offset` views later; returns
/// its task. `marker` is set when the Disrupter's task first polls its vote receiver.
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
        Epoch::new(EPOCH),
        vote,
        certificate,
        resolver,
        relay,
        None,
        view_offset,
    )
}

/// A [Prefix] that does nothing, the type of an absent hook.
pub struct NoPrefix;

impl<P: Simplex> Prefix<P> for NoPrefix {
    fn plan(&mut self, _pins: &mut Pins<'_>) -> Budget {
        Budget::default()
    }

    fn run(self: Box<Self>, _cx: PrefixContext<P>) -> PrefixFuture {
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::Runner as _;

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
            let mut automaton = TapAutomaton {
                inner: silent.clone(),
                tap: tap.clone(),
                context: Arc::new(Mutex::new(context.child("tap"))),
            };
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
            let mut automaton = TapAutomaton {
                inner: silent.clone(),
                tap: tap.clone(),
                context: Arc::new(Mutex::new(context.child("tap"))),
            };
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
                    relay: relay.clone(),
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
        let mut pins = Pins::new(&mut input, false);
        pins.term_length(TermLength::ONE);
        assert_eq!(pins.input().optimistic_views, ViewDelta::new(3));
        assert!(!pins.lookahead(ViewDelta::new(4)));
        assert!(pins.lookahead(ViewDelta::zero()));
        assert!(pins.configuration(N4F1C3));
        assert_eq!(pins.input().certify, CertifyChoice::Always);
        assert!(!pins.configuration(crate::N4F3C1));
        let mut twins = Pins::new(&mut input, true);
        assert!(!twins.configuration(N4F0C4));
        assert_eq!(input.configuration, N4F1C3);
    }
}
