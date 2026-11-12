//! The environment of a restart run: the crash and restart schedule over the
//! correct nodes and the conditions of the links among them.
//!
//! Neither is adversarial. Every identity is correct, every engine runs the
//! real code, and a link delays or loses a message but never changes it.
//!
//! A [`Program`] lays both out in time. The restart schedule is drawn from
//! the run's tape with the sampler the stateful restart targets use. A
//! ceremony lasts far longer than the sampler's delays, so each event also
//! draws from the tape how far its delay is stretched and how long its
//! identity stays down. The events run one after another, so at most one
//! identity is down at any moment. The temporary cuts come from the input's
//! controls and also run one after another, on their own timeline, so a cut
//! may overlap a crash.
//!
//! A program also carries the [`Pacing`] of the run: which of the durable
//! writes an engine makes shortly before one of its crashes are held, so that
//! the crash falls between two of them. A driver paces an engine by giving it
//! a secret store paced by [`Program::pacing`]. An identity whose writes are
//! held is slow, so the pacing holds writes only for the identity the
//! schedule crashes next, and only once the identity that was down before it
//! is back: one identity at a time is down or slow.
//!
//! [`play`] runs a [`Stack`] of engines under a program. A restart is an
//! abort of the engine's task, which crashes every actor the engine started,
//! followed by a new start of the same identity: the stack keeps the
//! identity's storage partitions and its secret store and registers its
//! channels again. Every instance of an engine is watched for as long as it
//! runs, and how it left the run is recorded for I8: an instance the schedule
//! aborted was crashed, and one whose task ended on its own stopped.
//!
//! An event runs at its time, or as soon as the stack has settled if that
//! comes first: once every engine that can still make progress has reached
//! the end of what the driver observes, waiting for the event's time would
//! only idle. An identity that is down, or that no peer can reach, makes no
//! progress until an event brings it back, so the stack settles without it.
//! The whole program is therefore played out unless the run's timeout or a
//! stopped engine ends it first, and a long outage costs no more than the
//! time the other identities need.
//!
//! A program may start one identity late ([`Program::joining`]): the others
//! start with the run, and the late one once the stack says so. Its own
//! outage counts from its start, and so does the restart schedule, unless
//! the program has the schedule's clock start with the run. The outages that
//! are still to come when the identity starts are then laid out one after
//! another, each due no sooner after the restart before it than the restart
//! schedule puts a crash after a restart, and the pacing is told the times
//! they got, so the schedule the pacing holds writes for is the schedule that
//! is played. Until the late identity has started it is as unavailable as one
//! that is down: no write is held, and a schedule whose clock starts with it
//! crashes nobody.
//!
//! A stack may have the end of its runs follow the engines a restart brought
//! back ([`Stack::follows`]). An engine that restarts where it had already
//! reached the end of what the driver observes settles the stack as soon as it
//! has set itself up. The run then goes on until every engine whose latest
//! instance a restart started has applied a block since, or [`FOLLOW`] has
//! passed since that restart, whichever comes first. The wait asserts
//! nothing: it ends silently at its bound, and the run's timeout ends it like
//! any other wait.
//!
//! Where a crash found its engine is read from the height the engine's
//! marshal reports in the runtime's metrics ([`processed_height`],
//! [`position`]). It is counted for a run's report and feeds no check. The
//! same height tells whether a restarted engine has applied a block.
//!
//! Nothing here depends on what the engines run, so the bootstrap, the
//! reshare restart, and the state-sync drivers share it.

use super::{
    EPOCH_LENGTH, Outcome, PublicKey,
    context::EngineContext,
    input::{Cut, CutScope, EnvironmentControls},
    invariants::{Exit, Instance},
    pacing::{EnginePacing, Pacing, SETTLE, Trace},
};
use crate::stateful::runner;
use commonware_consensus::types::{Epoch, EpochPhase, Epocher as _, FixedEpocher, Height};
use commonware_macros::select;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock as _, Handle, Metrics as _, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use futures::{
    FutureExt as _,
    future::{Either, pending},
};
use rand::RngExt as _;
use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::{Duration, SystemTime},
};

/// Choices of how often an event of the restart schedule doubles its delay:
/// from not at all to one time fewer than this. The shared sampler draws
/// delays of under a second, which suits a stateful run; a ceremony lasts
/// seconds to tens of seconds, and a crash must be able to land anywhere in
/// it, and after it.
const DELAY_DOUBLINGS: u8 = 6;

/// The unit of a crashed identity's downtime, and the shortest downtime: an
/// event keeps its identity down for one to [`MAX_DOWNTIME_STEPS`] of these,
/// doubled fewer than [`DOWNTIME_DOUBLINGS`] times.
pub(super) const DOWNTIME_STEP: Duration = Duration::from_millis(100);

/// Most downtime steps one event of the restart schedule may draw.
pub(super) const MAX_DOWNTIME_STEPS: u8 = 16;

/// Doublings an event of the restart schedule may apply to its downtime, so
/// that an identity can miss anything from a few messages to the whole
/// ceremony.
const DOWNTIME_DOUBLINGS: u8 = 6;

/// The unit of a cut's delay and of its duration. The input's documentation
/// states this value.
pub(super) const CUT_STEP: Duration = Duration::from_millis(500);

/// How long the end of a run follows an engine a restart brought back, at
/// most, counted from that restart. A stack that follows its engines
/// ([`Stack::follows`]) ends its run once every such engine has applied a
/// block since its restart or this much time has passed since it.
pub(super) const FOLLOW: Duration = Duration::from_millis(2_500);

/// How often the end of a run reads the heights the engines it follows have
/// processed.
const FOLLOW_STEP: Duration = Duration::from_millis(250);

/// Labels of the contexts the engines of a restart run run on. An engine's
/// marshal reports the height it has processed in a gauge named after them.
const CLUSTER_LABEL: &str = "correct";
const NODE_LABEL: &str = "node";
const ENGINE_LABEL: &str = "engine";
const INDEX_ATTRIBUTE: &str = "index";

/// The context the engines of a run on `context` are below.
pub(super) fn cluster(context: &deterministic::Context) -> deterministic::Context {
    context.child(CLUSTER_LABEL)
}

/// The context of the identity at `index`, below the context `cluster` of a
/// run's engines, and the context an engine of that identity runs on.
pub(super) fn contexts(
    cluster: &deterministic::Context,
    index: usize,
) -> (deterministic::Context, EngineContext) {
    let node = cluster
        .child(NODE_LABEL)
        .with_attribute(INDEX_ATTRIBUTE, index);
    let engine = EngineContext::new(node.child(ENGINE_LABEL), index);
    (node, engine)
}

/// The height the marshal of the engine at `index` reports as processed, read
/// from the metrics the engine registered below `cluster`. An engine that has
/// not started its marshal reports none.
pub(super) fn processed_height(cluster: &deterministic::Context, index: usize) -> Option<u64> {
    read_height(&cluster.encode(), index)
}

/// The height the marshal of the engine at `index` reports as processed in
/// `metrics`, the encoded metrics of a run.
fn read_height(metrics: &str, index: usize) -> Option<u64> {
    let gauge = format!("{CLUSTER_LABEL}_{NODE_LABEL}_{ENGINE_LABEL}_marshal_processed_height{{");
    let engine = format!("{INDEX_ATTRIBUTE}=\"{index}\"");
    metrics.lines().find_map(|line| {
        let (name, value) = line.rsplit_once(' ')?;
        (name.starts_with(&gauge) && name.contains(&engine))
            .then(|| value.parse().ok())
            .flatten()
    })
}

/// Where in a run a crash found its engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Landing {
    /// In the dealing window of an epoch the run was asked to complete.
    Dealing,
    /// In the inclusion window of such an epoch, before the engine applied
    /// the epoch's final block.
    Inclusion,
    /// At the boundary of such an epoch: the engine has registered the next
    /// epoch's scheme, and its marshal has not recorded the epoch's final
    /// block. Only a stack whose engines register schemes can tell, so
    /// [`position`] never places an engine here.
    Boundary,
    /// After the engine's marshal recorded the final block of the last such
    /// epoch.
    Finished,
}

/// The epoch an engine whose marshal has processed the chain up to
/// `processed` resumes in, and the window of that epoch a crash finds it in,
/// in a run that is over once its engines have entered the epoch `last`.
///
/// The engine resumes in the epoch of the next block it applies: one whose
/// marshal has recorded an epoch's final block resumes in the next epoch's
/// dealing window.
pub(super) fn position(processed: u64, last: Epoch) -> (Epoch, Landing) {
    let next = FixedEpocher::new(EPOCH_LENGTH)
        .containing(Height::new(processed + 1))
        .expect("every height belongs to an epoch");
    let landing = if next.epoch() >= last {
        Landing::Finished
    } else {
        match next.phase() {
            EpochPhase::Early => Landing::Dealing,
            EpochPhase::Midpoint | EpochPhase::Late => Landing::Inclusion,
        }
    };
    (next.epoch(), landing)
}

/// One step of a run's environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// Abort the engine of the identity at this index.
    Crash(usize),
    /// Start the engine of the identity at this index on what it retained.
    Restart(usize),
    /// Remove these directed links, each a `(sender, receiver)` pair.
    Cut(Vec<(usize, usize)>),
    /// Install these directed links again.
    Heal(Vec<(usize, usize)>),
}

/// One outage of a restart schedule: the crash of an identity's engine and
/// the restart that follows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Outage {
    /// When the engine is crashed, on the clock the outage is laid out on.
    pub(super) at: Duration,
    /// The identity whose engine is crashed.
    pub(super) victim: usize,
    /// How long the identity stays down.
    pub(super) downtime: Duration,
}

/// An identity that a program starts late, and what the restart schedule
/// does around its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Join {
    /// The identity that starts once [`Stack::joined`] resolves.
    pub(super) identity: usize,
    /// The identity's own outage, if it has one: how long after its start it
    /// is crashed, and how long it stays down.
    pub(super) restart: Option<(Duration, Duration)>,
    /// When the first outage of the restart schedule is due on the
    /// schedule's clock, in place of the delay the tape draws for it. The
    /// later outages keep their distances from it.
    pub(super) lead: Duration,
    /// Whether the schedule's clock starts with the run. Otherwise it starts
    /// when the identity does, and until then the identity counts as the
    /// run's impaired one.
    pub(super) early: bool,
}

/// The part of a program that waits for an identity to start late.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Joining {
    identity: usize,
    /// The restart schedule, on its own clock, and the identity's own outage,
    /// on a clock that starts when the identity does. Each outage is named by
    /// its position among the crashes the pacing was laid out with.
    schedule: VecDeque<(usize, Outage)>,
    own: Option<(usize, Outage)>,
    early: bool,
}

/// A run's environment laid out in time: every event with its offset from
/// the start of the run, in the order the events are due, and the pacing of
/// the engines' writes around the crashes among them.
///
/// A program that starts an identity late holds its outages apart: their
/// offsets are known only once the identity has started.
///
/// A program is played once: its pacing keeps what the run did.
pub(super) struct Program {
    events: Vec<(Duration, Event)>,
    joining: Option<Joining>,
    pacing: Pacing,
}

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Program")
            .field("events", &self.events)
            .field("joining", &self.joining)
            .finish_non_exhaustive()
    }
}

/// Two programs are the same when their events and their outages are. The
/// pacing is drawn from the tape they are drawn from.
impl PartialEq for Program {
    fn eq(&self, other: &Self) -> bool {
        self.events == other.events && self.joining == other.joining
    }
}

impl Eq for Program {}

/// The directed links `cut` removes among `identities` identities.
fn cut_links(cut: &Cut, identities: usize) -> Vec<(usize, usize)> {
    let identity = usize::from(cut.identity) % identities;
    let peers = (0..identities).filter(|peer| *peer != identity);
    match cut.scope {
        CutScope::Inbound => peers.map(|peer| (peer, identity)).collect(),
        CutScope::Outbound => peers.map(|peer| (identity, peer)).collect(),
        CutScope::Both => peers
            .flat_map(|peer| [(peer, identity), (identity, peer)])
            .collect(),
        CutScope::To(peer) => {
            let peer = usize::from(peer) % identities;
            if peer == identity {
                Vec::new()
            } else {
                vec![(identity, peer)]
            }
        }
    }
}

/// The restart schedule of `restarts` outages among `identities` identities
/// that the tape `entropy` draws: each outage waits, crashes its identity,
/// and brings it back before the next one starts.
pub(super) fn schedule(restarts: u8, entropy: &[u8], identities: usize) -> Vec<Outage> {
    let mut rng = FuzzRng::new(entropy.to_vec());
    let schedule = runner::restart_schedule(&mut rng, restarts, identities);
    let mut at = Duration::ZERO;
    schedule
        .into_iter()
        .map(|(delay, victim)| {
            let mut sample = [0u8; 2];
            rng.fill(&mut sample[..]);
            let delay = delay * (1 << (sample[0] % DELAY_DOUBLINGS));
            let steps = 1 + u32::from(sample[1] % MAX_DOWNTIME_STEPS);
            let doublings = (sample[1] / MAX_DOWNTIME_STEPS) % DOWNTIME_DOUBLINGS;
            at += delay;
            let outage = Outage {
                at,
                victim,
                downtime: DOWNTIME_STEP * steps * (1 << doublings),
            };
            at += outage.downtime;
            outage
        })
        .collect()
}

/// Lay `outages` out one after another from `free` on, in the order they are
/// due, so that at most one identity is down at any moment and the crash
/// after a restart is due no sooner than the restart schedule has it.
///
/// An outage that is due before `free` starts at `free`. One that is due
/// while an earlier one lasts, or less than [`SETTLE`] after that one's
/// restart is due, starts [`SETTLE`] after that restart is due: the shortest
/// delay [`schedule`] puts between a restart and the next crash, and the
/// time the pacing lets an identity settle before it holds a write of the
/// next one. Outages that are due together keep the order they are given in.
fn lay_out<T>(mut outages: Vec<(T, Outage)>, mut free: Duration) -> Vec<(T, Outage)> {
    outages.sort_by_key(|(_, outage)| outage.at);
    for (_, outage) in &mut outages {
        outage.at = outage.at.max(free);
        free = outage.at + outage.downtime + SETTLE;
    }
    outages
}

impl Program {
    /// Lay out the environment `controls` describe over `identities`
    /// identities, drawing the restart schedule from the tape `entropy`.
    pub(super) fn new(controls: &EnvironmentControls, entropy: Vec<u8>, identities: usize) -> Self {
        let mut events = Vec::new();

        // Each restart event waits, crashes its identity, and brings it back
        // before the next event starts.
        let mut crashes = Vec::new();
        for outage in schedule(controls.restarts, &entropy, identities) {
            events.push((outage.at, Event::Crash(outage.victim)));
            crashes.push((outage.at, outage.victim));
            events.push((outage.at + outage.downtime, Event::Restart(outage.victim)));
        }

        // Each cut is healed before the next one starts.
        let mut at = Duration::ZERO;
        for cut in &controls.cuts {
            let links = cut_links(cut, identities);
            at += CUT_STEP * u32::from(cut.delay);
            events.push((at, Event::Cut(links.clone())));
            at += CUT_STEP * u32::from(cut.duration);
            events.push((at, Event::Heal(links)));
        }

        // The sort is stable, so each timeline keeps its own order.
        events.sort_by_key(|(at, _)| *at);
        Self {
            events,
            joining: None,
            pacing: Pacing::new(&entropy, &crashes, identities),
        }
    }

    /// Lay out a run among `identities` identities in which the identity
    /// `join` names starts late, with a restart schedule of `restarts`
    /// outages drawn from the tape `entropy` and no cut.
    ///
    /// The schedule is the one [`Program::new`] draws from the same tape,
    /// with its first outage due when `join` says. The pacing draws for
    /// every outage of it and for the late identity's own, and learns when
    /// each is due once the identity has started.
    pub(super) fn joining(restarts: u8, entropy: Vec<u8>, identities: usize, join: Join) -> Self {
        let mut outages = schedule(restarts, &entropy, identities);
        if let Some(drawn) = outages.first().map(|first| first.at) {
            for outage in &mut outages {
                outage.at = outage.at - drawn + join.lead;
            }
        }
        let own = join.restart.map(|(delay, downtime)| Outage {
            at: delay,
            victim: join.identity,
            downtime,
        });
        Self::late(join.identity, outages, own, join.early, |crashes| {
            Pacing::new(&entropy, crashes, identities)
        })
    }

    /// A program that starts `identity` late, with the restart schedule
    /// `outages` on the schedule's clock, which starts with the run if
    /// `early`, and the identity's own outage `own` on a clock that starts
    /// when the identity does. `pace` lays out the pacing of the crashes it
    /// is given: those of the schedule, then the identity's own.
    fn late(
        identity: usize,
        outages: Vec<Outage>,
        own: Option<Outage>,
        early: bool,
        pace: impl FnOnce(&[(Duration, usize)]) -> Pacing,
    ) -> Self {
        let crashes: Vec<_> = outages
            .iter()
            .chain(&own)
            .map(|outage| (outage.at, outage.victim))
            .collect();
        let pacing = pace(&crashes);
        let own = own.map(|own| (outages.len(), own));
        let schedule: VecDeque<_> = outages.into_iter().enumerate().collect();

        // Until the identity starts, the pacing holds the crashes that can
        // come before it does: those of a schedule whose clock starts with
        // the run.
        let joining = Joining {
            identity,
            schedule,
            own,
            early,
        };
        pacing.reschedule(&joining.due());
        Self {
            events: Vec::new(),
            joining: Some(joining),
            pacing,
        }
    }

    /// The pacing of the writes of the engine of the identity at `index`.
    pub(super) fn pacing(&self, index: usize) -> EnginePacing {
        self.pacing.engine(index)
    }

    /// The events with their offsets from the start of the run.
    #[cfg(test)]
    pub(super) fn events(&self) -> &[(Duration, Event)] {
        &self.events
    }

    /// The restart schedule of a program that starts an identity late, on
    /// the schedule's clock, and the identity's own outage, on a clock that
    /// starts when the identity does.
    #[cfg(test)]
    pub(super) fn outages(&self) -> (Vec<Outage>, Option<Outage>) {
        let joining = self
            .joining
            .as_ref()
            .expect("the program starts an identity late");
        (
            joining.schedule.iter().map(|(_, outage)| *outage).collect(),
            joining.own.map(|(_, outage)| outage),
        )
    }

    /// The outages of a program that starts an identity late as the
    /// environment lays them out if the identity starts `now` into the run
    /// with every outage still to come, in the order they are played.
    #[cfg(test)]
    pub(super) fn laid_out(&self, now: Duration) -> Vec<Outage> {
        let joining = self
            .joining
            .clone()
            .expect("the program starts an identity late");
        let laid = joining.remaining(now);
        laid.into_iter().map(|(_, outage)| outage).collect()
    }
}

impl Joining {
    /// The crashes that can come before the late identity starts, for the
    /// pacing: those of the schedule, if its clock started with the run.
    fn due(&self) -> Vec<(usize, Duration)> {
        if !self.early {
            return Vec::new();
        }
        self.schedule
            .iter()
            .map(|(position, outage)| (*position, outage.at))
            .collect()
    }

    /// The outages that are still to come when the late identity starts,
    /// `now` into the run, laid out one after another with their offsets
    /// from the start of the run (see [`lay_out`]).
    ///
    /// The identity's own outage counts from its start, and so does the
    /// schedule unless its clock started with the run. Of two outages due
    /// together, the identity's own goes first. The first of them may be due
    /// with the identity's start: nothing is waited for after a first start.
    fn remaining(self, now: Duration) -> Vec<(usize, Outage)> {
        let origin = if self.early { Duration::ZERO } else { now };
        let own = self.own.map(|(position, outage)| {
            let at = now + outage.at;
            (position, Outage { at, ..outage })
        });
        let rest = self.schedule.into_iter().map(|(position, outage)| {
            let at = origin + outage.at;
            (position, Outage { at, ..outage })
        });
        lay_out(own.into_iter().chain(rest).collect(), now)
    }
}

/// The engines a restart driver runs: one per identity, each of which the
/// environment may crash and start again.
pub(super) trait Stack {
    /// Start the engine of the identity at `index` and return its handle.
    ///
    /// This is both the first start and every restart. A restart finds the
    /// storage partitions and the secret store the identity's previous
    /// engine left, and runs under the same key over the same channels,
    /// registered again.
    fn start(&mut self, index: usize) -> impl Future<Output = Handle<()>> + Send;

    /// Note that the schedule is about to crash the engine of the identity at
    /// `index`, which is still running.
    fn crashing(&mut self, index: usize);

    /// Resolve once the engine of every identity not marked in `absent` has
    /// reached the end of what the driver observes of it.
    ///
    /// An absent identity is down or cut off from every peer.
    fn settled(&mut self, absent: &[bool]) -> impl Future<Output = ()> + Send;

    /// Resolve once the identity a program starts late is to start.
    ///
    /// Only a program that starts an identity late asks. The future may be
    /// dropped and asked for again.
    fn joined(&mut self) -> impl Future<Output = ()> + Send {
        pending()
    }

    /// Whether the end of a run follows the engines a restart brought back
    /// (see [`FOLLOW`]). The run of a stack that does not ends as soon as
    /// the stack has settled.
    fn follows(&self) -> bool {
        false
    }
}

/// What the end of a run saw of an engine whose latest instance a restart
/// started. It is counted for a run's report and feeds no check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Followed {
    /// The identity whose engine was restarted.
    pub(super) engine: usize,
    /// The simulated time from that restart to the end of the run.
    pub(super) lasted: Duration,
    /// How far the height the engine's marshal has processed is past the
    /// height it had processed when the engine was crashed: the blocks the
    /// engine applied since its restart, less those it applied a second
    /// time.
    pub(super) blocks: u64,
    /// Whether the end of the run waited for the engine until [`FOLLOW`] had
    /// passed since its restart, and not until it applied a block.
    pub(super) expired: bool,
}

/// The engines a restart brought back, for the end of a run to follow.
struct Follower {
    /// The context the heights the engines have processed are read through.
    context: deterministic::Context,
    /// The height the marshal of each identity's engine had processed when
    /// the engine was last crashed, if it was.
    left: Vec<Option<u64>>,
    /// When the latest instance of each identity's engine started, if a
    /// restart started it.
    since: Vec<Option<SystemTime>>,
    /// The identities whose time ran out before their engine applied a
    /// block.
    expired: Vec<bool>,
}

impl Follower {
    fn new(context: deterministic::Context, identities: usize) -> Self {
        Self {
            context,
            left: vec![None; identities],
            since: vec![None; identities],
            expired: vec![false; identities],
        }
    }

    /// Note that the engine of the identity at `index`, which is still
    /// running, is about to be crashed.
    fn crashing(&mut self, index: usize) {
        // An engine crashed before its marshal has reported a height is
        // where its last crash left it, or at the start of the chain.
        let processed = processed_height(&self.context, index).or(self.left[index]);
        self.left[index] = Some(processed.unwrap_or_default());
        self.since[index] = None;
        self.expired[index] = false;
    }

    /// Note that a new instance of the engine of the identity at `index` has
    /// started.
    fn started(&mut self, index: usize) {
        if self.left[index].is_some() {
            self.since[index] = Some(self.context.current());
        }
    }

    /// Resolve once every engine a restart brought back has applied a block
    /// since that restart, or [`FOLLOW`] has passed since it.
    ///
    /// The height an engine had processed when it was crashed is the height
    /// its restart resumes from, or is ahead of it by the heights whose
    /// record the crash dropped, so an engine past it has applied a block.
    async fn settled(&mut self) {
        // The engines still waited for, each with the end of its time.
        let mut waiting: Vec<(usize, SystemTime)> = self
            .since
            .iter()
            .enumerate()
            .filter_map(|(index, since)| Some((index, (*since)? + FOLLOW)))
            .collect();
        while !waiting.is_empty() {
            let now = self.context.current();
            let metrics = self.context.encode();
            waiting.retain(|(index, until)| {
                if read_height(&metrics, *index) > self.left[*index] {
                    return false;
                }
                self.expired[*index] = now >= *until;
                now < *until
            });
            let Some(next) = waiting.iter().map(|(_, until)| *until).min() else {
                return;
            };
            self.context.sleep_until(next.min(now + FOLLOW_STEP)).await;
        }
    }

    /// What the run saw of every engine a restart brought back, in identity
    /// order.
    fn followed(&self) -> Vec<Followed> {
        let now = self.context.current();
        let metrics = self.context.encode();
        self.since
            .iter()
            .enumerate()
            .filter_map(|(engine, since)| {
                let lasted = now
                    .duration_since((*since)?)
                    .expect("simulated time does not run backwards");
                let left = self.left[engine].unwrap_or_default();
                Some(Followed {
                    engine,
                    lasted,
                    blocks: read_height(&metrics, engine)
                        .unwrap_or(left)
                        .saturating_sub(left),
                    expired: self.expired[engine],
                })
            })
            .collect()
    }
}

/// What a run under a [`Program`] came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Played {
    /// Why the run stopped.
    pub(super) outcome: Outcome,
    /// Every engine instance the run started, in the order they started.
    pub(super) instances: Vec<Instance>,
    /// The simulated time the run took.
    pub(super) elapsed: Duration,
    /// What the program's pacing did: the writes it held, how each ended,
    /// and the outages of the engines.
    pub(super) paced: Trace,
    /// What the end of the run saw of the engines a restart brought back, if
    /// the stack follows them.
    pub(super) followed: Vec<Followed>,
}

impl Played {
    /// How many engines whose latest instance a restart started the end of
    /// the run waited for until [`FOLLOW`] had passed since that restart.
    pub(super) fn expired(&self) -> usize {
        self.followed.iter().filter(|engine| engine.expired).count()
    }

    /// The engine the last restart of the run brought back, as the end of
    /// the run saw it.
    pub(super) fn last_restarted(&self) -> Option<&Followed> {
        self.followed.iter().min_by_key(|engine| engine.lasted)
    }
}

/// Why a run ended before its program was played out and its stack settled.
enum Interrupt {
    /// The engine of the identity at this index ended on its own.
    Stopped(usize),
    /// The run's bounded timeout expired.
    Timeout,
}

/// The engines of a run: the instance each identity is running and every
/// instance the run started.
struct Engines {
    /// The handle of each identity's engine, or none while it is down.
    running: Vec<Option<Handle<()>>>,
    /// The position in `instances` of each identity's latest instance.
    current: Vec<usize>,
    instances: Vec<Instance>,
    /// When the run started, and when it gives up.
    start: SystemTime,
    deadline: SystemTime,
    /// The pacing of the engines' writes, told of every start and crash.
    pacing: Pacing,
    /// The engines a restart brought back, if the stack follows them.
    follower: Option<Follower>,
}

impl Engines {
    /// Start the engine of the identity at `index` as a new instance.
    async fn start<S: Stack>(&mut self, stack: &mut S, index: usize) {
        self.running[index] = Some(stack.start(index).await);

        // The identity is up from here: the engine is spawned, and none of
        // its tasks runs before this task yields.
        self.pacing.started(index);
        if let Some(follower) = &mut self.follower {
            follower.started(index);
        }
        self.current[index] = self.instances.len();
        self.instances.push(Instance {
            engine: index,
            exit: Exit::Running,
        });
    }

    /// Crash the engine of the identity at `index`.
    async fn crash<S: Stack>(&mut self, stack: &mut S, index: usize) -> Result<(), Interrupt> {
        let mut handle = self.running[index]
            .take()
            .expect("the schedule crashes only a running engine");

        // An engine whose task has already ended was not crashed.
        if (&mut handle).now_or_never().is_some() {
            return Err(Interrupt::Stopped(index));
        }
        if let Some(follower) = &mut self.follower {
            follower.crashing(index);
        }
        stack.crashing(index);
        self.pacing.crashing(index);

        // Aborting the engine's task aborts every task below it, and the
        // handle resolves once the engine is gone.
        handle.abort();
        let _ = handle.await;
        self.instances[self.current[index]].exit = Exit::Crashed;
        Ok(())
    }

    /// Run the engines that start with the run until `stack` says the
    /// identity `joining` starts late is to start, and start it. Returns the
    /// outages that are still to come as events.
    ///
    /// A schedule whose clock started with the run is played meanwhile. An
    /// outage of it that names the late identity does nothing, and an
    /// identity that is down when the late one is to start comes back first,
    /// after the shortest downtime at least.
    async fn join<S: Stack>(
        &mut self,
        context: &deterministic::Context,
        stack: &mut S,
        mut joining: Joining,
    ) -> Result<Vec<(Duration, Event)>, Interrupt> {
        loop {
            let due = match joining.schedule.front() {
                Some((_, outage)) if joining.early => {
                    Either::Left(context.sleep_until(self.start + outage.at))
                }
                _ => Either::Right(pending()),
            };
            let arrived = self
                .wait(context, async {
                    select! {
                        _ = stack.joined() => true,
                        _ = due => false,
                    }
                })
                .await?;
            if arrived {
                break;
            }
            let (_, outage) = joining.schedule.pop_front().expect("an outage was due");

            // An identity that has not started is not crashed.
            if outage.victim == joining.identity {
                self.pacing.reschedule(&joining.due());
                continue;
            }
            self.crash(stack, outage.victim).await?;
            let crashed = context.current();
            let back = context.sleep_until(self.start + outage.at + outage.downtime);
            let arrived = self
                .wait(context, async {
                    select! {
                        _ = stack.joined() => true,
                        _ = back => false,
                    }
                })
                .await?;
            if arrived {
                let up = context.sleep_until(crashed + DOWNTIME_STEP);
                self.wait(context, up).await?;
            }
            self.start(stack, outage.victim).await;
            if arrived {
                break;
            }
        }

        // The pacing learns when each outage that is still to come is due
        // before the identity starts: no write is held until it has.
        let now = context
            .current()
            .duration_since(self.start)
            .expect("simulated time does not run backwards");
        let identity = joining.identity;
        let remaining = joining.remaining(now);
        let crashes: Vec<_> = remaining
            .iter()
            .map(|(position, outage)| (*position, outage.at))
            .collect();
        self.pacing.reschedule(&crashes);
        self.start(stack, identity).await;
        Ok(remaining
            .into_iter()
            .flat_map(|(_, outage)| {
                [
                    (outage.at, Event::Crash(outage.victim)),
                    (outage.at + outage.downtime, Event::Restart(outage.victim)),
                ]
            })
            .collect())
    }

    /// Wait until the engines a restart brought back have been followed (see
    /// [`Follower::settled`]), if the stack follows them.
    async fn follow(&mut self, context: &deterministic::Context) -> Result<(), Interrupt> {
        let Some(mut follower) = self.follower.take() else {
            return Ok(());
        };
        let followed = self.wait(context, follower.settled()).await;
        self.follower = Some(follower);
        followed
    }

    /// Wait for `ready`, unless an engine stops or the deadline passes first.
    async fn wait<T>(
        &mut self,
        context: &deterministic::Context,
        ready: impl Future<Output = T>,
    ) -> Result<T, Interrupt> {
        let stopped = poll_fn(|cx| {
            for (index, handle) in self.running.iter_mut().enumerate() {
                if let Some(handle) = handle
                    && Pin::new(handle).poll(cx).is_ready()
                {
                    return Poll::Ready(index);
                }
            }
            Poll::Pending
        });
        select! {
            index = stopped => Err(Interrupt::Stopped(index)),
            _ = context.sleep_until(self.deadline) => Err(Interrupt::Timeout),
            ready = ready => Ok(ready),
        }
    }
}

/// Play `events` over `engines` and wait for `stack` to settle. If `joining`
/// is given, its identity starts late and its outages are the events.
#[allow(clippy::too_many_arguments)]
async fn drive<S: Stack>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    participants: &[PublicKey],
    link: &Link,
    events: Vec<(Duration, Event)>,
    joining: Option<Joining>,
    stack: &mut S,
    engines: &mut Engines,
) -> Result<(), Interrupt> {
    let identities = participants.len();
    let late = joining.as_ref().map(|joining| joining.identity);
    for index in (0..identities).filter(|index| Some(*index) != late) {
        engines.start(stack, index).await;
    }
    let events = match joining {
        Some(joining) => engines.join(context, stack, joining).await?,
        None => events,
    };

    // The identity that is down and when it was crashed, and the links that
    // are cut.
    let mut down = None;
    let mut cut = BTreeSet::new();
    for (at, event) in events {
        // An identity makes no progress while it is down or while no peer
        // reaches it.
        let absent: Vec<bool> = (0..identities)
            .map(|index| {
                down.is_some_and(|(victim, _)| victim == index)
                    || (0..identities)
                        .filter(|peer| *peer != index)
                        .all(|peer| cut.contains(&(peer, index)))
            })
            .collect();

        // The event is due at its time, or once nothing is left to observe.
        let due = context.sleep_until(engines.start + at);
        let early = stack.settled(&absent);
        engines
            .wait(context, async {
                select! {
                    _ = due => {},
                    _ = early => {},
                }
            })
            .await?;

        match event {
            Event::Crash(index) => {
                engines.crash(stack, index).await?;
                down = Some((index, context.current()));
            }
            Event::Restart(index) => {
                // A restart brought forward still follows a downtime.
                if let Some((_, crashed)) = down.take() {
                    let up = context.sleep_until(crashed + DOWNTIME_STEP);
                    engines.wait(context, up).await?;
                }
                engines.start(stack, index).await;
            }
            Event::Cut(links) => {
                for (sender, receiver) in links {
                    oracle
                        .remove_link(participants[sender].clone(), participants[receiver].clone())
                        .await
                        .expect("a cut removes a link that is up");
                    cut.insert((sender, receiver));
                }
            }
            Event::Heal(links) => {
                for (sender, receiver) in links {
                    oracle
                        .add_link(
                            participants[sender].clone(),
                            participants[receiver].clone(),
                            link.clone(),
                        )
                        .await
                        .expect("a cut restores a link it removed");
                    cut.remove(&(sender, receiver));
                }
            }
        }
    }

    // Every crash has been followed by its restart and every cut healed.
    let absent = vec![false; identities];
    engines.wait(context, stack.settled(&absent)).await?;

    // An engine a restart brought back may have settled the stack as it set
    // itself up.
    engines.follow(context).await
}

/// Run the engines of `stack`, one per identity of `participants`, under
/// `program`, with every link the program restores under the conditions of
/// `link`.
///
/// The run ends when the program has been played out, the stack has settled,
/// and the engines a restart brought back have been followed, if the stack
/// follows them (see [`FOLLOW`]); when an engine stops on its own; or when
/// `timeout` of simulated time has passed.
pub(super) async fn play<S: Stack>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    participants: &[PublicKey],
    link: Link,
    program: Program,
    stack: &mut S,
    timeout: Duration,
) -> Played {
    let start = context.current();
    let Program {
        events,
        joining,
        pacing,
    } = program;
    pacing.begin(context.child("pacing"));

    // An identity that starts late is the run's impaired identity until it
    // has started, unless the schedule's clock starts without it.
    if let Some(joining) = joining.as_ref().filter(|joining| !joining.early) {
        pacing.absent(joining.identity);
    }
    let mut engines = Engines {
        running: Vec::with_capacity(participants.len()),
        current: Vec::with_capacity(participants.len()),
        instances: Vec::with_capacity(participants.len()),
        start,
        deadline: start + timeout,
        pacing,
        follower: stack
            .follows()
            .then(|| Follower::new(context.child("follower"), participants.len())),
    };
    engines.running.resize_with(participants.len(), || None);
    engines.current.resize(participants.len(), 0);
    let outcome = match drive(
        context,
        oracle,
        participants,
        &link,
        events,
        joining,
        stack,
        &mut engines,
    )
    .await
    {
        Ok(()) => Outcome::Completed,
        Err(Interrupt::Timeout) => Outcome::Timeout,
        Err(Interrupt::Stopped(index)) => {
            engines.instances[engines.current[index]].exit = Exit::Stopped;
            Outcome::Stopped
        }
    };
    let elapsed = context
        .current()
        .duration_since(start)
        .expect("simulated time does not run backwards");
    Played {
        outcome,
        paced: engines.pacing.trace(),
        followed: engines
            .follower
            .as_ref()
            .map(Follower::followed)
            .unwrap_or_default(),
        instances: engines.instances,
        elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            BOOTSTRAP_RUN_TIMEOUT, LinkControls,
            fixtures::{committee, tape},
            invariants,
            pacing::{Operation, SETTLE, Secret},
        },
        stateful::stack::TEST_QUOTA,
    };
    use commonware_p2p::{Receiver as _, Recipients, Sender as _};
    use commonware_runtime::{
        Runner as _, Spawner as _,
        telemetry::metrics::{GaugeExt as _, MetricsExt as _},
    };
    use commonware_utils::{NZUsize, sync::Mutex};
    use std::sync::Arc;

    const IDENTITIES: usize = 4;

    impl Program {
        /// A program of `events` among `identities` identities whose every
        /// crash reaches `reach` back and holds one in `odds` of the writes
        /// its engine starts in that window, or none of them if `odds` is
        /// zero. The stage of each held write is drawn from `tape`.
        pub(in crate::dkg) fn scripted(
            events: Vec<(Duration, Event)>,
            tape: &[u8],
            identities: usize,
            reach: Duration,
            odds: u8,
        ) -> Self {
            let crashes: Vec<_> = events
                .iter()
                .filter_map(|(at, event)| match event {
                    Event::Crash(victim) => Some((*at, *victim)),
                    _ => None,
                })
                .collect();
            Self {
                events,
                joining: None,
                pacing: Pacing::scripted(tape, &crashes, identities, reach, odds),
            }
        }

        /// A program of `events` among [`IDENTITIES`] identities that holds
        /// no write.
        fn unpaced(events: Vec<(Duration, Event)>) -> Self {
            Self::scripted(events, &[], IDENTITIES, Duration::ZERO, 0)
        }

        /// A program among [`IDENTITIES`] identities that starts the last of
        /// them late, with the restart schedule `outages` and the late
        /// identity's own outage `own`. Every crash reaches `reach` back and
        /// holds one in `odds` of the writes its engine starts in that
        /// window, or none of them if `odds` is zero.
        fn latecomer(
            outages: Vec<Outage>,
            own: Option<Outage>,
            early: bool,
            reach: Duration,
            odds: u8,
        ) -> Self {
            Self::late(LATE, outages, own, early, |crashes| {
                Pacing::scripted(&[1], crashes, IDENTITIES, reach, odds)
            })
        }
    }

    /// The identity the programs here start late.
    const LATE: usize = IDENTITIES - 1;

    fn outage(at: u64, victim: usize, downtime: u64) -> Outage {
        Outage {
            at: Duration::from_millis(at),
            victim,
            downtime: Duration::from_millis(downtime),
        }
    }

    const LINKS: LinkControls = LinkControls {
        latency_ms: 10,
        jitter_ms: 0,
        delivery_percent: 100,
    };

    fn controls(restarts: u8, cuts: Vec<Cut>) -> EnvironmentControls {
        EnvironmentControls {
            restarts,
            links: LINKS,
            cuts,
        }
    }

    fn at(millis: u64, event: Event) -> (Duration, Event) {
        (Duration::from_millis(millis), event)
    }

    /// How a fake engine ends on its own.
    #[derive(Clone, Copy)]
    enum Quit {
        Returns,
        Panics,
    }

    /// When a fake engine that quits does so, after it starts.
    const QUITS_AFTER: Duration = Duration::from_millis(100);

    /// A stack whose engines only wait.
    struct Fake {
        context: deterministic::Context,
        /// The identity whose engine ends on its own, and how.
        quits: Option<(usize, Quit)>,
        /// When the engines settle.
        settles_at: SystemTime,
        /// The identity whose engine settles only once it has been absent
        /// and has come back, if any.
        lagging: Option<usize>,
        /// Whether the lagging identity has been absent.
        lagged: bool,
        /// The absent identities each call to `settled` was given.
        asked: Arc<Mutex<Vec<Vec<usize>>>>,
        /// The identities started and the identities crashed, in order.
        started: Arc<Mutex<Vec<usize>>>,
        crashed: Arc<Mutex<Vec<usize>>>,
    }

    impl Stack for Fake {
        async fn start(&mut self, index: usize) -> Handle<()> {
            self.started.lock().push(index);
            let quit = self
                .quits
                .filter(|(quitter, _)| *quitter == index)
                .map(|(_, quit)| quit);
            self.context
                .child("engine")
                .with_attribute("index", index)
                .spawn(move |context| async move {
                    let Some(quit) = quit else {
                        return std::future::pending().await;
                    };
                    context.sleep(QUITS_AFTER).await;
                    if matches!(quit, Quit::Panics) {
                        panic!("boom");
                    }
                })
        }

        fn crashing(&mut self, index: usize) {
            self.crashed.lock().push(index);
        }

        async fn settled(&mut self, absent: &[bool]) {
            self.asked.lock().push(
                absent
                    .iter()
                    .enumerate()
                    .filter_map(|(index, absent)| absent.then_some(index))
                    .collect(),
            );
            if let Some(lagging) = self.lagging {
                if absent[lagging] {
                    self.lagged = true;
                } else if !self.lagged {
                    return std::future::pending().await;
                }
            }
            self.context.sleep_until(self.settles_at).await;
        }
    }

    /// What one played program left behind.
    struct Run {
        played: Played,
        started: Vec<usize>,
        crashed: Vec<usize>,
        /// The distinct sets of absent identities the stack was asked to
        /// settle without, in the order they first appeared.
        absent: Vec<Vec<usize>>,
    }

    /// Play `events` for at most `timeout` over fake engines that settle
    /// `settles_after` into the run.
    fn run(
        events: Vec<(Duration, Event)>,
        quits: Option<(usize, Quit)>,
        settles_after: Duration,
        timeout: Duration,
    ) -> Run {
        run_lagging(events, quits, None, settles_after, timeout)
    }

    /// Like [`run`], with the engine of `lagging` settling only once its
    /// identity has been absent and has come back.
    fn run_lagging(
        events: Vec<(Duration, Event)>,
        quits: Option<(usize, Quit)>,
        lagging: Option<usize>,
        settles_after: Duration,
        timeout: Duration,
    ) -> Run {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, _) = runner::tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let participants = committee();
                let oracle =
                    runner::network_with(&context, &participants, LINKS.link(), NZUsize!(1)).await;
                let (started, crashed) = (Arc::default(), Arc::default());
                let asked = Arc::default();
                let mut stack = Fake {
                    settles_at: context.current() + settles_after,
                    context: context.child("fake"),
                    quits,
                    lagging,
                    lagged: false,
                    asked: Arc::clone(&asked),
                    started: Arc::clone(&started),
                    crashed: Arc::clone(&crashed),
                };
                let played = play(
                    &context,
                    &oracle,
                    &participants,
                    LINKS.link(),
                    Program::unpaced(events),
                    &mut stack,
                    timeout,
                )
                .await;
                let (started, crashed) = (started.lock().clone(), crashed.lock().clone());
                let mut absent: Vec<Vec<usize>> = Vec::new();
                for asked in asked.lock().iter() {
                    if !absent.contains(asked) {
                        absent.push(asked.clone());
                    }
                }
                Run {
                    played,
                    started,
                    crashed,
                    absent,
                }
            })
        });
        result.expect("the root task returns")
    }

    /// Later than any event of the programs below, and than their timeout.
    const NEVER: Duration = Duration::from_secs(60);
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Whether `elapsed` is `expected`, give or take the executor's ticks.
    fn about(elapsed: Duration, expected: Duration) -> bool {
        elapsed >= expected && elapsed < expected + Duration::from_millis(20)
    }

    fn exits(run: &Run) -> Vec<(usize, Exit)> {
        run.played
            .instances
            .iter()
            .map(|instance| (instance.engine, instance.exit))
            .collect()
    }

    #[test]
    fn restart_events_run_one_at_a_time() {
        for seed in 0..=255 {
            let program = Program::new(&controls(4, Vec::new()), tape(seed), IDENTITIES);
            assert_eq!(program.events.len(), 8);
            let mut previous = Duration::ZERO;
            for pair in program.events.chunks(2) {
                let [
                    (crash, Event::Crash(victim)),
                    (restart, Event::Restart(restarted)),
                ] = pair
                else {
                    panic!("every crash is followed by its restart: {pair:?}");
                };
                assert_eq!(victim, restarted);
                assert!(*victim < IDENTITIES);

                // The shared sampler's delay, doubled at most five times. It
                // is never shorter than the time the pacing lets an identity
                // settle after its restart.
                let delay = *crash - previous;
                assert!(delay >= Duration::from_millis(50), "{delay:?}");
                assert!(delay >= SETTLE, "{delay:?}");
                assert!(delay <= Duration::from_millis(800) * 32, "{delay:?}");
                let downtime = *restart - *crash;
                assert!(downtime >= DOWNTIME_STEP, "{downtime:?}");
                assert!(downtime <= DOWNTIME_STEP * 16 * 32, "{downtime:?}");
                previous = *restart;
            }
        }
    }

    #[test]
    fn restart_schedule_spans_startup_to_long_outages() {
        let events: Vec<_> = (0..=255)
            .flat_map(|seed| Program::new(&controls(4, Vec::new()), tape(seed), IDENTITIES).events)
            .collect();
        let crashes = events
            .chunks(2)
            .map(|pair| pair[0].0)
            .collect::<Vec<Duration>>();
        let downtimes = events
            .chunks(2)
            .map(|pair| pair[1].0 - pair[0].0)
            .collect::<Vec<Duration>>();
        assert!(crashes.iter().any(|at| *at <= Duration::from_millis(100)));
        assert!(crashes.iter().any(|at| *at >= Duration::from_secs(20)));
        assert!(downtimes.contains(&DOWNTIME_STEP));
        assert!(
            downtimes
                .iter()
                .any(|down| *down >= Duration::from_secs(30))
        );
    }

    #[test]
    fn schedule_depends_only_on_the_tape() {
        let draw = |seed| Program::new(&controls(3, Vec::new()), tape(seed), IDENTITIES);
        assert_eq!(draw(7), draw(7));
        assert_ne!(draw(7), draw(8));
    }

    #[test]
    fn cut_scopes_name_their_links() {
        let cut = |identity, scope| {
            cut_links(
                &Cut {
                    delay: 0,
                    duration: 1,
                    identity,
                    scope,
                },
                IDENTITIES,
            )
        };
        assert_eq!(cut(1, CutScope::Inbound), vec![(0, 1), (2, 1), (3, 1)]);
        assert_eq!(cut(1, CutScope::Outbound), vec![(1, 0), (1, 2), (1, 3)]);
        assert_eq!(
            cut(3, CutScope::Both),
            vec![(0, 3), (3, 0), (1, 3), (3, 1), (2, 3), (3, 2)]
        );
        assert_eq!(cut(2, CutScope::To(0)), vec![(2, 0)]);
        assert_eq!(cut(2, CutScope::To(2)), Vec::new());

        // An identity past the last one wraps.
        assert_eq!(cut(5, CutScope::To(4)), vec![(1, 0)]);
    }

    #[test]
    fn cuts_run_one_after_another_beside_the_restarts() {
        let cuts = vec![
            Cut {
                delay: 2,
                duration: 3,
                identity: 0,
                scope: CutScope::To(1),
            },
            Cut {
                delay: 0,
                duration: 1,
                identity: 2,
                scope: CutScope::To(3),
            },
        ];
        let program = Program::new(&controls(0, cuts.clone()), tape(0), IDENTITIES);
        assert_eq!(
            program.events,
            vec![
                (CUT_STEP * 2, Event::Cut(vec![(0, 1)])),
                (CUT_STEP * 5, Event::Heal(vec![(0, 1)])),
                (CUT_STEP * 5, Event::Cut(vec![(2, 3)])),
                (CUT_STEP * 6, Event::Heal(vec![(2, 3)])),
            ]
        );

        // Adding restarts leaves the cuts where they were, and the merged
        // program in time order.
        let merged = Program::new(&controls(2, cuts), tape(0), IDENTITIES);
        let cut_events: Vec<_> = merged
            .events
            .iter()
            .filter(|(_, event)| matches!(event, Event::Cut(_) | Event::Heal(_)))
            .cloned()
            .collect();
        assert_eq!(cut_events, program.events);
        assert_eq!(merged.events.len(), 8);
        assert!(merged.events.is_sorted_by_key(|(at, _)| *at));
    }

    #[test]
    fn crashed_instance_is_restarted_and_not_stopped() {
        let run = run(
            vec![
                at(100, Event::Crash(2)),
                at(300, Event::Restart(2)),
                at(400, Event::Crash(0)),
                at(500, Event::Restart(0)),
            ],
            None,
            Duration::from_millis(600),
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Completed);
        assert!(about(run.played.elapsed, Duration::from_millis(600)));
        assert_eq!(run.started, vec![0, 1, 2, 3, 2, 0]);
        assert_eq!(run.crashed, vec![2, 0]);
        assert_eq!(
            exits(&run),
            vec![
                (0, Exit::Crashed),
                (1, Exit::Running),
                (2, Exit::Crashed),
                (3, Exit::Running),
                (2, Exit::Running),
                (0, Exit::Running),
            ]
        );
        assert_eq!(
            invariants::check_instances_running(&run.played.instances),
            2
        );
    }

    #[test]
    fn engine_down_when_the_run_ends_was_crashed() {
        let run = run(
            vec![at(100, Event::Crash(1)), at(900, Event::Restart(1))],
            None,
            NEVER,
            Duration::from_millis(500),
        );
        assert_eq!(run.played.outcome, Outcome::Timeout);
        assert_eq!(run.started, vec![0, 1, 2, 3]);
        assert_eq!(exits(&run)[1], (1, Exit::Crashed));
        assert_eq!(
            invariants::check_instances_running(&run.played.instances),
            1
        );
    }

    /// The engine ends before the schedule would have crashed it, so the
    /// crash that was due never excuses it.
    #[test]
    fn engine_that_returns_is_stopped() {
        let run = run(
            vec![at(400, Event::Crash(2)), at(500, Event::Restart(2))],
            Some((2, Quit::Returns)),
            NEVER,
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Stopped);
        assert!(about(run.played.elapsed, QUITS_AFTER));
        assert!(run.crashed.is_empty());
        assert_eq!(exits(&run)[2], (2, Exit::Stopped));
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn engine_that_returns_is_rejected() {
        let run = run(
            vec![at(400, Event::Crash(2)), at(500, Event::Restart(2))],
            Some((2, Quit::Returns)),
            NEVER,
            TIMEOUT,
        );
        invariants::check_instances_running(&run.played.instances);
    }

    /// An instance a restart brought back is watched like the first one.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [1] stopped before the run ended")]
    fn restarted_engine_that_fails_is_rejected() {
        let run = run(
            vec![at(10, Event::Crash(1)), at(200, Event::Restart(1))],
            Some((1, Quit::Panics)),
            NEVER,
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Stopped);
        assert_eq!(
            exits(&run)
                .into_iter()
                .filter(|(engine, _)| *engine == 1)
                .collect::<Vec<_>>(),
            vec![(1, Exit::Crashed), (1, Exit::Stopped)]
        );
        invariants::check_instances_running(&run.played.instances);
    }

    #[test]
    fn run_that_never_settles_times_out() {
        let run = run(Vec::new(), None, NEVER, TIMEOUT);
        assert_eq!(run.played.outcome, Outcome::Timeout);
        assert!(about(run.played.elapsed, TIMEOUT));
        assert!(exits(&run).iter().all(|(_, exit)| *exit == Exit::Running));
        assert_eq!(
            invariants::check_instances_running(&run.played.instances),
            0
        );
    }

    /// Once the stack has settled, the rest of the program runs without
    /// waiting for its times, and a restart still follows a downtime.
    #[test]
    fn events_run_early_once_the_stack_settles() {
        let run = run(
            vec![
                at(100, Event::Crash(3)),
                at(5_000, Event::Restart(3)),
                at(6_000, Event::Crash(0)),
                at(7_000, Event::Restart(0)),
            ],
            None,
            Duration::from_millis(150),
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Completed);
        assert_eq!(run.started, vec![0, 1, 2, 3, 3, 0]);
        assert_eq!(run.crashed, vec![3, 0]);

        // Identity 3 comes back a downtime after the stack settles at 150,
        // and identity 0 is crashed at once and comes back a downtime later.
        assert!(about(
            run.played.elapsed,
            Duration::from_millis(100) + DOWNTIME_STEP * 2
        ));
        assert_eq!(
            invariants::check_instances_running(&run.played.instances),
            2
        );

        // The stack does not follow its engines, so the run ends with the
        // last restart.
        assert_eq!(run.played.followed, Vec::new());
    }

    /// An identity that is down keeps nobody waiting: once the others have
    /// settled its restart is brought forward.
    #[test]
    fn stack_settles_without_the_identity_that_is_down() {
        let run = run_lagging(
            vec![at(100, Event::Crash(2)), at(9_000, Event::Restart(2))],
            None,
            Some(2),
            Duration::from_millis(500),
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Completed);
        assert_eq!(run.started, vec![0, 1, 2, 3, 2]);
        assert_eq!(run.absent, vec![vec![], vec![2]]);
        assert!(about(run.played.elapsed, Duration::from_millis(500)));
    }

    /// An identity no peer reaches keeps nobody waiting either, while one
    /// that only cannot be heard, or that lost a single link, does.
    #[test]
    fn stack_settles_without_the_identity_no_peer_reaches() {
        let inbound = vec![(0, 1), (2, 1), (3, 1)];
        let run = run_lagging(
            vec![
                at(100, Event::Cut(inbound.clone())),
                at(9_000, Event::Heal(inbound)),
            ],
            None,
            Some(1),
            Duration::from_millis(500),
            TIMEOUT,
        );
        assert_eq!(run.played.outcome, Outcome::Completed);
        assert_eq!(run.absent, vec![vec![], vec![1]]);
        assert!(about(run.played.elapsed, Duration::from_millis(500)));

        for links in [vec![(1, 0), (1, 2), (1, 3)], vec![(0, 1), (2, 1)]] {
            let run = run_lagging(
                vec![
                    at(100, Event::Cut(links.clone())),
                    at(2_000, Event::Heal(links)),
                ],
                None,
                Some(1),
                Duration::from_millis(500),
                Duration::from_secs(3),
            );

            // The heal waits for its time, and identity 1 was never absent.
            assert_eq!(run.played.outcome, Outcome::Timeout);
            assert_eq!(run.absent, vec![Vec::<usize>::new()]);
        }
    }

    /// A stack that is settled from the start and has the end of its runs
    /// follow the engines a restart brought back. Its engines only report a
    /// height the way a marshal does: an instance reports the height its
    /// identity has reached as it starts, and one more whenever it applies a
    /// block.
    struct Climbers {
        /// The context the engines of a run are below.
        context: deterministic::Context,
        /// How long the engine of each identity takes to apply a block, if
        /// it applies any.
        block: Vec<Option<Duration>>,
        /// The height each identity has reached, kept across its restarts.
        heights: Arc<Mutex<Vec<u64>>>,
    }

    impl Stack for Climbers {
        async fn start(&mut self, index: usize) -> Handle<()> {
            let (_, engine) = contexts(&self.context, index);
            let block = self.block[index];
            let heights = Arc::clone(&self.heights);
            engine.spawn(move |context| async move {
                let processed = context
                    .child("marshal")
                    .gauge("processed_height", "the height an engine has processed");
                loop {
                    let _ = processed.try_set(heights.lock()[index]);
                    match block {
                        Some(block) => context.sleep(block).await,
                        None => pending().await,
                    }
                    heights.lock()[index] += 1;
                }
            })
        }

        fn crashing(&mut self, _: usize) {}

        async fn settled(&mut self, _: &[bool]) {}

        fn follows(&self) -> bool {
            true
        }
    }

    /// Play `events` for at most `timeout` over [`Climbers`] whose engines
    /// take `block` to apply a block.
    fn climb(
        events: Vec<(Duration, Event)>,
        block: [Option<Duration>; IDENTITIES],
        timeout: Duration,
    ) -> Played {
        deterministic::Runner::default().start(|context| async move {
            let participants = committee();
            let oracle =
                runner::network_with(&context, &participants, LINKS.link(), NZUsize!(1)).await;
            let mut stack = Climbers {
                context: cluster(&context),
                block: block.to_vec(),
                heights: Arc::new(Mutex::new(vec![0; IDENTITIES])),
            };
            play(
                &context,
                &oracle,
                &participants,
                LINKS.link(),
                Program::unpaced(events),
                &mut stack,
                timeout,
            )
            .await
        })
    }

    /// Whether `elapsed` is `expected` or follows it by no more than the
    /// time between two readings of the heights, give or take the executor's
    /// ticks.
    fn read_after(elapsed: Duration, expected: Duration) -> bool {
        elapsed >= expected && elapsed < expected + FOLLOW_STEP + Duration::from_millis(20)
    }

    /// How long an engine of the tests below takes to apply a block.
    const BLOCK: Duration = Duration::from_millis(400);

    /// The stack is settled when the restart completes, and the run goes on
    /// until the engine the restart brought back has applied a block.
    #[test]
    fn restarted_engine_is_followed_until_it_applies_a_block() {
        let played = climb(
            vec![at(100, Event::Crash(2)), at(200, Event::Restart(2))],
            [None, None, Some(BLOCK), None],
            TIMEOUT,
        );
        assert_eq!(played.outcome, Outcome::Completed);

        // The crash is brought forward to the start of the run, and the
        // restart follows it by the shortest downtime.
        assert!(read_after(played.elapsed, DOWNTIME_STEP + BLOCK));
        let [followed] = played.followed[..] else {
            panic!("one engine was restarted: {:?}", played.followed);
        };
        assert_eq!(
            (followed.engine, followed.blocks, followed.expired),
            (2, 1, false)
        );
        assert!(read_after(followed.lasted, BLOCK));
        assert_eq!(played.expired(), 0);
        assert_eq!(played.last_restarted(), Some(&followed));
    }

    /// An engine that applies no block after its restart is waited for until
    /// [`FOLLOW`] has passed since the restart, and no longer.
    #[test]
    fn restarted_engine_that_applies_no_block_is_followed_for_a_bounded_time() {
        let played = climb(
            vec![at(100, Event::Crash(2)), at(200, Event::Restart(2))],
            [None; IDENTITIES],
            NEVER,
        );
        assert_eq!(played.outcome, Outcome::Completed);
        assert!(about(played.elapsed, DOWNTIME_STEP + FOLLOW));
        let [followed] = played.followed[..] else {
            panic!("one engine was restarted: {:?}", played.followed);
        };
        assert_eq!(
            (followed.engine, followed.blocks, followed.expired),
            (2, 0, true)
        );
        assert!(about(followed.lasted, FOLLOW));
        assert_eq!(played.expired(), 1);
    }

    /// The wait counts from each engine's own restart. An engine that
    /// applied a block before the program was played out is not waited for,
    /// and neither is an engine that was never restarted.
    #[test]
    fn each_restarted_engine_is_followed_from_its_own_restart() {
        let played = climb(
            vec![
                at(100, Event::Crash(1)),
                at(200, Event::Restart(1)),
                at(300, Event::Crash(3)),
                at(400, Event::Restart(3)),
            ],
            [Some(BLOCK), Some(Duration::from_millis(30)), None, None],
            NEVER,
        );
        assert_eq!(played.outcome, Outcome::Completed);

        // Identity 1 is back after one downtime and identity 3 after two,
        // and only identity 3 keeps the run going.
        assert!(about(played.elapsed, DOWNTIME_STEP * 2 + FOLLOW));
        let [first, second] = played.followed[..] else {
            panic!("two engines were restarted: {:?}", played.followed);
        };
        assert_eq!((first.engine, first.expired), (1, false));
        assert!(first.blocks > 0, "{first:?}");
        assert!(about(first.lasted, DOWNTIME_STEP + FOLLOW));
        assert_eq!((second.engine, second.blocks, second.expired), (3, 0, true));
        assert!(about(second.lasted, FOLLOW));
        assert_eq!(played.last_restarted(), Some(&second));

        // Without a restart the run ends as soon as the stack has settled.
        let played = climb(Vec::new(), [None; IDENTITIES], NEVER);
        assert_eq!(played.outcome, Outcome::Completed);
        assert_eq!((played.elapsed, played.followed.len()), (Duration::ZERO, 0));
    }

    /// The wait asserts nothing and is a wait like any other: the run's
    /// timeout ends it.
    #[test]
    fn timeout_ends_the_wait_for_a_restarted_engine() {
        let timeout = DOWNTIME_STEP + FOLLOW / 2;
        let played = climb(
            vec![at(100, Event::Crash(0)), at(200, Event::Restart(0))],
            [None; IDENTITIES],
            timeout,
        );
        assert_eq!(played.outcome, Outcome::Timeout);
        assert!(about(played.elapsed, timeout));
        let [followed] = played.followed[..] else {
            panic!("one engine was restarted: {:?}", played.followed);
        };
        assert_eq!(
            (followed.engine, followed.blocks, followed.expired),
            (0, 0, false)
        );
        assert!(followed.lasted < FOLLOW, "{followed:?}");
        assert_eq!(invariants::check_instances_running(&played.instances), 1);
    }

    /// A stack whose engines make a write of the DKG module's own state every
    /// ten milliseconds, paced by the program they are played under, and
    /// never settle.
    struct Writers {
        context: deterministic::Context,
        /// The pacing of each identity's engine.
        pacing: Vec<EnginePacing>,
        /// When an identity that starts late is to start.
        joins_at: SystemTime,
    }

    impl Writers {
        fn new(context: &deterministic::Context, program: &Program, joins_after: Duration) -> Self {
            Self {
                context: context.child("writers"),
                pacing: (0..IDENTITIES).map(|index| program.pacing(index)).collect(),
                joins_at: context.current() + joins_after,
            }
        }
    }

    impl Stack for Writers {
        async fn start(&mut self, index: usize) -> Handle<()> {
            let pacing = self.pacing[index].clone();
            self.context
                .child("writer")
                .with_attribute("index", index)
                .spawn(move |context| async move {
                    loop {
                        pacing
                            .write(Operation::Secret(Secret::Seed), async {})
                            .await;
                        context.sleep(Duration::from_millis(10)).await;
                    }
                })
        }

        fn crashing(&mut self, _: usize) {}

        async fn settled(&mut self, _: &[bool]) {
            std::future::pending().await
        }

        async fn joined(&mut self) {
            self.context.sleep_until(self.joins_at).await;
        }
    }

    /// Play `program` over [`Writers`] for at most `timeout`.
    fn write_under(program: Program, timeout: Duration) -> Played {
        write_joining(program, Duration::ZERO, timeout)
    }

    /// Play `program` over [`Writers`] for at most `timeout`, with the
    /// identity it starts late, if any, to start `joins_after` into the run.
    fn write_joining(program: Program, joins_after: Duration, timeout: Duration) -> Played {
        deterministic::Runner::default().start(|context| async move {
            let participants = committee();
            let oracle =
                runner::network_with(&context, &participants, LINKS.link(), NZUsize!(1)).await;
            let mut stack = Writers::new(&context, &program, joins_after);
            play(
                &context,
                &oracle,
                &participants,
                LINKS.link(),
                program,
                &mut stack,
                timeout,
            )
            .await
        })
    }

    /// Playing a program tells its pacing when the run begins and of every
    /// start and crash, so a write an engine makes in the window of its crash
    /// is held, the crash drops it, and the played run counts it. The writes
    /// of the other engines, and those the engine makes after it comes back,
    /// are not held.
    #[test]
    fn played_program_paces_the_writes_before_a_crash() {
        let program = Program::scripted(
            vec![at(100, Event::Crash(2)), at(300, Event::Restart(2))],
            &[1],
            IDENTITIES,
            Duration::from_millis(50),
            1,
        );
        let played = write_under(program, Duration::from_millis(500));
        assert_eq!(played.outcome, Outcome::Timeout);
        let trace = played.paced;
        let paced = trace.counts();
        assert_eq!(paced.crashes, 1, "{paced:?}");
        assert_eq!(paced.before + paced.durable, 1, "{paced:?}");
        assert_eq!(paced.dkg_before + paced.dkg_durable, 1, "{paced:?}");
        assert_eq!(
            (
                paced.unsynced,
                paced.resumed,
                paced.abandoned,
                paced.pending
            ),
            (0, 0, 0, 0),
            "{paced:?}"
        );
        let [hold] = trace.holds() else {
            panic!("one write was held: {trace:?}");
        };
        assert_eq!((hold.engine, hold.instance), (2, 1));
        assert_eq!(trace.dropped(2).len(), 1);
        assert_eq!(trace.overlaps(), 0);
    }

    /// The window of the second crash reaches back past the first identity's
    /// whole outage, and every write in a window is held. The second
    /// identity's writes are still not held until the first identity has
    /// been crashed, has come back, and has had its time to settle, so the
    /// two are never impaired together.
    #[test]
    fn held_writes_wait_for_the_identity_that_was_down_before() {
        let program = Program::scripted(
            vec![
                at(1_000, Event::Crash(0)),
                at(2_000, Event::Restart(0)),
                at(3_000, Event::Crash(1)),
                at(3_500, Event::Restart(1)),
            ],
            &[1],
            IDENTITIES,
            Duration::from_secs(8),
            1,
        );
        let played = write_under(program, Duration::from_secs(4));
        assert_eq!(played.outcome, Outcome::Timeout);
        let trace = played.paced;
        assert_eq!(trace.overlaps(), 0, "{trace:?}");
        let [first, second] = &trace.impairments()[..] else {
            panic!("each crashed identity was impaired once: {trace:?}");
        };
        assert_eq!((first.engine, second.engine), (0, 1));

        // Identity 0 is slow from the start of the run until its crash, and
        // down until its restart.
        assert!(first.from < Duration::from_millis(20), "{first:?}");
        let back = first.until.expect("identity 0 came back");
        assert!(about(back, Duration::from_secs(2)), "{first:?}");

        // Identity 1 is slow only once identity 0 has settled.
        assert!(second.from >= back + SETTLE, "{second:?}");
        assert!(second.from < back + SETTLE + Duration::from_millis(20));
        let back = second.until.expect("identity 1 came back");
        assert!(about(back, Duration::from_millis(3_500)), "{second:?}");

        // Each crash dropped the one write its engine had held, and nothing
        // else was held.
        assert_eq!(trace.holds().len(), 2, "{trace:?}");
        assert_eq!(trace.dropped(0).len(), 1);
        assert_eq!(trace.dropped(1).len(), 1);
    }

    /// Schedules drawn from the tape, with every crash holding every write
    /// its engine starts in the longest window: whatever the schedule, no
    /// two identities are impaired at once, and the crashes do find writes
    /// held.
    #[test]
    fn no_two_identities_are_impaired_at_once() {
        let mut dropped = 0;
        for seed in 0..48 {
            let events = Program::new(&controls(4, Vec::new()), tape(seed), IDENTITIES).events;
            let program =
                Program::scripted(events, &tape(seed), IDENTITIES, Duration::from_secs(8), 1);
            let played = write_under(program, BOOTSTRAP_RUN_TIMEOUT);
            let trace = played.paced;
            assert_eq!(trace.overlaps(), 0, "seed {seed}: {trace:?}");
            dropped += trace.counts().crashes;
        }
        assert!(dropped > 48, "{dropped}");
    }

    #[test]
    fn outages_are_laid_out_one_at_a_time() {
        let laid = |outages: Vec<Outage>, free| {
            lay_out(outages.into_iter().enumerate().collect(), free)
                .into_iter()
                .map(|(given, outage)| (given, outage.at.as_millis() as u64))
                .collect::<Vec<_>>()
        };
        assert!(laid(Vec::new(), Duration::ZERO).is_empty());

        // Outages that do not overlap keep their times, in the order they
        // are due.
        assert_eq!(
            laid(
                vec![outage(500, 3, 100), outage(50, 0, 200)],
                Duration::ZERO
            ),
            vec![(1, 50), (0, 500)]
        );

        // An outage that is due while another lasts starts once that one
        // has ended and its identity has settled, and so does the one after
        // it.
        let settle = SETTLE.as_millis() as u64;
        assert_eq!(
            laid(
                vec![
                    outage(70, 3, 300),
                    outage(100, 1, 400),
                    outage(150, 2, 50),
                    outage(2_000, 3, 10),
                ],
                Duration::ZERO
            ),
            vec![
                (0, 70),
                (1, 370 + settle),
                (2, 770 + 2 * settle),
                (3, 2_000)
            ]
        );

        // Of two outages due together, the one given first goes first.
        assert_eq!(
            laid(vec![outage(0, 2, 100), outage(0, 1, 100)], Duration::ZERO),
            vec![(0, 0), (1, 100 + settle)]
        );

        // An outage that is due before the first free moment starts there:
        // nothing has been restarted that it would have to wait for.
        assert_eq!(
            laid(
                vec![outage(900, 2, 100), outage(40, 1, 100)],
                Duration::from_millis(250)
            ),
            vec![(1, 250), (0, 900)]
        );

        // An outage that is due after another has ended, and sooner than
        // the restart schedule puts a crash after a restart, waits out the
        // difference. One that is due later keeps its time.
        assert_eq!(
            laid(
                vec![outage(0, 1, 100), outage(100 + settle - 1, 2, 100)],
                Duration::ZERO
            ),
            vec![(0, 0), (1, 100 + settle)]
        );
        assert_eq!(
            laid(
                vec![outage(0, 1, 100), outage(100 + settle + 1, 2, 100)],
                Duration::ZERO
            ),
            vec![(0, 0), (1, 100 + settle + 1)]
        );
    }

    /// The distance from each restart to the crash after it, in the order
    /// the outages are laid out, and the distance from `free` to the first
    /// crash.
    fn distances(laid: &[(usize, Outage)], free: Duration) -> (Duration, Vec<Duration>) {
        let first = laid.first().map_or(Duration::ZERO, |(_, first)| first.at) - free;
        let later = laid
            .windows(2)
            .map(|pair| pair[1].1.at - (pair[0].1.at + pair[0].1.downtime))
            .collect();
        (first, later)
    }

    /// Whatever the tape draws, and wherever the first outage of the
    /// schedule and the late identity's own are put, the crash after a
    /// laid-out restart is due no sooner than the crash after a restart of
    /// the restart schedule is. Only the first outage after the late
    /// identity's start is exempt, and it does fall with that start.
    #[test]
    fn laid_out_outages_keep_the_schedule_s_distance_after_a_restart() {
        let now = Duration::from_millis(1_234);
        let (mut pushed, mut immediate) = (0, 0);
        for seed in 0..=255u16 {
            // The shortest distance the restart schedule itself keeps.
            let drawn = schedule(4, &tape(seed), IDENTITIES);
            for pair in drawn.windows(2) {
                assert!(pair[1].at - (pair[0].at + pair[0].downtime) >= SETTLE);
            }

            for (lead, own) in [(0, 0), (0, 30), (20, 0), (70, 110), (640, 9_600)] {
                let join = Join {
                    identity: LATE,
                    restart: Some((
                        Duration::from_millis(own),
                        DOWNTIME_STEP * (1 + u32::from(seed % 16)),
                    )),
                    lead: Duration::from_millis(lead),
                    early: false,
                };
                let joining = Program::joining(3, tape(seed), IDENTITIES, join)
                    .joining
                    .expect("the program starts an identity late");
                let undelayed: Vec<_> = joining.clone().remaining(now);
                let (first, later) = distances(&undelayed, now);
                assert_eq!(first, Duration::from_millis(lead.min(own)));
                immediate += usize::from(first.is_zero());
                for distance in later {
                    assert!(distance >= SETTLE, "seed {seed}: {undelayed:?}");
                    pushed += usize::from(distance == SETTLE);
                }

                // No two of them overlap, and each stays down as long as it
                // was drawn to.
                let mut downtimes: Vec<_> = undelayed
                    .iter()
                    .map(|(position, outage)| (*position, outage.downtime))
                    .collect();
                downtimes.sort();
                let mut given: Vec<_> = joining
                    .schedule
                    .iter()
                    .chain(&joining.own)
                    .map(|(position, outage)| (*position, outage.downtime))
                    .collect();
                given.sort();
                assert_eq!(downtimes, given);
            }
        }
        assert!(pushed > 100, "{pushed}");
        assert!(immediate > 100, "{immediate}");
    }

    /// The schedule of a program that starts an identity late is the one
    /// the tape draws for every restart run, with its first outage due when
    /// the program is told and the others at their distances from it, and
    /// the late identity's own outage beside it.
    #[test]
    fn joining_schedule_is_the_tape_s_with_its_first_outage_moved() {
        for seed in 0..32 {
            let drawn = Program::new(&controls(3, Vec::new()), tape(seed), IDENTITIES).events;
            let lead = Duration::from_millis(u64::from(seed) * 10);
            let join = Join {
                identity: LATE,
                restart: Some((Duration::from_millis(70), Duration::from_millis(300))),
                lead,
                early: seed % 2 == 0,
            };
            let (schedule, own) = Program::joining(3, tape(seed), IDENTITIES, join).outages();
            assert_eq!(own, Some(outage(70, LATE, 300)));
            assert_eq!(schedule.len(), 3);
            assert_eq!(schedule[0].at, lead);
            let moved = drawn[0].0 - lead.min(drawn[0].0);
            let delayed = lead - lead.min(drawn[0].0);
            for (outage, pair) in schedule.iter().zip(drawn.chunks(2)) {
                assert_eq!(
                    pair[0],
                    (outage.at + moved - delayed, Event::Crash(outage.victim))
                );
                assert_eq!(
                    pair[1],
                    (
                        outage.at + outage.downtime + moved - delayed,
                        Event::Restart(outage.victim)
                    )
                );
            }
        }

        // A schedule of no outage has none to move.
        let join = Join {
            identity: LATE,
            restart: None,
            lead: Duration::from_millis(40),
            early: false,
        };
        let (schedule, own) = Program::joining(0, tape(0), IDENTITIES, join).outages();
        assert!(schedule.is_empty());
        assert_eq!(own, None);
    }

    /// What a stack was asked to do, and when, in milliseconds into the
    /// run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Did {
        Started(usize),
        Crashed(usize),
    }

    /// A stack of engines that only wait, one of which is to start late.
    struct Latecomer {
        fake: Fake,
        origin: SystemTime,
        /// When the late identity is to start, if ever.
        joins_at: Option<SystemTime>,
        log: Arc<Mutex<Vec<(u64, Did)>>>,
    }

    impl Latecomer {
        fn note(&self, did: Did) {
            let elapsed = self
                .fake
                .context
                .current()
                .duration_since(self.origin)
                .expect("simulated time does not run backwards");
            self.log.lock().push((elapsed.as_millis() as u64, did));
        }
    }

    impl Stack for Latecomer {
        async fn start(&mut self, index: usize) -> Handle<()> {
            self.note(Did::Started(index));
            self.fake.start(index).await
        }

        fn crashing(&mut self, index: usize) {
            self.note(Did::Crashed(index));
            self.fake.crashing(index);
        }

        async fn settled(&mut self, absent: &[bool]) {
            self.fake.settled(absent).await;
        }

        async fn joined(&mut self) {
            match self.joins_at {
                Some(at) => self.fake.context.sleep_until(at).await,
                None => std::future::pending().await,
            }
        }
    }

    /// Play `program`, which starts [`LATE`] late, over fake engines for at
    /// most `timeout`. The late identity is to start `joins_after` into the
    /// run, if at all, and the engines settle `settles_after` into it.
    /// Returns what the run came to and what the stack was asked to do.
    fn run_joining(
        program: Program,
        quits: Option<(usize, Quit)>,
        joins_after: Option<Duration>,
        settles_after: Duration,
        timeout: Duration,
    ) -> (Played, Vec<(u64, Did)>) {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, _) = runner::tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let participants = committee();
                let oracle =
                    runner::network_with(&context, &participants, LINKS.link(), NZUsize!(1)).await;
                let log = Arc::default();
                let origin = context.current();
                let mut stack = Latecomer {
                    fake: Fake {
                        settles_at: origin + settles_after,
                        context: context.child("fake"),
                        quits,
                        lagging: None,
                        lagged: false,
                        asked: Arc::default(),
                        started: Arc::default(),
                        crashed: Arc::default(),
                    },
                    origin,
                    joins_at: joins_after.map(|after| origin + after),
                    log: Arc::clone(&log),
                };
                let played = play(
                    &context,
                    &oracle,
                    &participants,
                    LINKS.link(),
                    program,
                    &mut stack,
                    timeout,
                )
                .await;
                let log = log.lock().clone();
                (played, log)
            })
        });
        result.expect("the root task returns")
    }

    /// Assert that `log` holds `expected`, in order, each at its time give
    /// or take the executor's ticks.
    fn assert_did(log: &[(u64, Did)], expected: &[(u64, Did)]) {
        assert_eq!(log.len(), expected.len(), "{log:?}");
        for ((at, did), (due, wanted)) in log.iter().zip(expected) {
            assert_eq!(did, wanted, "{log:?}");
            assert!(at >= due && *at < due + 20, "{log:?}");
        }
    }

    /// The late identity starts when the stack says, and the outages follow
    /// its start: its own on its own clock, the schedule's on a clock that
    /// starts with it, one after another. Until it has started nobody is
    /// crashed, and it is on the trace as the run's impaired identity.
    #[test]
    fn late_identity_starts_when_the_stack_says_and_the_outages_follow() {
        let program = Program::latecomer(
            vec![outage(100, 2, 200), outage(600, 0, 100)],
            Some(outage(150, LATE, 100)),
            false,
            Duration::ZERO,
            0,
        );
        let (played, log) = run_joining(
            program,
            None,
            Some(Duration::from_secs(1)),
            Duration::from_secs(2),
            TIMEOUT,
        );
        assert_eq!(played.outcome, Outcome::Completed);
        assert!(about(played.elapsed, Duration::from_secs(2)));

        // The late identity's own outage is due while identity 2 is down,
        // and starts once identity 2 is back and has had its time to settle.
        let settle = SETTLE.as_millis() as u64;
        assert_did(
            &log,
            &[
                (0, Did::Started(0)),
                (0, Did::Started(1)),
                (0, Did::Started(2)),
                (1_000, Did::Started(LATE)),
                (1_100, Did::Crashed(2)),
                (1_300, Did::Started(2)),
                (1_300 + settle, Did::Crashed(LATE)),
                (1_400 + settle, Did::Started(LATE)),
                (1_600, Did::Crashed(0)),
                (1_700, Did::Started(0)),
            ],
        );
        assert_eq!(invariants::check_instances_running(&played.instances), 3);
        let trace = played.paced;
        assert_eq!(trace.overlaps(), 0, "{trace:?}");
        let impairments = trace.impairments();
        assert_eq!(
            impairments
                .iter()
                .map(|impairment| impairment.engine)
                .collect::<Vec<_>>(),
            vec![LATE, 2, LATE, 0]
        );
        assert_eq!(impairments[0].from, Duration::ZERO);
        let started = impairments[0].until.expect("the late identity started");
        assert!(about(started, Duration::from_secs(1)));
    }

    /// With the schedule's clock starting with the run, an outage that is
    /// due before the late identity starts is played, one that names the
    /// late identity then does nothing, and an identity that is down when
    /// the late one is to start comes back first. The outages that are
    /// still to come keep their times, and the late identity's own counts
    /// from its start.
    #[test]
    fn schedule_whose_clock_starts_with_the_run_is_played_before_the_join() {
        let program = Program::latecomer(
            vec![
                outage(100, LATE, 100),
                outage(300, 1, 200),
                outage(900, 2, 5_000),
                outage(20_000, 0, 100),
            ],
            Some(outage(50, LATE, 100)),
            true,
            Duration::ZERO,
            0,
        );
        let (played, log) = run_joining(
            program,
            None,
            Some(Duration::from_secs(1)),
            Duration::from_millis(1_200),
            TIMEOUT,
        );
        assert_eq!(played.outcome, Outcome::Completed);

        // Identity 2 is brought back when the late identity is to start,
        // and the last outage runs once the stack has settled.
        assert_did(
            &log,
            &[
                (0, Did::Started(0)),
                (0, Did::Started(1)),
                (0, Did::Started(2)),
                (300, Did::Crashed(1)),
                (500, Did::Started(1)),
                (900, Did::Crashed(2)),
                (1_000, Did::Started(2)),
                (1_000, Did::Started(LATE)),
                (1_050, Did::Crashed(LATE)),
                (1_150, Did::Started(LATE)),
                (1_200, Did::Crashed(0)),
                (1_300, Did::Started(0)),
            ],
        );

        // The late identity is no impaired identity before it starts.
        let trace = played.paced;
        assert_eq!(trace.overlaps(), 0, "{trace:?}");
        assert_eq!(
            trace
                .impairments()
                .iter()
                .map(|impairment| impairment.engine)
                .collect::<Vec<_>>(),
            vec![1, 2, LATE, 0]
        );
    }

    /// An identity that is crashed just before the late one is to start
    /// stays down for the shortest downtime, and the late one waits for it.
    #[test]
    fn identity_down_at_the_join_comes_back_after_a_downtime() {
        let program =
            Program::latecomer(vec![outage(960, 1, 5_000)], None, true, Duration::ZERO, 0);
        let (played, log) = run_joining(
            program,
            None,
            Some(Duration::from_secs(1)),
            Duration::from_millis(1_500),
            TIMEOUT,
        );
        assert_eq!(played.outcome, Outcome::Completed);
        let back = 960 + DOWNTIME_STEP.as_millis() as u64;
        assert_did(
            &log,
            &[
                (0, Did::Started(0)),
                (0, Did::Started(1)),
                (0, Did::Started(2)),
                (960, Did::Crashed(1)),
                (back, Did::Started(1)),
                (back, Did::Started(LATE)),
            ],
        );
    }

    /// A run whose late identity is never to start ends at its timeout with
    /// the others running, and one in which an engine stops before that is
    /// stopped.
    #[test]
    fn run_ends_before_the_late_identity_starts() {
        let program = || {
            Program::latecomer(
                vec![outage(100, 1, 100)],
                Some(outage(0, LATE, 100)),
                false,
                Duration::ZERO,
                0,
            )
        };
        let (played, log) = run_joining(program(), None, None, NEVER, Duration::from_millis(500));
        assert_eq!(played.outcome, Outcome::Timeout);
        assert_did(
            &log,
            &[
                (0, Did::Started(0)),
                (0, Did::Started(1)),
                (0, Did::Started(2)),
            ],
        );
        assert_eq!(
            played.instances,
            (0..LATE)
                .map(|engine| Instance {
                    engine,
                    exit: Exit::Running
                })
                .collect::<Vec<_>>()
        );

        // The late identity never started, and it stayed the impaired one.
        let impairments = played.paced.impairments();
        assert_eq!(impairments.len(), 1);
        assert_eq!((impairments[0].engine, impairments[0].until), (LATE, None));

        let (played, _) = run_joining(program(), Some((1, Quit::Returns)), None, NEVER, TIMEOUT);
        assert_eq!(played.outcome, Outcome::Stopped);
        assert!(about(played.elapsed, QUITS_AFTER));
        assert_eq!(
            played.instances[1],
            Instance {
                engine: 1,
                exit: Exit::Stopped
            }
        );
    }

    /// The pacing of a program that starts an identity late holds the
    /// schedule that is played. No write is held before the late identity
    /// has started. Its own crash is on the schedule: the writes it makes
    /// from its start on are held and the crash drops one. The writes of
    /// the identity crashed after it are held once it is back and has had
    /// its time to settle, and the crash drops one of those too.
    #[test]
    fn late_identity_s_own_crash_is_paced() {
        let program = Program::latecomer(
            vec![outage(600, 1, 100)],
            Some(outage(200, LATE, 100)),
            false,
            Duration::from_secs(8),
            1,
        );
        let played = write_joining(program, Duration::from_secs(1), Duration::from_secs(2));
        assert_eq!(played.outcome, Outcome::Timeout);
        let trace = played.paced;
        assert_eq!(trace.overlaps(), 0, "{trace:?}");
        let [absence, own, next] = &trace.impairments()[..] else {
            panic!("three spans of impairment: {trace:?}");
        };
        assert_eq!((absence.engine, own.engine, next.engine), (LATE, LATE, 1));

        // The late identity is absent until it starts, slow from then on,
        // and down from its crash until its restart.
        assert_eq!(absence.from, Duration::ZERO);
        let started = absence.until.expect("the late identity started");
        assert!(about(started, Duration::from_secs(1)), "{absence:?}");
        assert!(own.from >= started, "{own:?}");
        assert!(own.from < started + Duration::from_millis(20), "{own:?}");
        let back = own.until.expect("the late identity came back");
        assert!(about(back, Duration::from_millis(1_300)), "{own:?}");

        // Identity 1 is slow only once the late identity has settled.
        assert!(next.from >= back + SETTLE, "{next:?}");
        assert!(next.from < back + SETTLE + Duration::from_millis(20));
        assert_eq!(trace.holds().len(), 2, "{trace:?}");
        assert_eq!(trace.dropped(LATE).len(), 1);
        assert_eq!(trace.dropped(1).len(), 1);
        assert_eq!(trace.interrupted(LATE), 1);
    }

    /// With the schedule's clock starting with the run, an identity is
    /// crashed before the late one starts, and no write of it is held: not
    /// every identity is up.
    #[test]
    fn nothing_is_held_before_the_late_identity_starts() {
        let program = Program::latecomer(
            vec![outage(300, 1, 100), outage(1_500, 2, 100)],
            None,
            true,
            Duration::from_secs(8),
            1,
        );
        let played = write_joining(program, Duration::from_secs(1), Duration::from_secs(2));
        let trace = played.paced;
        assert_eq!(trace.overlaps(), 0, "{trace:?}");
        assert!(trace.dropped(1).is_empty(), "{trace:?}");
        assert_eq!(trace.dropped(2).len(), 1, "{trace:?}");
        let [first, second] = &trace.impairments()[..] else {
            panic!("two spans of impairment: {trace:?}");
        };
        assert_eq!((first.engine, second.engine), (1, 2));
        assert!(about(first.from, Duration::from_millis(300)), "{first:?}");
        assert!(second.from >= Duration::from_secs(1), "{second:?}");
        assert!(second.from < Duration::from_millis(1_020), "{second:?}");
    }

    /// A cut link delivers nothing, the opposite direction keeps delivering,
    /// and the healed link delivers again.
    #[test]
    fn cut_link_drops_until_it_is_healed() {
        let config = deterministic::Config::new();
        let heard = deterministic::Runner::new(config).start(|context| async move {
            let participants = committee();
            let oracle =
                runner::network_with(&context, &participants, LINKS.link(), NZUsize!(1)).await;
            let mut endpoints = Vec::new();
            for identity in &participants[..2] {
                endpoints.push(
                    oracle
                        .control(identity.clone())
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("channel registration failed"),
                );
            }
            let (mut to_zero, mut from_zero) = endpoints.remove(1);
            let (mut to_one, mut from_one) = endpoints.remove(0);

            // Identity 0 and identity 1 send each other the time, every 100
            // milliseconds from 50 on.
            let (zero, one) = (participants[0].clone(), participants[1].clone());
            drop(context.child("talk").spawn(move |context| async move {
                context.sleep(Duration::from_millis(50)).await;
                for tick in 0u8..6 {
                    let _ = to_one.send(Recipients::One(one.clone()), vec![tick], false);
                    let _ = to_zero.send(Recipients::One(zero.clone()), vec![tick], false);
                    context.sleep(Duration::from_millis(100)).await;
                }
            }));
            let heard = Arc::new(Mutex::new((Vec::new(), Vec::new())));
            let record = Arc::clone(&heard);
            drop(context.child("hear_one").spawn(move |_| async move {
                while let Ok((_, message)) = from_zero.recv().await {
                    record.lock().1.push(message.as_ref()[0]);
                }
            }));
            let record = Arc::clone(&heard);
            drop(context.child("hear_zero").spawn(move |_| async move {
                while let Ok((_, message)) = from_one.recv().await {
                    record.lock().0.push(message.as_ref()[0]);
                }
            }));

            let mut stack = Fake {
                settles_at: context.current() + Duration::from_millis(900),
                context: context.child("fake"),
                quits: None,
                lagging: None,
                lagged: false,
                asked: Arc::default(),
                started: Arc::default(),
                crashed: Arc::default(),
            };
            let played = play(
                &context,
                &oracle,
                &participants,
                LINKS.link(),
                Program::unpaced(vec![
                    at(200, Event::Cut(vec![(0, 1)])),
                    at(400, Event::Heal(vec![(0, 1)])),
                ]),
                &mut stack,
                TIMEOUT,
            )
            .await;
            assert_eq!(played.outcome, Outcome::Completed);
            heard.lock().clone()
        });

        // Identity 1 misses what identity 0 sent at 250 and 350.
        assert_eq!(heard.1, vec![0, 1, 4, 5]);
        assert_eq!(heard.0, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn position_follows_the_processed_height() {
        // Heights 1 to 15 are the dealing window of epoch zero, 16 its
        // midpoint, and 31 its final block. Height 32 opens epoch one.
        let last = Epoch::new(2);
        let at = |processed| position(processed, last);
        assert_eq!(at(0), (Epoch::zero(), Landing::Dealing));
        assert_eq!(at(14), (Epoch::zero(), Landing::Dealing));
        assert_eq!(at(15), (Epoch::zero(), Landing::Inclusion));
        assert_eq!(at(30), (Epoch::zero(), Landing::Inclusion));
        assert_eq!(at(31), (Epoch::new(1), Landing::Dealing));
        assert_eq!(at(46), (Epoch::new(1), Landing::Dealing));
        assert_eq!(at(47), (Epoch::new(1), Landing::Inclusion));
        assert_eq!(at(62), (Epoch::new(1), Landing::Inclusion));

        // An engine that applied the final block of the last epoch asked
        // for has finished, however far the chain goes on.
        assert_eq!(at(63), (Epoch::new(2), Landing::Finished));
        assert_eq!(at(200), (Epoch::new(6), Landing::Finished));
        assert_eq!(position(31, Epoch::new(1)).1, Landing::Finished);
    }
}
