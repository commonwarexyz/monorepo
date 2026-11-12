//! Pacing of the engines' durable writes around their scheduled crashes.
//!
//! A crash is an abort of an engine's tasks, and an abort takes effect only
//! where a task is suspended. The harness secret store and the deterministic
//! runtime's storage complete every write in one poll, so on their own they
//! never let a crash fall between two writes an engine makes one after the
//! other, or between a write and the moment the engine learns it completed.
//! Pacing does: it holds some of the writes an engine makes shortly before a
//! crash the schedule holds for it, so that the crash finds them suspended.
//!
//! A held write is suspended either before it is applied or after it is
//! applied and before its future resolves, until just past the time of the
//! crash. The crash drops it there. A write dropped before it was applied
//! leaves no trace. A write dropped after it was applied is as durable as
//! the same write is once it has resolved: a write of the secret store, a
//! synced write of a blob, and a sync are in place although the engine never
//! saw them complete, and a write or a resize of a blob that no sync covers
//! is lost with the blob. A sync dropped before it was applied covers
//! nothing, so the writes it was to cover are lost with the blob although
//! their futures had resolved. A write that is not held, and a held write no
//! crash drops, completes as it would have. Nothing else is produced: no
//! write is applied in part, none is applied after its future was dropped,
//! and none that was durable when it resolved is lost.
//!
//! Every decision comes from the run's tape. Each scheduled crash draws how
//! long before it the writes of its engine may be held, and how many of them
//! are: none, some of the writes of the DKG module's own state, or some of
//! every write. Each write that falls in that window draws whether it is held
//! and at which stage. The tape is read backwards for this, so the draws are
//! independent of the ones the runtime and the restart schedule make from its
//! start.
//!
//! An engine whose writes are held is slow from its first held write until
//! its crash, so its identity is the run's one faulty identity from that
//! write until its restart has completed. A write is therefore held only for
//! the identity the schedule crashes next, only while every identity is up,
//! and no sooner than [`SETTLE`] after the restart before that crash
//! completed. At no moment does one identity have a write held while another
//! has one held or is down. A [`Trace`] records every held write and every
//! outage of a run, so that this can be checked.

use crate::stateful::runner::unattributed;
use commonware_runtime::{
    Blob, Clock as _, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions, deterministic,
};
use commonware_utils::{FuzzRng, sync::Mutex};
use futures::Stream;
use rand::RngExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    future::Future,
    ops::AddAssign,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// How long before a scheduled crash the writes of its engine may be held.
/// Each crash draws one of these.
const REACHES: [Duration; 4] = [
    Duration::from_millis(100),
    Duration::from_millis(500),
    Duration::from_millis(2_000),
    Duration::from_millis(8_000),
];

/// How many of the writes in a crash's window are held: one in the first
/// number of the writes of the DKG module's own state, and one in the second
/// of every other write, or none of them where the number is zero. Each crash
/// draws one of these pairs.
///
/// The writes of the DKG module's own state are few next to those of the
/// chain, and holding a write of the chain soon stops the blocks the DKG
/// module acts on, so they are held more often, and for some crashes they
/// alone are. A power of two leaves the bits of a write's sample above it
/// for the choice of the stage.
const ODDS: [(u8, u8); 4] = [(0, 0), (2, 0), (2, 4), (4, 16)];

/// How long past the time of its crash a held write stays suspended. The
/// driver performs a crash a few executor iterations after its time, and the
/// crash must find the write still suspended. A write whose crash does not
/// come resumes after this long.
const GRACE: Duration = Duration::from_millis(20);

/// How long after a restart has completed no write is held.
///
/// It is the shortest delay the restart schedule puts between the due time
/// of a restart and the due time of the next crash, and the environment
/// keeps the same distance between the outages it lays out around an
/// identity that starts late. A crash that is brought forward can follow a
/// completed restart sooner, but a held write never does: the first held
/// write is where the next identity becomes unavailable, and pacing keeps
/// that distance from the completed restart.
pub(super) const SETTLE: Duration = Duration::from_millis(50);

/// Where a held write is suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    /// Before the write is applied.
    Before,
    /// After the write is applied and before its future resolves.
    After,
}

/// What a partition of an engine's storage holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Partition {
    /// The reshare actor's journal of the dealings, the acks, and the dealer
    /// logs of its ceremonies.
    Journal,
    /// The material of a DKG state sync.
    StateSync,
    /// The record the caller of a state-synced engine keeps of its sync: the
    /// floor of a sync in progress, or its completion.
    Ledger,
    /// The journal of a Simplex engine: the bootstrap chain's, or one epoch's
    /// of those the orchestrator runs. The orchestrator stores nothing else.
    Consensus,
    /// Marshal's caches and its archives of blocks and finalizations.
    Chain,
    /// A partition this harness does not know.
    Unknown,
}

/// Parts of the names of the partitions that hold the chain.
const CHAIN: [&str; 4] = ["-cache-", "-application-", "-blocks-", "-finalizations-"];

impl Partition {
    /// What the partition called `name` holds.
    ///
    /// The DKG module names the partitions of an engine by appending to the
    /// prefix the harness gives the engine. What a partition holds decides
    /// how often its writes are held ([`ODDS`]) and how the run report counts
    /// them, so each restart driver has a test that fails if its engines
    /// open a partition this does not know, or none it takes for the journal.
    pub(super) fn named(name: &str) -> Self {
        let epoch = |name: &str| {
            name.rsplit_once("-orchestrator_consensus_")
                .is_some_and(|(_, epoch)| epoch.parse::<u64>().is_ok())
        };
        if name.ends_with("-reshare_events") {
            Self::Journal
        } else if name.ends_with("_dkg_state_sync") {
            Self::StateSync
        } else if name.ends_with("-joiner") {
            Self::Ledger
        } else if name.ends_with("-simplex") || epoch(name) {
            Self::Consensus
        } else if CHAIN.iter().any(|part| name.contains(part)) {
            Self::Chain
        } else {
            Self::Unknown
        }
    }
}

/// A write of the secret store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Secret {
    Share,
    Seed,
    Dealing,
    Prune,
}

/// A change of a blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Change {
    /// A write of bytes, synced as it is made or not.
    Write { synced: bool },
    /// A resize.
    Resize,
    /// A sync of everything written and resized before it.
    Sync,
}

/// A durable write an engine makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    /// A write of the secret store.
    Secret(Secret),
    /// A change of a blob in a partition that holds this.
    Blob(Partition, Change),
}

impl Operation {
    /// Whether the write changes the DKG module's own state: the secret
    /// store, the reshare actor's journal, or the material of a state sync.
    /// The record a caller keeps of a state sync counts with them: the DKG
    /// module leaves that record to its caller.
    pub(super) const fn dkg(self) -> bool {
        matches!(
            self,
            Self::Secret(_)
                | Self::Blob(
                    Partition::Journal | Partition::StateSync | Partition::Ledger,
                    _
                )
        )
    }

    /// Whether the write is durable once it is applied. A write of a blob
    /// that is not synced as it is made, and a resize, are durable only once
    /// a later sync covers them.
    pub(super) const fn durable(self) -> bool {
        matches!(
            self,
            Self::Secret(_) | Self::Blob(_, Change::Write { synced: true } | Change::Sync)
        )
    }
}

/// How a held write ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum End {
    /// It is still held.
    Pending,
    /// No crash dropped it, and it went on once its hold ended.
    Resumed,
    /// The crash of its engine dropped it.
    Crashed,
    /// Its engine dropped it while the engine was running.
    Abandoned,
}

/// One held write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Hold {
    /// The identity whose engine made the write.
    pub(super) engine: usize,
    /// Which start of that engine the instance that made the write is,
    /// counting from one.
    pub(super) instance: usize,
    pub(super) operation: Operation,
    /// Whether the write has been applied. For a write that was dropped,
    /// whether it had been applied by then.
    pub(super) applied: bool,
    /// When the hold began, from the start of the run.
    pub(super) from: Duration,
    /// When the hold ended, or none while the write is held.
    pub(super) until: Option<Duration>,
    pub(super) end: End,
}

/// One outage: an identity's engine from its crash until its restart has
/// completed, or an identity that joins the run late until its first start
/// has.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Outage {
    engine: usize,
    /// Which start of the engine the crashed instance was, counting from one,
    /// or zero for an identity that has not started yet.
    instance: usize,
    /// When the engine was crashed, from the start of the run.
    from: Duration,
    /// When its restart completed, or none while it is down.
    until: Option<Duration>,
}

/// A span of a run in which one identity was impaired: it had a write held
/// or was down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Impairment {
    pub(super) engine: usize,
    pub(super) from: Duration,
    /// When the impairment ended, or none if it lasted to the end of the
    /// trace.
    pub(super) until: Option<Duration>,
}

impl Impairment {
    /// Whether this impairment and `other` share a moment.
    fn overlaps(&self, other: &Self) -> bool {
        let before =
            |from: Duration, until: Option<Duration>| until.is_none_or(|until| from < until);
        before(self.from, other.until) && before(other.from, self.until)
    }
}

/// How the held writes of a run ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacedCounts {
    /// Crashes that dropped at least one held write of their engine.
    pub crashes: usize,
    /// Held writes a crash dropped before they were applied. Nothing of such
    /// a write is in place. Where it was a sync, the writes it was to cover
    /// were lost with their blob although their futures had resolved, as
    /// every write an engine has not synced is.
    pub before: usize,
    /// Held writes a crash dropped after they were applied and that are in
    /// place as a whole, although the engine never saw them complete: writes
    /// of the secret store, synced writes of a blob, and syncs.
    pub durable: usize,
    /// Held writes a crash dropped after they were applied to a blob without
    /// a sync: writes that are not synced as they are made, and resizes. The
    /// engine's own reads saw such a change until the crash. Only a sync of
    /// its blob makes it durable, and the task that would issue that sync is
    /// the one the hold suspends, so the crash discarded the change with the
    /// blob. The harness does not look for a sync by another task; no
    /// measured run had one.
    pub unsynced: usize,
    /// How many of `before` were writes of the DKG module's own state.
    pub dkg_before: usize,
    /// How many of `durable` were writes of the DKG module's own state.
    pub dkg_durable: usize,
    /// How many of `unsynced` were writes of the DKG module's own state.
    pub dkg_unsynced: usize,
    /// Held writes that no crash dropped and that completed after their hold.
    pub resumed: usize,
    /// Held writes dropped while their engine was running, by the engine
    /// itself.
    pub abandoned: usize,
    /// Held writes that were still held when the run ended.
    pub pending: usize,
}

impl AddAssign for PacedCounts {
    fn add_assign(&mut self, other: Self) {
        self.crashes += other.crashes;
        self.before += other.before;
        self.durable += other.durable;
        self.unsynced += other.unsynced;
        self.dkg_before += other.dkg_before;
        self.dkg_durable += other.dkg_durable;
        self.dkg_unsynced += other.dkg_unsynced;
        self.resumed += other.resumed;
        self.abandoned += other.abandoned;
        self.pending += other.pending;
    }
}

impl fmt::Display for PacedCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "paced_crashes={} held_before={} held_durable={} held_unsynced={} dkg_before={} \
             dkg_durable={} dkg_unsynced={} held_resumed={} held_abandoned={} held_pending={}",
            self.crashes,
            self.before,
            self.durable,
            self.unsynced,
            self.dkg_before,
            self.dkg_durable,
            self.dkg_unsynced,
            self.resumed,
            self.abandoned,
            self.pending,
        )
    }
}

/// What the pacing of a run did: every write it held and every outage of an
/// engine, in the order they began.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Trace {
    holds: Vec<Hold>,
    outages: Vec<Outage>,
    /// What each partition an engine opened holds, with the engine's
    /// identity.
    #[cfg(test)]
    opened: BTreeSet<(usize, Partition)>,
}

impl Trace {
    /// How the held writes ended.
    pub(super) fn counts(&self) -> PacedCounts {
        let mut counts = PacedCounts::default();
        let mut interrupted = BTreeSet::new();
        for hold in &self.holds {
            let dkg = usize::from(hold.operation.dkg());
            match hold.end {
                End::Pending => counts.pending += 1,
                End::Resumed => counts.resumed += 1,
                End::Abandoned => counts.abandoned += 1,
                End::Crashed => {
                    interrupted.insert((hold.engine, hold.instance));
                    if !hold.applied {
                        counts.before += 1;
                        counts.dkg_before += dkg;
                    } else if hold.operation.durable() {
                        counts.durable += 1;
                        counts.dkg_durable += dkg;
                    } else {
                        counts.unsynced += 1;
                        counts.dkg_unsynced += dkg;
                    }
                }
            }
        }
        counts.crashes = interrupted.len();
        counts
    }

    /// How many crashes of the engine of the identity at `engine` dropped at
    /// least one held write.
    pub(super) fn interrupted(&self, engine: usize) -> usize {
        self.holds
            .iter()
            .filter(|hold| hold.engine == engine && hold.end == End::Crashed)
            .map(|hold| hold.instance)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// The spans in which an identity was impaired, one for each instance of
    /// an engine that had a write held or was crashed, in the order they
    /// began.
    ///
    /// An instance is impaired from its first held write, or from its crash
    /// if it had none, until the restart after its crash has completed. An
    /// instance no crash has come for is impaired until its last hold ended.
    /// An identity that joins the run late is impaired from the start of the
    /// run until its first start has completed.
    pub(super) fn impairments(&self) -> Vec<Impairment> {
        let mut spans: BTreeMap<(usize, usize), (Duration, Option<Duration>)> = BTreeMap::new();
        for hold in &self.holds {
            spans
                .entry((hold.engine, hold.instance))
                .and_modify(|(from, until)| {
                    *from = (*from).min(hold.from);
                    *until = until.zip(hold.until).map(|(until, ended)| until.max(ended));
                })
                .or_insert((hold.from, hold.until));
        }
        for outage in &self.outages {
            spans
                .entry((outage.engine, outage.instance))
                .and_modify(|(from, until)| {
                    *from = (*from).min(outage.from);
                    *until = outage.until;
                })
                .or_insert((outage.from, outage.until));
        }
        let mut impairments: Vec<_> = spans
            .into_iter()
            .map(|((engine, _), (from, until))| Impairment {
                engine,
                from,
                until,
            })
            .collect();
        impairments.sort_by_key(|impairment| impairment.from);
        impairments
    }

    /// How many pairs of impairments of two different identities share a
    /// moment. The fault bound of a restart run is one identity at a time,
    /// so there must be none.
    pub(super) fn overlaps(&self) -> usize {
        let impairments = self.impairments();
        impairments
            .iter()
            .enumerate()
            .flat_map(|(index, one)| {
                impairments[index + 1..]
                    .iter()
                    .map(move |other| (one, other))
            })
            .filter(|(one, other)| one.engine != other.engine && one.overlaps(other))
            .count()
    }

    /// Every held write, in the order the holds began.
    #[cfg(test)]
    pub(super) fn holds(&self) -> &[Hold] {
        &self.holds
    }

    /// The held writes the crashes of the engine of the identity at `engine`
    /// dropped, each with the stage the crash found it at, in the order the
    /// holds began.
    #[cfg(test)]
    pub(super) fn dropped(&self, engine: usize) -> Vec<(Operation, Stage)> {
        self.holds
            .iter()
            .filter(|hold| hold.engine == engine && hold.end == End::Crashed)
            .map(|hold| {
                let stage = if hold.applied {
                    Stage::After
                } else {
                    Stage::Before
                };
                (hold.operation, stage)
            })
            .collect()
    }

    /// What the partitions the engine of the identity at `engine` opened
    /// hold.
    #[cfg(test)]
    pub(super) fn opened(&self, engine: usize) -> Vec<Partition> {
        self.opened
            .iter()
            .filter(|(opener, _)| *opener == engine)
            .map(|(_, partition)| *partition)
            .collect()
    }
}

/// A crash the schedule holds.
#[derive(Clone, Copy)]
struct Crash {
    /// The identity whose engine it crashes.
    victim: usize,
    /// When the crash is due, from the start of the run.
    at: Duration,
    /// How long before the crash the engine's writes may be held.
    reach: Duration,
    /// One in this many of those writes is held, or none if it is zero: for
    /// the writes of the DKG module's own state, and for every other write.
    odds: (u8, u8),
}

/// One identity's engine as the pacing sees it.
struct Engine {
    /// Whether the engine is up: its latest start has completed and the
    /// schedule has not crashed it since.
    up: bool,
    /// How many starts of the engine have completed.
    starts: usize,
}

/// The clock a run's pacing reads once the run has begun.
struct Started {
    context: deterministic::Context,
    /// When the run began. Crashes are due at their offsets from it.
    origin: SystemTime,
}

impl Started {
    /// How long the run has lasted.
    fn elapsed(&self) -> Duration {
        self.context
            .current()
            .duration_since(self.origin)
            .expect("simulated time does not run backwards")
    }
}

struct State {
    rng: FuzzRng,
    /// None until the run begins. Nothing is held before that.
    started: Option<Started>,
    /// Every crash the pacing was laid out with, with what it drew.
    drawn: Vec<Crash>,
    /// The crashes the schedule still holds, soonest first.
    crashes: VecDeque<Crash>,
    engines: Vec<Engine>,
    /// When the latest restart of an engine completed, if one has.
    restarted: Option<Duration>,
    /// The identity that is impaired, if one is: it has had a write held, or
    /// was crashed, and its restart has not completed since.
    impaired: Option<usize>,
    trace: Trace,
}

impl State {
    /// How long the run has lasted, or no time if it has not begun.
    fn elapsed(&self) -> Duration {
        self.started
            .as_ref()
            .map_or(Duration::ZERO, Started::elapsed)
    }
}

/// The pacing of one run: which writes of each engine are held.
pub(super) struct Pacing {
    state: Arc<Mutex<State>>,
}

impl Pacing {
    /// Lay out the pacing of a run among `identities` identities whose
    /// schedule holds `crashes`, each the offset of a crash from the start of
    /// the run and the identity it crashes, in the order they are due. The
    /// decisions are drawn from `tape`.
    pub(super) fn new(tape: &[u8], crashes: &[(Duration, usize)], identities: usize) -> Self {
        let mut rng = FuzzRng::new(tape.iter().rev().copied().collect());
        let drawn: Vec<Crash> = crashes
            .iter()
            .map(|(at, victim)| {
                let mut sample = [0u8; 1];
                rng.fill(&mut sample[..]);
                let sample = usize::from(sample[0]);
                Crash {
                    victim: *victim,
                    at: *at,
                    reach: REACHES[sample % REACHES.len()],
                    odds: ODDS[sample / REACHES.len() % ODDS.len()],
                }
            })
            .collect();
        let engines = (0..identities)
            .map(|_| Engine {
                up: false,
                starts: 0,
            })
            .collect();
        Self {
            state: Arc::new(Mutex::new(State {
                rng,
                started: None,
                crashes: drawn.iter().copied().collect(),
                drawn,
                engines,
                restarted: None,
                impaired: None,
                trace: Trace::default(),
            })),
        }
    }

    /// Note that the run begins now, by the clock of `context`. The offsets
    /// of the scheduled crashes count from here.
    pub(super) fn begin(&self, context: deterministic::Context) {
        let origin = context.current();
        self.state.lock().started = Some(Started { context, origin });
    }

    /// Replace the crashes the schedule still holds by `crashes`: the crashes
    /// that are still to come, soonest first, each named by its position
    /// among the crashes this pacing was laid out with and given the offset
    /// from the start of the run at which it is now due. A crash that is left
    /// out is not waited for until it is named again. Every crash keeps the
    /// window and the odds it drew.
    ///
    /// This is for a schedule whose times are known only once the run is
    /// under way.
    pub(super) fn reschedule(&self, crashes: &[(usize, Duration)]) {
        let mut state = self.state.lock();
        let state = &mut *state;
        state.crashes = crashes
            .iter()
            .map(|(position, at)| Crash {
                at: *at,
                ..state.drawn[*position]
            })
            .collect();
    }

    /// Note that the identity at `index` joins the run late. Until its first
    /// start has completed it is as unavailable as an identity that is down,
    /// so it is the run's impaired identity from the start of the run: no
    /// write is held and no identity may be crashed until then.
    pub(super) fn absent(&self, index: usize) {
        let mut state = self.state.lock();
        let state = &mut *state;
        let now = state.elapsed();
        debug_assert!(
            state.impaired.is_none(),
            "identity {index} joins late while identity {:?} is impaired",
            state.impaired
        );
        state.impaired = Some(index);
        state.trace.outages.push(Outage {
            engine: index,
            instance: 0,
            from: now,
            until: None,
        });
    }

    /// The pacing of the engine of the identity at `index`.
    pub(super) fn engine(&self, index: usize) -> EnginePacing {
        EnginePacing {
            state: self.state.clone(),
            engine: index,
        }
    }

    /// Note that a start of the engine of the identity at `index` has
    /// completed: the engine is running, and no task of it has run yet.
    pub(super) fn started(&self, index: usize) {
        let mut state = self.state.lock();
        let state = &mut *state;
        let now = state.elapsed();
        let engine = &mut state.engines[index];
        engine.up = true;
        engine.starts += 1;

        // A start that follows a crash ends the identity's outage. So does
        // the first start of an identity that joins late, and that is a first
        // start: no write waits for it to settle.
        let outage = state
            .trace
            .outages
            .iter_mut()
            .find(|outage| outage.engine == index && outage.until.is_none());
        if let Some(outage) = outage {
            outage.until = Some(now);
            if outage.instance > 0 {
                state.restarted = Some(now);
            }
            if state.impaired == Some(index) {
                state.impaired = None;
            }
        }
    }

    /// Note that the schedule is crashing the engine of the identity at
    /// `index`: the soonest crash it held is the one under way.
    pub(super) fn crashing(&self, index: usize) {
        let mut state = self.state.lock();
        let state = &mut *state;
        let now = state.elapsed();
        let crash = state.crashes.pop_front();
        debug_assert!(
            crash.is_some_and(|crash| crash.victim == index),
            "identity {index} is crashed out of the schedule's turn"
        );
        debug_assert!(
            state.impaired.is_none_or(|impaired| impaired == index),
            "identity {index} is crashed while identity {:?} is impaired",
            state.impaired
        );
        state.impaired = Some(index);
        let engine = &mut state.engines[index];
        engine.up = false;
        state.trace.outages.push(Outage {
            engine: index,
            instance: engine.starts,
            from: now,
            until: None,
        });
    }

    /// What the pacing has done so far: the writes it held, how each ended,
    /// and the outages of the engines.
    pub(super) fn trace(&self) -> Trace {
        let trace = self.state.lock().trace.clone();
        debug_assert_eq!(
            trace.overlaps(),
            0,
            "two identities were impaired at once: {:?}",
            trace.impairments()
        );
        trace
    }
}

/// The pacing of one engine's writes. It is the same across the engine's
/// restarts.
#[derive(Clone)]
pub(super) struct EnginePacing {
    state: Arc<Mutex<State>>,
    engine: usize,
}

/// A decision to hold a write.
struct Decision {
    stage: Stage,
    /// The position of the hold in the run's trace.
    hold: usize,
    /// Resolves when the hold ends.
    release: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl EnginePacing {
    /// Decide whether a write the engine starts now is held.
    fn decide(&self, operation: Operation) -> Option<Decision> {
        let mut state = self.state.lock();
        let state = &mut *state;
        let started = state.started.as_ref()?;

        // A held write makes its identity the faulty one until its restart
        // has completed, and one identity is faulty at a time. So a write is
        // held only while every identity is up, only for the identity whose
        // crash is the schedule's next outage, and only once the identity
        // that came back last has had its time to settle.
        if state.engines.iter().any(|engine| !engine.up) {
            return None;
        }
        let crash = state.crashes.front()?;
        if crash.victim != self.engine {
            return None;
        }
        let now = started.elapsed();
        if state
            .restarted
            .is_some_and(|restarted| now < restarted + SETTLE)
        {
            return None;
        }
        let until = crash.at + GRACE;
        let odds = if operation.dkg() {
            crash.odds.0
        } else {
            crash.odds.1
        };
        if odds == 0 || now + crash.reach < crash.at || now >= until {
            return None;
        }
        let mut sample = [0u8; 1];
        state.rng.fill(&mut sample[..]);
        if sample[0] % odds != 0 {
            return None;
        }
        let stage = if (sample[0] / odds) % 2 == 0 {
            Stage::Before
        } else {
            Stage::After
        };
        debug_assert!(
            state
                .impaired
                .is_none_or(|impaired| impaired == self.engine),
            "a write of identity {} is held while identity {:?} is impaired",
            self.engine,
            state.impaired
        );
        state.impaired = Some(self.engine);
        let hold = state.trace.holds.len();
        state.trace.holds.push(Hold {
            engine: self.engine,
            instance: state.engines[self.engine].starts,
            operation,
            applied: false,
            from: now,
            until: None,
            end: End::Pending,
        });
        Some(Decision {
            stage,
            hold,
            release: Box::pin(started.context.sleep_until(started.origin + until)),
        })
    }

    /// Record that the held write at `hold` of the trace has been applied.
    fn applied(&self, hold: usize) {
        self.state.lock().trace.holds[hold].applied = true;
    }

    /// Record that the hold at `hold` of the trace ended and its write goes
    /// on.
    fn resumed(&self, hold: usize) {
        let mut state = self.state.lock();
        let now = state.elapsed();
        let hold = &mut state.trace.holds[hold];
        hold.until = Some(now);
        hold.end = End::Resumed;
    }

    /// Record that the held write at `hold` of the trace was dropped, unless
    /// its hold had ended.
    fn dropped(&self, hold: usize) {
        let mut state = self.state.lock();
        let state = &mut *state;
        let now = state.elapsed();
        let hold = &mut state.trace.holds[hold];
        if hold.end != End::Pending {
            return;
        }

        // The crash of an instance drops what the instance holds. Anything
        // else is the engine dropping a write of its own while it runs.
        let engine = &state.engines[self.engine];
        hold.until = Some(now);
        hold.end = if engine.up && engine.starts == hold.instance {
            End::Abandoned
        } else {
            End::Crashed
        };
    }

    /// Record that the engine opened a partition that holds `partition`.
    #[cfg(test)]
    fn opened(&self, partition: Partition) {
        self.state
            .lock()
            .trace
            .opened
            .insert((self.engine, partition));
    }

    /// Run `apply`, which makes the one write `operation`, held if the tape
    /// says so.
    ///
    /// The write is whatever `apply` does when it is polled. A hold comes
    /// before `apply` is first polled or after it has completed, never in
    /// between, so pacing adds no point at which a write is made in part.
    pub(super) async fn write<T>(&self, operation: Operation, apply: impl Future<Output = T>) -> T {
        let Some(decision) = unattributed(|| self.decide(operation)) else {
            return apply.await;
        };
        let held = Held {
            pacing: self,
            hold: decision.hold,
        };
        let apply = async {
            let applied = apply.await;
            unattributed(|| self.applied(held.hold));
            applied
        };
        match decision.stage {
            Stage::Before => {
                decision.release.await;
                unattributed(|| self.resumed(held.hold));
                apply.await
            }
            Stage::After => {
                let applied = apply.await;
                decision.release.await;
                unattributed(|| self.resumed(held.hold));
                applied
            }
        }
    }
}

/// A write while it is held. Dropping it before its hold ends records that
/// the write was dropped.
struct Held<'a> {
    pacing: &'a EnginePacing,
    /// The position of the hold in the run's trace.
    hold: usize,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        unattributed(|| self.pacing.dropped(self.hold));
    }
}

/// A blob of an engine. Its writes, resizes, and syncs may be held; its reads
/// never are.
///
/// Everything is forwarded to the wrapped blob unchanged. A held operation
/// reaches the wrapped blob later than it was issued, or resolves later than
/// the wrapped blob completed it, as an operation on a slow device does.
/// Dropping this blob drops the wrapped one, so what the engine wrote and did
/// not sync is lost with it.
pub(super) struct PacedBlob<B> {
    inner: B,
    /// The pacing of the engine that opened the blob and what the blob's
    /// partition holds, or none if the engine's storage is not paced.
    pacing: Option<(EnginePacing, Partition)>,
}

impl<B: Blob> PacedBlob<B> {
    /// Wrap `inner`, a blob of `partition`, paced by `pacing` if there is
    /// one.
    pub(super) fn new(inner: B, pacing: Option<&EnginePacing>, partition: &str) -> Self {
        let pacing = pacing.map(|pacing| {
            let partition = Partition::named(partition);
            #[cfg(test)]
            unattributed(|| pacing.opened(partition));
            (pacing.clone(), partition)
        });
        Self { inner, pacing }
    }

    /// Run `apply`, which makes the one change `change` of the wrapped blob,
    /// held if the blob is paced and the tape says so.
    async fn write<T>(&self, change: Change, apply: impl Future<Output = T>) -> T {
        match &self.pacing {
            Some((pacing, partition)) => {
                pacing
                    .write(Operation::Blob(*partition, change), apply)
                    .await
            }
            None => apply.await,
        }
    }
}

impl<B: Blob> Blob for PacedBlob<B> {
    fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.inner.read_at_buf(offset, len, bufs, options)
    }

    fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.inner.read_at(offset, len, options)
    }

    fn read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
        self.inner.read_many(ranges, options)
    }

    fn start_read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl Future<Output = Handle<Vec<IoBufsMut>>> + Send {
        self.inner.start_read_many(ranges, options)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let change = Change::Write {
            synced: options.contains(WriteOptions::SYNC),
        };
        self.write(change, self.inner.write_at(offset, bufs.into(), options))
            .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.write(Change::Resize, self.inner.resize(len)).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.write(Change::Sync, self.inner.sync()).await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.write(Change::Sync, self.inner.start_sync()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::context::EngineContext;
    use commonware_macros::select;
    use commonware_runtime::{Runner as _, Spawner as _, Storage as _, Supervisor as _};
    use futures::join;

    impl Pacing {
        /// Like [`Self::new`], with every crash reaching `reach` back and
        /// holding one in `odds` of the writes in its window, or none of them
        /// if `odds` is zero.
        pub(in crate::dkg) fn scripted(
            tape: &[u8],
            crashes: &[(Duration, usize)],
            identities: usize,
            reach: Duration,
            odds: u8,
        ) -> Self {
            let pacing = Self::new(tape, crashes, identities);
            pacing.force(reach, odds);
            pacing
        }

        /// Have every crash reach `reach` back and hold one in `odds` of
        /// the writes in its window, or none of them if `odds` is zero,
        /// whatever it drew.
        pub(in crate::dkg) fn force(&self, reach: Duration, odds: u8) {
            let mut state = self.state.lock();
            let state = &mut *state;
            for crash in state.crashes.iter_mut().chain(&mut state.drawn) {
                crash.reach = reach;
                crash.odds = (odds, odds);
            }
        }

        /// The pacing of a run of one engine that begins now, by the clock of
        /// `context`, and whose schedule holds one crash, due `crash` from now.
        /// Every write the engine starts within `reach` of the crash is held, the
        /// first of them at `stage`. The engine is running.
        pub(in crate::dkg) fn holding(
            context: &deterministic::Context,
            stage: Stage,
            crash: Duration,
            reach: Duration,
        ) -> Self {
            let started = |tape: &[u8], crash| {
                let pacing = Self::scripted(tape, &[(crash, 0)], 1, reach, 1);
                pacing.begin(context.child("pacing"));
                pacing.started(0);
                pacing
            };

            // The first sample of the tape decides the stage, so try tapes on a
            // crash that is due at once until one decides for `stage`.
            let tape = (0..=u8::MAX)
                .map(|seed| vec![seed])
                .find(|tape| {
                    started(tape, Duration::ZERO)
                        .engine(0)
                        .decide(SEED)
                        .is_some_and(|decision| decision.stage == stage)
                })
                .expect("some tape holds its first write at either stage");
            started(&tape, crash)
        }
    }

    /// The reshare actor's journal of engine 0, and a blob in it.
    const PARTITION: &str = "engine-0-reshare_events";
    const NAME: &[u8] = b"blob";

    /// A write of the secret store.
    const SEED: Operation = Operation::Secret(Secret::Seed);

    /// When the one crash of most schedules here is due, and how far back
    /// its window reaches.
    const CRASH: Duration = Duration::from_millis(200);
    const REACH: Duration = Duration::from_millis(50);

    /// A moment inside the window of the crash.
    const INSIDE: Duration = Duration::from_millis(175);

    /// The context of engine 0, with its storage paced by `pacing`.
    fn engine(context: &deterministic::Context, pacing: &Pacing) -> EngineContext {
        EngineContext::new(context.child("engine"), 0).paced(Some(pacing.engine(0)))
    }

    /// What the blob holds once every handle to it is gone.
    async fn durable(context: &deterministic::Context) -> Vec<u8> {
        let (blob, len) = context
            .open(PARTITION, NAME)
            .await
            .expect("the blob opens once its handle is dropped");
        blob.read_at(0, len as usize, ReadOptions::default())
            .await
            .expect("the blob holds its length")
            .coalesce()
            .as_ref()
            .to_vec()
    }

    /// What the pacing counts when one crash drops one held write of the DKG
    /// module's own state.
    fn one_dropped(stage: Stage, durable: bool) -> PacedCounts {
        let count = |counted: bool| usize::from(counted);
        let (before, after) = (stage == Stage::Before, stage == Stage::After);
        PacedCounts {
            crashes: 1,
            before: count(before),
            durable: count(after && durable),
            unsynced: count(after && !durable),
            dkg_before: count(before),
            dkg_durable: count(after && durable),
            dkg_unsynced: count(after && !durable),
            ..PacedCounts::default()
        }
    }

    /// Run an engine that durably writes `old`, then, inside the window of
    /// its crash, starts a durable write of `new` that is held at `stage`,
    /// and crash it there. Returns what the blob holds afterwards and what
    /// the pacing did.
    fn crashed_in_a_write(stage: Stage) -> (Vec<u8>, Trace) {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, stage, CRASH, REACH);
            let handle = engine(&context, &pacing).spawn(|context| async move {
                let (blob, _) = context.open(PARTITION, NAME).await.expect("open");
                blob.write_at(0, b"old", WriteOptions::SYNC)
                    .await
                    .expect("write");
                context.sleep(INSIDE).await;
                blob.write_at(0, b"new", WriteOptions::SYNC)
                    .await
                    .expect("write");
                unreachable!("the crash comes while the write is held");
            });
            context.sleep(CRASH).await;
            pacing.crashing(0);
            handle.abort();
            let _ = handle.await;
            (durable(&context).await, pacing.trace())
        })
    }

    #[test]
    fn write_dropped_before_it_is_applied_leaves_no_trace() {
        let (durable, trace) = crashed_in_a_write(Stage::Before);
        assert_eq!(durable, b"old");
        assert_eq!(trace.counts(), one_dropped(Stage::Before, true));
        let journaled = Operation::Blob(Partition::Journal, Change::Write { synced: true });
        assert_eq!(trace.dropped(0), vec![(journaled, Stage::Before)]);
    }

    #[test]
    fn synced_write_dropped_after_it_is_applied_is_durable() {
        let (durable, trace) = crashed_in_a_write(Stage::After);
        assert_eq!(durable, b"new");
        assert_eq!(trace.counts(), one_dropped(Stage::After, true));
        let journaled = Operation::Blob(Partition::Journal, Change::Write { synced: true });
        assert_eq!(trace.dropped(0), vec![(journaled, Stage::After)]);
    }

    /// A write that is not synced as it is made, and a resize, held after
    /// they were applied: the engine's own reads see the change, and the
    /// crash discards it with the blob, as it does a change the engine saw
    /// complete and did not sync.
    #[test]
    fn unsynced_write_dropped_after_it_is_applied_is_lost_with_the_blob() {
        for resize in [false, true] {
            let (seen, durable, trace) =
                deterministic::Runner::default().start(|context| async move {
                    let pacing = Pacing::holding(&context, Stage::After, CRASH, REACH);
                    let seen = Arc::new(Mutex::new(None));
                    let handle = engine(&context, &pacing).spawn({
                        let seen = seen.clone();
                        move |context| async move {
                            let (blob, _) = context.open(PARTITION, NAME).await.expect("open");
                            blob.write_at(0, b"old", WriteOptions::SYNC)
                                .await
                                .expect("write");
                            context.sleep(INSIDE).await;
                            let change = async {
                                if resize {
                                    blob.resize(1).await.expect("resize");
                                } else {
                                    blob.write_at(0, b"new", WriteOptions::default())
                                        .await
                                        .expect("write");
                                }
                            };

                            // What the engine reads of all three bytes while
                            // the change is held.
                            let read = async {
                                context.sleep(Duration::from_millis(1)).await;
                                let read = blob.read_at(0, 3, ReadOptions::default()).await;
                                *seen.lock() =
                                    Some(read.ok().map(|read| read.coalesce().as_ref().to_vec()));
                            };
                            join!(change, read);
                            unreachable!("the crash comes while the change is held");
                        }
                    });
                    context.sleep(CRASH).await;
                    pacing.crashing(0);
                    handle.abort();
                    let _ = handle.await;
                    let seen = seen.lock().take();
                    (seen, durable(&context).await, pacing.trace())
                });
            let (applied, change) = if resize {
                (None, Change::Resize)
            } else {
                (Some(b"new".to_vec()), Change::Write { synced: false })
            };
            assert_eq!(seen, Some(applied), "resize: {resize}");
            assert_eq!(durable, b"old", "resize: {resize}");
            assert_eq!(trace.counts(), one_dropped(Stage::After, false));
            assert_eq!(
                trace.dropped(0),
                vec![(Operation::Blob(Partition::Journal, change), Stage::After)]
            );
        }
    }

    /// A sync is applied as a whole or not at all. Dropped before it is
    /// applied, it covers nothing: the write it was to cover is lost with
    /// the blob although its future had resolved.
    #[test]
    fn sync_dropped_while_held_covers_all_or_nothing() {
        for (stage, expected) in [(Stage::Before, &b"old"[..]), (Stage::After, &b"new"[..])] {
            let (durable, trace) = deterministic::Runner::default().start(|context| async move {
                let pacing = Pacing::holding(&context, stage, CRASH, REACH);
                let handle = engine(&context, &pacing).spawn(|context| async move {
                    let (blob, _) = context.open(PARTITION, NAME).await.expect("open");
                    blob.write_at(0, b"old", WriteOptions::SYNC)
                        .await
                        .expect("write");
                    blob.write_at(0, b"new", WriteOptions::default())
                        .await
                        .expect("write");
                    context.sleep(INSIDE).await;
                    blob.sync().await.expect("sync");
                    unreachable!("the crash comes while the sync is held");
                });
                context.sleep(CRASH).await;
                pacing.crashing(0);
                handle.abort();
                let _ = handle.await;
                (durable(&context).await, pacing.trace())
            });
            assert_eq!(durable, expected, "{stage:?}");
            assert_eq!(trace.counts(), one_dropped(stage, true), "{stage:?}");
            assert_eq!(
                trace.dropped(0),
                vec![(Operation::Blob(Partition::Journal, Change::Sync), stage)]
            );
        }
    }

    /// A write that resolved and was synced survives the crash, and one that
    /// resolved and was not synced is lost with the blob, as on the runtime's
    /// own storage. Neither was held: both were made outside the window.
    #[test]
    fn resolved_write_is_durable_once_synced() {
        let (durable, counts) = deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::Before, CRASH, REACH);
            let handle = engine(&context, &pacing).spawn(|context| async move {
                let (blob, _) = context.open(PARTITION, NAME).await.expect("open");
                blob.write_at(0, b"old", WriteOptions::default())
                    .await
                    .expect("write");
                blob.sync().await.expect("sync");
                blob.write_at(0, b"new", WriteOptions::default())
                    .await
                    .expect("write");
                std::future::pending::<()>().await;
            });
            context.sleep(CRASH).await;
            pacing.crashing(0);
            handle.abort();
            let _ = handle.await;
            (durable(&context).await, pacing.trace().counts())
        });
        assert_eq!(durable, b"old");
        assert_eq!(counts, PacedCounts::default());
    }

    /// A held write no crash drops resumes just past the time of the crash
    /// and is then made, at either stage.
    #[test]
    fn held_write_resumes_when_no_crash_comes() {
        for stage in [Stage::Before, Stage::After] {
            let (resumed, durable, counts) =
                deterministic::Runner::default().start(|context| async move {
                    let began = context.current();
                    let pacing = Pacing::holding(&context, stage, CRASH, REACH);
                    let handle = engine(&context, &pacing).spawn(|context| async move {
                        let (blob, _) = context.open(PARTITION, NAME).await.expect("open");
                        context.sleep(INSIDE).await;
                        blob.write_at(0, b"new", WriteOptions::SYNC)
                            .await
                            .expect("write");
                        let resumed = context.current();

                        // Past the window, nothing is held.
                        blob.sync().await.expect("sync");
                        assert_eq!(context.current(), resumed);
                        resumed
                    });
                    let resumed = handle.await.expect("the engine's task returns");
                    let resumed = resumed
                        .duration_since(began)
                        .expect("simulated time does not run backwards");
                    (resumed, durable(&context).await, pacing.trace().counts())
                });
            let expected = CRASH + GRACE;
            assert!(
                resumed >= expected && resumed < expected + Duration::from_millis(5),
                "{stage:?}: {resumed:?}"
            );
            assert_eq!(durable, b"new");
            assert_eq!(
                counts,
                PacedCounts {
                    resumed: 1,
                    ..PacedCounts::default()
                }
            );
        }
    }

    /// Reads are never held, and neither is anything on a context that is
    /// not paced.
    #[test]
    fn reads_and_unpaced_blobs_are_never_held() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::Before, CRASH, REACH);
            let paced = engine(&context, &pacing);
            let unpaced = EngineContext::new(context.child("unpaced"), 0);
            context.sleep(INSIDE).await;
            let started = context.current();

            let (blob, _) = unpaced.open(PARTITION, NAME).await.expect("open");
            blob.write_at(0, b"new", WriteOptions::SYNC)
                .await
                .expect("write");
            blob.resize(2).await.expect("resize");
            blob.sync().await.expect("sync");
            blob.start_sync().await.await.expect("sync");
            drop(blob);

            let (blob, len) = paced.open(PARTITION, NAME).await.expect("open");
            let read = blob
                .read_at(0, len as usize, ReadOptions::default())
                .await
                .expect("read");
            assert_eq!(read.coalesce(), b"ne");
            assert_eq!(context.current(), started);
            let trace = pacing.trace();
            assert_eq!(trace.counts(), PacedCounts::default());

            // Only the paced context's open is on record.
            assert_eq!(trace.opened(0), vec![Partition::Journal]);
        });
    }

    /// The first 64 decisions of an engine inside the window of its crash,
    /// under `tape`.
    fn decisions(tape: &[u8]) -> Vec<Option<Stage>> {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::scripted(tape, &[(CRASH, 0)], 1, REACH, 4);
            pacing.begin(context.child("pacing"));
            pacing.started(0);
            context.sleep(INSIDE).await;
            let engine = pacing.engine(0);
            (0..64)
                .map(|_| engine.decide(SEED).map(|decision| decision.stage))
                .collect()
        })
    }

    #[test]
    fn decisions_depend_only_on_the_tape() {
        let tape =
            |seed: u8| -> Vec<u8> { (0..96u8).map(|byte| byte.wrapping_mul(seed)).collect() };
        let drawn = decisions(&tape(7));
        assert_eq!(drawn, decisions(&tape(7)));
        assert_ne!(drawn, decisions(&tape(9)));

        // One write in four is held, at either stage.
        let held = drawn.iter().flatten().count();
        assert!((8..=24).contains(&held), "{drawn:?}");
        assert!(drawn.contains(&Some(Stage::Before)), "{drawn:?}");
        assert!(drawn.contains(&Some(Stage::After)), "{drawn:?}");
    }

    /// What each crash of a schedule draws from the tape.
    #[test]
    fn crashes_draw_their_windows_from_the_tape() {
        let draw = |seed: u8| {
            let pacing = Pacing::new(&[seed, 1, 2, 3], &[(CRASH, 0), (CRASH * 2, 1)], 2);
            let state = pacing.state.lock();
            state
                .crashes
                .iter()
                .map(|crash| (crash.victim, crash.at, crash.reach, crash.odds))
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(5), draw(5));
        let drawn: Vec<_> = (0..=u8::MAX).flat_map(draw).collect();
        for reach in REACHES {
            assert!(drawn.iter().any(|(_, _, drawn, _)| *drawn == reach));
        }
        for odds in ODDS {
            assert!(drawn.iter().any(|(_, _, _, drawn)| *drawn == odds));
        }

        // The schedule itself is kept: who is crashed, and when.
        assert!(
            drawn
                .chunks(2)
                .all(|pair| (pair[0].0, pair[0].1) == (0, CRASH)
                    && (pair[1].0, pair[1].1) == (1, CRASH * 2))
        );
    }

    /// The writes of the DKG module's own state and the other writes are
    /// held at the odds their crash drew for each.
    #[test]
    fn writes_are_held_at_the_odds_of_what_they_change() {
        let chain = Operation::Blob(Partition::Chain, Change::Sync);
        let journal = Operation::Blob(Partition::Journal, Change::Sync);
        let held = |odds: (u8, u8), operation: Operation| {
            deterministic::Runner::default().start(|context| async move {
                let pacing = Pacing::scripted(&[3], &[(CRASH, 0)], 1, REACH, 1);
                pacing.state.lock().crashes[0].odds = odds;
                pacing.begin(context.child("pacing"));
                pacing.started(0);
                context.sleep(INSIDE).await;
                let engine = pacing.engine(0);
                (0..64)
                    .filter(|_| engine.decide(operation).is_some())
                    .count()
            })
        };
        assert_eq!(held((1, 0), SEED), 64);
        assert_eq!(held((1, 0), journal), 64);
        assert_eq!(held((1, 0), chain), 0);
        assert_eq!(held((0, 1), SEED), 0);
        assert_eq!(held((0, 1), journal), 0);
        assert_eq!(held((0, 1), chain), 64);
    }

    /// Nothing is held before the run begins, outside the window of a crash,
    /// for an identity with no crash to come, or once the crash has been
    /// performed.
    #[test]
    fn writes_are_held_only_in_the_window_of_a_crash_to_come() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::scripted(&[1], &[(CRASH, 0)], 2, REACH, 1);
            let engine = pacing.engine(0);
            let held = || engine.decide(SEED).is_some();
            assert!(!held());

            pacing.begin(context.child("pacing"));
            pacing.started(0);
            pacing.started(1);
            assert!(!held());
            context
                .sleep(CRASH - REACH - Duration::from_millis(5))
                .await;
            assert!(!held());
            context.sleep(Duration::from_millis(10)).await;
            assert!(held());

            // The other identity has no crash to come.
            assert!(pacing.engine(1).decide(SEED).is_none());

            // The window stays open a little past the time of the crash.
            context.sleep(REACH).await;
            assert!(held());
            context.sleep(GRACE).await;
            assert!(!held());
        });

        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::Before, CRASH, REACH);
            let engine = pacing.engine(0);
            context.sleep(INSIDE).await;
            assert!(engine.decide(SEED).is_some());
            pacing.crashing(0);
            assert!(engine.decide(SEED).is_none());
            pacing.started(0);
            assert!(engine.decide(SEED).is_none());
        });
    }

    /// An identity that has not started is not up, so nothing is held until
    /// every identity has started.
    #[test]
    fn nothing_is_held_until_every_identity_has_started() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::scripted(&[1], &[(CRASH, 0)], 2, REACH, 1);
            pacing.begin(context.child("pacing"));
            pacing.started(0);
            context.sleep(INSIDE).await;
            assert!(pacing.engine(0).decide(SEED).is_none());
            pacing.started(1);
            assert!(pacing.engine(0).decide(SEED).is_some());
        });
    }

    /// An identity that joins late is the run's impaired identity until its
    /// first start has completed: nothing is held until then, the span is on
    /// the trace, and a write may be held as soon as it has started, because
    /// a first start has no time to settle.
    #[test]
    fn identity_that_joins_late_is_impaired_until_it_starts() {
        deterministic::Runner::default().start(|context| async move {
            let millis = Duration::from_millis;
            let pacing = Pacing::scripted(&[1], &[(millis(400), 1)], 2, millis(1_000), 1);
            pacing.begin(context.child("pacing"));
            pacing.absent(1);
            pacing.started(0);
            context.sleep(millis(300)).await;
            assert!(pacing.engine(0).decide(SEED).is_none());
            assert!(pacing.engine(1).decide(SEED).is_none());
            pacing.started(1);
            assert!(pacing.engine(0).decide(SEED).is_none());
            assert!(pacing.engine(1).decide(SEED).is_some());

            // The absence ends where the hold begins, so the two spans of the
            // one identity share no moment with any other's.
            let trace = pacing.trace();
            assert_eq!(trace.overlaps(), 0);
            assert_eq!(
                trace.impairments(),
                vec![
                    Impairment {
                        engine: 1,
                        from: Duration::ZERO,
                        until: Some(millis(300)),
                    },
                    Impairment {
                        engine: 1,
                        from: millis(300),
                        until: None,
                    },
                ]
            );
        });
    }

    /// A crash of another identity while one is still to join is an overlap.
    #[test]
    fn outage_before_a_late_identity_starts_is_an_overlap() {
        let millis = Duration::from_millis;
        let trace = Trace {
            holds: Vec::new(),
            outages: vec![
                Outage {
                    engine: 4,
                    instance: 0,
                    from: Duration::ZERO,
                    until: Some(millis(500)),
                },
                Outage {
                    engine: 1,
                    instance: 1,
                    from: millis(200),
                    until: Some(millis(300)),
                },
                Outage {
                    engine: 2,
                    instance: 1,
                    from: millis(500),
                    until: Some(millis(600)),
                },
            ],
            opened: BTreeSet::new(),
        };
        assert_eq!(trace.overlaps(), 1);
    }

    /// A schedule whose times are known only once the run is under way: the
    /// crashes that are still to come are given their order and their times,
    /// each keeps what it drew, and one that is left out is not waited for.
    #[test]
    fn rescheduled_crashes_keep_their_draws() {
        deterministic::Runner::default().start(|context| async move {
            let millis = Duration::from_millis;
            let crashes = [(millis(100), 0), (millis(200), 1), (millis(300), 2)];
            let pacing = Pacing::new(&[7, 9, 200, 33], &crashes, 3);
            let held = || -> Vec<_> {
                pacing
                    .state
                    .lock()
                    .crashes
                    .iter()
                    .map(|crash| (crash.at, crash.victim, crash.reach, crash.odds))
                    .collect()
            };
            let drawn = held();
            assert_eq!(
                drawn.iter().map(|crash| crash.1).collect::<Vec<_>>(),
                vec![0, 1, 2]
            );

            // The last crash goes first, the first one last, and the second
            // is left out.
            pacing.reschedule(&[(2, millis(50)), (0, millis(900))]);
            let at =
                |crash: (Duration, usize, Duration, (u8, u8)), at| (at, crash.1, crash.2, crash.3);
            assert_eq!(
                held(),
                vec![at(drawn[2], millis(50)), at(drawn[0], millis(900))]
            );

            // The crashes are performed in the new order.
            pacing.begin(context.child("pacing"));
            for index in 0..3 {
                pacing.started(index);
            }
            pacing.crashing(2);
            pacing.started(2);
            pacing.crashing(0);
            assert!(held().is_empty());

            // A crash that was left out can be named again.
            pacing.reschedule(&[(1, millis(950))]);
            assert_eq!(held(), vec![at(drawn[1], millis(950))]);
            pacing.started(0);
            pacing.crashing(1);
        });
    }

    /// The crashes of one engine that dropped a held write are counted by
    /// the instance that held it.
    #[test]
    fn interrupted_counts_the_crashes_of_one_engine() {
        let millis = Duration::from_millis;
        let hold = |engine, instance, end| Hold {
            engine,
            instance,
            operation: SEED,
            applied: false,
            from: millis(100),
            until: Some(millis(200)),
            end,
        };
        let trace = Trace {
            holds: vec![
                hold(0, 1, End::Crashed),
                hold(0, 1, End::Crashed),
                hold(0, 2, End::Resumed),
                hold(0, 3, End::Crashed),
                hold(1, 1, End::Crashed),
            ],
            outages: Vec::new(),
            opened: BTreeSet::new(),
        };
        assert_eq!(trace.interrupted(0), 2);
        assert_eq!(trace.interrupted(1), 1);
        assert_eq!(trace.interrupted(2), 0);
        assert_eq!(trace.counts().crashes, 3);
    }

    /// Two crashes whose windows are both open from the start of the run.
    /// Only the identity that is crashed next has its writes held. The other
    /// one's are held once the first is back and has had its time to settle,
    /// so the two are never impaired together.
    #[test]
    fn writes_are_held_only_for_the_identity_crashed_next() {
        deterministic::Runner::default().start(|context| async move {
            let millis = Duration::from_millis;
            let crashes = [(millis(200), 0), (millis(600), 1)];
            let pacing = Pacing::scripted(&[1], &crashes, 2, millis(1_000), 1);
            pacing.begin(context.child("pacing"));
            pacing.started(0);
            pacing.started(1);
            let held = |index: usize| pacing.engine(index).decide(SEED).is_some();

            context.sleep(millis(150)).await;
            assert!(!held(1));
            assert!(held(0));
            assert!(!held(1));

            // Identity 0 is down.
            context.sleep(millis(50)).await;
            pacing.crashing(0);
            assert!(!held(0));
            assert!(!held(1));

            // Identity 0 is back and settles.
            context.sleep(millis(100)).await;
            pacing.started(0);
            assert!(!held(1));
            context.sleep(SETTLE - millis(5)).await;
            assert!(!held(1));
            context.sleep(millis(10)).await;
            assert!(held(1));
            assert!(!held(0));

            let trace = pacing.trace();
            assert_eq!(trace.overlaps(), 0);
            let [first, second] = &trace.impairments()[..] else {
                panic!("each identity was impaired once: {trace:?}");
            };
            assert_eq!((first.engine, second.engine), (0, 1));
            let back = first.until.expect("identity 0 came back");
            assert!(first.from < back);
            assert!(second.from >= back + SETTLE - millis(5));
            assert_eq!(second.until, None);
        });
    }

    /// A held write its engine drops while it is running is not a crash's.
    #[test]
    fn held_write_dropped_by_a_running_engine_is_abandoned() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::Before, CRASH, REACH);
            let engine = pacing.engine(0);
            context.sleep(INSIDE).await;
            select! {
                _ = engine.write(SEED, async {}) => unreachable!("the write is held"),
                _ = context.sleep(Duration::from_millis(1)) => {},
            }
            let trace = pacing.trace();
            assert_eq!(
                trace.counts(),
                PacedCounts {
                    abandoned: 1,
                    ..PacedCounts::default()
                }
            );
            assert!(!trace.holds()[0].applied);
            assert!(trace.dropped(0).is_empty());
        });
    }

    /// A write that is still held when the trace is read is counted as
    /// pending.
    #[test]
    fn write_still_held_is_pending() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::After, CRASH, REACH);
            let engine = pacing.engine(0);
            drop(context.child("engine").spawn(move |context| async move {
                context.sleep(INSIDE).await;
                engine.write(SEED, async {}).await;
            }));
            context.sleep(INSIDE + Duration::from_millis(5)).await;
            let trace = pacing.trace();
            assert_eq!(
                trace.counts(),
                PacedCounts {
                    pending: 1,
                    ..PacedCounts::default()
                }
            );
            let [hold] = trace.holds() else {
                panic!("one write is held: {trace:?}");
            };
            assert_eq!((hold.engine, hold.instance), (0, 1));
            assert_eq!(hold.operation, SEED);
            assert!(hold.applied);
            assert_eq!((hold.until, hold.end), (None, End::Pending));
        });
    }

    #[test]
    fn partitions_are_told_by_their_names() {
        for (name, expected) in [
            ("engine-0-reshare_events", Partition::Journal),
            ("engine-3_dkg_state_sync", Partition::StateSync),
            ("engine-1-simplex", Partition::Consensus),
            ("engine-4-orchestrator_consensus_0", Partition::Consensus),
            ("engine-4-orchestrator_consensus_12", Partition::Consensus),
            ("engine-2-blocks-key", Partition::Chain),
            ("engine-2-finalizations-metadata", Partition::Chain),
            ("engine-2-marshal-application-metadata", Partition::Chain),
            ("engine-2-marshal-cache-metadata", Partition::Chain),
            (
                "engine-2-marshal-cache-cache-0-notarizations-value",
                Partition::Chain,
            ),
            ("engine-2-application-metadata", Partition::Chain),
            ("engine-2-cache-cache-3-verified-key", Partition::Chain),
            ("engine-4-joiner", Partition::Ledger),
            ("engine-0-reshare_journal", Partition::Unknown),
            ("engine-0-reshare_events-key", Partition::Unknown),
            ("engine-4-orchestrator_consensus_", Partition::Unknown),
            ("engine-0", Partition::Unknown),
        ] {
            assert_eq!(Partition::named(name), expected, "{name}");
        }

        // What the odds and the report take for the DKG module's own state,
        // and what is durable once it is applied.
        let write = |synced| Change::Write { synced };
        assert!(SEED.dkg() && SEED.durable());
        for change in [write(true), write(false), Change::Resize, Change::Sync] {
            let durable = matches!(change, Change::Write { synced: true } | Change::Sync);
            for (partition, dkg) in [
                (Partition::Journal, true),
                (Partition::StateSync, true),
                (Partition::Ledger, true),
                (Partition::Consensus, false),
                (Partition::Chain, false),
                (Partition::Unknown, false),
            ] {
                let operation = Operation::Blob(partition, change);
                assert_eq!(operation.dkg(), dkg, "{operation:?}");
                assert_eq!(operation.durable(), durable, "{operation:?}");
            }
        }
    }

    /// The check a trace is put to: a hold of one identity that shares a
    /// moment with a hold or an outage of another is an overlap, and spans
    /// that only follow each other are not.
    #[test]
    fn impairments_of_two_identities_at_once_are_overlaps() {
        let millis = Duration::from_millis;
        let hold = |engine, from, until: Option<u64>| Hold {
            engine,
            instance: 1,
            operation: SEED,
            applied: false,
            from: millis(from),
            until: until.map(millis),
            end: until.map_or(End::Pending, |_| End::Crashed),
        };
        let outage = |engine, from, until: Option<u64>| Outage {
            engine,
            instance: 1,
            from: millis(from),
            until: until.map(millis),
        };
        let trace = |holds: Vec<Hold>, outages: Vec<Outage>| Trace {
            holds,
            outages,
            opened: BTreeSet::new(),
        };

        // One identity held, crashed, and restarted, then the next.
        let sequential = trace(
            vec![hold(0, 100, Some(200)), hold(1, 350, Some(500))],
            vec![outage(0, 200, Some(300)), outage(1, 500, None)],
        );
        assert_eq!(sequential.overlaps(), 0);
        assert_eq!(
            sequential.impairments(),
            vec![
                Impairment {
                    engine: 0,
                    from: millis(100),
                    until: Some(millis(300)),
                },
                Impairment {
                    engine: 1,
                    from: millis(350),
                    until: None,
                },
            ]
        );

        // Two identities held at once.
        let both = trace(
            vec![hold(0, 100, Some(200)), hold(1, 150, Some(500))],
            vec![outage(0, 200, Some(300)), outage(1, 500, Some(600))],
        );
        assert_eq!(both.overlaps(), 1);

        // One identity held through the outage of another.
        let through = trace(
            vec![hold(1, 250, Some(500))],
            vec![outage(0, 200, Some(300)), outage(1, 500, Some(600))],
        );
        assert_eq!(through.overlaps(), 1);

        // One identity held while another never comes back.
        let down = trace(vec![hold(1, 900, None)], vec![outage(0, 200, None)]);
        assert_eq!(down.overlaps(), 1);

        // Two instances of one identity are not two identities.
        let mut again = hold(0, 250, Some(400));
        again.instance = 2;
        let same = trace(
            vec![hold(0, 100, Some(200)), again],
            vec![outage(0, 200, Some(300))],
        );
        assert_eq!(same.overlaps(), 0);
        assert_eq!(same.impairments().len(), 2);
    }
}
