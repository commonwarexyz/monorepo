//! Adaptive execution policies for collection operations and spawned jobs.
//!
//! Entries are keyed by callsite, input-size bucket, work-size bucket, and planning parallelism
//! so a decision learned for one workload does not leak into another. The policy compares recent
//! wall-clock estimates of each path and picks whichever is faster, with ties going to serial
//! (equal wall time for fewer busy workers).
//!
//! The tuner considers serial execution for small cases where it can avoid dispatch overhead.
//! A large serial run keeps the caller busy without help from the pool, so serial is gated by
//! a live cost estimate both when sampled and when preferred.
//!
//! Sampling serial (the seed and every probe) requires the projected serial cost to fit under
//! [`SERIAL_SAMPLE_BUDGET_NS`]. The projection multiplies the chosen placement's estimated wall
//! time by its planning parallelism. Preferring serial in steady state requires both the projected
//! and the measured serial cost to fit under the same budget. The budget applies to estimates;
//! the current call's cost is known only after it completes.
//!
//! Every gate reads a live quantity, so no state is absorbing. The projection comes from the
//! parallel samples, and parallel records one every [`PREFERRED_SAMPLE_INTERVAL`] calls while it is
//! preferred and at every probe otherwise.
//!
//! Within the budget, a [`Cadence`] probes the losing path on an interval that grows exponentially
//! with how badly it lost and with how many consecutive probe slots confirmed the ordering, up to
//! `RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT` calls.
//!
//! Probes are never suppressed by the loser's own stale estimate, so an estimate poisoned by
//! transient conditions, such as pool contention at startup, can recover through later probes.
//!
//! [`Placement`] decides where a parallel run's placed work goes. Only a caller outside the
//! strategy's pool chooses a placement. A worker keeps every placed call under the placement of the
//! job it runs, so the timing of the outermost call (a run's wall time or a job's elapsed time)
//! covers the placed calls nested in its work.
//!
//! Each run entry learns its placement as a [`Choice`]. The choice seeds Wide and then Local,
//! prefers the faster, and probes the slower on the intervals above.
//!
//! Each placement has its own cadence for the serial-versus-parallel decision. A caller compares
//! serial against the placement it would use, on that placement's cadence. That is the placement
//! it is confined to, or the preferred placement when it has a choice. Every caller on one cadence
//! makes the same comparison, so each probe and sample slot lands on a caller that can act on it.
//!
//! For a run, a caller with a choice consults the placement first on every call. The slower
//! placement's probe interval follows its loss to the faster of the preferred placement and serial,
//! so it is probed even while serial wins, and no more often than its loss to serial warrants.
//! Serial counts only while it could be preferred. Once the budget gates it out, the slower
//! placement races the preferred one alone.
//!
//! Spawned jobs compare inline against the overhead of offloading them, just as runs compare serial
//! against a placement's wall time. Callers outside the strategy's pool share one hand-off overhead
//! estimate and one cadence. A worker keeps its job under the placement of the job it runs, and its
//! round trip is not a hand-off, so workers keep an overhead estimate and cadence of their own.
//!
//! On a pool with multiple groups, an admitted external root also chooses descendant placement.
//! Every external root may start on any worker. A Local choice confines descendants to that
//! worker's group; a narrow remainder group uses Wide without recording a placement sample.
//! The choice compares worker-measured job times; it excludes queueing, late result polling,
//! and work the consumer performs after receiving the result. Overflow roots run Wide without
//! consulting or training this choice. Nested jobs inherit placement and do not train it either.
//! A lower sample of the losing descendant placement replaces its estimate immediately, so an
//! old delay cannot dominate its infrequent probes. Other samples use the usual estimate update.
//!
//! A confined caller compares serial with its own placement even when callers with a choice
//! prefer the other placement.
//!
//! The placements' parallel estimates are shared. The runs of a confined caller keep the estimate
//! of its placement current for callers with a choice, and a call site reached both ways blends the
//! timings of both. Each placement's wall time projects a serial cost at its planning parallelism.
//! Local runs share one planning width within an entry, and the entry's key includes the strategy's
//! parallelism override.
//!
//! Timing is coarse, with one wall-clock sample per measured call. A parallel sample includes any
//! queueing behind other work on a group, so contention pushes the parallel estimate up and steers
//! concurrent callers back toward serial. When contention inflates the projection past the budget,
//! the same pressure instead biases the entry to parallel until the contention subsides.
//!
//! Fallible operations record samples only on success. Error paths often abort early, and recording
//! their short wall time would let garbage inputs drag an estimate down and unlock a serial sample
//! of genuine work. Both paths produce identical results, so a misjudged call costs only
//! throughput, never correctness.
//!
//! State updates are serialized per policy entry, but calls do not hold the entry lock while work
//! executes. Concurrent calls may therefore make decisions from an estimate that another in-flight
//! call later updates, and measured samples are applied in completion order.

use dashmap::DashMap;
use std::{panic::Location, sync::Arc, time::Duration};

// Refresh the preferred path periodically so its EWMA does not go stale.
const PREFERRED_SAMPLE_INTERVAL: u32 = 10;

// Probe the losing path this often when its estimate is within 2x of the winner's and the ordering
// has no confirmations.
const RESAMPLE_INTERVAL: u32 = 100;

// Each additional multiple of the winner's wall time and each confirmation of the ordering doubles
// the probe interval, up to this shift (100 << 5 = 3,200 calls). The cap keeps every path
// discoverable while the interval amortizes the cost of a mispriced probe across thousands of
// calls. A parallel probe pays any pool queueing in full.
const MAX_RESAMPLE_SHIFT: u32 = 5;

// Serial is seeded or probed only when its projected cost fits this budget. Preferring it also
// requires its measured cost to fit.
const SERIAL_SAMPLE_BUDGET_NS: u64 = 10_000_000;

// Only jobs estimated within this budget are eligible to run inline on the caller.
const SPAWN_INLINE_BUDGET_NS: u64 = 1_000_000;

// Track a short EWMA so recent measurements outweigh old startup noise.
const EWMA_PREVIOUS_WEIGHT: u64 = 4;
const EWMA_NEXT_WEIGHT: u64 = 1;
const EWMA_WEIGHT: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_NEXT_WEIGHT;

type RunEntries = DashMap<Key, RunEntry>;
type SpawnEntries = DashMap<Key, SpawnEntry>;

/// The path the policy chose for a call: the strategy runs the matching serial or parallel body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RunExecution {
    /// The serial body, on the calling thread.
    Serial,
    /// The parallel body. The body of `Strategy::run` runs on the calling thread and hands the
    /// strategy the work to distribute. A collection operation runs it on the workers of its
    /// placement.
    Parallel,
}

/// How the spawn policy runs a job: inline on the calling task, or handed off to a pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnExecution {
    /// On the calling task, at submission.
    Inline,
    /// On a pool worker, with the result sent back to the awaiting task.
    Offload,
}

/// Where a parallel run's placed work runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Placement {
    /// Any worker of the strategy's pool, offered first to the caller's home group. A sort from
    /// outside the pool never runs here.
    Wide,
    /// The workers of one group: the group homed in the calling thread's last-level cache domain,
    /// or a worker's own group under a local placement. An operation that runs on one group takes
    /// the least loaded group when its caller cannot get one in its domain.
    Local,
}

/// The placements a run's caller may use, each with the parallelism it plans with there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pools {
    /// Only this placement takes part in the decision.
    Fixed(Placement, usize),
    /// Wide or Local, with Local's planning parallelism.
    Either(usize),
}

/// Where an offloaded job runs, as its round trip is recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnPool {
    /// The submitting worker's own pool, under the placement of the job it runs. Its round trip is
    /// not a hand-off, so it feeds the overhead estimate kept for workers.
    Own,
    /// A hand-off from outside the strategy's pool to a group the strategy picks. A fixed plan also
    /// names it. Its timed round trip feeds the hand-off overhead that callers outside the pool
    /// compare inline against.
    Pool,
}

/// The decisions for one spawned job and whether the caller should time it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpawnPlan {
    /// Whether the job runs inline or on a pool.
    pub(super) execution: SpawnExecution,
    /// The pool an offloaded job runs on. An inline job records no round trip, so its pool is not
    /// consulted.
    pub(super) pool: SpawnPool,
    /// The descendant placement of an admitted external root on a grouped pool. Local uses the
    /// group of the worker that starts the root. `None` keeps the queued job's placement.
    pub(super) placement: Option<Placement>,
    /// Whether the caller times the job and reports the samples.
    pub(super) measure: bool,
}

impl SpawnPlan {
    /// An untimed plan to run the job on `execution`, with no learned choices. Its pool names the
    /// hand-off from outside the strategy's pool, and a worker keeps the job in its own pool
    /// whatever the plan says.
    pub(super) const fn fixed(execution: SpawnExecution) -> Self {
        Self {
            execution,
            pool: SpawnPool::Pool,
            placement: None,
            measure: false,
        }
    }
}

/// Adaptive execution decisions (serial vs parallel for collection operations, inline vs
/// offload for spawned jobs), shared cheaply across [`super::Rayon`] clones.
#[derive(Clone, Debug, Default)]
pub(super) struct Policy {
    run_entries: Arc<RunEntries>,
    spawn_entries: Arc<SpawnEntries>,
}

impl Policy {
    /// Chooses the execution path for this call site and, for a parallel run, the placement.
    ///
    /// `pools` reports the placements the caller may use. It is called before every adaptive
    /// decision, since the decision depends on them.
    pub(super) fn choose_run(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        pools: impl FnOnce() -> Pools,
    ) -> RunPlan {
        let mut plan = RunPlan {
            execution: RunExecution::Serial,
            placement: Placement::Wide,
            measure: false,
        };

        // A strategy configured for serial execution cannot benefit from rayon scheduling, so
        // always run serial and never spend a measurement on it.
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, work, parallelism);

        // A caller decides between serial and the placement it would use, on that placement's
        // cadence. A caller with a choice of placements consults the placement first. The lookup
        // runs before the entry is locked, since it takes the groups' locks.
        let local_parallelism = match pools() {
            Pools::Fixed(placement, pool_parallelism) => {
                (plan.execution, plan.measure) = self
                    .run_entries
                    .entry(key)
                    .or_default()
                    .choose(placement, pool_parallelism);
                if plan.execution == RunExecution::Parallel {
                    plan.placement = placement;
                }
                return plan;
            }
            Pools::Either(local_parallelism) => local_parallelism,
        };

        // A placement seed or probe takes the call as a timed parallel run and leaves both
        // execution cadences unchanged, so the probes never displace each other's boundary.
        let mut entry = self.run_entries.entry(key).or_default();
        let preferred = entry.placement.preferred();
        let preferred_parallelism = match preferred {
            Placement::Wide => parallelism,
            Placement::Local => local_parallelism,
        };
        let serial_ns = entry.serial_ns.get();
        let rival_ns = entry.serial_rival_ns(preferred, preferred_parallelism);
        let (placement, _) = entry.placement.choose(rival_ns);
        if placement == preferred {
            (plan.execution, plan.measure) = entry.choose(preferred, preferred_parallelism);
            if plan.execution != RunExecution::Parallel {
                return plan;
            }
        } else {
            // Until serial is measured, a placement's first sample leaves its serial
            // comparison due.
            if serial_ns.is_none() && entry.placement.estimate(placement).is_none() {
                entry.cadences[placement as usize].saturate();
            }
            (plan.execution, plan.measure) = (RunExecution::Parallel, true);
        }
        plan.placement = placement;
        plan
    }

    /// Records the wall time of a run that followed `plan`.
    pub(super) fn record_run_placed(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        plan: RunPlan,
        elapsed: Duration,
    ) {
        if parallelism <= 1 {
            return;
        }
        let key = Key::new(caller, len, work, parallelism);
        let mut entry = self.run_entries.entry(key).or_default();
        match plan.execution {
            RunExecution::Serial => entry.serial_ns.record(nanos(elapsed)),
            RunExecution::Parallel => entry.placement.record(plan.placement, nanos(elapsed)),
        }
    }

    /// Plans a spawned job, including whether the caller should time it and report the samples to
    /// [`Self::record_spawn_inline`], [`Self::record_spawn_job`], and
    /// [`Self::record_spawn_round_trip`].
    ///
    /// `own_pool` marks a worker of the strategy's pool. It keeps its job in that pool, under the
    /// placement of the job it runs, and decides on the cadence and overhead estimate kept for
    /// workers. A caller outside the pool decides on the hand-off overhead and its own cadence.
    pub(super) fn choose_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        own_pool: bool,
    ) -> SpawnPlan {
        // A single worker cannot overlap a hand-off, so always inline (nothing to measure).
        let mut plan = SpawnPlan::fixed(SpawnExecution::Inline);
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, len, parallelism);
        let spawner = if own_pool {
            plan.pool = SpawnPool::Own;
            Spawner::Worker
        } else {
            Spawner::Outside
        };
        let mut entry = self.spawn_entries.entry(key).or_default();
        (plan.execution, plan.measure) = entry.choose(spawner, SPAWN_INLINE_BUDGET_NS);
        plan
    }

    /// Chooses descendants' placement after a group admits an external root. Roots that overflow
    /// their group run Wide without advancing this choice or contributing placement samples.
    pub(super) fn choose_spawn_placement(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        mut plan: SpawnPlan,
    ) -> SpawnPlan {
        assert!(
            plan.execution == SpawnExecution::Offload
                && plan.pool == SpawnPool::Pool
                && plan.placement.is_none()
        );
        let key = Key::new(caller, len, len, parallelism);
        let (placement, measure) = self
            .spawn_entries
            .entry(key)
            .or_default()
            .placement
            .choose(None);
        plan.placement = Some(placement);
        plan.measure |= measure;
        plan
    }

    /// Records the wall time of a spawned job that ran inline on the calling task.
    pub(super) fn record_spawn_inline(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        job: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, |entry| {
            entry.inline_ns.record(nanos(job));
        });
    }

    /// Records the wall time of a spawned job that ran on a pool worker.
    pub(super) fn record_spawn_job(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        plan: SpawnPlan,
        job: Duration,
    ) {
        let job = nanos(job);
        self.record_spawn(caller, len, parallelism, |entry| {
            entry.job_ns.record(job);
            if let Some(placement) = plan.placement {
                entry.placement.record_spawn(placement, job);
            }
        });
    }

    /// Records one offloaded spawn's round trip under `plan`: the elapsed time from spawn entry
    /// until the awaiting future observes the result, and the job's own wall time within it.
    ///
    /// The round trip minus the job feeds the hand-off overhead estimate, or the overhead estimate
    /// kept for workers when the job stayed in the submitter's own pool.
    pub(super) fn record_spawn_round_trip(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        plan: SpawnPlan,
        round_trip: Duration,
        job: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, |entry| {
            let overhead = nanos(round_trip.saturating_sub(job));
            match plan.pool {
                SpawnPool::Own => entry.own_overhead_ns.record(overhead),
                SpawnPool::Pool => entry.overhead_ns.record(overhead),
            }
        });
    }

    /// Applies `record` to the spawn entry for this call site.
    fn record_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        record: impl FnOnce(&mut SpawnEntry),
    ) {
        if parallelism <= 1 {
            return;
        }
        let key = Key::new(caller, len, len, parallelism);
        record(&mut self.spawn_entries.entry(key).or_default());
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.run_entries.len()
    }

    #[cfg(test)]
    pub(super) fn spawn_len(&self) -> usize {
        self.spawn_entries.len()
    }

    /// Whether the spawn entry for this call site has recorded a sample of an offloaded job: a
    /// hand-off overhead, a worker's own-pool overhead, or a job wall. An inline sample does not
    /// count, and an entry that only `choose_spawn` has touched has no estimates.
    #[cfg(test)]
    pub(super) fn spawn_recorded(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> bool {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries.get(&key).is_some_and(|entry| {
            entry.overhead_ns.get().is_some()
                || entry.own_overhead_ns.get().is_some()
                || entry.job_ns.get().is_some()
        })
    }

    /// The job wall estimate, in nanoseconds, that pool workers recorded for this call site, or
    /// `None` until a worker has recorded one.
    #[cfg(test)]
    pub(super) fn spawn_job_estimate(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> Option<u64> {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries
            .get(&key)
            .and_then(|entry| entry.job_ns.get())
    }

    /// Whether descendant placement has been consulted or sampled for this call site.
    #[cfg(test)]
    pub(super) fn spawn_placement_used(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> bool {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries.get(&key).is_some_and(|entry| {
            let choice = &entry.placement;
            choice.wide_ns.get().is_some()
                || choice.local_ns.get().is_some()
                || choice.cadence.since_probe != 0
                || choice.cadence.boundary.is_some()
        })
    }

    /// The hand-off overhead and the overhead kept for workers, in nanoseconds, of the spawn entry
    /// for this call site, or `None` when the entry does not exist.
    #[cfg(test)]
    pub(super) fn spawn_overhead_estimates(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> Option<(Option<u64>, Option<u64>)> {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries
            .get(&key)
            .map(|entry| (entry.overhead_ns.get(), entry.own_overhead_ns.get()))
    }

    /// Records the wall time of a run on `execution` for this call site.
    #[cfg(test)]
    pub(super) fn record_run(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        execution: RunExecution,
        elapsed: Duration,
    ) {
        let key = Key::new(caller, len, work, parallelism);
        self.run_entries
            .entry(key)
            .or_default()
            .record(execution, elapsed);
    }

    /// The Wide and Local estimates, in nanoseconds, of the run entry for this call site, or
    /// `None` when the entry does not exist.
    #[cfg(test)]
    pub(super) fn run_placement_estimates(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
    ) -> Option<(Option<u64>, Option<u64>)> {
        let key = Key::new(caller, len, work, parallelism);
        self.run_entries.get(&key).map(|entry| {
            (
                entry.placement.wide_ns.get(),
                entry.placement.local_ns.get(),
            )
        })
    }

    #[cfg(test)]
    pub(super) fn get_entry(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
    ) -> Option<(Option<u64>, Option<u64>)> {
        let key = Key::new(caller, len, work, parallelism);
        self.run_entries
            .get(&key)
            .map(|e| (e.serial_ns.get(), e.parallel_ns()))
    }
}

/// Identifies a stream of similar calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct Key {
    file: &'static str,
    line: u32,
    column: u32,
    len_bucket: u8,
    work_bucket: u8,
    parallelism: usize,
}

impl Key {
    const fn new(
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
    ) -> Self {
        Self {
            file: caller.file(),
            line: caller.line(),
            column: caller.column(),
            len_bucket: len_bucket(len),
            work_bucket: len_bucket(work),
            parallelism,
        }
    }
}

/// An empty, seeded, or live wall-clock estimate in nanoseconds.
#[derive(Clone, Copy, Debug, Default)]
enum Estimate {
    #[default]
    Empty,
    Seed(u64),
    Live(u64),
}

impl Estimate {
    const fn get(&self) -> Option<u64> {
        match *self {
            Self::Empty => None,
            Self::Seed(value) | Self::Live(value) => Some(value),
        }
    }

    /// Seeds from the first sample and replaces that seed if the second sample is lower. Other
    /// samples blend into the EWMA, moving the estimate by at most a fifth of the gap.
    fn record(&mut self, sample_ns: u64) {
        *self = match *self {
            Self::Empty => Self::Seed(sample_ns),
            Self::Seed(current) if sample_ns < current => Self::Live(sample_ns),
            Self::Seed(current) | Self::Live(current) => {
                Self::Live(update_ewma(current, sample_ns))
            }
        };
    }
}

/// Paces measurement and probing for one policy entry.
///
/// Between boundaries the preferred path is measured every [`PREFERRED_SAMPLE_INTERVAL`] calls so
/// its estimate stays live. The boundary recurs every `RESAMPLE_INTERVAL << shift` calls, where the
/// shift sums two counts and is capped at [`MAX_RESAMPLE_SHIFT`]. The gap adds one once the loser
/// takes twice the winner's wall time and one more for each further multiple up to the same cap, so
/// a blowout is re-checked rarely. The confirmations add one each, so a race whose ordering holds
/// backs off however close it is.
///
/// A boundary confirms the ordering when the same path is preferred as at the previous boundary and
/// the gap's count is no smaller. Movement that stays within the same whole multiple of the
/// winner's wall time still confirms, so such noise does not reset the count.
///
/// Any call that finds the other path preferred, or the gap's count smaller than at the latest
/// boundary, clears the confirmations. The interval falls back at once to what the gap alone sets,
/// and only later boundaries that confirm the ordering rebuild the count. The first boundary starts
/// it at zero.
///
/// A boundary whose probe is disallowed still measures the preferred path and confirms the
/// ordering like any other boundary, so once the probe is allowed again, it comes within the
/// capped interval.
#[derive(Clone, Copy, Debug)]
struct Cadence<P> {
    // Calls since the latest boundary.
    since_probe: u32,
    // The preferred path and the gap's count at the latest boundary, or `None` before the first.
    boundary: Option<(P, u32)>,
    // Consecutive boundaries that confirmed the ordering, cleared by any call that contradicts the
    // latest one. The count stops at `MAX_RESAMPLE_SHIFT`, since more could not lengthen the
    // interval.
    confirmations: u32,
}

impl<P> Cadence<P> {
    const fn new() -> Self {
        Self {
            since_probe: 0,
            boundary: None,
            confirmations: 0,
        }
    }
}

impl<P> Default for Cadence<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Copy + PartialEq> Cadence<P> {
    // Saturate the counter so the next call lands on a boundary (used at seed time so a freshly
    // seeded entry is re-examined immediately instead of waiting a full interval that a
    // low-frequency callsite may never reach).
    const fn saturate(&mut self) {
        self.since_probe = u32::MAX;
    }

    // Arbitrates one call between a `preferred` and a `loser` path. Returns the path to run and
    // whether the caller should time it. The loser runs at an allowed probe boundary, and a
    // disallowed boundary still measures the preferred path. Either kind of boundary resets the
    // counter and updates the confirmations.
    fn arbitrate(
        &mut self,
        preferred: P,
        loser: P,
        winner_ns: u64,
        loser_ns: u64,
        probe_allowed: bool,
    ) -> (P, bool) {
        let slowdown = loser_ns / winner_ns.max(1);
        let gap_shift = slowdown
            .saturating_sub(1)
            .min(u64::from(MAX_RESAMPLE_SHIFT)) as u32;
        let confirmed = self
            .boundary
            .is_some_and(|(path, shift)| path == preferred && gap_shift >= shift);
        if !confirmed {
            self.confirmations = 0;
        }
        let interval =
            RESAMPLE_INTERVAL << (gap_shift + self.confirmations).min(MAX_RESAMPLE_SHIFT);
        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe >= interval {
            self.since_probe = 0;
            self.boundary = Some((preferred, gap_shift));
            if confirmed {
                self.confirmations = (self.confirmations + 1).min(MAX_RESAMPLE_SHIFT);
            }
            if probe_allowed {
                return (loser, true);
            }
            return (preferred, true);
        }
        (
            preferred,
            self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
        )
    }
}

/// Timing state for one [`Key`].
#[derive(Clone, Copy, Debug, Default)]
struct RunEntry {
    // The serial wall time. Every caller runs serial on its own thread, so one estimate serves
    // callers with a choice and confined callers alike.
    serial_ns: Estimate,
    // The parallel wall time of each placement, shared by callers with a choice and confined
    // callers. A caller with a choice compares serial against the preferred placement alone, so a
    // probe of the slower placement never raises the estimate it compares against. A confined
    // caller compares serial against the placement it is confined to.
    placement: Choice,
    // The cadences on which serial is arbitrated against each placement, indexed by placement.
    // Every caller on one cadence compares serial against the same placement, so each probe lands
    // on a caller that can act on it.
    cadences: [Cadence<RunExecution>; 2],
}

impl RunEntry {
    // Projects the serial cost from the placement's wall time and planning parallelism.
    fn projected_serial(parallel_ns: u64, parallelism: usize) -> u64 {
        parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX))
    }

    // Returns the preferred placement's wall time, or `None` until Wide is measured. A caller with
    // a choice decides on this estimate.
    #[cfg(test)]
    const fn parallel_ns(&self) -> Option<u64> {
        self.placement.estimate(self.placement.preferred())
    }

    // The estimate of `placement` and the serial cost projected at its planning parallelism,
    // or `None` until that placement is measured.
    fn estimates(&self, placement: Placement, parallelism: usize) -> Option<(u64, u64)> {
        let parallel_ns = self.placement.estimate(placement)?;
        let projected_ns = Self::projected_serial(parallel_ns, parallelism);
        Some((parallel_ns, projected_ns))
    }

    // Returns the path to prefer: the faster estimate, provided both the projected and
    // measured serial cost fit under the budget (the tuner only arbitrates small cases).
    // Ties go to serial (equal wall time for fewer busy workers).
    const fn preferred(serial_ns: u64, parallel_ns: u64, projected_ns: u64) -> RunExecution {
        if projected_ns >= SERIAL_SAMPLE_BUDGET_NS
            || serial_ns >= SERIAL_SAMPLE_BUDGET_NS
            || parallel_ns < serial_ns
        {
            RunExecution::Parallel
        } else {
            RunExecution::Serial
        }
    }

    // Returns the measured serial wall time while serial could be preferred over `placement`, or
    // `None` otherwise. Serial can be preferred only while both its measured cost and the cost
    // projected from `placement` fit the budget, and a path that cannot be preferred must not pace
    // the placements' probes.
    fn serial_rival_ns(&self, placement: Placement, parallelism: usize) -> Option<u64> {
        let serial_ns = self.serial_ns.get()?;
        let (_, projected_ns) = self.estimates(placement, parallelism)?;
        (serial_ns < SERIAL_SAMPLE_BUDGET_NS && projected_ns < SERIAL_SAMPLE_BUDGET_NS)
            .then_some(serial_ns)
    }

    // Returns the path to run, serial or `placement`, and whether the caller should time it and
    // report the elapsed time to [`Policy::record_run_placed`]. The decision is made on that
    // placement's cadence.
    fn choose(&mut self, placement: Placement, parallelism: usize) -> (RunExecution, bool) {
        let serial_ns = self.serial_ns;
        let estimates = self.estimates(placement, parallelism);
        let cadence = &mut self.cadences[placement as usize];

        // Seed this placement's estimate with its first call. Until serial is measured, saturating
        // the placement's cadence keeps it due for an immediate boundary, so its next call offers
        // the serial seed as soon as the parallel estimate lands (when the projection allows). Once
        // serial is measured, the seed leaves the cadence fresh, since the boundary could only
        // probe a path that is already priced.
        let Some((parallel_ns, projected_ns)) = estimates else {
            if serial_ns.get().is_none() {
                cadence.saturate();
            }
            return (RunExecution::Parallel, true);
        };

        // The projection gates serial in both sampling and preference: a case whose projection
        // exceeds the budget never runs serial. It is live: parallel keeps refreshing whenever
        // it executes, so a case that shrinks into the budget unlocks on its own.
        let can_sample_serial = projected_ns < SERIAL_SAMPLE_BUDGET_NS;

        // Until serial is sampled, parallel is preferred by default and each boundary doubles as
        // the seed slot. The tie adds no gap, and each boundary confirms parallel like any held
        // ordering, so the retries of a seed whose sample never lands back off to the cap.
        let (preferred, loser, winner_ns, loser_ns) = serial_ns.get().map_or(
            (
                RunExecution::Parallel,
                RunExecution::Serial,
                parallel_ns,
                parallel_ns,
            ),
            |serial_ns| match Self::preferred(serial_ns, parallel_ns, projected_ns) {
                RunExecution::Serial => (
                    RunExecution::Serial,
                    RunExecution::Parallel,
                    serial_ns,
                    parallel_ns,
                ),
                RunExecution::Parallel => (
                    RunExecution::Parallel,
                    RunExecution::Serial,
                    parallel_ns,
                    serial_ns,
                ),
            },
        );

        // Exactly one caller crosses the boundary, and a serial seed whose sample never lands
        // is simply offered again at the next boundary. A serial seed or probe must fit the
        // live projection. A parallel probe is always allowed: it pays the true parallel wall
        // (including any pool queueing), which the capped interval amortizes.
        let probe_allowed = preferred == RunExecution::Serial || can_sample_serial;
        cadence.arbitrate(preferred, loser, winner_ns, loser_ns, probe_allowed)
    }

    // Records a serial run, or a Wide parallel run.
    #[cfg(test)]
    fn record(&mut self, execution: RunExecution, elapsed: Duration) {
        match execution {
            RunExecution::Serial => self.serial_ns.record(nanos(elapsed)),
            RunExecution::Parallel => self.placement.record(Placement::Wide, nanos(elapsed)),
        }
    }
}

/// The decisions for one run and whether the caller should time it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RunPlan {
    /// Whether the run is serial or parallel.
    pub(super) execution: RunExecution,
    /// The placement a parallel run uses. A serial run always carries [`Placement::Wide`].
    pub(super) placement: Placement,
    /// Whether the run is timed and recorded with [`Policy::record_run_placed`].
    pub(super) measure: bool,
}

/// A duration as a nanosecond sample, saturating at `u64::MAX`.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A learned choice between the Wide and Local placements.
///
/// Runs confined to one placement record into its estimate without consulting the choice, so
/// either estimate may exist before the first consultation.
#[derive(Clone, Copy, Debug, Default)]
struct Choice {
    /// Timings of Wide runs.
    wide_ns: Estimate,
    /// Timings of Local runs.
    local_ns: Estimate,
    /// The schedule for probing the slower placement.
    cadence: Cadence<Placement>,
}

impl Choice {
    /// The faster placement once both are measured, and Wide until then or on a tie.
    const fn preferred(&self) -> Placement {
        match (self.wide_ns.get(), self.local_ns.get()) {
            (Some(wide_ns), Some(local_ns)) if local_ns < wide_ns => Placement::Local,
            _ => Placement::Wide,
        }
    }

    /// The estimate of `placement`, or `None` until it is measured.
    const fn estimate(&self, placement: Placement) -> Option<u64> {
        match placement {
            Placement::Wide => self.wide_ns.get(),
            Placement::Local => self.local_ns.get(),
        }
    }

    /// Returns the placement to use and whether to measure it.
    ///
    /// A placement without an estimate is timed first, Wide before Local. After that the faster
    /// placement is preferred and the slower one is probed on the choice's own [`Cadence`]. The
    /// probe interval grows with the slower placement's loss to the faster of the preferred
    /// placement and `rival_ns`. A caller that could still take a path other than the placements
    /// passes that path's measured wall time as `rival_ns`, and a caller with no such path or no
    /// measurement of it passes `None`.
    fn choose(&mut self, rival_ns: Option<u64>) -> (Placement, bool) {
        let (Some(wide_ns), Some(local_ns)) = (self.wide_ns.get(), self.local_ns.get()) else {
            // Saturating the cadence keeps the choice due for a boundary while it seeds, so the
            // call after the seeds probes the loser.
            self.cadence.saturate();
            let placement = if self.wide_ns.get().is_none() {
                Placement::Wide
            } else {
                Placement::Local
            };
            return (placement, true);
        };

        let (preferred, loser, winner_ns, loser_ns) = match self.preferred() {
            Placement::Local => (Placement::Local, Placement::Wide, local_ns, wide_ns),
            Placement::Wide => (Placement::Wide, Placement::Local, wide_ns, local_ns),
        };
        let winner_ns = rival_ns.map_or(winner_ns, |rival_ns| rival_ns.min(winner_ns));
        self.cadence
            .arbitrate(preferred, loser, winner_ns, loser_ns, true)
    }

    /// Folds `sample_ns`, in nanoseconds, into the estimate of `placement`.
    fn record(&mut self, placement: Placement, sample_ns: u64) {
        match placement {
            Placement::Wide => self.wide_ns.record(sample_ns),
            Placement::Local => self.local_ns.record(sample_ns),
        }
    }

    /// Records a spawned root's descendant-placement sample. Lower samples of the currently
    /// losing placement take effect immediately; its infrequent probes must not retain old delays.
    fn record_spawn(&mut self, placement: Placement, sample_ns: u64) {
        let loser = placement != self.preferred();
        let estimate = match placement {
            Placement::Wide => &mut self.wide_ns,
            Placement::Local => &mut self.local_ns,
        };
        match estimate.get() {
            Some(current) if loser && sample_ns < current => *estimate = Estimate::Live(sample_ns),
            _ => estimate.record(sample_ns),
        }
    }
}

/// A population of spawning callers with its own execution cadence. Every caller in one population
/// compares inline against the same overhead estimate, so each probe lands on a caller that can act
/// on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Spawner {
    /// A worker of the strategy's pool. It keeps its job under the placement of the job it runs.
    Worker,
    /// A caller outside the pool. It hands its job off to a group the strategy chooses.
    Outside,
}

/// Timing state for one spawn [`Key`].
///
/// Since caller overlap cannot be observed, the policy prefers inline only when the job wall is no
/// greater than both the round-trip overhead EWMA its caller compares against and
/// [`SPAWN_INLINE_BUDGET_NS`]. The overhead is everything an offloaded run costs around the job
/// itself (hand-off setup, queueing, worker wake, result send, task wake, and the observing poll),
/// so a caller that waits on the result inlines whenever that is measured cheaper.
///
/// A caller that polls late inflates its overhead samples with overlap slack. That biases the
/// decision toward inline. The budget limits the estimated cost admitted onto the calling task.
///
/// The job wall is tracked per execution path. The worker-measured wall can include the cost of
/// moving the job to another core, so the decision prefers the inline-measured wall once one
/// exists. While offload is preferred, its probe boundary runs inline whenever the live worker wall
/// fits the budget, so an entry seeded into offload can still observe the inline wall.
#[derive(Clone, Copy, Debug, Default)]
struct SpawnEntry {
    // Only admitted external roots on grouped pools choose and train descendant placement.
    placement: Choice,
    // The hand-off overhead: the time from spawn entry to observed result of a job offloaded from
    // outside the pool, minus the job's own wall time.
    overhead_ns: Estimate,
    // The job's own wall time on a pool worker.
    job_ns: Estimate,
    // The job's own wall time inline on the calling task.
    inline_ns: Estimate,
    // The round-trip overhead of jobs that workers keep in their own pools. Such a worker may run
    // the job itself while it waits, so its overhead is not a hand-off's.
    own_overhead_ns: Estimate,
    // The cadences on which each [`Spawner`] arbitrates inline against its overhead, indexed by
    // spawner. Workers compare against their own overhead, so their probes must not consume the
    // slots of outside callers.
    cadences: [Cadence<SpawnExecution>; 2],
}

impl SpawnEntry {
    // Decides, on `spawner`'s cadence, whether its call runs inline or offloaded and whether the
    // caller should time it. A worker compares inline against the overhead kept for workers, and a
    // caller outside the pool against the hand-off overhead. `budget` caps the job wall eligible
    // for inlining.
    fn choose(&mut self, spawner: Spawner, budget: u64) -> (SpawnExecution, bool) {
        let overhead_ns = match spawner {
            Spawner::Worker => self.own_overhead_ns,
            Spawner::Outside => self.overhead_ns,
        };
        let cadence = &mut self.cadences[spawner as usize];

        // Seed both offload estimates before ever inlining.
        let (Some(overhead_ns), Some(job_ns)) = (overhead_ns.get(), self.job_ns.get()) else {
            cadence.saturate();
            return (SpawnExecution::Offload, true);
        };

        // Ties go to inline: equal cost for one fewer pool wake. An inline probe is gated on
        // the live worker wall fitting the budget: the inline wall is only observable by
        // inlining, so without the probe an entry seeded into offload could never learn it,
        // and gating on the live worker wall (not the stale inline estimate) lets a poisoned
        // inline estimate recover. An offload probe is always allowed, since it keeps the
        // offload estimates tracking the live pool.
        let bound = self.inline_ns.get().unwrap_or(job_ns);
        let threshold = overhead_ns.min(budget);
        let (preferred, loser, winner_ns, loser_ns, probe_allowed) = if bound > threshold {
            (
                SpawnExecution::Offload,
                SpawnExecution::Inline,
                threshold,
                bound,
                job_ns < budget,
            )
        } else {
            (
                SpawnExecution::Inline,
                SpawnExecution::Offload,
                bound,
                threshold,
                true,
            )
        };
        cadence.arbitrate(preferred, loser, winner_ns, loser_ns, probe_allowed)
    }
}

fn update_ewma(current: u64, next: u64) -> u64 {
    let weighted = u128::from(current) * u128::from(EWMA_PREVIOUS_WEIGHT)
        + u128::from(next) * u128::from(EWMA_NEXT_WEIGHT);
    (weighted / u128::from(EWMA_WEIGHT))
        .try_into()
        .unwrap_or(u64::MAX)
}

// Exact lengths are grouped into powers-of-two buckets to bound policy growth and avoid
// overfitting to tiny input differences.
const fn len_bucket(len: usize) -> u8 {
    if len == 0 {
        0
    } else {
        (usize::BITS - len.leading_zeros()) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cadence, Choice, MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL, Placement, Policy, Pools,
        RESAMPLE_INTERVAL, RunEntry, RunExecution, RunPlan, SPAWN_INLINE_BUDGET_NS, SpawnEntry,
        SpawnExecution, SpawnPlan, SpawnPool, Spawner,
    };
    use commonware_utils::Widen;
    use std::{cell::Cell, panic::Location, time::Duration};

    const PARALLELISM: usize = 4;

    /// The placements of a caller outside the strategy's pool, with a two-worker local group.
    const EITHER: Pools = Pools::Either(2);

    /// The placements of a caller confined to `placement`, with the strategy's parallelism on the
    /// whole pool and two workers on a local group.
    const fn confined(placement: Placement) -> Pools {
        match placement {
            Placement::Wide => Pools::Fixed(Placement::Wide, PARALLELISM),
            Placement::Local => Pools::Fixed(Placement::Local, 2),
        }
    }

    /// The placement other than `placement`.
    const fn other(placement: Placement) -> Placement {
        match placement {
            Placement::Wide => Placement::Local,
            Placement::Local => Placement::Wide,
        }
    }

    const fn plan_of(execution: SpawnExecution, pool: SpawnPool, measure: bool) -> SpawnPlan {
        SpawnPlan {
            execution,
            pool,
            placement: None,
            measure,
        }
    }

    fn choose(entry: &mut RunEntry) -> (RunExecution, bool) {
        entry.choose(entry.placement.preferred(), PARALLELISM)
    }

    /// The path `entry` prefers between serial and its preferred placement, projecting serial from
    /// that placement at [`PARALLELISM`].
    fn preferred(entry: &RunEntry) -> RunExecution {
        let parallel_ns = entry.parallel_ns().unwrap();
        RunEntry::preferred(
            entry.serial_ns.get().unwrap(),
            parallel_ns,
            RunEntry::projected_serial(parallel_ns, PARALLELISM),
        )
    }

    #[test]
    fn starts_parallel_then_seeds_serial_immediately() {
        let mut entry = RunEntry::default();

        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
        entry.record(RunExecution::Parallel, Duration::from_micros(100));

        // The projection fits the budget, so the serial seed is offered on the very next
        // call rather than after a full interval.
        assert_eq!(choose(&mut entry), (RunExecution::Serial, true));
        entry.record(RunExecution::Serial, Duration::from_micros(95));

        // With both estimates seeded, the boundary resumes its normal cadence.
        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
    }

    #[test]
    fn defers_serial_seed_when_projection_exceeds_budget() {
        let mut entry = RunEntry::default();

        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
        entry.record(RunExecution::Parallel, Duration::from_millis(10));

        // The projection (10ms x 4) is over budget, so the immediate boundary refreshes
        // parallel instead of seeding serial and the cadence resets to a full interval.
        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
        assert!(entry.serial_ns.get().is_none());
        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
    }

    #[test]
    fn never_seeds_serial_when_projection_exceeds_budget() {
        // A serial pass could cost up to parallel * parallelism. When that projection exceeds
        // the budget, the tuner biases to parallel without ever paying a serial sample.
        let mut entry = RunEntry::default();

        entry.record(RunExecution::Parallel, Duration::from_millis(10));

        for i in 1..=(2 * RESAMPLE_INTERVAL) {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert!(entry.serial_ns.get().is_none());
    }

    #[test]
    fn never_runs_serial_on_big_work() {
        // The production profile of a large signature batch: parallel wall of 25ms on a
        // 12-thread pool. Serial must never run, no matter how many calls arrive.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(25));

        for _ in 0..10_000 {
            let (execution, measure) = entry.choose(entry.placement.preferred(), 12);
            assert_eq!(execution, RunExecution::Parallel);
            if measure {
                entry.record(RunExecution::Parallel, Duration::from_millis(25));
            }
        }
        assert!(entry.serial_ns.get().is_none());
    }

    #[test]
    fn big_serial_estimate_biases_parallel() {
        // Both estimates exceed the budget and serial nominally wins the comparison, but the
        // tuner only arbitrates small cases: big work runs parallel outright, and the serial
        // probe stays suppressed because the projection is over budget too.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(30));
        entry.record(RunExecution::Serial, Duration::from_millis(12));

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            let (execution, _) = choose(&mut entry);
            assert_eq!(execution, RunExecution::Parallel);
        }
    }

    #[test]
    fn projection_gates_preferred_serial() {
        // A workload grew within its bucket: parallel is now 25ms on a 12-thread pool
        // (projection 300ms, well over budget), but a stale serial estimate from a smaller
        // input claims 8ms. The live projection must keep serial from running.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(25));
        entry.record(RunExecution::Serial, Duration::from_millis(8));

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            let (execution, _) = entry.choose(entry.placement.preferred(), 12);
            assert_eq!(execution, RunExecution::Parallel);
        }
    }

    #[test]
    fn prefers_serial_when_faster() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(95));

        assert_eq!(choose(&mut entry), (RunExecution::Serial, false));
    }

    #[test]
    fn prefers_parallel_when_it_wins_wall_time() {
        // Serial is only 2x slower in wall time (cheaper in worker time on a 4-thread pool),
        // but the policy optimizes latency: parallel wins.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(200));

        assert_eq!(choose(&mut entry), (RunExecution::Parallel, false));
    }

    #[test]
    fn prefers_serial_on_tie() {
        // Equal wall time: serial occupies one worker instead of the whole pool.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(100));

        assert_eq!(choose(&mut entry), (RunExecution::Serial, false));
    }

    #[test]
    fn pre_seed_parallel_samples_blend() {
        // Before serial is seeded there is no loser: parallel samples smooth into the EWMA,
        // so a single outlier (a contended call) cannot swing the projection that gates
        // serial sampling.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(10));
        entry.record(RunExecution::Parallel, Duration::from_millis(20));

        assert_eq!(entry.parallel_ns(), Some(12_000_000));
    }

    #[test]
    fn blends_preferred_samples_with_integer_math() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_nanos(1000));
        entry.record(RunExecution::Serial, Duration::from_nanos(100));

        // Serial is preferred, so further serial samples blend 4:1.
        entry.record(RunExecution::Serial, Duration::from_nanos(200));

        assert_eq!(entry.serial_ns.get(), Some(120));
    }

    #[test]
    fn blends_preferred_parallel_samples() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_nanos(100));
        entry.record(RunExecution::Serial, Duration::from_nanos(1000));

        // Parallel is preferred, so further parallel samples blend 4:1.
        entry.record(RunExecution::Parallel, Duration::from_nanos(200));

        assert_eq!(entry.parallel_ns(), Some(120));
    }

    #[test]
    fn probes_blend_into_stale_estimates() {
        // One probe moves an established estimate by a fifth of the gap.
        let mut entry = RunEntry::default();
        for _ in 0..2 {
            entry.record(RunExecution::Parallel, Duration::from_millis(25));
            entry.record(RunExecution::Serial, Duration::from_millis(100));
        }

        entry.record(RunExecution::Serial, Duration::from_millis(5));

        assert_eq!(entry.serial_ns.get(), Some(81_000_000));
        assert_eq!(preferred(&entry), RunExecution::Parallel);
    }

    #[test]
    fn seeds_serial_once_projection_shrinks_into_budget() {
        // The projection is live: a key that starts over budget seeds serial at the first
        // boundary after refreshes shrink the parallel estimate into the budget.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(10));

        for _ in 1..RESAMPLE_INTERVAL {
            let (execution, measure) = choose(&mut entry);
            assert_eq!(execution, RunExecution::Parallel);
            if measure {
                entry.record(RunExecution::Parallel, Duration::from_micros(100));
            }
        }
        assert_eq!(choose(&mut entry), (RunExecution::Serial, true));
    }

    #[test]
    fn resamples_other_execution() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(80));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
    }

    #[test]
    fn resamples_serial_when_parallel_wins() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(150));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Serial, true));
    }

    #[test]
    fn resample_interval_doubles_per_slowdown_multiple() {
        // Parallel lost by 2x-3x, so the probe interval doubles once.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(250));
        entry.record(RunExecution::Serial, Duration::from_micros(100));

        for i in 1..(2 * RESAMPLE_INTERVAL) {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
    }

    #[test]
    fn resample_interval_is_capped() {
        // Serial lost by 9x, so the interval shift is capped and the probe still happens.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(900));

        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Serial, true));
    }

    #[test]
    fn recovers_from_a_stale_estimate() {
        // An established parallel estimate of 2ms favors serial at 1ms. The projection remains
        // under budget (2ms x 4 = 8ms), so probes can discover parallel's current cost of 0.5ms.
        let mut entry = RunEntry::default();
        for _ in 0..2 {
            entry.record(RunExecution::Parallel, Duration::from_millis(2));
            entry.record(RunExecution::Serial, Duration::from_millis(1));
        }
        assert_eq!(preferred(&entry), RunExecution::Serial);

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=2_000 {
            if preferred(&entry) == RunExecution::Parallel {
                flipped_at = Some(i - 1);
                break;
            }
            let (execution, measure) = choose(&mut entry);
            match execution {
                RunExecution::Parallel => {
                    assert!(measure);
                    probes += 1;
                    entry.record(RunExecution::Parallel, Duration::from_micros(500));
                }
                RunExecution::Serial => {
                    if measure {
                        entry.record(RunExecution::Serial, Duration::from_millis(1));
                    }
                }
            }
        }

        // The estimate converges 2 -> 1.7 -> 1.46 -> 1.268 -> 1.1144 -> 0.99152ms over five probes.
        // The first probe comes 200 calls in, since parallel trails by 2x. It brings parallel
        // within 2x, a whole multiple closer, so the next probe comes 100 calls later and resets
        // the confirmations. Each later probe confirms that serial still wins, so the intervals run
        // 100, 200, and 400, and the flip happens at call 1,000.
        assert_eq!(probes, 5);
        assert_eq!(flipped_at, Some(1_000));
    }

    #[test]
    fn seed_offered_once_per_interval() {
        // Exactly one caller crosses the probe boundary and receives the serial seed, so
        // concurrent callers cannot herd onto serial. A seed whose sample never lands (the
        // call panicked) is offered again at the next boundary, so the key never wedges.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(250));

        for round in 0..2 {
            for i in 1..RESAMPLE_INTERVAL {
                assert_eq!(
                    choose(&mut entry),
                    (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0),
                    "round {round}"
                );
            }
            assert_eq!(choose(&mut entry), (RunExecution::Serial, true));
        }

        // Each boundary confirms parallel, so the later retries back off to the capped interval
        // and then keep coming at it.
        let cap = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        let seeds: Vec<_> = (2 * RESAMPLE_INTERVAL + 1..=4 * cap)
            .filter(|_| choose(&mut entry) == (RunExecution::Serial, true))
            .collect();
        assert_eq!(seeds, [400, 800, 1_600, 3_200, 6_400, 9_600, 12_800]);

        entry.record(RunExecution::Serial, Duration::from_millis(1));
        assert_eq!(choose(&mut entry).0, RunExecution::Parallel);
    }

    #[test]
    fn probes_big_serial_when_projection_is_affordable() {
        // A stale serial estimate above the budget must remain discoverable: the probe gate
        // reads the live projection.
        let mut entry = RunEntry::default();
        for _ in 0..2 {
            entry.record(RunExecution::Parallel, Duration::from_micros(500));
            entry.record(RunExecution::Serial, Duration::from_millis(15));
        }
        assert_eq!(preferred(&entry), RunExecution::Parallel);

        // Slowdown 15ms / 500us = 30 caps the shift, so the probe fires at 100 << 5 calls.
        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Serial, true));

        entry.record(RunExecution::Serial, Duration::from_micros(300));
        assert_eq!(entry.serial_ns.get(), Some(12_060_000));
    }

    #[test]
    fn one_fast_sample_preserves_an_established_preference() {
        // The established serial estimate stays above parallel after one unusually fast sample.
        let mut entry = RunEntry::default();
        for _ in 0..2 {
            entry.record(RunExecution::Parallel, Duration::from_micros(800));
            entry.record(RunExecution::Serial, Duration::from_millis(3));
        }
        assert_eq!(preferred(&entry), RunExecution::Parallel);

        entry.record(RunExecution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns.get(), Some(2_404_000));
        assert_eq!(preferred(&entry), RunExecution::Parallel);
    }

    #[test]
    fn refreshes_preferred_parallel_sample() {
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(100));
        entry.record(RunExecution::Serial, Duration::from_micros(410));

        for i in 1..PREFERRED_SAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (RunExecution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (RunExecution::Parallel, true));
    }

    /// Drives `cadence` through `calls` calls of a race that `preferred` wins in 1,000 ns against
    /// the other path's `loser_ns`, and returns the calls, counted from one, that crossed a
    /// boundary. Each boundary must be timed and must run the other path exactly when
    /// `probe_allowed`.
    fn boundaries(
        cadence: &mut Cadence<RunExecution>,
        calls: u32,
        preferred: RunExecution,
        loser_ns: u64,
        probe_allowed: bool,
    ) -> Vec<u32> {
        let loser = match preferred {
            RunExecution::Serial => RunExecution::Parallel,
            RunExecution::Parallel => RunExecution::Serial,
        };
        (1..=calls)
            .filter(|call| {
                let (path, measure) =
                    cadence.arbitrate(preferred, loser, 1_000, loser_ns, probe_allowed);
                let boundary = cadence.since_probe == 0;
                assert!(
                    !boundary || measure,
                    "call {call}: a boundary must be timed"
                );
                assert_eq!(
                    path == loser,
                    boundary && probe_allowed,
                    "call {call}: the loser must run exactly at an allowed boundary"
                );
                boundary
            })
            .collect()
    }

    #[test]
    fn cadence_backs_off_with_each_confirmation() {
        // A loser within 2x of the winner starts at the base interval. The first boundary has no
        // earlier preference to confirm, and every later one confirms the one before, so each
        // interval after the second doubles until it reaches the cap.
        let mut cadence = Cadence::default();
        assert_eq!(
            boundaries(&mut cadence, 13_000, RunExecution::Serial, 1_000, true),
            [100, 200, 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800]
        );

        // A loser four times slower starts three doublings up, and the confirmations add to them.
        let mut cadence = Cadence::default();
        assert_eq!(
            boundaries(&mut cadence, 13_000, RunExecution::Serial, 4_000, true),
            [800, 1_600, 3_200, 6_400, 9_600, 12_800]
        );
    }

    #[test]
    fn cadence_resets_confirmations_on_a_flip() {
        // Serial holds through enough boundaries to reach the cap, and parallel becomes preferred
        // a thousand calls into the next capped interval.
        let mut cadence = Cadence::default();
        assert_eq!(
            boundaries(&mut cadence, 7_400, RunExecution::Serial, 1_000, true),
            [100, 200, 400, 800, 1_600, 3_200, 6_400]
        );

        // The confirmations were of serial, so they stop lengthening the interval at once, and the
        // next call is already past the base interval. That boundary finds the other path preferred
        // and restarts the count, so the intervals back off from the base as they did after the
        // first boundary.
        assert_eq!(
            boundaries(&mut cadence, 6_400, RunExecution::Parallel, 1_000, true),
            [1, 101, 301, 701, 1_501, 3_101, 6_301]
        );
    }

    #[test]
    fn cadence_counts_a_disallowed_boundary_as_a_confirmation() {
        // The first three boundaries cannot probe the loser, so they time the preferred path. The
        // preferred path held at each, so each still counts. The probes that follow land where they
        // would have without the gate: 800, 1,600, and 3,200 calls from the start, or 400, 1,200,
        // and 2,800 calls after the gated stretch.
        let mut cadence = Cadence::default();
        assert_eq!(
            boundaries(&mut cadence, 400, RunExecution::Parallel, 1_000, false),
            [100, 200, 400]
        );
        assert_eq!(
            boundaries(&mut cadence, 2_800, RunExecution::Parallel, 1_000, true),
            [400, 1_200, 2_800]
        );
    }

    #[test]
    fn cadence_resets_confirmations_when_the_loser_closes_a_multiple() {
        // The loser starts within 2x of the winner, and two boundaries confirm serial.
        let mut cadence = Cadence::default();
        assert_eq!(
            boundaries(&mut cadence, 400, RunExecution::Serial, 1_500, true),
            [100, 200, 400]
        );

        // The loser falls a multiple further behind. A wider gap still confirms, so its doubling
        // adds to the two confirmations: 800 calls, then 1,600, then the cap.
        assert_eq!(
            boundaries(&mut cadence, 5_600, RunExecution::Serial, 2_900, true),
            [800, 2_400, 5_600]
        );

        // The loser moves within that multiple, from 2.9x to 2.0x the winner. The gap's count is
        // unchanged, so the cadence stays at the cap.
        assert_eq!(
            boundaries(&mut cadence, 4_200, RunExecution::Serial, 2_000, true),
            [3_200]
        );

        // The loser then closes a whole multiple, to 1.5x, a thousand calls into the next capped
        // interval. The confirmations stop lengthening the interval at once and the next call is
        // past the base interval. That boundary finds the gap smaller and starts the count again,
        // so the intervals back off from the base as after a flip.
        assert_eq!(
            boundaries(&mut cadence, 3_200, RunExecution::Serial, 1_500, true),
            [1, 101, 301, 701, 1_501, 3_101]
        );
    }

    #[test]
    fn spawn_seeds_offload_then_inlines_a_sub_overhead_job() {
        let mut entry = SpawnEntry::default();

        // The first call seeds both estimates from an offloaded run.
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );

        // A 2us job behind a 50us round-trip overhead.
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);

        // The seed leaves the entry due for an immediate boundary, which re-measures offload.
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);

        // The job costs less than the overhead and fits the budget, so it runs inline.
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_keeps_offloading_a_job_bigger_than_the_overhead() {
        // A 50us job behind a 5us round-trip overhead, so offloading is cheaper under any polling.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(50_000);
        entry.overhead_ns.record(5_000);

        // The seed leaves the entry due for a boundary, which probes inline (the worker wall
        // fits the budget) to observe the inline wall.
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(50_000);

        // The inline wall confirms the job is bigger than the overhead, so offload holds until
        // the next (backed-off) boundary.
        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS) {
                (SpawnExecution::Offload, measure) => {
                    if measure {
                        entry.job_ns.record(50_000);
                        entry.overhead_ns.record(5_000);
                    }
                }
                (execution, _) => panic!("expected offload, got {execution:?}"),
            }
        }
    }

    #[test]
    fn spawn_probe_learns_the_inline_wall() {
        // The worker-measured wall (25us, migrated to another core) exceeds the 10us overhead,
        // so the entry seeds into offload. The boundary probe runs the job inline, the inline
        // wall (8us) comes in under the overhead, and the entry flips: without the probe this
        // state is unlearnable.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(25_000);
        entry.overhead_ns.record(10_000);

        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(8_000);

        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_budget_caps_inline_when_the_overhead_is_inflated() {
        // A contended pool measured the round-trip overhead at 50ms. The 2ms job is cheaper, but its
        // EWMA exceeds the inline budget, so it remains offloaded.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000_000);
        entry.overhead_ns.record(50_000_000);

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS) {
                (SpawnExecution::Offload, measure) => {
                    if measure {
                        entry.job_ns.record(2_000_000);
                        entry.overhead_ns.record(50_000_000);
                    }
                }
                (execution, _) => panic!("expected offload, got {execution:?}"),
            }
        }
    }

    #[test]
    fn spawn_single_worker_always_inlines() {
        // With one worker a hand-off cannot overlap, so the policy inlines without measuring.
        let policy = Policy::default();
        let location = Location::caller();
        assert_eq!(
            policy.choose_spawn(location, 64, 1, false),
            plan_of(SpawnExecution::Inline, SpawnPool::Pool, false)
        );
    }

    #[test]
    fn spawn_inline_ewma_crossing_the_overhead_revokes_inline() {
        // A converged-inline entry whose inline wall grows: the flip must come from the inline
        // EWMA while the worker wall stays low, pinning that the decision prefers the inline
        // wall once one exists.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);
        entry.inline_ns.record(2_000);
        assert!(matches!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));

        // One grown sample blends the inline EWMA over the 50us overhead.
        entry.inline_ns.record(500_000);
        assert_eq!(entry.inline_ns.get(), Some(101_600));
        assert!(matches!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, _)
        ));
    }

    #[test]
    fn spawn_entries_bucket_by_len() {
        let policy = Policy::default();
        let location = Location::caller();

        let _ = policy.choose_spawn(location, 1, PARALLELISM, false);
        let _ = policy.choose_spawn(location, 2, PARALLELISM, false);
        let _ = policy.choose_spawn(location, 3, PARALLELISM, false);

        assert_eq!(policy.spawn_len(), 2);
    }

    #[test]
    fn spawn_records_feed_choose() {
        // Policy-level wiring for the three spawn record paths: the worker and future samples
        // seed the entry, and the probe's inline sample drives the flip.
        let policy = Policy::default();
        let location = Location::caller();

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false),
            plan_of(SpawnExecution::Offload, SpawnPool::Pool, true)
        );
        policy.record_spawn_job(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, SpawnPool::Pool, true),
            Duration::from_micros(25),
        );
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, SpawnPool::Pool, true),
            Duration::from_micros(10),
            Duration::ZERO,
        );

        // The boundary probes inline (the worker wall fits the budget).
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false),
            plan_of(SpawnExecution::Inline, SpawnPool::Pool, true)
        );

        // The probe's inline wall beats the overhead, so the entry flips inline: recording it
        // anywhere but the inline estimate would leave the entry offloaded.
        policy.record_spawn_inline(location, 64, PARALLELISM, Duration::from_micros(8));
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false),
            plan_of(SpawnExecution::Inline, SpawnPool::Pool, false)
        );
    }

    #[test]
    fn grouped_spawn_learns_from_external_job_samples() {
        let policy = Policy::default();
        let location = Location::caller();
        let key = super::Key::new(location, 64, 64, PARALLELISM);
        let next = || {
            let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
            policy.choose_spawn_placement(location, 64, PARALLELISM, plan)
        };
        for (placement, millis) in [(Placement::Wide, 8), (Placement::Local, 2)] {
            let plan = next();
            assert_eq!(plan.execution, SpawnExecution::Offload);
            assert_eq!(plan.placement, Some(placement));
            assert!(plan.measure);

            // A result can be dropped before it is observed. Only the worker's successful job
            // sample is needed to seed the descendant placement.
            policy.record_spawn_job(
                location,
                64,
                PARALLELISM,
                plan,
                Duration::from_millis(millis),
            );
        }

        let worker = policy.choose_spawn(location, 64, PARALLELISM, true);
        assert_eq!(worker.pool, SpawnPool::Own);
        assert_eq!(worker.placement, None);
        policy.record_spawn_job(location, 64, PARALLELISM, worker, Duration::from_millis(30));
        let entry = policy.spawn_entries.get(&key).unwrap();
        assert_eq!(entry.placement.estimate(Placement::Wide), Some(8_000_000));
        assert_eq!(entry.placement.estimate(Placement::Local), Some(2_000_000));
        drop(entry);

        // The first boundary probes the loser, then the preferred placement resumes.
        assert_eq!(next().placement, Some(Placement::Wide));
        assert_eq!(next().placement, Some(Placement::Local));
    }

    /// Drives `calls` admitted external roots of one call site as the strategy does, and returns
    /// each root's placement and whether it was measured. A measured root reports `wall` of its
    /// placement as its job wall time, with a small hand-off overhead on top.
    fn drive_roots(
        policy: &Policy,
        location: &'static Location<'static>,
        calls: usize,
        mut wall: impl FnMut(Placement) -> Duration,
    ) -> Vec<(Placement, bool)> {
        (0..calls)
            .map(|_| {
                let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
                let plan = policy.choose_spawn_placement(location, 64, PARALLELISM, plan);
                let placement = plan.placement.unwrap();
                if plan.measure {
                    let job = wall(placement);
                    let round_trip = job + Duration::from_micros(50);
                    policy.record_spawn_job(location, 64, PARALLELISM, plan, job);
                    policy.record_spawn_round_trip(
                        location,
                        64,
                        PARALLELISM,
                        plan,
                        round_trip,
                        job,
                    );
                }
                (placement, plan.measure)
            })
            .collect()
    }

    fn wide_runs(runs: &[(Placement, bool)]) -> Vec<usize> {
        runs.iter()
            .enumerate()
            .filter_map(|(index, &(placement, _))| (placement == Placement::Wide).then_some(index))
            .collect()
    }

    /// Wide's seed and first probe ran cold, so Local leads. Wide's next probe beats Local, and
    /// Wide takes the lead at once.
    #[test]
    fn spawn_placement_faster_probe_overrides_a_cold_loser() {
        let policy = Policy::default();
        let mut cold = [10_000, 5_600].into_iter();
        let runs = drive_roots(
            &policy,
            Location::caller(),
            2 * RESAMPLE_INTERVAL as usize,
            |placement| {
                Duration::from_micros(match placement {
                    Placement::Wide => cold.next().unwrap_or(4_700),
                    Placement::Local => 5_200,
                })
            },
        );
        let probe = wide_runs(&runs)[2];
        assert!(
            runs[probe + 1..]
                .iter()
                .all(|&(placement, _)| placement == Placement::Wide)
        );
    }

    /// One slow sample of the leading Wide placement hands the lead to Local. Wide is then sampled
    /// only at probes, and its first probe restores the lead.
    #[test]
    fn spawn_placement_faster_probe_recovers_from_a_preferred_spike() {
        let policy = Policy::default();
        let mut measured = 0;
        let runs = drive_roots(
            &policy,
            Location::caller(),
            2 * RESAMPLE_INTERVAL as usize,
            |placement| {
                Duration::from_micros(match placement {
                    Placement::Wide => {
                        measured += 1;
                        if measured == 2 { 12_300 } else { 4_660 }
                    }
                    Placement::Local => 5_250,
                })
            },
        );
        let spike = runs
            .iter()
            .enumerate()
            .filter(|&(_, &(placement, measured))| placement == Placement::Wide && measured)
            .nth(1)
            .unwrap()
            .0;
        let probe = wide_runs(&runs)
            .into_iter()
            .find(|&index| index > spike)
            .unwrap();
        assert!(probe > spike + 1, "the spike must hand the lead to Local");
        assert!(
            runs[probe + 1..]
                .iter()
                .all(|&(placement, _)| placement == Placement::Wide)
        );
    }

    /// A slow probe of the losing placement blends into its estimate, so the next probe follows
    /// the usual backoff instead of the long one that the outlier alone would set.
    #[test]
    fn spawn_placement_slow_probe_stays_damped() {
        let policy = Policy::default();
        let mut probes = 0;
        let runs = drive_roots(
            &policy,
            Location::caller(),
            6 * RESAMPLE_INTERVAL as usize,
            |placement| {
                Duration::from_micros(match placement {
                    Placement::Wide => {
                        probes += 1;
                        if probes == 3 { 30_000 } else { 5_500 }
                    }
                    Placement::Local => 5_200,
                })
            },
        );
        let wide = wide_runs(&runs);
        assert!(wide[3] - wide[2] <= (RESAMPLE_INTERVAL << 2) as usize);
    }

    /// A lucky probe can hand the lead to the slower Wide placement. Wide is then measured as the
    /// preferred placement, and its true wall time returns the lead to Local within two samples.
    #[test]
    fn spawn_placement_lucky_probe_reverts_within_two_samples() {
        let policy = Policy::default();
        let mut probes = 0;
        let runs = drive_roots(
            &policy,
            Location::caller(),
            2 * RESAMPLE_INTERVAL as usize,
            |placement| {
                Duration::from_micros(match placement {
                    Placement::Wide => {
                        probes += 1;
                        if probes == 3 { 4_500 } else { 5_200 }
                    }
                    Placement::Local => 4_700,
                })
            },
        );
        let lucky = wide_runs(&runs)[2];
        let back = lucky
            + runs[lucky..]
                .iter()
                .position(|&(placement, _)| placement == Placement::Local)
                .unwrap();
        assert!(back > lucky + 1, "the lucky probe must make Wide preferred");
        let measured = runs[lucky + 1..back]
            .iter()
            .filter(|&&(_, measured)| measured)
            .count();
        assert!(measured <= 2);
    }

    #[test]
    fn grouped_spawn_round_trip_does_not_train_descendant_placement() {
        let policy = Policy::default();
        let location = Location::caller();
        let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
        let plan = policy.choose_spawn_placement(location, 64, PARALLELISM, plan);
        assert_eq!(plan.placement, Some(Placement::Wide));
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan,
            Duration::from_secs(1),
            Duration::from_millis(2),
        );
        let key = super::Key::new(location, 64, 64, PARALLELISM);
        let entry = policy.spawn_entries.get(&key).unwrap();
        assert_eq!(entry.placement.estimate(Placement::Wide), None);
        assert_eq!(entry.placement.estimate(Placement::Local), None);
        drop(entry);
        let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
        assert_eq!(
            policy
                .choose_spawn_placement(location, 64, PARALLELISM, plan)
                .placement,
            Some(Placement::Wide)
        );
    }

    #[test]
    fn unplaced_spawns_leave_placement_seeds_and_probes_unchanged() {
        let policy = Policy::default();
        let location = Location::caller();
        let key = super::Key::new(location, 64, 64, PARALLELISM);
        let overflow = || {
            for _ in 0..(2 * RESAMPLE_INTERVAL) {
                let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
                assert_eq!(plan.execution, SpawnExecution::Offload);
                assert_eq!(plan.placement, None);
                if plan.measure {
                    policy.record_spawn_job(
                        location,
                        64,
                        PARALLELISM,
                        plan,
                        Duration::from_millis(8),
                    );
                }
            }
        };
        overflow();
        {
            let entry = policy.spawn_entries.get(&key).unwrap();
            assert_eq!(entry.placement.estimate(Placement::Wide), None);
            assert_eq!(entry.placement.estimate(Placement::Local), None);
        }

        // Only admitted roots advance the seed sequence and the immediate loser probe.
        for (expected, millis) in [
            (Placement::Wide, 8),
            (Placement::Local, 2),
            (Placement::Wide, 8),
            (Placement::Local, 2),
        ] {
            overflow();
            let plan = policy.choose_spawn(location, 64, PARALLELISM, false);
            let plan = policy.choose_spawn_placement(location, 64, PARALLELISM, plan);
            assert_eq!(plan.placement, Some(expected));
            policy.record_spawn_job(
                location,
                64,
                PARALLELISM,
                plan,
                Duration::from_millis(millis),
            );
        }
    }

    #[test]
    fn choice_seeds_both_pools_then_prefers_the_faster() {
        let mut choice = Choice::default();

        // Each placement is seeded once, in order, and the seeds leave the choice due for an
        // immediate boundary that probes the loser.
        assert_eq!(choice.choose(None).0, Placement::Wide);
        choice.record(Placement::Wide, 100_000);
        assert_eq!(choice.choose(None).0, Placement::Local);
        choice.record(Placement::Local, 50_000);
        assert_eq!(choice.choose(None).0, Placement::Wide);
        choice.record(Placement::Wide, 100_000);

        // The loser is twice as slow, so it is probed at double the base interval.
        let interval = RESAMPLE_INTERVAL << 1;
        for _ in 1..interval {
            assert_eq!(choice.choose(None).0, Placement::Local);
        }
        assert_eq!(choice.choose(None).0, Placement::Wide);
    }

    #[test]
    fn choice_ties_go_to_the_shared_pool() {
        let mut choice = Choice::default();

        // With equal estimates and the cadence between boundaries, the call uses Wide.
        choice.record(Placement::Wide, 50_000);
        choice.record(Placement::Local, 50_000);
        choice.cadence.since_probe = 1;

        assert_eq!(choice.choose(None).0, Placement::Wide);
    }

    /// A seed slower than its placement's second sample, as on the first call of a cold pool, is
    /// replaced by that sample, so the placement can win before its next probe. Later samples,
    /// and a second sample slower than the seed, blend as usual.
    #[test]
    fn choice_faster_second_sample_replaces_the_seed() {
        let mut choice = Choice::default();
        assert_eq!(choice.choose(None), (Placement::Wide, true));
        choice.record(Placement::Wide, 6_000_000);
        assert_eq!(choice.choose(None), (Placement::Local, true));
        choice.record(Placement::Local, 5_200_000);

        // The boundary after the seeds probes the loser, which beats the winner.
        assert_eq!(choice.choose(None), (Placement::Wide, true));
        choice.record(Placement::Wide, 4_800_000);
        assert_eq!(choice.estimate(Placement::Wide), Some(4_800_000));
        assert_eq!(choice.preferred(), Placement::Wide);
        assert_eq!(choice.choose(None), (Placement::Wide, false));

        choice.record(Placement::Wide, 5_500_000);
        assert_eq!(choice.estimate(Placement::Wide), Some(4_940_000));

        let mut slower = Choice::default();
        slower.record(Placement::Wide, 5_000_000);
        slower.record(Placement::Wide, 6_000_000);
        assert_eq!(slower.estimate(Placement::Wide), Some(5_200_000));
    }

    /// A caller with a choice of placements whose Local seed fails, and whose Wide seed was slow,
    /// still moves to Wide once Wide's probe beats Local. A failed call records nothing.
    #[test]
    fn errored_seed_and_slow_first_seed_still_prefer_the_faster_placement() {
        let policy = Policy::default();
        let location = Location::caller();
        let plan = |placement| RunPlan {
            execution: RunExecution::Parallel,
            placement,
            measure: true,
        };
        let call = || policy.choose_run(location, 10, 10, PARALLELISM, || EITHER);
        let record = |plan, millis| {
            policy.record_run_placed(
                location,
                10,
                10,
                PARALLELISM,
                plan,
                Duration::from_millis(millis),
            );
        };

        // The projections exceed the serial budget, so no call offers serial.
        let seed = call();
        assert_eq!(seed, plan(Placement::Wide));
        record(seed, 8);
        assert_eq!(call(), plan(Placement::Local));
        let seed = call();
        assert_eq!(seed, plan(Placement::Local));
        record(seed, 6);
        let probe = call();
        assert_eq!(probe, plan(Placement::Wide));
        record(probe, 5);
        assert_eq!(call(), plan(Placement::Wide));
    }

    /// Drives one call through the run policy and returns its execution path and placement.
    /// `pools` are the placements the caller may use. `wall` gives the time each path and
    /// placement takes, and the call records it only when its plan is measured.
    fn run_with(
        policy: &Policy,
        location: &'static Location<'static>,
        pools: Pools,
        wall: impl Fn(RunExecution, Placement) -> Duration,
    ) -> (RunExecution, Placement) {
        let plan = policy.choose_run(location, 10, 10, PARALLELISM, || pools);
        if plan.measure {
            policy.record_run_placed(
                location,
                10,
                10,
                PARALLELISM,
                plan,
                wall(plan.execution, plan.placement),
            );
        }
        (plan.execution, plan.placement)
    }

    #[test]
    fn run_local_seed_offers_serial_at_its_first_execution_decision() {
        let policy = Policy::default();
        let location = Location::caller();
        let wall = walls(Placement::Local, 50, 100, 200);

        let plans: Vec<_> = (0..4)
            .map(|_| run_with(&policy, location, EITHER, wall))
            .collect();
        assert_eq!(
            plans,
            [
                (RunExecution::Parallel, Placement::Wide),
                (RunExecution::Parallel, Placement::Local),
                (RunExecution::Parallel, Placement::Wide),
                (RunExecution::Serial, Placement::Wide),
            ]
        );
        assert_eq!(
            policy.get_entry(location, 10, 10, PARALLELISM),
            Some((Some(50_000), Some(100_000)))
        );
    }

    #[test]
    fn run_pool_seeded_after_serial_leaves_its_cadence_fresh() {
        // Workers of a local group seed Local and then serial, which wins. A caller confined to
        // Wide then seeds it, twice as slow as serial. Serial is already priced, so the seed leaves
        // no boundary due. The caller runs serial from its next call on and probes Wide once the
        // interval its loss sets has passed.
        let policy = Policy::default();
        let location = Location::caller();
        let wall = walls(Placement::Wide, 50, 100, 80);
        let local = confined(Placement::Local);
        assert_eq!(
            run_with(&policy, location, local, wall),
            (RunExecution::Parallel, Placement::Local)
        );
        assert_eq!(
            run_with(&policy, location, local, wall),
            (RunExecution::Serial, Placement::Wide)
        );
        let shared = confined(Placement::Wide);
        assert_eq!(
            run_with(&policy, location, shared, wall),
            (RunExecution::Parallel, Placement::Wide)
        );
        let probes: Vec<u32> = (1..=2 * RESAMPLE_INTERVAL)
            .filter(|_| run_with(&policy, location, shared, wall).0 == RunExecution::Parallel)
            .collect();
        assert_eq!(probes, [2 * RESAMPLE_INTERVAL]);
    }

    #[test]
    fn run_placement_is_learned_only_with_a_local_pool() {
        // With parallel established as the preferred path, its Wide samples already measure Wide,
        // so the first caller with a choice seeds Local at once. Once the seed boundary has probed
        // the loser, the faster placement is preferred, and a caller confined to Wide keeps it.
        let policy = Policy::default();
        let location = Location::caller();
        policy.record_run(
            location,
            10,
            10,
            PARALLELISM,
            RunExecution::Parallel,
            Duration::from_millis(1),
        );
        policy.record_run(
            location,
            10,
            10,
            PARALLELISM,
            RunExecution::Serial,
            Duration::from_millis(100),
        );
        let wall = |_, placement| match placement {
            Placement::Wide => Duration::from_millis(2),
            Placement::Local => Duration::from_micros(500),
        };

        let shared = confined(Placement::Wide);
        let seen: Vec<_> = [shared, EITHER, EITHER, EITHER, EITHER, shared]
            .into_iter()
            .map(|pools| run_with(&policy, location, pools, wall))
            .collect();
        assert_eq!(
            seen,
            [
                (RunExecution::Parallel, Placement::Wide),
                (RunExecution::Parallel, Placement::Local),
                (RunExecution::Parallel, Placement::Wide),
                (RunExecution::Parallel, Placement::Local),
                (RunExecution::Parallel, Placement::Local),
                (RunExecution::Parallel, Placement::Wide),
            ]
        );
    }

    #[test]
    fn run_parallel_estimate_follows_the_preferred_pool() {
        // Once Local is preferred, a probe of the slower Wide placement must not make parallel look
        // slower than serial. Serial sits between the two placements, so an estimate that blended
        // both would hand the site to serial after every probe of Wide.
        let policy = Policy::default();
        let location = Location::caller();
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(100),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(900),
        };
        for (execution, placement) in [
            (RunExecution::Parallel, Placement::Wide),
            (RunExecution::Parallel, Placement::Local),
            (RunExecution::Serial, Placement::Wide),
        ] {
            let plan = RunPlan {
                execution,
                placement,
                measure: true,
            };
            policy.record_run_placed(
                location,
                10,
                10,
                PARALLELISM,
                plan,
                wall(execution, placement),
            );
        }

        // Wide is more than ten times slower than Local, so the placement probes it at the capped
        // interval. Each probe records its slow sample and must leave the local preference
        // untouched. Serial is probed on its own cadence and never becomes preferred. It is within
        // 2x of Local, and every probe confirms Local, so its probes back off from the base
        // interval.
        let calls = (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT) * 2 + RESAMPLE_INTERVAL * 3;
        let mut parallel_local = 0;
        let mut wide_probes = 0;
        let mut serial_runs = 0;
        for _ in 0..calls {
            match run_with(&policy, location, EITHER, wall) {
                (RunExecution::Parallel, Placement::Local) => parallel_local += 1,
                (RunExecution::Parallel, Placement::Wide) => wide_probes += 1,
                (RunExecution::Serial, _) => serial_runs += 1,
            }
        }
        let (serial_ns, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
        assert_eq!(parallel_ns, Some(80_000));
        assert_eq!(serial_ns, Some(100_000));
        assert!(
            wide_probes >= 2,
            "Wide must keep being probed, probed {wide_probes} times"
        );
        assert!(
            serial_runs <= steady_probes(calls, 0),
            "serial must only ever be probed, ran {serial_runs}"
        );
        assert_eq!(parallel_local, calls - wide_probes - serial_runs);
    }

    #[test]
    fn run_serial_projection_uses_the_local_parallelism() {
        // A local sample is projected onto a serial run with the local group's parallelism, so a
        // narrow group under a wide strategy still lets serial be sampled. A 200 us run on a
        // 2-worker group projects to 400 us and fits the budget, while the strategy's 64-way
        // parallelism would project 12.8 ms and never sample serial. An affordable, faster serial
        // path must also slow the probes of the wide placement.
        for pools in [EITHER, confined(Placement::Local)] {
            let policy = Policy::default();
            let location = Location::caller();
            let parallelism = 64;
            let mut serial_runs = 0;
            let mut wide_runs = 0;
            for _ in 0..(RESAMPLE_INTERVAL * 4) {
                let plan = policy.choose_run(location, 10, 10, parallelism, || pools);
                let wall = match (plan.execution, plan.placement) {
                    (RunExecution::Serial, _) => Duration::from_micros(15),
                    (RunExecution::Parallel, Placement::Local) => Duration::from_micros(200),
                    (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(300),
                };
                policy.record_run_placed(location, 10, 10, parallelism, plan, wall);
                if plan.execution == RunExecution::Serial {
                    serial_runs += 1;
                } else if plan.placement == Placement::Wide {
                    wide_runs += 1;
                }
            }
            assert!(
                serial_runs > 0,
                "{pools:?}: serial must be sampled once the local projection fits"
            );
            assert!(
                wide_runs <= 2,
                "{pools:?}: the fast serial path must delay further wide probes"
            );
        }
    }

    #[test]
    fn run_serial_projection_follows_recent_local_runs() {
        // Expensive local runs keep serial over budget. When the same work becomes cheaper,
        // timed parallel runs must bring the projection down and permit a serial sample.
        let policy = Policy::default();
        let location = Location::caller();
        let parallelism = 64;
        let pools = Pools::Fixed(Placement::Local, 2);
        for _ in 0..4 * RESAMPLE_INTERVAL {
            let plan = policy.choose_run(location, 10, 10, parallelism, || pools);
            assert_eq!(
                plan.execution,
                RunExecution::Parallel,
                "serial must not run while the local projection exceeds the budget"
            );
            if plan.measure {
                policy.record_run_placed(
                    location,
                    10,
                    10,
                    parallelism,
                    plan,
                    Duration::from_millis(8),
                );
            }
        }

        let mut serial_runs = 0;
        for _ in 0..4 * RESAMPLE_INTERVAL {
            let plan = policy.choose_run(location, 10, 10, parallelism, || pools);
            if plan.measure {
                let wall = match plan.execution {
                    RunExecution::Serial => Duration::from_micros(150),
                    RunExecution::Parallel => Duration::from_micros(200),
                };
                policy.record_run_placed(location, 10, 10, parallelism, plan, wall);
            }
            serial_runs += usize::from(plan.execution == RunExecution::Serial);
        }
        assert!(
            serial_runs > 0,
            "serial must be sampled once the local projection fits the budget"
        );
    }

    /// Records one timed run per sample: its execution, the placement of a parallel run, and its
    /// wall time in microseconds. Local runs plan with two workers.
    fn record_samples(
        policy: &Policy,
        location: &'static Location<'static>,
        samples: &[(RunExecution, Placement, u64)],
    ) {
        for &(execution, placement, wall) in samples {
            let plan = RunPlan {
                execution,
                placement,
                measure: true,
            };
            policy.record_run_placed(
                location,
                10,
                10,
                PARALLELISM,
                plan,
                Duration::from_micros(wall),
            );
        }
    }

    /// Seeds one run entry with serial between the two placements. `preferred` beats serial, and
    /// the other placement is nine times slower than serial.
    fn seed_preferred(policy: &Policy, location: &'static Location<'static>, preferred: Placement) {
        record_samples(
            policy,
            location,
            &[
                (RunExecution::Parallel, other(preferred), 900),
                (RunExecution::Parallel, preferred, 80),
                (RunExecution::Serial, Placement::Wide, 100),
            ],
        );
        let (serial_ns, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
        assert_eq!((serial_ns, parallel_ns), (Some(100_000), Some(80_000)));
    }

    /// Wall times in microseconds of serial, of a parallel run on `pool`, and of one on the other
    /// placement.
    fn walls(
        pool: Placement,
        serial: u64,
        own: u64,
        other: u64,
    ) -> impl Fn(RunExecution, Placement) -> Duration + Copy {
        move |execution, placement| {
            Duration::from_micros(match execution {
                RunExecution::Serial => serial,
                RunExecution::Parallel if placement == pool => own,
                RunExecution::Parallel => other,
            })
        }
    }

    /// The most probes of a losing path over `calls` calls when that path is at least
    /// `MAX_RESAMPLE_SHIFT + 1` times slower than the winner. Its probe interval is then capped,
    /// whatever the confirmations, and a cadence advances at most once per call, so it gets at most
    /// one probe per capped interval.
    const fn loser_probes(calls: u32) -> u32 {
        calls / (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT)
    }

    /// The boundaries a fresh cadence crosses over `calls` calls while one path stays preferred
    /// and the loser trails it by `gap_shift` doublings. The first two intervals take
    /// `RESAMPLE_INTERVAL << gap_shift` calls, since the first boundary has no earlier preference
    /// to confirm, and each later boundary doubles the next interval up to the cap.
    ///
    /// A cadence that starts such a race at a boundary with confirmations already counted, or whose
    /// gap only grows from `gap_shift`, has intervals at least as long, so this bounds its
    /// boundaries too.
    const fn steady_probes(calls: u32, gap_shift: u32) -> u32 {
        let mut boundaries: u32 = 0;
        let mut elapsed = 0;
        loop {
            let shift = gap_shift + boundaries.saturating_sub(1);
            let shift = if shift < MAX_RESAMPLE_SHIFT {
                shift
            } else {
                MAX_RESAMPLE_SHIFT
            };
            elapsed += RESAMPLE_INTERVAL << shift;
            if elapsed > calls {
                return boundaries;
            }
            boundaries += 1;
        }
    }

    /// Calls within which probes rediscover a placement that is remembered as nine times slower
    /// than serial but has since become faster, and the cadence backs off to the cap again.
    ///
    /// Each probe closes a fifth of the gap, so the placement overtakes serial at the thirteenth
    /// probe when it runs at half of serial's wall and at the fourteenth at six tenths. A probe
    /// that brings the placement a whole multiple of serial's wall closer resets the
    /// confirmations, so the intervals follow the gap. Only probes that leave the gap's count
    /// unchanged back off.
    ///
    /// At six tenths the gap's count before each probe runs 5, 5, 4, 3, 3, 2, 1, 1, 1, and then 0
    /// five times, so the probes come 3,200, 3,200, 1,600, 800, 800, 400, 200, 200, 400, 100, 100,
    /// 200, 400, and 800 calls apart, 12,400 calls in all. At half of serial's wall the thirteen
    /// probes take 11,600 calls.
    ///
    /// The flip restarts the confirmations. The placement keeps gaining on serial afterwards, so
    /// the gap never shrinks while the count climbs back. With a gap of `g` doublings the intervals
    /// run `RESAMPLE_INTERVAL << g` twice and then double up to half the cap, so those below the
    /// cap sum to at most one capped interval. Five capped intervals cover the 15,600 calls this
    /// takes at six tenths.
    const DISCOVERY: u32 = 5 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT);

    /// Calls in which a cadence at the cap crosses exactly one boundary.
    const SETTLED: u32 = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;

    /// Drives a caller confined to `pool` through [`DISCOVERY`] calls, then returns how many of
    /// the next [`SETTLED`] run on that placement.
    fn pool_runs_once_settled(
        policy: &Policy,
        location: &'static Location<'static>,
        pool: Placement,
        wall: impl Fn(RunExecution, Placement) -> Duration + Copy,
    ) -> u32 {
        for _ in 0..DISCOVERY {
            run_with(policy, location, confined(pool), wall);
        }
        let runs = (0..SETTLED)
            .filter(|_| {
                run_with(policy, location, confined(pool), wall) == (RunExecution::Parallel, pool)
            })
            .count();
        u32::try_from(runs).unwrap()
    }

    #[test]
    fn run_confined_to_one_pool_is_decided_against_that_pool() {
        // The entry prefers the other placement over serial, and the caller's placement is nine
        // times slower than serial. A confined caller must run serial except for its own cadence's
        // probes of that placement, and must leave both placement estimates intact so a caller with
        // a choice uses the preferred placement at once.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, other(pool));
            let wall = walls(pool, 100, 900, 80);
            let calls = 20_000;
            let mut serial_runs = 0;
            let mut pool_runs = 0;
            for _ in 0..calls {
                match run_with(&policy, location, confined(pool), wall) {
                    (RunExecution::Serial, _) => serial_runs += 1,
                    (RunExecution::Parallel, placement) => {
                        assert_eq!(
                            placement, pool,
                            "a confined caller must stay in its placement"
                        );
                        pool_runs += 1;
                    }
                }
            }
            assert!(
                pool_runs <= loser_probes(calls),
                "{pool:?}: the caller must use its placement only for probes, ran {pool_runs} \
                 there and {serial_runs} serial"
            );
            assert_eq!(serial_runs + pool_runs, calls);
            let (serial_ns, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
            assert_eq!((serial_ns, parallel_ns), (Some(100_000), Some(80_000)));
            assert_eq!(
                run_with(&policy, location, EITHER, wall),
                (RunExecution::Parallel, other(pool))
            );
        }
    }

    #[test]
    fn run_interleaved_callers_each_use_their_fastest_path() {
        // Callers with a choice and callers confined to Wide share the entry. Each must get the
        // decision that is right for it, with no relearning in between, each paying only its own
        // cadences' probes.
        let wall = walls(Placement::Wide, 100, 900, 80);
        let calls = 20_000;
        for parity in 0..2 {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, Placement::Local);
            let mut with_pool_local = 0;
            let mut with_pool_other = 0;
            let mut without_pool_serial = 0;
            let mut without_pool_wide = 0;
            for call in 0..calls {
                if call % 2 == parity {
                    match run_with(&policy, location, EITHER, wall) {
                        (RunExecution::Parallel, Placement::Local) => with_pool_local += 1,
                        _ => with_pool_other += 1,
                    }
                } else {
                    match run_with(&policy, location, confined(Placement::Wide), wall) {
                        (RunExecution::Serial, _) => without_pool_serial += 1,
                        _ => without_pool_wide += 1,
                    }
                }
            }

            // Only the caller with a choice advances Local's run cadence and the placement choice,
            // so it pays their probes of serial and of Wide over its own calls. Serial is within 2x
            // of Local and every probe confirms Local, so its probes back off from the base
            // interval. Wide loses by more than the capped margin.
            assert!(
                with_pool_other <= steady_probes(calls / 2, 0) + loser_probes(calls / 2),
                "parity {parity}: the caller with a choice must leave Local only for probes, ran \
                 {with_pool_local} local and {with_pool_other} elsewhere"
            );

            // The confined caller runs serial apart from its own cadence's probes.
            assert!(
                without_pool_wide <= loser_probes(calls / 2),
                "parity {parity}: the confined caller must run serial apart from its probes, \
                 ran {without_pool_serial} serial and {without_pool_wide} wide"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_rediscovers_it_once_faster() {
        // The entry prefers the other placement and remembers the caller's placement as nine times
        // slower than serial, but the caller's placement actually beats serial. A confined caller
        // must find that out through its own cadence's probes and then run there.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, other(pool));
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 100, 50, 80));
            assert!(
                pool_runs >= SETTLED - 1,
                "{pool:?}: the caller must settle on its placement, ran {pool_runs} of {SETTLED} \
                 there"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_notices_serial_slowing_down() {
        // The entry prefers the other placement and serial beats the caller's placement as
        // remembered, but serial has slowed past that placement. A confined caller times its own
        // serial runs, so it finds that out and moves to its placement.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, other(pool));
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 200, 150, 80));
            assert!(
                pool_runs >= SETTLED - 1,
                "{pool:?}: the caller must settle on its placement, ran {pool_runs} of {SETTLED} \
                 there"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_is_decided_on_its_own_cadence_while_serial_wins() {
        // As remembered, serial beats the other placement and the other placement beats the
        // caller's, so the run cadence prefers serial. A confined caller decides on its own
        // cadence. Its probes find that its placement has become faster than serial, and the
        // caller moves to it.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, pool, 900),
                    (RunExecution::Parallel, other(pool), 120),
                    (RunExecution::Serial, Placement::Wide, 100),
                ],
            );
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 100, 50, 120));
            assert!(
                pool_runs >= SETTLED - 1,
                "{pool:?}: the caller must settle on its placement, ran {pool_runs} of {SETTLED} \
                 there"
            );
        }
    }

    #[test]
    fn run_with_a_choice_rediscovers_a_pool_while_serial_wins() {
        // Serial beats the preferred placement, so the run cadence keeps a caller with a choice on
        // serial. The other placement is remembered as nine times slower than serial but is
        // actually the fastest path. The placement choice probes it on its own interval over the
        // caller's calls, and twelve probes bring it past the preferred placement. One more probe
        // on that placement's run cadence then brings it past serial. Both stages fit within the
        // `DISCOVERY` calls a confined caller takes to rediscover its placement and back off again.
        //
        // Once there, it leaves that placement only for the run cadence's probes of serial and the
        // choice's probes of the placement it preferred before. Both cadences are back at the cap,
        // so over `SETTLED` calls the choice probes exactly once. The run cadence skips that call
        // and probes serial at most once.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, pool, 900),
                    (RunExecution::Parallel, other(pool), 120),
                    (RunExecution::Serial, Placement::Wide, 100),
                ],
            );
            let wall = walls(pool, 100, 50, 120);
            for _ in 0..DISCOVERY {
                run_with(&policy, location, EITHER, wall);
            }
            let pool_runs = (0..SETTLED)
                .filter(|_| {
                    run_with(&policy, location, EITHER, wall) == (RunExecution::Parallel, pool)
                })
                .count();
            let pool_runs = u32::try_from(pool_runs).unwrap();
            assert!(
                pool_runs >= SETTLED - 2,
                "{pool:?}: the caller must settle on its placement, ran {pool_runs} of {SETTLED} \
                 there"
            );
        }
    }

    #[test]
    fn run_with_a_choice_probes_pools_that_lose_to_serial_on_the_capped_interval() {
        // Serial is ten times faster than the preferred placement, and the other placement is only
        // half again slower than that. Both placements lose to serial by more than the capped
        // margin, so a caller with a choice probes each of them once per capped interval at most,
        // however close the placements are to each other.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, other(pool), 150),
                    (RunExecution::Parallel, pool, 100),
                    (RunExecution::Serial, Placement::Wide, 10),
                ],
            );
            let wall = walls(pool, 10, 100, 150);
            let calls = 20_000;
            let parallel_runs = (0..calls)
                .filter(|_| run_with(&policy, location, EITHER, wall).0 == RunExecution::Parallel)
                .count();
            assert!(
                parallel_runs <= 2 * Widen::widen(loser_probes(calls)),
                "{pool:?}: each placement must be probed at most once per capped interval, ran \
                 {parallel_runs} parallel"
            );
        }
    }

    #[test]
    fn run_with_a_choice_paces_pool_probes_without_serial_once_the_budget_gates_it() {
        // Serial is sixty times faster than either placement, but serial projected from the
        // preferred placement exceeds the budget, so serial never runs and the preferred placement
        // is the only path the other placement races. The placements are within a whole multiple
        // of each other, so the other placement's first probe comes after one plain resample
        // interval and later ones back off only with confirmations. Serial's wall time must not
        // stretch that interval to the cap.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, other(pool), 6_100),
                    (RunExecution::Parallel, pool, 6_000),
                    (RunExecution::Serial, Placement::Wide, 100),
                ],
            );
            let wall = walls(pool, 100, 6_000, 6_100);
            let calls = 20_000;
            let other_runs: Vec<u32> = (0..calls)
                .filter(|_| {
                    run_with(&policy, location, EITHER, wall)
                        == (RunExecution::Parallel, other(pool))
                })
                .collect();
            assert_eq!(
                other_runs.first().map(|call| call + 1),
                Some(RESAMPLE_INTERVAL),
                "{pool:?}: the other placement's first probe must come after one resample interval"
            );
            assert!(
                other_runs.len() <= Widen::widen(steady_probes(calls, 0)),
                "{pool:?}: the other placement must back off only with confirmations, probed {} \
                 times",
                other_runs.len()
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_keeps_big_work_there() {
        // The entry prefers the other placement and serial beats the caller's placement, but serial
        // projected from that placement's estimate at its parallelism exceeds the budget the tuner
        // arbitrates within. A confined caller therefore stays on its placement, where the tuner
        // leaves big work, and never samples serial.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, pool, 6_000),
                    (RunExecution::Parallel, other(pool), 1_000),
                    (RunExecution::Serial, Placement::Wide, 2_000),
                ],
            );
            let wall = walls(pool, 2_000, 6_000, 1_000);
            let serial_runs = (0..2_000)
                .filter(|_| {
                    run_with(&policy, location, confined(pool), wall).0 == RunExecution::Serial
                })
                .count();
            assert_eq!(serial_runs, 0, "{pool:?}: serial must never run");
        }
    }

    #[test]
    fn run_confined_to_one_pool_pays_only_its_own_probes() {
        // A confined caller decides on its own cadence however the placement choice stands, and
        // pays exactly that cadence's probes. Its placement is remembered as nine times slower than
        // serial but is actually faster, so its probes find that out, and afterwards serial is
        // probed on that cadence alone.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();

            // The first call seeds the caller's placement, and the boundary it leaves due seeds
            // serial.
            let remembered = walls(pool, 100, 900, 900);
            assert_eq!(
                run_with(&policy, location, confined(pool), remembered),
                (RunExecution::Parallel, pool)
            );
            assert_eq!(
                run_with(&policy, location, confined(pool), remembered),
                (RunExecution::Serial, Placement::Wide)
            );
            let (serial_ns, _) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
            assert_eq!(serial_ns, Some(100_000));
            let seeded = match pool {
                Placement::Wide => (Some(900_000), None),
                Placement::Local => (None, Some(900_000)),
            };
            assert_eq!(
                policy.run_placement_estimates(location, 10, 10, PARALLELISM),
                Some(seeded)
            );
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 100, 60, 60));
            assert_eq!(
                pool_runs,
                SETTLED - 1,
                "{pool:?}: the caller must pay exactly its own cadence's probes"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_never_consults_the_placement() {
        // A worker of a local group seeds and keeps using Local, planning with its group's width,
        // although a caller with a choice would seed Wide first. Its samples land in the local
        // estimate alone, so the first caller with a choice still seeds Wide.
        let policy = Policy::default();
        let location = Location::caller();
        let local = confined(Placement::Local);
        let plan = policy.choose_run(location, 10, 10, PARALLELISM, || local);
        assert_eq!(
            plan,
            RunPlan {
                execution: RunExecution::Parallel,
                placement: Placement::Local,
                measure: true,
            }
        );
        policy.record_run_placed(
            location,
            10,
            10,
            PARALLELISM,
            plan,
            Duration::from_micros(80),
        );
        let wall = walls(Placement::Local, 100, 80, 900);
        assert_eq!(
            run_with(&policy, location, local, wall),
            (RunExecution::Serial, Placement::Wide)
        );
        for _ in 0..RESAMPLE_INTERVAL {
            assert_ne!(
                run_with(&policy, location, local, wall),
                (RunExecution::Parallel, Placement::Wide)
            );
        }
        assert_eq!(
            policy.run_placement_estimates(location, 10, 10, PARALLELISM),
            Some((None, Some(80_000)))
        );
        assert_eq!(
            run_with(&policy, location, EITHER, wall),
            (RunExecution::Parallel, Placement::Wide)
        );
    }

    #[test]
    fn run_callers_of_different_pools_keep_independent_cadences() {
        // Callers with a choice and callers confined to Wide share one entry, and the callers
        // with a choice prefer Local. With steady wall times the estimates never move, so each
        // population must make the same decisions, probes and samples included, as when it calls
        // alone. A caller never advances the cadence of a placement it does not decide on.
        let wall = |execution, placement| {
            Duration::from_micros(match (execution, placement) {
                (RunExecution::Serial, _) => 100,
                (RunExecution::Parallel, Placement::Local) => 80,
                (RunExecution::Parallel, Placement::Wide) => 120,
            })
        };
        let location = Location::caller();
        let seeded = || {
            let policy = Policy::default();
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Serial, Placement::Wide, 100),
                    (RunExecution::Parallel, Placement::Local, 80),
                    (RunExecution::Parallel, Placement::Wide, 120),
                ],
            );
            policy
        };
        let decide = |policy: &Policy, pools: Pools| {
            let plan = policy.choose_run(location, 10, 10, PARALLELISM, || pools);
            if plan.measure {
                let elapsed = wall(plan.execution, plan.placement);
                policy.record_run_placed(location, 10, 10, PARALLELISM, plan, elapsed);
            }
            plan
        };
        let populations = [EITHER, confined(Placement::Wide)];
        let calls = 10 * RESAMPLE_INTERVAL;
        let alone: Vec<Vec<RunPlan>> = populations
            .iter()
            .map(|&pools| {
                let policy = seeded();
                (0..calls).map(|_| decide(&policy, pools)).collect()
            })
            .collect();
        let policy = seeded();
        let mut together = vec![Vec::new(); populations.len()];
        for _ in 0..calls {
            for (plans, &pools) in together.iter_mut().zip(&populations) {
                plans.push(decide(&policy, pools));
            }
        }
        assert_eq!(together, alone);
    }

    #[test]
    fn run_confined_to_the_local_pool_keeps_the_choosers_estimate_live() {
        // Workers of a local group time their runs on their own cadence, into the local estimate
        // that a caller with a choice decides on. When Local slows past Wide, that caller moves to
        // Wide on its next call without timing Local itself.
        let policy = Policy::default();
        let location = Location::caller();
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 120),
                (RunExecution::Parallel, Placement::Local, 80),
                (RunExecution::Serial, Placement::Wide, 1_000),
            ],
        );
        let slow = walls(Placement::Local, 1_000, 300, 120);
        for _ in 0..RESAMPLE_INTERVAL {
            run_with(&policy, location, confined(Placement::Local), slow);
        }
        assert_eq!(
            run_with(&policy, location, EITHER, slow),
            (RunExecution::Parallel, Placement::Wide)
        );
    }

    #[test]
    fn run_with_the_local_pool_decides_once_per_call_on_a_shared_preferred_entry() {
        // A caller with a choice on an entry that prefers Wide decides on Wide's run cadence once
        // per call, so over a settled window it pays that cadence's serial probes and the choice's
        // probes of Local, and no more.
        //
        // Each cadence starts fresh, and serial and Local both trail Wide within 2x. Every probe
        // confirms Wide, so each cadence probes 100, 200, 400, and 800 calls into its own count.
        // The run cadence skips the choice's four probes, so its boundaries slip by at most four
        // calls and both sets land within the window.
        let policy = Policy::default();
        let location = Location::caller();
        for (execution, placement, wall) in [
            (RunExecution::Parallel, Placement::Wide, 60),
            (RunExecution::Parallel, Placement::Local, 80),
            (RunExecution::Serial, Placement::Wide, 100),
        ] {
            let plan = RunPlan {
                execution,
                placement,
                measure: true,
            };
            policy.record_run_placed(
                location,
                10,
                10,
                PARALLELISM,
                plan,
                Duration::from_micros(wall),
            );
        }
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(100),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(60),
        };
        let settled = 1_000;
        let other = (0..settled)
            .filter(|_| {
                run_with(&policy, location, EITHER, wall)
                    != (RunExecution::Parallel, Placement::Wide)
            })
            .count();
        let other = u32::try_from(other).unwrap();
        assert_eq!(
            other,
            2 * steady_probes(settled, 0),
            "the caller must leave Wide for exactly its probes, ran {other} of \
             {settled} elsewhere"
        );
    }

    #[test]
    fn run_interleaved_callers_keep_the_local_estimate_live() {
        // Serial projects over the budget, so it never runs, and every call is parallel and
        // advances a cadence. Only timed local runs refresh the local estimate. Whatever rhythm the
        // confined callers keep with the caller that has a choice, the placement choice must keep
        // timing that caller's local runs, so the estimate follows Local when it slows down.
        let wall = |slow: bool| {
            move |execution, placement| match (execution, placement) {
                (RunExecution::Serial, _) => {
                    panic!("serial must not run while it projects over the budget")
                }
                (RunExecution::Parallel, Placement::Local) => {
                    Duration::from_micros(if slow { 8_000 } else { 6_000 })
                }
                (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(9_000),
            }
        };
        let rhythms = [2, 10]
            .into_iter()
            .flat_map(|period| (0..period).map(move |phase| (period, phase)));
        for (period, phase) in rhythms {
            let policy = Policy::default();
            let location = Location::caller();
            for (placement, wall) in [(Placement::Wide, 9_000), (Placement::Local, 6_000)] {
                let plan = RunPlan {
                    execution: RunExecution::Parallel,
                    placement,
                    measure: true,
                };
                policy.record_run_placed(
                    location,
                    10,
                    10,
                    PARALLELISM,
                    plan,
                    Duration::from_micros(wall),
                );
            }
            let calls = 5_000;
            let local_runs = (0..calls)
                .filter(|&call| {
                    let pools = if call % period == phase {
                        EITHER
                    } else {
                        confined(Placement::Wide)
                    };
                    run_with(&policy, location, pools, wall(call >= calls / 2))
                        == (RunExecution::Parallel, Placement::Local)
                })
                .count();
            let local_runs = u32::try_from(local_runs).unwrap();

            // The caller with a choice runs on Local apart from the choice's probes of Wide. Wide
            // is within 2x of Local, and every probe confirms Local, so those probes back off from
            // the base interval over that caller's calls.
            let with_pool = calls / period;
            assert!(
                local_runs >= with_pool - steady_probes(with_pool, 0),
                "period {period} phase {phase}: the caller must keep Local, ran \
                 {local_runs} local"
            );
            let (_, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
            assert!(
                parallel_ns.unwrap() >= 7_900_000,
                "period {period} phase {phase}: the local estimate must follow Local as it slows, \
                 {parallel_ns:?}"
            );
        }
    }

    #[test]
    fn run_interleaved_callers_rediscover_a_faster_local_pool() {
        // Serial and Local both speed up. Confined callers sample serial on every tenth call of
        // their cadence. When the caller with a choice makes one call in ten, serial overtakes the
        // local estimate before that caller has refreshed it, and the run cadence prefers serial.
        //
        // That caller's probes of parallel must keep landing on it at whatever phase of the others'
        // calls it runs, so Local is timed again and preferred once more. In a strict alternation
        // both estimates refresh apace, and the caller with a choice must keep Local.
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(60),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(30),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(900),
        };
        let rhythms = [2, 10]
            .into_iter()
            .flat_map(|period| (0..period).map(move |phase| (period, phase)));
        for (period, phase) in rhythms {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, Placement::Local);
            let calls = 20_000;
            let settled = calls / 2;
            let (mut with_pool, mut local_runs) = (0, 0);
            for call in 0..calls {
                let chooser = call % period == phase;
                let pools = if chooser {
                    EITHER
                } else {
                    confined(Placement::Wide)
                };
                let run = run_with(&policy, location, pools, wall);
                if call >= settled && chooser {
                    with_pool += 1;
                    local_runs += u32::from(run == (RunExecution::Parallel, Placement::Local));
                }
            }

            // By the settled half the run cadence prefers Local over serial, and the placement
            // choice prefers it over Wide by more than the capped margin. Both gaps only grow as
            // the local estimate falls, so neither count resets. After its first boundary in the
            // window, such a cadence has intervals no shorter than a fresh cadence's from the
            // second on. It therefore crosses at most one boundary more than a fresh cadence over
            // as many calls.
            assert!(
                local_runs
                    >= with_pool
                        - (steady_probes(with_pool, 0) + 1)
                        - (loser_probes(with_pool) + 1),
                "period {period} phase {phase}: the caller must keep Local, ran \
                 {local_runs} of {with_pool} local"
            );
        }
    }

    #[test]
    fn run_backs_off_a_stable_close_race_until_it_flips() {
        // Serial beats Wide by a sixth of Wide's wall. The race is within 2x, so the gap alone
        // would re-check it every `RESAMPLE_INTERVAL` calls. A caller confined to Wide decides it
        // on Wide's fresh cadence.
        let policy = Policy::default();
        let location = Location::caller();
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 120),
                (RunExecution::Serial, Placement::Wide, 100),
            ],
        );
        let pools = confined(Placement::Wide);
        let runs_of = |execution, calls: u32, serial: u64| -> Vec<u32> {
            let wall = walls(Placement::Wide, serial, 120, 120);
            (1..=calls)
                .filter(|_| run_with(&policy, location, pools, wall).0 == execution)
                .collect()
        };

        // Every probe confirms that serial wins, so each interval after the second doubles until it
        // reaches the cap. That gives eleven probes over 20,000 calls, where the gap alone would
        // take 200.
        let calls = 20_000;
        let probes = runs_of(RunExecution::Parallel, calls, 100);
        assert_eq!(
            probes,
            [
                100, 200, 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800, 16_000, 19_200
            ]
        );
        assert_eq!(
            u32::try_from(probes.len()).unwrap(),
            steady_probes(calls, 0)
        );

        // Serial then slows to twice Wide's wall. It stays preferred for ten calls, until its
        // next sample flips the preference to Wide. The confirmations were of serial, and the
        // call after the flip is long past the base interval, so it probes serial at once. The
        // intervals then back off from the base again, so serial is probed six times over the next
        // capped interval of calls, where keeping serial's confirmations would allow one.
        let serial_runs = runs_of(
            RunExecution::Serial,
            RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT,
            240,
        );
        assert_eq!(
            serial_runs,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 111, 311, 711, 1_511, 3_111
            ]
        );
    }

    #[test]
    fn run_resets_confidence_on_a_flip_between_boundaries() {
        // Serial beats Wide by a sixth, and a steady race backs a caller confined to Wide off to
        // the cap. The last of its 6,400 calls is a boundary with five confirmations.
        let policy = Policy::default();
        let location = Location::caller();
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 120),
                (RunExecution::Serial, Placement::Wide, 100),
            ],
        );
        let pools = confined(Placement::Wide);
        let run = |serial, pool| {
            run_with(
                &policy,
                location,
                pools,
                walls(Placement::Wide, serial, pool, pool),
            )
            .0
        };
        for _ in 0..6_400 {
            run(100, 120);
        }

        // Serial's next sample, ten calls in, raises its estimate to 140 us and flips the
        // preference to Wide. Wide's next sample, ten calls later, raises its estimate to
        // 146 us and flips it back. Both flips land before the base interval ends.
        assert!((0..10).all(|_| run(300, 120) == RunExecution::Serial));
        assert!((0..10).all(|_| run(300, 250) == RunExecution::Parallel));

        // The flips cleared the confirmations, so Wide is probed when the base interval ends.
        let probes: Vec<_> = (21..=RESAMPLE_INTERVAL)
            .filter(|_| run(140, 146) == RunExecution::Parallel)
            .collect();
        assert_eq!(probes, [RESAMPLE_INTERVAL]);
    }

    #[test]
    fn run_rediscovers_a_stale_pool_while_a_noisy_close_race_backs_off() {
        // A caller confined to Wide has an established estimate nine times slower than serial,
        // but Wide currently takes half of serial's wall. Each probe closes a fifth of the gap,
        // so Wide overtakes serial at the thirteenth.
        //
        // While Wide trails by several multiples of serial's wall, most probes bring it a
        // multiple closer and reset the confirmations, so the intervals follow the gap. Inside the
        // last multiple the remaining probes confirm and back off from the base interval. The
        // caller settles on Wide the call after the thirteenth probe, 11,601 calls in, where
        // the gap alone would take 10,501.
        let pools = confined(Placement::Wide);
        let policy = Policy::default();
        let location = Location::caller();
        for _ in 0..2 {
            record_samples(
                &policy,
                location,
                &[
                    (RunExecution::Parallel, Placement::Wide, 900),
                    (RunExecution::Serial, Placement::Wide, 100),
                ],
            );
        }
        let faster = walls(Placement::Wide, 100, 50, 50);
        let mut pool_runs = Vec::new();
        let settled = (1..=DISCOVERY).find(|&call| {
            let on_pool = run_with(&policy, location, pools, faster).0 == RunExecution::Parallel;
            let settled = on_pool && pool_runs.last() == Some(&(call - 1));
            if on_pool {
                pool_runs.push(call);
            }
            settled
        });
        assert_eq!(
            settled,
            Some(11_601),
            "the caller must rediscover Wide within {DISCOVERY} calls"
        );
        assert_eq!(
            pool_runs,
            [
                3_200, 6_400, 8_000, 8_800, 9_200, 9_600, 9_800, 10_000, 10_100, 10_200, 10_400,
                10_800, 11_600, 11_601
            ]
        );

        // A close race whose loser moves within one multiple still backs off. Serial wins in 100 us
        // and Wide's probes alternate between 110 and 190 us. Every probe moves Wide's
        // estimate, half of them toward serial, but the estimate stays within 2x of serial. Every
        // probe therefore confirms, and the probes back off to the cap as in a steady race.
        let policy = Policy::default();
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 150),
                (RunExecution::Serial, Placement::Wide, 100),
            ],
        );
        let samples = Cell::new(0);
        let noisy = |execution, _| {
            Duration::from_micros(match execution {
                RunExecution::Serial => 100,
                RunExecution::Parallel => {
                    samples.set(samples.get() + 1);
                    if samples.get() % 2 == 1 { 110 } else { 190 }
                }
            })
        };
        let probes: Vec<u32> = (1..=20_000)
            .filter(|_| run_with(&policy, location, pools, noisy).0 == RunExecution::Parallel)
            .collect();
        assert_eq!(
            probes,
            [
                100, 200, 400, 800, 1_600, 3_200, 6_400, 9_600, 12_800, 16_000, 19_200
            ]
        );
        assert_eq!(samples.get(), 11, "every probe must be timed");
    }

    fn spawn_call(
        policy: &Policy,
        location: &'static Location<'static>,
        worker: bool,
        job: Duration,
        overhead: Duration,
    ) -> SpawnPlan {
        let plan = policy.choose_spawn(location, 64, PARALLELISM, worker);
        if plan.measure {
            match plan.execution {
                SpawnExecution::Inline => {
                    policy.record_spawn_inline(location, 64, PARALLELISM, job);
                }
                SpawnExecution::Offload => {
                    policy.record_spawn_job(location, 64, PARALLELISM, plan, job);
                    policy.record_spawn_round_trip(
                        location,
                        64,
                        PARALLELISM,
                        plan,
                        job + overhead,
                        job,
                    );
                }
            }
        }
        plan
    }

    #[test]
    fn spawn_worker_round_trips_leave_outside_callers_inline() {
        // A worker that keeps its job in its own pool usually runs it while it waits, so its round
        // trip is far cheaper than an outside caller's hand-off. However often workers call, an
        // outside caller must keep inlining a job its own hand-off would slow down.
        for pattern in [
            &[false][..],
            &[false, true, true],
            &[false, true, true, true, true, true, true],
        ] {
            let policy = Policy::default();
            let location = Location::caller();
            let job = Duration::from_micros(15);
            let (mut calls, mut offloads) = (0, 0);
            for i in 0..30_000 {
                let worker = pattern[i % pattern.len()];
                let overhead = Duration::from_micros(if worker { 1 } else { 30 });
                let plan = spawn_call(&policy, location, worker, job, overhead);
                if !worker {
                    calls += 1;
                    offloads += usize::from(plan.execution == SpawnExecution::Offload);
                }
            }
            assert!(
                offloads * 50 <= calls,
                "outside callers must keep inlining ({pattern:?}): offloaded {offloads} of {calls}"
            );
        }
    }

    #[test]
    fn spawn_site_only_workers_call_reaches_inline() {
        // A site only workers call learns from its own round trips: a 1 us job against a 3 us
        // own-pool overhead settles inline.
        let policy = Policy::default();
        let location = Location::caller();
        let job = Duration::from_micros(1);
        let overhead = Duration::from_micros(3);
        let mut inline = 0;
        for _ in 0..1_000 {
            let plan = spawn_call(&policy, location, true, job, overhead);
            inline += usize::from(plan.execution == SpawnExecution::Inline);
        }
        assert!(
            inline > 900,
            "a worker-only site must settle inline: inlined {inline} of 1000"
        );
    }

    #[test]
    fn spawn_populations_keep_independent_cadences() {
        // Workers and outside callers share one entry. Every job takes 20 us wherever it runs, and
        // each round trip adds the same overhead on every call: 15 us in a worker's own pool and
        // 30 us for a hand-off. The estimates therefore never move, and each population must make
        // the same decisions, probes and samples included, as when it calls alone. Neither
        // population advances the other's cadence.
        let job = Duration::from_micros(20);
        let overhead = |worker: bool| Duration::from_micros(if worker { 15 } else { 30 });
        let location = Location::caller();
        let seeded = || {
            let policy = Policy::default();
            policy.record_spawn_inline(location, 64, PARALLELISM, job);
            policy.record_spawn_job(
                location,
                64,
                PARALLELISM,
                plan_of(SpawnExecution::Offload, SpawnPool::Pool, true),
                job,
            );
            for (pool, worker) in [(SpawnPool::Own, true), (SpawnPool::Pool, false)] {
                policy.record_spawn_round_trip(
                    location,
                    64,
                    PARALLELISM,
                    plan_of(SpawnExecution::Offload, pool, true),
                    job + overhead(worker),
                    job,
                );
            }
            policy
        };

        // Inline loses to the overhead kept for workers and beats the hand-off, so each population
        // probes a different losing path.
        let populations = [("workers", true), ("outside callers", false)];
        let calls = 10 * RESAMPLE_INTERVAL;
        let alone: Vec<Vec<SpawnPlan>> = populations
            .iter()
            .map(|&(_, worker)| {
                let policy = seeded();
                (0..calls)
                    .map(|_| spawn_call(&policy, location, worker, job, overhead(worker)))
                    .collect()
            })
            .collect();
        for (plans, (population, _)) in alone.iter().zip(&populations) {
            assert!(
                plans
                    .iter()
                    .any(|plan| plan.execution != plans[0].execution),
                "{population} must probe their losing path within {calls} calls"
            );
        }

        // The populations then call in turn on one entry.
        let policy = seeded();
        let mut together = vec![Vec::new(); populations.len()];
        for _ in 0..calls {
            for (plans, &(_, worker)) in together.iter_mut().zip(&populations) {
                plans.push(spawn_call(&policy, location, worker, job, overhead(worker)));
            }
        }
        for ((together, alone), (population, _)) in together.iter().zip(&alone).zip(&populations) {
            let diverged = together
                .iter()
                .zip(alone)
                .position(|(call, own)| call != own);
            assert_eq!(diverged, None, "{population} must decide as they do alone");
        }
    }

    #[test]
    fn spawn_recorded_observes_own_pool_round_trip_before_job_recording() {
        let policy = Policy::default();
        let location = Location::caller();
        let plan = policy.choose_spawn(location, 64, PARALLELISM, true);
        assert_eq!(plan, plan_of(SpawnExecution::Offload, SpawnPool::Own, true));
        assert!(!policy.spawn_recorded(location, 64, PARALLELISM));

        // The awaiting future can record the round trip before the worker records its job. The
        // round trip is not a hand-off, so it trains only the overhead kept for workers.
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan,
            Duration::from_micros(30),
            Duration::from_micros(10),
        );
        assert!(policy.spawn_recorded(location, 64, PARALLELISM));
        assert_eq!(
            policy.spawn_overhead_estimates(location, 64, PARALLELISM),
            Some((None, Some(20_000)))
        );
    }

    #[test]
    fn pools_are_asked_for_every_run() {
        // Looking the local group up takes the groups' locks. A run asks for its placements on
        // every call, since each decision depends on them.
        let policy = Policy::default();
        let location = Location::caller();

        // Serial beats both placements by a wide margin, so the entry prefers the path that places
        // no work.
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 1_000),
                (RunExecution::Parallel, Placement::Local, 1_000),
                (RunExecution::Serial, Placement::Wide, 10),
            ],
        );

        let mut serial_runs = 0;
        for _ in 0..1_000 {
            let mut looked_up = false;
            let plan = policy.choose_run(location, 10, 10, PARALLELISM, || {
                looked_up = true;
                EITHER
            });
            assert!(looked_up, "a run must ask for its placements");
            serial_runs += usize::from(plan.execution == RunExecution::Serial);
        }
        assert!(
            serial_runs > 900,
            "serial must be preferred, ran {serial_runs}"
        );
    }

    #[test]
    fn spawn_uses_job_ewma() {
        // A converged-inline entry: cheap job, expensive round trip.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);
        entry.inline_ns.record(2_000);

        // The latest inline sample exceeds the overhead, but the EWMA remains below it.
        entry.inline_ns.record(100_000);
        assert_eq!(entry.inline_ns.get(), Some(21_600));
        assert!(matches!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));
    }

    #[test]
    fn spawn_recovers_from_a_stale_inline_estimate() {
        // An established inline estimate can outlive the contention it measured. Boundary probes
        // are gated on the live worker wall, so samples bring the inline estimate down until
        // inline execution returns.
        //
        // Each probe closes a fifth of the gap between the 15 ms estimate and the 2 us wall, so the
        // estimate first falls under the 50 us overhead at the 26th probe (2 us plus 14,998 us x
        // 0.8^26, about 47 us). Through the 17th probe the estimate stays at least six times the
        // overhead, so the first eighteen intervals are the cap.
        //
        // From there most probes bring the estimate a multiple of the overhead closer and reset the
        // confirmations, so the intervals follow the gap: 1,600 (five times the overhead), 800
        // (four), 400 (three), 200 and 200 (two), and then 100, 100, and 200 inside the last
        // multiple as the count climbs again. Recovery takes 61,200 calls.
        let mut entry = SpawnEntry::default();
        for _ in 0..2 {
            entry.job_ns.record(2_000);
            entry.overhead_ns.record(50_000);
            entry.inline_ns.record(15_000_000);
        }

        let limit = 18 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT) + 3_600;
        let mut calls: u32 = 0;
        loop {
            calls += 1;
            assert!(
                calls <= limit,
                "inline execution must recover within {limit} calls"
            );
            match entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS) {
                (SpawnExecution::Inline, measure) => {
                    if measure {
                        entry.inline_ns.record(2_000);
                    }
                    if entry.inline_ns.get().unwrap() <= 50_000 {
                        break;
                    }
                }
                (SpawnExecution::Offload, measure) => {
                    if measure {
                        entry.job_ns.record(2_000);
                        entry.overhead_ns.record(50_000);
                    }
                }
            }
        }
        assert_eq!(calls, limit, "recovery must follow the derived schedule");
    }

    #[test]
    fn spawn_inline_records_on_cadence_and_probes_offload() {
        // The overhead is within 2x of the job, so the cadence probes at its base interval.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(30_000);
        entry.overhead_ns.record(50_000);

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        // The boundary hands one call back to the pool so the overhead estimate stays live.
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
    }

    #[test]
    fn spawn_probe_interval_is_capped() {
        // Inline wins by 25x, so the offload probe backs off to the capped interval while the
        // measure cadence continues, matching the serial-vs-parallel entries.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);

        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        assert_eq!(
            entry.choose(Spawner::Outside, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
    }
}
