//! Adaptive execution policies for collection operations and spawned jobs.
//!
//! Entries are keyed by callsite, input-size bucket, work-size bucket, and planning parallelism
//! so a decision learned for one workload does not leak into another. The policy compares recent
//! wall-clock estimates of each path and picks whichever is faster, with ties going to serial
//! (equal wall time for fewer busy workers).
//!
//! The tuner only arbitrates small cases. Choosing parallel for work that is better run
//! serially costs microseconds of dispatch overhead, while running big work serially forfeits
//! the pool's entire speedup, so serial is gated by a live estimate in both of its roles.
//! Sampling serial (the seed and every probe) requires the projected serial cost, parallel's
//! wall time multiplied by planning parallelism, to fit under [`SERIAL_SAMPLE_BUDGET_NS`].
//! Preferring serial in steady state requires both the projected and the measured serial
//! cost to fit under the same budget. Big cases therefore always run parallel and never pay
//! a serial sample.
//!
//! Every gate reads a live quantity, so no state is absorbing. The projection is derived from
//! the parallel estimate, which keeps refreshing (every [`PREFERRED_SAMPLE_INTERVAL`] calls)
//! whenever parallel executes. Within the budget, the losing path is probed on an interval
//! that grows exponentially with how badly it lost: a path within 2x of the winner is probed
//! every [`RESAMPLE_INTERVAL`] calls, and each additional multiple of the winner's wall time
//! doubles the interval, up to `RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT` calls. Probes are
//! never suppressed by the loser's own (stale) estimate, so an estimate poisoned by transient
//! conditions (pool contention at startup) converges back to the truth over a handful of
//! probes. After a path's first sample initializes its estimate,
//! every later sample blends into the EWMA, so a single outlier moves an established
//! estimate by at most a fifth of the gap.
//!
//! Placement decides whether a parallel run or an offloaded job uses the shared pool or the
//! local pool. The local pool is confined to the submitting thread's last-level cache domain.
//! Each entry learns its placement as a [`Choice`] that seeds both pools, prefers the faster
//! one, and probes the loser with the intervals above. The entry's parallel estimate is the
//! preferred pool's, so the serial-versus-parallel decision is made per population: a caller
//! with a local pool decides on the run cadence and consults the placement for a parallel run,
//! and a caller without one, which can only use the shared pool, decides between serial and
//! that pool on a cadence of its own against the shared estimate. Each cadence is advanced only
//! by the callers it decides for, so every probe and sample slot lands on a caller that can act
//! on it, and a preference learned by callers with the pool never commits a caller without it
//! to a shared run that serial would beat within the budget.
//!
//! Timing is coarse by design: each measured call records one wall-clock sample. Queueing on a
//! shared pool is included in a parallel sample's elapsed time, so contention pushes the
//! parallel estimate up and steers concurrent callers back toward serial. On pools wide enough
//! that the inflated projection exceeds the budget, the same pressure instead biases the entry
//! to parallel until the contention subsides. Fallible operations
//! only record samples on success: error paths often abort early, and recording their short
//! wall time would let garbage inputs drag an estimate down and unlock a serial sample of
//! genuine work. Both paths produce identical results, so a misjudged call only costs
//! throughput, never correctness.
//!
//! State updates are serialized per policy entry, but calls do not hold the entry lock while work
//! executes. Concurrent calls may therefore make decisions from an estimate that another in-flight
//! call later updates, and measured samples are applied in completion order.

use dashmap::DashMap;
use std::{panic::Location, sync::Arc, time::Duration};

// Refresh the preferred path periodically so its EWMA does not go stale.
const PREFERRED_SAMPLE_INTERVAL: u32 = 10;
// Probe the losing path this often when its estimate is within 2x of the winner's.
const RESAMPLE_INTERVAL: u32 = 100;
// Each additional multiple of the winner's wall time doubles the probe interval, up to this
// shift (100 << 5 = 3,200 calls). The cap keeps every path discoverable while the interval
// amortizes the cost of a mispriced probe (including pool queueing, which a parallel probe
// pays in full) across thousands of calls.
const MAX_RESAMPLE_SHIFT: u32 = 5;
// The tuner only arbitrates cases where a serial run is provably cheap: serial is seeded,
// probed, or preferred only when its projected and measured costs fit this budget.
const SERIAL_SAMPLE_BUDGET_NS: u64 = 10_000_000;
// Only jobs measured below this executor-friendly budget are eligible to run inline.
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
    /// The parallel body: a run's on the calling thread, which hands the strategy the work it
    /// distributes; a collection operation's on a pool.
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

/// Which pool runs a parallel run or an offloaded job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Placement {
    /// The strategy's shared pool.
    Wide,
    /// The domain pool of the submitting thread's last-level cache domain.
    Local,
}

/// The decisions for one spawned job and whether the caller should time it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpawnPlan {
    /// Whether the job runs inline or on a pool.
    pub(super) execution: SpawnExecution,
    /// The pool an offloaded job runs on, or `None` when the submitting worker keeps the job in
    /// its own pool. A `None` placement was not chosen, so its round trip teaches the placement
    /// nothing.
    pub(super) placement: Option<Placement>,
    /// Whether the caller times the job and reports the samples.
    pub(super) measure: bool,
}

impl SpawnPlan {
    /// A plan with no learned choices: `execution` on the shared pool, untimed.
    pub(super) const fn fixed(execution: SpawnExecution) -> Self {
        Self {
            execution,
            placement: Some(Placement::Wide),
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
    /// Chooses the execution path for this call site and, for a parallel run, the pool.
    ///
    /// `local` returns the local pool's parallelism, or `None` when the caller has no local
    /// pool. It is called before every adaptive decision, since the decision depends on which
    /// pool the caller has; looking the pool up may build it.
    pub(super) fn choose_run(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        local: impl FnOnce() -> Option<usize>,
    ) -> RunPlan {
        let mut plan = RunPlan {
            execution: RunExecution::Serial,
            placement: Placement::Wide,
            parallelism,
            measure: false,
        };

        // A strategy configured for serial execution cannot benefit from rayon scheduling, so
        // always run serial and never spend a measurement on it.
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, work, parallelism);

        // A caller without the local pool can only use the shared one, so it decides between
        // serial and that pool on the cadence kept for such callers; a caller with the pool
        // decides on the run cadence and, for a parallel run, the placement. The entry is not
        // held across the lookup, which may build the pool.
        let Some(local_parallelism) = local() else {
            (plan.execution, plan.measure) = self
                .run_entries
                .entry(key)
                .or_default()
                .choose(false, parallelism);
            return plan;
        };
        let mut entry = self.run_entries.entry(key).or_default();
        (plan.execution, plan.measure) = entry.choose(true, parallelism);
        if plan.execution != RunExecution::Parallel {
            return plan;
        }
        let (placement, measure) = entry.placement.choose();
        plan.placement = placement;
        plan.measure |= measure;
        if placement == Placement::Local {
            plan.parallelism = local_parallelism;
        }
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
            RunExecution::Parallel => {
                entry.record_parallel(plan.placement, plan.parallelism, elapsed)
            }
        }
    }

    /// Plans a spawned job, including whether the caller should time it and report the samples
    /// to [`Self::record_spawn_inline`], [`Self::record_spawn_job`], and
    /// [`Self::record_spawn_round_trip`].
    ///
    /// The job runs inline on the calling task when it is measured cheaper than the round trip
    /// of offloading it, and is offloaded otherwise. An offloaded job is also placed when
    /// `can_local` reports a local pool. `can_local` is called only for an offloaded job, since
    /// looking the pool up may build it.
    pub(super) fn choose_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        can_local: impl FnOnce() -> bool,
    ) -> SpawnPlan {
        // A single worker cannot overlap a hand-off, so always inline (nothing to measure).
        let mut plan = SpawnPlan::fixed(SpawnExecution::Inline);
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, len, parallelism);
        (plan.execution, plan.measure) = self
            .spawn_entries
            .entry(key)
            .or_default()
            .choose(SPAWN_INLINE_BUDGET_NS);

        // Only an offloaded job has a pool to choose. The caller times the run when either
        // cadence asks for a sample.
        if plan.execution == SpawnExecution::Offload && can_local() {
            let (placement, measure) = self
                .spawn_entries
                .entry(key)
                .or_default()
                .placement
                .choose();
            plan.placement = Some(placement);
            plan.measure |= measure;
        }
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
        job: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, |entry| {
            entry.job_ns.record(nanos(job));
        });
    }

    /// Records one offloaded spawn's round trip under `plan`: the elapsed time from spawn entry
    /// until the awaiting future observes the result, and the job's own wall time within it.
    ///
    /// The round trip minus the job feeds the hand-off overhead estimate, and a chosen placement
    /// records the whole round trip.
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
            entry
                .overhead_ns
                .record(nanos(round_trip.saturating_sub(job)));
            if let Some(placement) = plan.placement {
                entry.placement.record(placement, nanos(round_trip));
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

    /// Whether the spawn entry for this call site has recorded at least one sample
    /// (a choose-created but never-recorded entry has no estimates).
    #[cfg(test)]
    pub(super) fn spawn_recorded(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> bool {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries
            .get(&key)
            .is_some_and(|entry| entry.overhead_ns.get().is_some() || entry.job_ns.get().is_some())
    }

    /// The shared-pool and local-pool round-trip estimates, in nanoseconds, of the spawn entry
    /// for this call site, or `None` when the entry does not exist.
    #[cfg(test)]
    pub(super) fn spawn_placement_estimates(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> Option<(Option<u64>, Option<u64>)> {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries.get(&key).map(|entry| {
            (
                entry.placement.wide_ns.get(),
                entry.placement.local_ns.get(),
            )
        })
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

/// An EWMA-smoothed wall-clock estimate in nanoseconds.
///
/// The first sample initializes the estimate, and every later sample blends into the EWMA, so a
/// single outlier (a contended pool) moves an established estimate by at most a fifth of the gap.
#[derive(Clone, Copy, Debug, Default)]
struct Estimate(Option<u64>);

impl Estimate {
    const fn get(&self) -> Option<u64> {
        self.0
    }

    fn record(&mut self, sample_ns: u64) {
        self.0 = Some(
            self.0
                .map_or(sample_ns, |current| update_ewma(current, sample_ns)),
        );
    }
}

/// Paces measurement and probing for one policy entry.
///
/// Between boundaries the preferred path is measured every [`PREFERRED_SAMPLE_INTERVAL`] calls so
/// its estimate stays live. The boundary recurs every `RESAMPLE_INTERVAL << shift` calls, where
/// the shift grows with how badly the losing path lost (one doubling per multiple of the winner's
/// wall time, capped at [`MAX_RESAMPLE_SHIFT`]), so a close race is re-checked often while a
/// blowout is re-checked rarely yet remains discoverable.
#[derive(Clone, Copy, Debug, Default)]
struct Cadence {
    since_probe: u32,
}

impl Cadence {
    // Saturate the counter so the next call lands on a boundary (used at seed time so a freshly
    // seeded entry is re-examined immediately instead of waiting a full interval that a
    // low-frequency callsite may never reach).
    const fn saturate(&mut self) {
        self.since_probe = u32::MAX;
    }

    // Arbitrates one call between a `preferred` and a `loser` path, returning the path to run
    // and whether the caller should time it. The loser runs at an allowed probe boundary, and a
    // disallowed boundary still measures the preferred path and resets the counter.
    fn arbitrate<P: Copy>(
        &mut self,
        preferred: P,
        loser: P,
        winner_ns: u64,
        loser_ns: u64,
        probe_allowed: bool,
    ) -> (P, bool) {
        let slowdown = loser_ns / winner_ns.max(1);
        let shift = slowdown
            .saturating_sub(1)
            .min(u64::from(MAX_RESAMPLE_SHIFT)) as u32;
        let interval = RESAMPLE_INTERVAL << shift;
        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe >= interval {
            self.since_probe = 0;
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
    serial_ns: Estimate,
    cadence: Cadence,
    // The parallel wall time on each pool, consulted as a choice only when the caller has a
    // local pool. The entry's parallel estimate is the preferred pool's, so a probe of the
    // slower pool never raises it.
    placement: Choice,
    // The planning parallelism of the latest local run, so a serial cost projected from the
    // local estimate multiplies by the parallelism that produced it.
    local_parallelism: Option<usize>,
    // The cadence on which a caller without the local pool arbitrates serial against the
    // shared pool. Only such calls advance it, and they advance nothing else, so each
    // population's probes land on callers that can act on them.
    without_local: Cadence,
}

impl RunEntry {
    // A serial pass of work that parallel finishes in `parallel_ns` can take up to
    // `parallel_ns * parallelism`.
    fn projected_serial(parallel_ns: u64, parallelism: usize) -> u64 {
        parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX))
    }

    // The parallel estimate a caller with the local pool decides on: the preferred pool's wall
    // time, or `None` until the shared pool is measured.
    #[cfg(test)]
    const fn parallel_ns(&self) -> Option<u64> {
        self.placement.preferred_ns()
    }

    // The planning parallelism behind the preferred pool's estimate: the local pool's once it
    // is preferred.
    fn parallel_parallelism(&self, parallelism: usize) -> usize {
        match self.placement.preferred() {
            Placement::Local => self.local_parallelism.unwrap_or(parallelism),
            Placement::Wide => parallelism,
        }
    }

    // Returns the path to prefer: the faster estimate, provided both the projected and
    // measured serial cost fit under the budget (the tuner only arbitrates small cases).
    // Ties go to serial (equal wall time for fewer busy workers).
    fn preferred(serial_ns: u64, parallel_ns: u64, parallelism: usize) -> RunExecution {
        if Self::projected_serial(parallel_ns, parallelism) >= SERIAL_SAMPLE_BUDGET_NS
            || serial_ns >= SERIAL_SAMPLE_BUDGET_NS
            || parallel_ns < serial_ns
        {
            RunExecution::Parallel
        } else {
            RunExecution::Serial
        }
    }

    // Returns the path to run and whether the caller should time it and feed the elapsed duration
    // back to [`record`](Self::record). A caller with the local pool arbitrates serial against
    // the preferred pool on the run cadence; a caller without it arbitrates serial against the
    // shared pool, the only one it can use, on the cadence kept for such callers. Each cadence
    // is advanced only by its own population.
    fn choose(&mut self, with_local: bool, parallelism: usize) -> (RunExecution, bool) {
        let serial_ns = self.serial_ns;
        let (cadence, parallel_ns, parallelism) = if with_local {
            let parallelism = self.parallel_parallelism(parallelism);
            (
                &mut self.cadence,
                self.placement.preferred_ns(),
                parallelism,
            )
        } else {
            (
                &mut self.without_local,
                self.placement.wide_ns.get(),
                parallelism,
            )
        };

        // Seed the parallel estimate with the first call. Saturating this population's cadence
        // keeps it due for an immediate boundary, so its next call offers the serial seed as
        // soon as the parallel estimate lands (when the projection allows).
        let Some(parallel_ns) = parallel_ns else {
            cadence.saturate();
            return (RunExecution::Parallel, true);
        };

        // The projection gates serial in both sampling and preference: a case whose projection
        // exceeds the budget never runs serial. It is live: parallel keeps refreshing whenever
        // it executes, so a case that shrinks into the budget unlocks on its own.
        let can_sample_serial =
            Self::projected_serial(parallel_ns, parallelism) < SERIAL_SAMPLE_BUDGET_NS;

        // Until serial is sampled, parallel is preferred by default (winner and loser tie, so
        // the cadence runs at its base interval) and the boundary doubles as the seed slot.
        let (preferred, loser, winner_ns, loser_ns) = serial_ns.get().map_or(
            (
                RunExecution::Parallel,
                RunExecution::Serial,
                parallel_ns,
                parallel_ns,
            ),
            |serial_ns| match Self::preferred(serial_ns, parallel_ns, parallelism) {
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

    // Records a serial run, or a parallel run on the shared pool.
    #[cfg(test)]
    fn record(&mut self, execution: RunExecution, elapsed: Duration) {
        match execution {
            RunExecution::Serial => self.serial_ns.record(nanos(elapsed)),
            RunExecution::Parallel => self.placement.record(Placement::Wide, nanos(elapsed)),
        }
    }

    // Records the wall time of a parallel run on `placement` and, for the local pool, the
    // `parallelism` it planned with.
    fn record_parallel(&mut self, placement: Placement, parallelism: usize, elapsed: Duration) {
        self.placement.record(placement, nanos(elapsed));
        if placement == Placement::Local {
            self.local_parallelism = Some(parallelism);
        }
    }
}

/// The decisions for one run and whether the caller should time it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RunPlan {
    /// Whether the run is serial or parallel.
    pub(super) execution: RunExecution,
    /// The pool a parallel run uses. A serial run always carries [`Placement::Wide`].
    pub(super) placement: Placement,
    /// The planning parallelism of the pool a parallel run uses.
    pub(super) parallelism: usize,
    /// Whether the run is timed and recorded with [`Policy::record_run_placed`].
    pub(super) measure: bool,
}

/// A duration as a nanosecond sample, saturating at `u64::MAX`.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A learned choice between the shared pool and the local pool.
#[derive(Clone, Copy, Debug, Default)]
struct Choice {
    /// Timings on the shared pool. Calls that do not consult the choice can record here too, so
    /// this estimate may exist before the first consultation.
    wide_ns: Estimate,
    /// Timings on the local pool.
    local_ns: Estimate,
    /// The schedule for timing the preferred pool and probing the slower one.
    cadence: Cadence,
}

impl Choice {
    /// The faster pool once both are measured, and the shared pool until then or on a tie.
    const fn preferred(&self) -> Placement {
        match (self.wide_ns.get(), self.local_ns.get()) {
            (Some(wide_ns), Some(local_ns)) if local_ns < wide_ns => Placement::Local,
            _ => Placement::Wide,
        }
    }

    /// The estimate of the preferred pool, or `None` until the shared pool is measured.
    const fn preferred_ns(&self) -> Option<u64> {
        match (self.wide_ns.get(), self.local_ns.get()) {
            (Some(wide_ns), Some(local_ns)) if local_ns < wide_ns => Some(local_ns),
            (wide_ns, _) => wide_ns,
        }
    }

    /// Returns the pool to use and whether the caller should time the run.
    ///
    /// A pool without an estimate is timed first, the shared pool before the local pool. After
    /// that the faster pool is preferred, and the slower one is probed on the choice's own
    /// [`Cadence`].
    fn choose(&mut self) -> (Placement, bool) {
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
}

/// Timing state for one spawn [`Key`].
///
/// Since caller overlap cannot be observed, the policy inlines only when the job wall is no
/// greater than both the offload round-trip overhead EWMA and [`SPAWN_INLINE_BUDGET_NS`]. The
/// overhead is everything an offloaded run costs around the job itself (hand-off setup, queueing,
/// worker wake, result send, task wake, and the observing poll), so a caller that waits on the
/// result inlines whenever that is measured cheaper. A caller that polls late inflates its
/// overhead samples with overlap slack, which biases toward inline, and the budget bounds what
/// that bias can place on the calling task.
///
/// The job wall is tracked per execution path. The worker-measured wall carries the penalty of
/// migrating the job to another core, so the decision prefers the inline-measured wall once one
/// exists. The offload-state boundary probes inline when the live worker wall fits the budget,
/// so an entry seeded into offload can still observe the inline wall.
#[derive(Clone, Copy, Debug, Default)]
struct SpawnEntry {
    // Spawn entry to result observed, minus the job's own wall time, from offloaded runs.
    overhead_ns: Estimate,
    // The job's own wall time on a pool worker.
    job_ns: Estimate,
    // The job's own wall time inline on the calling task.
    inline_ns: Estimate,
    cadence: Cadence,
    // Which pool runs an offloaded job, consulted only when the caller has a local pool. The
    // pool changes the job's wall as well as the overhead, so it compares whole round trips.
    placement: Choice,
}

impl SpawnEntry {
    // Decides where this call runs and whether the caller should time it. `budget` caps the job
    // wall eligible for inlining.
    fn choose(&mut self, budget: u64) -> (SpawnExecution, bool) {
        // Seed both offload estimates before ever inlining.
        let (Some(overhead_ns), Some(job_ns)) = (self.overhead_ns.get(), self.job_ns.get()) else {
            self.cadence.saturate();
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
        self.cadence
            .arbitrate(preferred, loser, winner_ns, loser_ns, probe_allowed)
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
        Choice, MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL, Placement, Policy,
        RESAMPLE_INTERVAL, RunEntry, RunExecution, RunPlan, SPAWN_INLINE_BUDGET_NS, SpawnEntry,
        SpawnExecution, SpawnPlan,
    };
    use std::{panic::Location, time::Duration};

    const PARALLELISM: usize = 4;

    const fn plan_of(execution: SpawnExecution, placement: Placement, measure: bool) -> SpawnPlan {
        SpawnPlan {
            execution,
            placement: Some(placement),
            measure,
        }
    }

    fn choose(entry: &mut RunEntry) -> (RunExecution, bool) {
        entry.choose(true, PARALLELISM)
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
            let (execution, measure) = entry.choose(true, 12);
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
            let (execution, _) = entry.choose(true, 12);
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
        // A probe's sample blends like any other, so one probe moves a stale estimate by a
        // fifth of the gap rather than trusting a single measurement outright.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(25));
        entry.record(RunExecution::Serial, Duration::from_millis(100));

        entry.record(RunExecution::Serial, Duration::from_millis(5));

        assert_eq!(entry.serial_ns.get(), Some(81_000_000));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM
            ),
            RunExecution::Parallel
        );
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
    fn recovers_from_poisoned_estimate() {
        // Startup contention left parallel looking 2ms while serial measured 1ms, so serial
        // is preferred. The projection is still under budget (2ms x 4 = 8ms). The true
        // parallel cost is 0.5ms: probes blend the estimate down geometrically until the
        // preference flips.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(2));
        entry.record(RunExecution::Serial, Duration::from_millis(1));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM
            ),
            RunExecution::Serial
        );

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=1_000 {
            if RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM,
            ) == RunExecution::Parallel
            {
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

        // The estimate converges 2 -> 1.7 -> 1.46 -> 1.268 -> 1.1144 -> 0.99152ms over five
        // probes. The first probe interval is 200 (slowdown 2x) and shrinks to 100 once the
        // ratio drops below 2x, so the flip happens at call 600.
        assert_eq!(probes, 5);
        assert_eq!(flipped_at, Some(600));
    }

    #[test]
    fn seed_offered_once_per_interval() {
        // Exactly one caller crosses the probe boundary and receives the serial seed, so
        // concurrent callers cannot herd onto serial. A seed whose sample never lands (the
        // call panicked) is offered again one interval later instead of wedging the key.
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

        entry.record(RunExecution::Serial, Duration::from_millis(1));
        assert_eq!(choose(&mut entry).0, RunExecution::Parallel);
    }

    #[test]
    fn probes_big_serial_when_projection_is_affordable() {
        // A serial estimate poisoned over the budget (e.g. one contended stall) must not
        // lock serial out forever: the probe gate reads the live projection, not the stale
        // estimate.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(500));
        entry.record(RunExecution::Serial, Duration::from_millis(15));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM
            ),
            RunExecution::Parallel
        );

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
    fn poisoned_probe_cannot_flip_preference() {
        // A spuriously fast serial sample (e.g. from a contended probe) blends into the EWMA
        // and cannot flip the preference on its own.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(800));
        entry.record(RunExecution::Serial, Duration::from_millis(3));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM
            ),
            RunExecution::Parallel
        );

        entry.record(RunExecution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns.get(), Some(2_404_000));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns().unwrap(),
                PARALLELISM
            ),
            RunExecution::Parallel
        );
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

    #[test]
    fn spawn_seeds_offload_then_inlines_a_sub_overhead_job() {
        let mut entry = SpawnEntry::default();

        // The first call seeds both estimates from an offloaded run.
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        // A 2us job behind a 50us round-trip overhead.
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);

        // The seed leaves the entry due for an immediate boundary, which re-measures offload.
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);

        // The job costs less than the overhead and fits the budget, so it runs inline.
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_keeps_offloading_a_job_bigger_than_the_overhead() {
        // A 50us job behind a 5us round-trip overhead: offloading is cheaper under any polling.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(50_000);
        entry.overhead_ns.record(5_000);

        // The seed leaves the entry due for a boundary, which probes inline (the worker wall
        // fits the budget) to observe the inline wall.
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(50_000);

        // The inline wall confirms the job is bigger than the overhead, so offload holds until
        // the next (backed-off) boundary.
        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(SPAWN_INLINE_BUDGET_NS) {
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
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(25_000);
        entry.overhead_ns.record(10_000);

        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(8_000);

        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_budget_caps_inline_when_the_overhead_is_inflated() {
        // A contended pool measured the round-trip overhead at 50ms. The 2ms job is cheaper, but its
        // EWMA exceeds the inline budget, so it remains offloaded.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000_000);
        entry.overhead_ns.record(50_000_000);

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(SPAWN_INLINE_BUDGET_NS) {
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
            policy.choose_spawn(location, 64, 1, || false),
            plan_of(SpawnExecution::Inline, Placement::Wide, false)
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
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));

        // One grown sample blends the inline EWMA over the 50us overhead.
        entry.inline_ns.record(500_000);
        assert_eq!(entry.inline_ns.get(), Some(101_600));
        assert!(matches!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, _)
        ));
    }

    #[test]
    fn spawn_entries_bucket_by_len() {
        let policy = Policy::default();
        let location = Location::caller();

        let _ = policy.choose_spawn(location, 1, PARALLELISM, || false);
        let _ = policy.choose_spawn(location, 2, PARALLELISM, || false);
        let _ = policy.choose_spawn(location, 3, PARALLELISM, || false);

        assert_eq!(policy.spawn_len(), 2);
    }

    #[test]
    fn spawn_records_feed_choose() {
        // Policy-level wiring for the three spawn record paths: the worker and future samples
        // seed the entry, and the probe's inline sample drives the flip.
        let policy = Policy::default();
        let location = Location::caller();

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Offload, Placement::Wide, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, Duration::from_micros(25));
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, Placement::Wide, true),
            Duration::from_micros(10),
            Duration::ZERO,
        );

        // The boundary probes inline (the worker wall fits the budget).
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Inline, Placement::Wide, true)
        );

        // The probe's inline wall beats the overhead, so the entry flips inline: recording it
        // anywhere but the inline estimate would leave the entry offloaded.
        policy.record_spawn_inline(location, 64, PARALLELISM, Duration::from_micros(8));
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Inline, Placement::Wide, false)
        );
    }

    #[test]
    fn choice_seeds_both_pools_then_prefers_the_faster() {
        let mut choice = Choice::default();

        // Each pool is seeded once, in order, and the seeds leave the choice due for an
        // immediate boundary that probes the loser.
        assert_eq!(choice.choose(), (Placement::Wide, true));
        choice.record(Placement::Wide, 100_000);
        assert_eq!(choice.choose(), (Placement::Local, true));
        choice.record(Placement::Local, 50_000);
        assert_eq!(choice.choose(), (Placement::Wide, true));
        choice.record(Placement::Wide, 100_000);

        // The faster pool is preferred and measured every `PREFERRED_SAMPLE_INTERVAL` calls.
        // The loser is twice as slow, so it is probed at double the base interval.
        let interval = RESAMPLE_INTERVAL << 1;
        for i in 1..interval {
            assert_eq!(
                choice.choose(),
                (
                    Placement::Local,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i} must use the faster pool on its sampling cadence"
            );
        }
        assert_eq!(choice.choose(), (Placement::Wide, true));
    }

    #[test]
    fn choice_ties_go_to_the_shared_pool() {
        let mut choice = Choice::default();

        // With equal estimates and the cadence between boundaries, the call uses the shared
        // pool untimed.
        choice.record(Placement::Wide, 50_000);
        choice.record(Placement::Local, 50_000);
        choice.cadence.since_probe = 1;

        assert_eq!(choice.choose(), (Placement::Wide, false));
    }

    #[test]
    fn spawn_placement_is_learned_only_with_a_local_pool() {
        // A call without a local pool records its round trip on the shared-pool side, so the
        // first call with a local pool seeds the local side at once. The local job runs in half
        // the time, and placement compares whole round trips, so the local pool wins.
        let policy = Policy::default();
        let location = Location::caller();
        let job = Duration::from_millis(2);
        let overhead = Duration::from_micros(10);

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Offload, Placement::Wide, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, Placement::Wide, true),
            job + overhead,
            job,
        );

        // The job exceeds the inline budget, so the execution boundary re-measures offload
        // rather than probing inline, and a local pool seeds the local side.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || true),
            plan_of(SpawnExecution::Offload, Placement::Local, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job / 2);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, Placement::Local, true),
            job / 2 + overhead,
            job / 2,
        );

        // The local round trip was faster, so the seed boundary probes the shared pool once
        // and then the local pool is preferred between probes.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || true),
            plan_of(SpawnExecution::Offload, Placement::Wide, true)
        );
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || true),
            plan_of(SpawnExecution::Offload, Placement::Local, false)
        );

        // A caller without a local pool uses the shared pool without consulting the placement.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Offload, Placement::Wide, false)
        );
    }

    /// Drives one call through the run policy and returns its execution path and pool. `local`
    /// is the local pool's parallelism when the caller has one. `wall` gives the time each path
    /// and pool takes, and the call records it only when its plan is measured.
    fn run_with(
        policy: &Policy,
        location: &'static Location<'static>,
        local: Option<usize>,
        wall: impl Fn(RunExecution, Placement) -> Duration,
    ) -> (RunExecution, Placement) {
        let plan = policy.choose_run(location, 10, 10, PARALLELISM, || local);
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
    fn run_placement_is_learned_only_with_a_local_pool() {
        // With parallel established as the preferred path, its shared-pool samples already
        // measure the shared placement, so the first caller with a local pool seeds the local
        // one at once. Once the seed boundary has probed the loser, the faster pool is
        // preferred, and a caller without a local pool keeps the shared pool.
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

        let seen: Vec<_> = [None, Some(2), Some(2), Some(2), Some(2), None]
            .into_iter()
            .map(|local| run_with(&policy, location, local, wall))
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
        // Once the local pool is preferred, a probe of the slower shared pool must not make
        // parallel look slower than serial. Serial sits between the two pools, so an estimate
        // that blended both pools would hand the site to serial after every shared-pool probe.
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
                parallelism: 2,
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

        // The shared pool is more than ten times slower, so it is probed at the capped interval
        // of parallel calls. Each probe records its slow sample and must leave the local
        // preference untouched. Serial is probed on its own cadence and never becomes
        // preferred.
        let calls = (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT) * 2 + RESAMPLE_INTERVAL * 3;
        let mut parallel_local = 0;
        let mut wide_probes = 0;
        let mut serial_runs = 0;
        for _ in 0..calls {
            match run_with(&policy, location, Some(2), wall) {
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
            "the shared pool must keep being probed, {wide_probes}"
        );
        assert!(
            serial_runs <= calls / RESAMPLE_INTERVAL + 1,
            "serial must only ever be probed, ran {serial_runs}"
        );
        assert_eq!(parallel_local, calls - wide_probes - serial_runs);
    }

    #[test]
    fn run_serial_projection_uses_the_local_parallelism() {
        // A local sample is projected onto a serial run with the local pool's parallelism, so
        // a narrow local pool under a wide strategy still lets serial be sampled. A 200us run
        // on a 2-worker local pool projects to 400us and fits the budget, while the strategy's
        // 64-way parallelism would project 12.8ms and never sample serial.
        let policy = Policy::default();
        let location = Location::caller();
        let parallelism = 64;
        let mut serial_runs = 0;
        for _ in 0..(RESAMPLE_INTERVAL * 4) {
            let plan = policy.choose_run(location, 10, 10, parallelism, || Some(2));
            let wall = match (plan.execution, plan.placement) {
                (RunExecution::Serial, _) => Duration::from_micros(150),
                (RunExecution::Parallel, Placement::Local) => Duration::from_micros(200),
                (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(300),
            };
            policy.record_run_placed(location, 10, 10, parallelism, plan, wall);
            if plan.execution == RunExecution::Serial {
                serial_runs += 1;
            }
        }
        assert!(
            serial_runs > 0,
            "serial must be sampled once the local projection fits"
        );
    }

    /// Seeds one run entry with serial between the two pools: the local pool is preferred,
    /// and the shared pool is slower than serial.
    fn seed_local_preferred(policy: &Policy, location: &'static Location<'static>) {
        for (execution, placement, wall) in [
            (RunExecution::Parallel, Placement::Wide, 900),
            (RunExecution::Parallel, Placement::Local, 80),
            (RunExecution::Serial, Placement::Wide, 100),
        ] {
            let plan = RunPlan {
                execution,
                placement,
                parallelism: 2,
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
        let (serial_ns, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
        assert_eq!((serial_ns, parallel_ns), (Some(100_000), Some(80_000)));
    }

    /// The most shared-pool probes a run of `calls` pays on an entry whose shared pool is at
    /// least `MAX_RESAMPLE_SHIFT + 1` times slower than the winner, so that its probe interval
    /// is capped: one per capped interval, since a cadence advances at most once per call.
    const fn loser_probes(calls: u32) -> u32 {
        calls / (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT)
    }

    /// Calls within which probes rediscover a shared pool remembered as nine times slower than
    /// serial but now faster. Each probe closes a fifth of the gap, and the interval to the next
    /// probe shrinks with it: two probes at the capped interval of 3,200 calls, then 1,600, 800,
    /// 400, 400, 200, 200, and five at [`RESAMPLE_INTERVAL`], 10,500 calls for thirteen probes
    /// with the shared pool at half of serial, or 11,100 for fourteen at six tenths. Eight
    /// capped intervals leave margin over that derivation.
    const DISCOVERY: u32 = 8 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT);

    #[test]
    fn run_without_the_local_pool_is_decided_against_the_shared_pool() {
        // The entry prefers the local pool, which beats serial, while the shared pool is nine
        // times slower than serial. A caller without the local pool must run serial except for
        // its own cadence's probes of the shared pool, and must leave both pool estimates intact
        // so a caller that has the pool again uses it at once.
        let policy = Policy::default();
        let location = Location::caller();
        seed_local_preferred(&policy, location);
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(100),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(900),
        };
        let calls = 20_000;
        let mut serial_runs = 0;
        let mut wide_runs = 0;
        for _ in 0..calls {
            match run_with(&policy, location, None, wall) {
                (RunExecution::Serial, _) => serial_runs += 1,
                (RunExecution::Parallel, Placement::Wide) => wide_runs += 1,
                (RunExecution::Parallel, Placement::Local) => panic!("no local pool"),
            }
        }
        assert!(
            wide_runs <= loser_probes(calls),
            "{wide_runs} shared runs beyond the probes, {serial_runs} serial"
        );
        assert_eq!(serial_runs + wide_runs, calls);
        let (serial_ns, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
        assert_eq!((serial_ns, parallel_ns), (Some(100_000), Some(80_000)));
        assert_eq!(
            run_with(&policy, location, Some(2), wall),
            (RunExecution::Parallel, Placement::Local)
        );
    }

    #[test]
    fn run_interleaved_callers_each_use_their_fastest_path() {
        // Callers with and without the local pool share the entry. Each must get the decision
        // that is right for it, with no relearning in between, each paying only its own
        // cadences' probes.
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(100),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(900),
        };
        let calls = 20_000;
        for parity in 0..2 {
            let policy = Policy::default();
            let location = Location::caller();
            seed_local_preferred(&policy, location);
            let mut with_pool_local = 0;
            let mut with_pool_other = 0;
            let mut without_pool_serial = 0;
            let mut without_pool_wide = 0;
            for call in 0..calls {
                if call % 2 == parity {
                    match run_with(&policy, location, Some(2), wall) {
                        (RunExecution::Parallel, Placement::Local) => with_pool_local += 1,
                        _ => with_pool_other += 1,
                    }
                } else {
                    match run_with(&policy, location, None, wall) {
                        (RunExecution::Serial, _) => without_pool_serial += 1,
                        _ => without_pool_wide += 1,
                    }
                }
            }
            // Only the caller with the pool advances the run cadence and the placement, so it
            // pays their probes of serial and of the shared pool over its own calls.
            assert!(
                with_pool_other <= calls / 2 / RESAMPLE_INTERVAL + loser_probes(calls / 2),
                "parity {parity} with pool: {with_pool_local} local, {with_pool_other} other"
            );
            // The caller without it runs serial apart from its own cadence's probes.
            assert!(
                without_pool_wide <= loser_probes(calls / 2),
                "parity {parity} without pool: {without_pool_serial} serial, \
                 {without_pool_wide} wide"
            );
        }
    }

    #[test]
    fn run_without_the_local_pool_rediscovers_a_faster_shared_pool() {
        // The entry prefers the local pool and remembers the shared pool as nine times slower
        // than serial, but the shared pool now beats serial. Callers without the local pool
        // must find that out through their own cadence's probes and then run on the shared pool.
        let policy = Policy::default();
        let location = Location::caller();
        seed_local_preferred(&policy, location);
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(100),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(50),
        };
        for _ in 0..DISCOVERY {
            run_with(&policy, location, None, wall);
        }
        let settled = 1_000;
        let wide_runs = (0..settled)
            .filter(|_| run_with(&policy, location, None, wall).0 == RunExecution::Parallel)
            .count();
        assert!(
            wide_runs >= settled - settled / RESAMPLE_INTERVAL as usize,
            "{wide_runs} of {settled} runs on the shared pool"
        );
    }

    #[test]
    fn run_without_the_local_pool_notices_serial_slowing_down() {
        // The entry prefers the local pool and serial beats the shared pool as remembered, but
        // serial has slowed past the shared pool. A caller without the local pool times its own
        // serial runs, so it finds that out and moves to the shared pool.
        let policy = Policy::default();
        let location = Location::caller();
        seed_local_preferred(&policy, location);
        let wall = |execution, placement| match (execution, placement) {
            (RunExecution::Serial, _) => Duration::from_micros(200),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(80),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(150),
        };
        for _ in 0..DISCOVERY {
            run_with(&policy, location, None, wall);
        }
        let settled = 1_000;
        let wide_runs = (0..settled)
            .filter(|_| run_with(&policy, location, None, wall).0 == RunExecution::Parallel)
            .count();
        assert!(
            wide_runs >= settled - settled / RESAMPLE_INTERVAL as usize,
            "{wide_runs} of {settled} runs on the shared pool"
        );
    }

    #[test]
    fn run_without_the_local_pool_is_decided_on_its_own_cadence_while_serial_wins() {
        // Serial beats the local pool, which beats the shared pool as remembered, so the run
        // cadence prefers serial. A caller without the local pool does not take that decision:
        // its own cadence probes the shared pool, which has become faster than serial, and the
        // caller moves to it.
        let policy = Policy::default();
        let location = Location::caller();
        for (execution, placement, wall) in [
            (RunExecution::Parallel, Placement::Wide, 900),
            (RunExecution::Parallel, Placement::Local, 120),
            (RunExecution::Serial, Placement::Wide, 100),
        ] {
            let plan = RunPlan {
                execution,
                placement,
                parallelism: 2,
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
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(120),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(50),
        };
        for _ in 0..DISCOVERY {
            run_with(&policy, location, None, wall);
        }
        let settled = 1_000;
        let wide_runs = (0..settled)
            .filter(|_| run_with(&policy, location, None, wall).0 == RunExecution::Parallel)
            .count();
        assert!(
            wide_runs >= settled - settled / RESAMPLE_INTERVAL as usize,
            "{wide_runs} of {settled} runs on the shared pool"
        );
    }

    #[test]
    fn run_without_the_local_pool_keeps_big_work_on_the_shared_pool() {
        // The entry prefers the local pool, serial beats the shared pool, but serial projected
        // from the shared estimate at the shared pool's parallelism exceeds the budget the tuner
        // arbitrates within. A caller without the local pool therefore stays on the shared pool,
        // where the tuner leaves big work, and never samples serial.
        let policy = Policy::default();
        let location = Location::caller();
        for (execution, placement, wall) in [
            (RunExecution::Parallel, Placement::Wide, 3_000),
            (RunExecution::Parallel, Placement::Local, 1_000),
            (RunExecution::Serial, Placement::Wide, 2_000),
        ] {
            let plan = RunPlan {
                execution,
                placement,
                parallelism: 2,
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
            (RunExecution::Serial, _) => Duration::from_micros(2_000),
            (RunExecution::Parallel, Placement::Local) => Duration::from_micros(1_000),
            (RunExecution::Parallel, Placement::Wide) => Duration::from_micros(3_000),
        };
        let calls = 2_000;
        let serial_runs = (0..calls)
            .filter(|_| run_with(&policy, location, None, wall).0 == RunExecution::Serial)
            .count();
        assert_eq!(serial_runs, 0);
    }

    #[test]
    fn run_without_the_local_pool_keeps_probing_a_shared_preferred_entry() {
        // A caller without a local pool decides on its own cadence whichever pool the placement
        // prefers, and pays exactly that cadence's probes: with the shared pool remembered as
        // nine times slower than serial but now faster, its probes find out, and afterwards
        // serial is probed on that cadence alone.
        let policy = Policy::default();
        let location = Location::caller();
        // The first call seeds the shared pool, and the boundary it leaves due seeds serial.
        let remembered = |execution, _| match execution {
            RunExecution::Serial => Duration::from_micros(100),
            RunExecution::Parallel => Duration::from_micros(900),
        };
        assert_eq!(
            run_with(&policy, location, None, remembered),
            (RunExecution::Parallel, Placement::Wide)
        );
        assert_eq!(
            run_with(&policy, location, None, remembered),
            (RunExecution::Serial, Placement::Wide)
        );
        assert_eq!(
            policy.get_entry(location, 10, 10, PARALLELISM),
            Some((Some(100_000), Some(900_000)))
        );
        let wall = |execution, _| match execution {
            RunExecution::Serial => Duration::from_micros(100),
            RunExecution::Parallel => Duration::from_micros(60),
        };
        for _ in 0..DISCOVERY {
            run_with(&policy, location, None, wall);
        }
        let settled = 1_000;
        let wide_runs = (0..settled)
            .filter(|_| run_with(&policy, location, None, wall).0 == RunExecution::Parallel)
            .count();
        assert_eq!(wide_runs, settled - settled / RESAMPLE_INTERVAL as usize);
    }

    #[test]
    fn run_with_the_local_pool_decides_once_per_call_on_a_shared_preferred_entry() {
        // A caller with the pool on an entry that prefers the shared pool decides on the run
        // cadence once per call, so over a settled window it pays that cadence's serial probes and
        // the placement's probes of the local pool, and no more.
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
                parallelism: 2,
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
                run_with(&policy, location, Some(2), wall)
                    != (RunExecution::Parallel, Placement::Wide)
            })
            .count();
        assert!(
            (settled / RESAMPLE_INTERVAL as usize..=2 * settled / RESAMPLE_INTERVAL as usize)
                .contains(&other),
            "{other} of {settled} runs off the preferred path"
        );
    }

    #[test]
    fn run_interleaved_callers_keep_the_local_estimate_live() {
        // Big work: serial never runs, so every call is parallel and advances a cadence. The
        // local estimate is refreshed only by timed local runs, so whatever rhythm the callers
        // without the pool keep with the one that has it, the placement must keep timing that
        // caller's local runs, and the estimate follows the local pool when it slows down.
        let wall = |slow: bool| {
            move |execution, placement| match (execution, placement) {
                (RunExecution::Serial, _) => panic!("serial projects over the budget"),
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
                    parallelism: 2,
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
                    let local = (call % period == phase).then_some(2);
                    run_with(&policy, location, local, wall(call >= calls / 2))
                        == (RunExecution::Parallel, Placement::Local)
                })
                .count();
            // The caller with the pool runs on it apart from the placement's probes of the
            // shared pool, which is within 2x of the local one.
            let with_pool = calls / period;
            assert!(
                local_runs >= with_pool - with_pool / RESAMPLE_INTERVAL as usize,
                "period {period} phase {phase}: {local_runs} local runs"
            );
            let (_, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
            assert!(
                parallel_ns.unwrap() >= 7_900_000,
                "period {period} phase {phase}: local estimate {parallel_ns:?}"
            );
        }
    }

    #[test]
    fn run_interleaved_callers_rediscover_a_faster_local_pool() {
        // Serial and the local pool both speed up. Callers without the pool sample serial on
        // every tenth call of their cadence, so when the caller with the pool is one call in
        // ten, serial overtakes the local estimate before that caller has refreshed it, and the
        // run cadence prefers serial. That caller's probes of parallel must keep landing on it,
        // at whatever phase of the others' calls it runs, so the local pool is timed again and
        // preferred once more; in a strict alternation both estimates refresh apace and the
        // caller with the pool must simply keep it.
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
            seed_local_preferred(&policy, location);
            let calls = 20_000;
            let settled = calls / 2;
            let (mut with_pool, mut local_runs) = (0, 0);
            for call in 0..calls {
                let local = (call % period == phase).then_some(2);
                let run = run_with(&policy, location, local, wall);
                if call >= settled && local.is_some() {
                    with_pool += 1;
                    local_runs += usize::from(run == (RunExecution::Parallel, Placement::Local));
                }
            }
            assert!(
                local_runs >= with_pool - with_pool / RESAMPLE_INTERVAL as usize,
                "period {period} phase {phase}: {local_runs} local runs of {with_pool}"
            );
        }
    }

    #[test]
    fn spawn_placement_forced_by_a_worker_is_not_learned() {
        // A plan whose placement is `None` ran in a worker's own pool, so its round trip must
        // change neither pool's estimate. With the shared pool measured, the local side stays
        // unmeasured, and the next call with a local pool still seeds it.
        let policy = Policy::default();
        let location = Location::caller();
        let job = Duration::from_millis(2);
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || false),
            plan_of(SpawnExecution::Offload, Placement::Wide, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, Placement::Wide, true),
            job,
            job,
        );
        let estimates = policy.spawn_placement_estimates(location, 64, PARALLELISM);
        assert!(matches!(estimates, Some((Some(_), None))));
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            SpawnPlan {
                placement: None,
                ..plan_of(SpawnExecution::Offload, Placement::Local, true)
            },
            job * 2,
            job,
        );
        assert_eq!(
            policy.spawn_placement_estimates(location, 64, PARALLELISM),
            estimates
        );
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, || true),
            plan_of(SpawnExecution::Offload, Placement::Local, true)
        );
    }

    #[test]
    fn local_pool_is_looked_up_for_every_run_and_only_for_an_offloaded_job() {
        // Looking the local pool up may build it. A run asks for it on every call, since its
        // decision depends on which pool the caller has; an inline job must not ask for it.
        let policy = Policy::default();
        let location = Location::caller();

        // Serial beats parallel and the job beats its offload round trip by wide margins, so
        // both entries prefer the path that needs no pool.
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
            Duration::from_micros(10),
        );
        let job = Duration::from_micros(1);
        policy.record_spawn_inline(location, 64, PARALLELISM, job);
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, Placement::Wide, true),
            Duration::from_micros(50),
            job,
        );

        // Only the spawn cadence's offload probes consult the lookup for a job.
        let mut serial_runs = 0;
        let mut inline_jobs = 0;
        for _ in 0..1_000 {
            let mut looked_up = false;
            let plan = policy.choose_run(location, 10, 10, PARALLELISM, || {
                looked_up = true;
                Some(2)
            });
            assert!(looked_up);
            serial_runs += usize::from(plan.execution == RunExecution::Serial);

            let mut looked_up = false;
            let plan = policy.choose_spawn(location, 64, PARALLELISM, || {
                looked_up = true;
                true
            });
            assert_eq!(looked_up, plan.execution == SpawnExecution::Offload);
            inline_jobs += usize::from(plan.execution == SpawnExecution::Inline);
        }
        assert!(
            serial_runs > 900,
            "serial must be preferred, ran {serial_runs}"
        );
        assert!(
            inline_jobs > 900,
            "inline must be preferred, ran {inline_jobs}"
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
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));
    }

    #[test]
    fn spawn_recovers_after_a_transient_slow_run() {
        // A spike poisoned the inline estimate. Boundary probes are gated on the live worker
        // wall rather than the stale inline estimate, so probe samples blend the estimate back
        // down and inline execution returns.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns.record(50_000);
        entry.inline_ns.record(15_000_000);

        let mut calls: u32 = 0;
        loop {
            match entry.choose(SPAWN_INLINE_BUDGET_NS) {
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
            calls += 1;
            assert!(
                calls <= 100_000,
                "inline execution must recover within 100000 calls"
            );
        }
    }

    #[test]
    fn spawn_inline_records_on_cadence_and_probes_offload() {
        // The overhead is within 2x of the job, so the shared cadence probes at its base
        // interval.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(30_000);
        entry.overhead_ns.record(50_000);

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        // The boundary hands one call back to the pool so the overhead estimate stays live.
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
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
                entry.choose(SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        assert_eq!(
            entry.choose(SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
    }
}
