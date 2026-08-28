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
use std::{
    panic::Location,
    sync::Arc,
    time::{Duration, Instant},
};

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
    Serial,
    Parallel,
}

/// The placement the spawn policy chose: run the job inline on the calling task, or hand it off
/// to the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnExecution {
    Inline,
    Offload,
}

/// Adaptive execution decisions (serial vs parallel for collection operations, inline vs
/// offload for spawned jobs), shared cheaply across [`super::Rayon`] clones.
#[derive(Clone, Debug, Default)]
pub(super) struct Policy {
    run_entries: Arc<RunEntries>,
    spawn_entries: Arc<SpawnEntries>,
}

impl Policy {
    /// Runs `run` on the execution path preferred for this callsite and input size, occasionally
    /// timing the call so the decision tracks recent performance.
    ///
    /// Only successful calls record their elapsed time. Error paths often abort early, so
    /// recording their short wall time would poison the estimate used to choose between serial
    /// and parallel execution. Infallible operations wrap their result in `Ok` to share this
    /// path.
    pub(super) fn try_run<R, E>(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        run: impl FnOnce(RunExecution) -> Result<R, E>,
    ) -> Result<R, E> {
        // A strategy configured for serial execution cannot benefit from rayon scheduling, so
        // always run serial and never spend a measurement on it.
        if parallelism <= 1 {
            return run(RunExecution::Serial);
        }

        let key = Key::new(caller, len, work, parallelism);
        let (execution, measure) = self.run_entries.entry(key).or_default().choose(parallelism);
        let start = measure.then(Instant::now);
        let result = run(execution);
        if let (Some(start), Ok(_)) = (start, &result) {
            let mut entry = self.run_entries.entry(key).or_default();
            entry.record(execution, start.elapsed());
        }
        result
    }

    /// Chooses where to run a spawned job (inline on the calling task when the job is measured
    /// cheaper than the round trip of offloading it, offloaded to the pool otherwise) and whether
    /// the caller should time the run and feed the samples back via
    /// [`record_spawn_inline`](Self::record_spawn_inline),
    /// [`record_spawn_job`](Self::record_spawn_job), and
    /// [`record_spawn_overhead`](Self::record_spawn_overhead).
    pub(super) fn choose_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> (SpawnExecution, bool) {
        // A single worker cannot overlap a hand-off, so always inline (nothing to measure).
        if parallelism <= 1 {
            return (SpawnExecution::Inline, false);
        }
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries
            .entry(key)
            .or_default()
            .choose(SPAWN_INLINE_BUDGET_NS)
    }

    /// Records the wall time of a spawned job that ran inline on the calling task.
    pub(super) fn record_spawn_inline(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        job: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, job, |entry| &mut entry.inline_ns);
    }

    /// Records the wall time of a spawned job that ran on a pool worker.
    pub(super) fn record_spawn_job(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        job: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, job, |entry| &mut entry.job_ns);
    }

    /// Records one offloaded spawn's round-trip overhead: the elapsed time from spawn entry to
    /// the result being observed by the awaiting future, minus the job's own wall time.
    pub(super) fn record_spawn_overhead(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        overhead: Duration,
    ) {
        self.record_spawn(caller, len, parallelism, overhead, |entry| {
            &mut entry.overhead_ns
        });
    }

    /// Folds one spawn timing sample into the selected estimate.
    fn record_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        sample: Duration,
        estimate: impl FnOnce(&mut SpawnEntry) -> &mut Estimate,
    ) {
        if parallelism <= 1 {
            return;
        }
        let key = Key::new(caller, len, len, parallelism);
        let mut entry = self.spawn_entries.entry(key).or_default();
        estimate(&mut entry).record(u64::try_from(sample.as_nanos()).unwrap_or(u64::MAX));
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
            .map(|e| (e.serial_ns.get(), e.parallel_ns.get()))
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
    parallel_ns: Estimate,
    cadence: Cadence,
}

impl RunEntry {
    // A serial pass of work that parallel finishes in `parallel_ns` can take up to
    // `parallel_ns * parallelism`.
    fn projected_serial(parallel_ns: u64, parallelism: usize) -> u64 {
        parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX))
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
    // back to [`record`](Self::record).
    fn choose(&mut self, parallelism: usize) -> (RunExecution, bool) {
        // Seed the parallel estimate with the first call. Saturating the cadence keeps the
        // entry due for an immediate boundary, so the serial seed is offered as soon as the
        // parallel estimate lands (when the projection allows).
        let Some(parallel_ns) = self.parallel_ns.get() else {
            self.cadence.saturate();
            return (RunExecution::Parallel, true);
        };

        // The projection gates serial in both sampling and preference: a case whose projection
        // exceeds the budget never runs serial. It is live: parallel keeps refreshing whenever
        // it executes, so a case that shrinks into the budget unlocks on its own.
        let can_sample_serial =
            Self::projected_serial(parallel_ns, parallelism) < SERIAL_SAMPLE_BUDGET_NS;

        // Until serial is sampled, parallel is preferred by default (winner and loser tie, so
        // the cadence runs at its base interval) and the boundary doubles as the seed slot.
        let (preferred, loser, winner_ns, loser_ns) = self.serial_ns.get().map_or(
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
        self.cadence
            .arbitrate(preferred, loser, winner_ns, loser_ns, probe_allowed)
    }

    fn record(&mut self, execution: RunExecution, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        match execution {
            RunExecution::Serial => self.serial_ns.record(elapsed_ns),
            RunExecution::Parallel => self.parallel_ns.record(elapsed_ns),
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
/// The job wall is tracked per placement: the worker-measured wall carries the penalty of
/// migrating the job to another core, so the decision prefers the inline-measured wall once one
/// exists, and the offload-state boundary probes inline (when the live worker wall fits the
/// budget) so that estimate is observable from an entry seeded into offload.
#[derive(Clone, Copy, Debug, Default)]
struct SpawnEntry {
    // Spawn entry to result observed, minus the job's own wall time, from offloaded runs.
    overhead_ns: Estimate,
    // The job's own wall time on a pool worker.
    job_ns: Estimate,
    // The job's own wall time inline on the calling task.
    inline_ns: Estimate,
    cadence: Cadence,
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
        MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL, Policy, RESAMPLE_INTERVAL, RunEntry,
        RunExecution, SPAWN_INLINE_BUDGET_NS, SpawnEntry, SpawnExecution,
    };
    use std::{panic::Location, time::Duration};

    const PARALLELISM: usize = 4;

    fn choose(entry: &mut RunEntry) -> (RunExecution, bool) {
        entry.choose(PARALLELISM)
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
            let (execution, measure) = entry.choose(12);
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
            let (execution, _) = entry.choose(12);
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

        assert_eq!(entry.parallel_ns.get(), Some(12_000_000));
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

        assert_eq!(entry.parallel_ns.get(), Some(120));
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
                entry.parallel_ns.get().unwrap(),
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
                entry.parallel_ns.get().unwrap(),
                PARALLELISM
            ),
            RunExecution::Serial
        );

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=1_000 {
            if RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns.get().unwrap(),
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
                entry.parallel_ns.get().unwrap(),
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
                entry.parallel_ns.get().unwrap(),
                PARALLELISM
            ),
            RunExecution::Parallel
        );

        entry.record(RunExecution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns.get(), Some(2_404_000));
        assert_eq!(
            RunEntry::preferred(
                entry.serial_ns.get().unwrap(),
                entry.parallel_ns.get().unwrap(),
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
    fn try_run_records_success_not_errors() {
        let policy = Policy::default();
        let location = Location::caller();
        let len = 10;
        let work = 10;

        // An error on the first call creates an entry but leaves both estimates unset.
        let result: Result<(), ()> = policy.try_run(location, len, work, PARALLELISM, |_| Err(()));
        assert!(result.is_err());
        let (serial_ns, parallel_ns) = policy.get_entry(location, len, work, PARALLELISM).unwrap();
        assert!(serial_ns.is_none() && parallel_ns.is_none());

        // A successful call records the parallel estimate.
        let result: Result<(), ()> = policy.try_run(location, len, work, PARALLELISM, |_| Ok(()));
        assert!(result.is_ok());
        let (serial_ns, parallel_estimate) =
            policy.get_entry(location, len, work, PARALLELISM).unwrap();
        assert!(parallel_estimate.is_some());
        assert!(serial_ns.is_none());

        // Subsequent parallel errors must not overwrite the established estimate.
        for _ in 0..20 {
            let _: Result<(), ()> =
                policy.try_run(
                    location,
                    len,
                    work,
                    PARALLELISM,
                    |execution| match execution {
                        RunExecution::Parallel => Err(()),
                        RunExecution::Serial => Ok(()),
                    },
                );
        }
        let (_, parallel_ns) = policy.get_entry(location, len, work, PARALLELISM).unwrap();
        assert_eq!(parallel_ns, parallel_estimate);
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
            policy.choose_spawn(location, 64, 1),
            (SpawnExecution::Inline, false)
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

        let _ = policy.choose_spawn(location, 1, PARALLELISM);
        let _ = policy.choose_spawn(location, 2, PARALLELISM);
        let _ = policy.choose_spawn(location, 3, PARALLELISM);

        assert_eq!(policy.spawn_len(), 2);
    }

    #[test]
    fn spawn_records_feed_choose() {
        // Policy-level wiring for the three spawn record paths: the worker and future samples
        // seed the entry, and the probe's inline sample drives the flip.
        let policy = Policy::default();
        let location = Location::caller();

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM),
            (SpawnExecution::Offload, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, Duration::from_micros(25));
        policy.record_spawn_overhead(location, 64, PARALLELISM, Duration::from_micros(10));

        // The boundary probes inline (the worker wall fits the budget).
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM),
            (SpawnExecution::Inline, true)
        );

        // The probe's inline wall beats the overhead, so the entry flips inline: recording it
        // anywhere but the inline estimate would leave the entry offloaded.
        policy.record_spawn_inline(location, 64, PARALLELISM, Duration::from_micros(8));
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM),
            (SpawnExecution::Inline, false)
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
        // down and inline placement returns.
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
            assert!(calls <= 100_000, "inline placement never recovered");
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
