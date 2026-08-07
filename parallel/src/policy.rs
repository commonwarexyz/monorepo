//! Adaptive execution policy for collection operations.
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
// Track a short EWMA so recent measurements outweigh old startup noise.
const EWMA_PREVIOUS_WEIGHT: u64 = 4;
const EWMA_NEXT_WEIGHT: u64 = 1;
const EWMA_WEIGHT: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_NEXT_WEIGHT;

type Entries = DashMap<Key, Entry>;
type SpawnEntries = DashMap<Key, SpawnEntry>;

/// The path the policy chose for a call: the strategy runs the matching serial or parallel body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Execution {
    Serial,
    Parallel,
}

/// The path the spawn policy chose: run the job inline on the calling task, or offload it to the
/// pool, which overlaps it with the caller's other work at the cost of a hand-off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnExecution {
    Inline,
    Offload,
}

/// Adaptive serial-vs-parallel decisions, shared cheaply across [`super::Rayon`] clones.
#[derive(Clone, Debug, Default)]
pub(super) struct Policy {
    entries: Arc<Entries>,
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
        run: impl FnOnce(Execution) -> Result<R, E>,
    ) -> Result<R, E> {
        // A strategy configured for serial execution cannot benefit from rayon scheduling, so
        // always run serial and never spend a measurement on it.
        if parallelism <= 1 {
            return run(Execution::Serial);
        }

        let key = Key::new(caller, len, work, parallelism);
        let (execution, measure) = self.entries.entry(key).or_default().choose(parallelism);
        let start = measure.then(Instant::now);
        let result = run(execution);
        if let (Some(start), Ok(_)) = (start, &result) {
            let mut entry = self.entries.entry(key).or_default();
            entry.record(execution, start.elapsed());
        }
        result
    }

    /// Chooses whether to run a spawned job inline on the calling task or offload it to the pool,
    /// and whether the caller should time this run and feed the result back via
    /// [`record_spawn`](Self::record_spawn).
    pub(super) fn choose_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> (SpawnExecution, bool) {
        // A single worker cannot overlap a hand-off, so always inline.
        if parallelism <= 1 {
            return (SpawnExecution::Inline, false);
        }
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries
            .entry(key)
            .or_default()
            .choose(SERIAL_SAMPLE_BUDGET_NS)
    }

    /// Records the caller-visible cost of a spawned job. `caller_ns` is the marginal latency the
    /// chosen path added to the caller. For inline it is the job's wall time. For offload it is
    /// the hand-off setup plus the residual wait once the caller joined. `job_wall_ns` is the
    /// job's measured wall time on the pool (offload only). It estimates the inline cost and
    /// bounds inlining so a long job never blocks the calling task.
    pub(super) fn record_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        execution: SpawnExecution,
        caller_ns: Duration,
        job_wall_ns: Option<Duration>,
    ) {
        if parallelism <= 1 {
            return;
        }
        let key = Key::new(caller, len, len, parallelism);
        let caller_ns = u64::try_from(caller_ns.as_nanos()).unwrap_or(u64::MAX);
        let job_wall_ns = job_wall_ns.map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        self.spawn_entries
            .entry(key)
            .or_default()
            .record(execution, caller_ns, job_wall_ns);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
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
        self.entries.get(&key).map(|e| (e.serial_ns, e.parallel_ns))
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

/// Timing state for one [`Key`].
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    serial_ns: Option<u64>,
    parallel_ns: Option<u64>,
    since_probe: u32,
}

impl Entry {
    // A serial pass of work that parallel finishes in `parallel_ns` can take up to
    // `parallel_ns * parallelism`.
    fn projected_serial(parallel_ns: u64, parallelism: usize) -> u64 {
        parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX))
    }

    // Returns the path to prefer: the faster estimate, provided both the projected and
    // measured serial cost fit under the budget (the tuner only arbitrates small cases).
    // Ties go to serial (equal wall time for fewer busy workers).
    fn preferred(serial_ns: u64, parallel_ns: u64, parallelism: usize) -> Execution {
        if Self::projected_serial(parallel_ns, parallelism) >= SERIAL_SAMPLE_BUDGET_NS
            || serial_ns >= SERIAL_SAMPLE_BUDGET_NS
            || parallel_ns < serial_ns
        {
            Execution::Parallel
        } else {
            Execution::Serial
        }
    }

    // Returns the path to run and whether the caller should time it and feed the elapsed duration
    // back to [`record`](Self::record).
    fn choose(&mut self, parallelism: usize) -> (Execution, bool) {
        // Seed the parallel estimate with the first call. Saturating the probe counter keeps
        // the entry due for an immediate boundary, so the serial seed is offered as soon as
        // the parallel estimate lands (when the projection allows) instead of waiting a full
        // interval that a low-frequency callsite may never reach.
        let Some(parallel_ns) = self.parallel_ns else {
            self.since_probe = u32::MAX;
            return (Execution::Parallel, true);
        };

        // The projection gates serial in both sampling and preference: a case whose projection
        // exceeds the budget never runs serial. It is live: parallel keeps refreshing whenever
        // it executes, so a case that shrinks into the budget unlocks on its own.
        let can_sample_serial =
            Self::projected_serial(parallel_ns, parallelism) < SERIAL_SAMPLE_BUDGET_NS;

        // Until serial is sampled, parallel is preferred by default and the boundary doubles
        // as the seed slot. Once both estimates exist, the boundary probes the losing path on
        // an interval that doubles for each multiple of the winner's wall time it is behind,
        // so a close race is re-checked often while a blowout is re-checked rarely.
        let (preferred, interval) =
            self.serial_ns
                .map_or((Execution::Parallel, RESAMPLE_INTERVAL), |serial_ns| {
                    let preferred = Self::preferred(serial_ns, parallel_ns, parallelism);
                    let (winner_ns, loser_ns) = match preferred {
                        Execution::Serial => (serial_ns, parallel_ns),
                        Execution::Parallel => (parallel_ns, serial_ns),
                    };
                    let slowdown = loser_ns / winner_ns.max(1);
                    let shift = slowdown
                        .saturating_sub(1)
                        .min(u64::from(MAX_RESAMPLE_SHIFT)) as u32;
                    (preferred, RESAMPLE_INTERVAL << shift)
                });

        // Exactly one caller crosses the boundary, and a serial seed whose sample never lands
        // is simply offered again at the next boundary. A serial seed or probe must fit the
        // live projection. A parallel probe is always allowed: it pays the true parallel wall
        // (including any pool queueing), which the capped interval amortizes.
        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe >= interval {
            self.since_probe = 0;
            let probe = match preferred {
                Execution::Serial => Execution::Parallel,
                Execution::Parallel if can_sample_serial => Execution::Serial,
                Execution::Parallel => Execution::Parallel,
            };
            return (probe, true);
        }

        (
            preferred,
            self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
        )
    }

    // The first sample of each path initializes its estimate, and every later sample blends
    // into the EWMA, so a single outlier (a contended pool) moves an established estimate by
    // at most a fifth of the gap.
    fn record(&mut self, execution: Execution, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let estimate = match execution {
            Execution::Serial => &mut self.serial_ns,
            Execution::Parallel => &mut self.parallel_ns,
        };
        *estimate = Some(estimate.map_or(elapsed_ns, |current| update_ewma(current, elapsed_ns)));
    }
}

/// Timing state for one spawn [`Key`].
///
/// Offloading never makes the job itself run faster. What it buys is overlap: the calling task can
/// do other work while the job runs on the pool, so the caller waits only for whatever is left when
/// it finally awaits the result. `choose` therefore compares the caller's *wait*, not the job's
/// runtime: the whole job if inlined, versus the hand-off plus that leftover if offloaded (measured
/// in [`crate::Strategy::spawn`]). Offloading wins when the caller has enough of its own work to
/// overlap the job behind.
#[derive(Clone, Copy, Debug, Default)]
struct SpawnEntry {
    inline_ns: Option<u64>,
    offload_ns: Option<u64>,
    job_wall_ns: Option<u64>,
    // The most recent inline measurement, kept raw (not blended into `inline_ns`) so the
    // executor-block gate reacts to a single over-budget run instead of waiting for the EWMA.
    last_inline_ns: Option<u64>,
    since_probe: u32,
}

impl SpawnEntry {
    // Returns the path to run and whether the caller should time it. Offload is seeded first: it is
    // the only path that also measures the job's own wall time, which estimates the inline cost.
    // Once both estimates exist, the cheaper caller-visible cost wins (ties -> inline, which frees a
    // worker). Inlining is gated on the latest raw inline sample (or the pool wall before we have
    // one) against `budget`, so a single over-budget inline run switches to offloading at once and
    // a long job never blocks the calling task. The loser is probed on an interval that doubles
    // with how badly it lost, so a close race is re-checked often while a blowout is re-checked
    // rarely.
    fn choose(&mut self, budget: u64) -> (SpawnExecution, bool) {
        let Some(offload_ns) = self.offload_ns else {
            self.since_probe = u32::MAX;
            return (SpawnExecution::Offload, true);
        };
        let job_wall = self.job_wall_ns.unwrap_or(offload_ns);
        // `inline_est` (an EWMA) drives the cheaper-path preference. The safety gate instead uses
        // the latest raw inline sample, so a single over-budget run offloads immediately rather
        // than after the EWMA slowly crosses `budget`. Before any inline sample both fall back to
        // the offload-measured pool wall, which is also stale once the policy converges to inline.
        let inline_est = self.inline_ns.unwrap_or(job_wall);
        let inline_gate = self.last_inline_ns.unwrap_or(job_wall);
        let inline_safe = inline_gate < budget;
        let preferred = if inline_safe && inline_est <= offload_ns {
            SpawnExecution::Inline
        } else {
            SpawnExecution::Offload
        };
        let (winner_ns, loser_ns) = match preferred {
            SpawnExecution::Inline => (inline_est, offload_ns),
            SpawnExecution::Offload => (offload_ns, inline_est),
        };
        let slowdown = loser_ns / winner_ns.max(1);
        let shift = slowdown
            .saturating_sub(1)
            .min(u64::from(MAX_RESAMPLE_SHIFT)) as u32;
        let interval = RESAMPLE_INTERVAL << shift;

        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe >= interval {
            self.since_probe = 0;
            let probe = match preferred {
                SpawnExecution::Inline => SpawnExecution::Offload,
                // Probe inline whenever fresh offload evidence (`job_wall`, refreshed by the
                // offloads we are running) says the job is small enough to try safely, even if the
                // last inline sample was over budget. This lets a transient slow run recover once
                // the job shrinks again instead of offloading forever.
                SpawnExecution::Offload if job_wall < budget => SpawnExecution::Inline,
                SpawnExecution::Offload => SpawnExecution::Offload,
            };
            return (probe, true);
        }
        (
            preferred,
            self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
        )
    }

    fn record(&mut self, execution: SpawnExecution, caller_ns: u64, job_wall_ns: Option<u64>) {
        match execution {
            SpawnExecution::Inline => {
                self.inline_ns = Some(
                    self.inline_ns
                        .map_or(caller_ns, |current| update_ewma(current, caller_ns)),
                );
                // Keep the raw sample for the safety gate, unblended, so an over-budget run is
                // seen immediately rather than smoothed away by the EWMA above.
                self.last_inline_ns = Some(caller_ns);
            }
            SpawnExecution::Offload => {
                self.offload_ns = Some(
                    self.offload_ns
                        .map_or(caller_ns, |current| update_ewma(current, caller_ns)),
                );
                if let Some(job_wall_ns) = job_wall_ns {
                    self.job_wall_ns = Some(
                        self.job_wall_ns
                            .map_or(job_wall_ns, |current| update_ewma(current, job_wall_ns)),
                    );
                }
            }
        }
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
        Entry, Execution, MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL, Policy, RESAMPLE_INTERVAL,
        SERIAL_SAMPLE_BUDGET_NS, SpawnEntry, SpawnExecution,
    };
    use std::{panic::Location, time::Duration};

    const PARALLELISM: usize = 4;

    fn choose(entry: &mut Entry) -> (Execution, bool) {
        entry.choose(PARALLELISM)
    }

    #[test]
    fn starts_parallel_then_seeds_serial_immediately() {
        let mut entry = Entry::default();

        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
        entry.record(Execution::Parallel, Duration::from_micros(100));

        // The projection fits the budget, so the serial seed is offered on the very next
        // call rather than after a full interval.
        assert_eq!(choose(&mut entry), (Execution::Serial, true));
        entry.record(Execution::Serial, Duration::from_micros(95));

        // With both estimates seeded, the boundary resumes its normal cadence.
        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
    }

    #[test]
    fn defers_serial_seed_when_projection_exceeds_budget() {
        let mut entry = Entry::default();

        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
        entry.record(Execution::Parallel, Duration::from_millis(10));

        // The projection (10ms x 4) is over budget, so the immediate boundary refreshes
        // parallel instead of seeding serial and the cadence resets to a full interval.
        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
        assert!(entry.serial_ns.is_none());
        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
    }

    #[test]
    fn never_seeds_serial_when_projection_exceeds_budget() {
        // A serial pass could cost up to parallel * parallelism. When that projection exceeds
        // the budget, the tuner biases to parallel without ever paying a serial sample.
        let mut entry = Entry::default();

        entry.record(Execution::Parallel, Duration::from_millis(10));

        for i in 1..=(2 * RESAMPLE_INTERVAL) {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert!(entry.serial_ns.is_none());
    }

    #[test]
    fn never_runs_serial_on_big_work() {
        // The production profile of a large signature batch: parallel wall of 25ms on a
        // 12-thread pool. Serial must never run, no matter how many calls arrive.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(25));

        for _ in 0..10_000 {
            let (execution, measure) = entry.choose(12);
            assert_eq!(execution, Execution::Parallel);
            if measure {
                entry.record(Execution::Parallel, Duration::from_millis(25));
            }
        }
        assert!(entry.serial_ns.is_none());
    }

    #[test]
    fn big_serial_estimate_biases_parallel() {
        // Both estimates exceed the budget and serial nominally wins the comparison, but the
        // tuner only arbitrates small cases: big work runs parallel outright, and the serial
        // probe stays suppressed because the projection is over budget too.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(30));
        entry.record(Execution::Serial, Duration::from_millis(12));

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            let (execution, _) = choose(&mut entry);
            assert_eq!(execution, Execution::Parallel);
        }
    }

    #[test]
    fn projection_gates_preferred_serial() {
        // A workload grew within its bucket: parallel is now 25ms on a 12-thread pool
        // (projection 300ms, well over budget), but a stale serial estimate from a smaller
        // input claims 8ms. The live projection must keep serial from running.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(25));
        entry.record(Execution::Serial, Duration::from_millis(8));

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            let (execution, _) = entry.choose(12);
            assert_eq!(execution, Execution::Parallel);
        }
    }

    #[test]
    fn prefers_serial_when_faster() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(95));

        assert_eq!(choose(&mut entry), (Execution::Serial, false));
    }

    #[test]
    fn prefers_parallel_when_it_wins_wall_time() {
        // Serial is only 2x slower in wall time (cheaper in worker time on a 4-thread pool),
        // but the policy optimizes latency: parallel wins.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(200));

        assert_eq!(choose(&mut entry), (Execution::Parallel, false));
    }

    #[test]
    fn prefers_serial_on_tie() {
        // Equal wall time: serial occupies one worker instead of the whole pool.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(100));

        assert_eq!(choose(&mut entry), (Execution::Serial, false));
    }

    #[test]
    fn pre_seed_parallel_samples_blend() {
        // Before serial is seeded there is no loser: parallel samples smooth into the EWMA,
        // so a single outlier (a contended call) cannot swing the projection that gates
        // serial sampling.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(10));
        entry.record(Execution::Parallel, Duration::from_millis(20));

        assert_eq!(entry.parallel_ns, Some(12_000_000));
    }

    #[test]
    fn blends_preferred_samples_with_integer_math() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_nanos(1000));
        entry.record(Execution::Serial, Duration::from_nanos(100));

        // Serial is preferred, so further serial samples blend 4:1.
        entry.record(Execution::Serial, Duration::from_nanos(200));

        assert_eq!(entry.serial_ns, Some(120));
    }

    #[test]
    fn blends_preferred_parallel_samples() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_nanos(100));
        entry.record(Execution::Serial, Duration::from_nanos(1000));

        // Parallel is preferred, so further parallel samples blend 4:1.
        entry.record(Execution::Parallel, Duration::from_nanos(200));

        assert_eq!(entry.parallel_ns, Some(120));
    }

    #[test]
    fn probes_blend_into_stale_estimates() {
        // A probe's sample blends like any other, so one probe moves a stale estimate by a
        // fifth of the gap rather than trusting a single measurement outright.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(25));
        entry.record(Execution::Serial, Duration::from_millis(100));

        entry.record(Execution::Serial, Duration::from_millis(5));

        assert_eq!(entry.serial_ns, Some(81_000_000));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM
            ),
            Execution::Parallel
        );
    }

    #[test]
    fn seeds_serial_once_projection_shrinks_into_budget() {
        // The projection is live: a key that starts over budget seeds serial at the first
        // boundary after refreshes shrink the parallel estimate into the budget.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(10));

        for _ in 1..RESAMPLE_INTERVAL {
            let (execution, measure) = choose(&mut entry);
            assert_eq!(execution, Execution::Parallel);
            if measure {
                entry.record(Execution::Parallel, Duration::from_micros(100));
            }
        }
        assert_eq!(choose(&mut entry), (Execution::Serial, true));
    }

    #[test]
    fn resamples_other_execution() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(80));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
    }

    #[test]
    fn resamples_serial_when_parallel_wins() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(150));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Serial, true));
    }

    #[test]
    fn resample_interval_doubles_per_slowdown_multiple() {
        // Parallel lost by 2x-3x, so the probe interval doubles once.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(250));
        entry.record(Execution::Serial, Duration::from_micros(100));

        for i in 1..(2 * RESAMPLE_INTERVAL) {
            assert_eq!(
                choose(&mut entry),
                (Execution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
    }

    #[test]
    fn resample_interval_is_capped() {
        // Serial lost by 9x, so the interval shift is capped and the probe still happens.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(900));

        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Serial, true));
    }

    #[test]
    fn recovers_from_poisoned_estimate() {
        // Startup contention left parallel looking 2ms while serial measured 1ms, so serial
        // is preferred. The projection is still under budget (2ms x 4 = 8ms). The true
        // parallel cost is 0.5ms: probes blend the estimate down geometrically until the
        // preference flips.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(2));
        entry.record(Execution::Serial, Duration::from_millis(1));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM
            ),
            Execution::Serial
        );

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=1_000 {
            if Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM,
            ) == Execution::Parallel
            {
                flipped_at = Some(i - 1);
                break;
            }
            let (execution, measure) = choose(&mut entry);
            match execution {
                Execution::Parallel => {
                    assert!(measure);
                    probes += 1;
                    entry.record(Execution::Parallel, Duration::from_micros(500));
                }
                Execution::Serial => {
                    if measure {
                        entry.record(Execution::Serial, Duration::from_millis(1));
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
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(250));

        for round in 0..2 {
            for i in 1..RESAMPLE_INTERVAL {
                assert_eq!(
                    choose(&mut entry),
                    (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0),
                    "round {round}"
                );
            }
            assert_eq!(choose(&mut entry), (Execution::Serial, true));
        }

        entry.record(Execution::Serial, Duration::from_millis(1));
        assert_eq!(choose(&mut entry).0, Execution::Parallel);
    }

    #[test]
    fn probes_big_serial_when_projection_is_affordable() {
        // A serial estimate poisoned over the budget (e.g. one contended stall) must not
        // lock serial out forever: the probe gate reads the live projection, not the stale
        // estimate.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(500));
        entry.record(Execution::Serial, Duration::from_millis(15));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM
            ),
            Execution::Parallel
        );

        // Slowdown 15ms / 500us = 30 caps the shift, so the probe fires at 100 << 5 calls.
        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Serial, true));

        entry.record(Execution::Serial, Duration::from_micros(300));
        assert_eq!(entry.serial_ns, Some(12_060_000));
    }

    #[test]
    fn poisoned_probe_cannot_flip_preference() {
        // A spuriously fast serial sample (e.g. from a contended probe) blends into the EWMA
        // and cannot flip the preference on its own.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(800));
        entry.record(Execution::Serial, Duration::from_millis(3));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM
            ),
            Execution::Parallel
        );

        entry.record(Execution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns, Some(2_404_000));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns.unwrap(),
                PARALLELISM
            ),
            Execution::Parallel
        );
    }

    #[test]
    fn refreshes_preferred_parallel_sample() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(410));

        for i in 1..PREFERRED_SAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
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
                        Execution::Parallel => Err(()),
                        Execution::Serial => Ok(()),
                    },
                );
        }
        let (_, parallel_ns) = policy.get_entry(location, len, work, PARALLELISM).unwrap();
        assert_eq!(parallel_ns, parallel_estimate);
    }

    #[test]
    fn spawn_seeds_offload_then_inlines_a_tiny_poorly_overlapped_job() {
        let mut entry = SpawnEntry::default();

        // The first call seeds the offload estimate (and the job's own wall time).
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        // A 2us job whose caller-visible cost was 50us: the overlap did not hide it.
        entry.record(SpawnExecution::Offload, 50_000, Some(2_000));

        // The seed leaves the entry due for an immediate boundary, which re-probes offload.
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.record(SpawnExecution::Offload, 50_000, Some(2_000));

        // The job (2us) fits the budget and beats its 50us offload cost, so inline wins.
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_keeps_offloading_a_well_overlapped_job() {
        let mut entry = SpawnEntry::default();

        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        // A 50us job whose caller-visible cost was only 3us: the overlap hid almost all of it.
        entry.record(SpawnExecution::Offload, 3_000, Some(50_000));

        // Offload is preferred (3us beats a 50us inline), so the boundary probes the inline loser.
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.record(SpawnExecution::Inline, 50_000, None);

        // With both estimates known, offload still wins because the overlap makes it cheaper.
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS).0,
            SpawnExecution::Offload
        );
    }

    #[test]
    fn spawn_never_inlines_a_job_over_the_executor_block_budget() {
        let mut entry = SpawnEntry::default();

        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        // A job whose measured wall exceeds the budget must never run inline (it would stall the
        // async executor), no matter how the caller-visible cost compares.
        let over_budget = SERIAL_SAMPLE_BUDGET_NS * 2;
        entry.record(SpawnExecution::Offload, over_budget, Some(over_budget));

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            assert_eq!(
                entry.choose(SERIAL_SAMPLE_BUDGET_NS).0,
                SpawnExecution::Offload
            );
            entry.record(SpawnExecution::Offload, over_budget, Some(over_budget));
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
    fn spawn_offloads_after_a_single_over_budget_inline_sample() {
        // Start from a cheap, converged inline estimate: offload is expensive, inline is cheap, and
        // both sit well under the budget.
        let mut entry = SpawnEntry {
            offload_ns: Some(30_000_000), // offloading measured at 30ms
            inline_ns: Some(2_000),       // established cheap inline EWMA (2us)
            last_inline_ns: Some(2_000),
            job_wall_ns: Some(2_000),
            ..Default::default()
        };
        // One inline run now measures 15ms, over the 10ms budget. The blended `inline_ns` stays
        // ~3ms (still "safe" on its own), but the raw safety gate must offload on this single
        // sample rather than wait for the EWMA to cross the budget.
        entry.record(SpawnExecution::Inline, 15_000_000, None);
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS).0,
            SpawnExecution::Offload
        );
    }

    #[test]
    fn spawn_probes_inline_to_recover_after_a_transient_slow_run() {
        // A transient slow inline left `last_inline_ns` over budget, so the gate is unsafe and the
        // entry is offloading. Fresh offloads now show the job is small again (`job_wall` under
        // budget), and the entry is due for a boundary.
        let mut entry = SpawnEntry {
            offload_ns: Some(5_000),          // 5us
            job_wall_ns: Some(2_000),         // 2us: fresh offload evidence, the job is small
            inline_ns: Some(3_000_000),       // stale 3ms EWMA from the slow run
            last_inline_ns: Some(15_000_000), // 15ms: over budget, currently locks out inline
            since_probe: u32::MAX,
        };
        // Rather than offload forever, the boundary schedules a controlled inline probe because the
        // offload evidence is under budget.
        assert_eq!(
            entry.choose(SERIAL_SAMPLE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        // The probe measures the now-tiny job, clearing the raw over-budget gate so the entry can
        // inline again.
        entry.record(SpawnExecution::Inline, 2_000, None);
        assert!(entry.last_inline_ns.unwrap() < SERIAL_SAMPLE_BUDGET_NS);
    }
}
