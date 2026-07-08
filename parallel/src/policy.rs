//! Adaptive execution policy for collection operations.
//!
//! Entries are keyed by callsite, input-size bucket, work-size bucket, and thread count so a
//! decision learned for one workload does not leak into another. The policy compares recent
//! wall-clock estimates of each path and picks whichever is faster, with ties going to
//! serial (equal wall time for fewer busy workers).
//!
//! The tuner only arbitrates small cases. Choosing parallel for work that is better run
//! serially costs microseconds of dispatch overhead, while running big work serially forfeits
//! the pool's entire speedup, so the serial path is only ever executed where a live estimate
//! bounds its cost under [`SERIAL_SAMPLE_BUDGET_NS`]: a serial seed or probe requires the
//! projected serial cost (parallel's wall time multiplied by pool parallelism, an upper bound)
//! to fit the budget, and a measured serial estimate at or over the budget biases to parallel
//! outright. Big cases therefore always run parallel and never pay a serial sample.
//!
//! Every gate reads a live quantity, so no state is absorbing. The projection is derived from
//! the parallel estimate, which keeps refreshing (every [`PREFERRED_SAMPLE_INTERVAL`] calls)
//! whenever parallel executes. Within the budget, the losing path is probed on an interval
//! that grows exponentially with how badly it lost: a path within 2x of the winner is probed
//! every [`RESAMPLE_INTERVAL`] calls, and each additional multiple of the winner's wall time
//! doubles the interval, up to `RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT` calls. Probes are
//! never suppressed by the loser's own (stale) estimate, so an estimate poisoned by transient
//! conditions (pool contention at startup, an early-exit error path) converges back to the
//! truth over a handful of probes. Every sample blends into its path's EWMA, so a single
//! outlier moves an estimate by at most a fifth of the gap.
//!
//! Timing is coarse by design: each measured call records one wall-clock sample. Queueing on a
//! shared pool is included in a parallel sample's elapsed time, so contention pushes the
//! parallel estimate up and steers concurrent callers back toward serial. Both paths produce
//! identical results, so a misjudged call only costs throughput, never correctness.
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
// shift (100 << 5 = 3,200 calls). Slowdowns are bounded by pool parallelism, so a capped
// probe adds well under 1% amortized overhead on typical pools while keeping every path
// discoverable.
const MAX_RESAMPLE_SHIFT: u32 = 5;
// The tuner only arbitrates cases where a serial run is provably cheap: serial is seeded or
// probed only when its projected cost fits this budget, and a measured serial estimate at or
// over it biases to parallel outright.
const SERIAL_SAMPLE_BUDGET_NS: u64 = 10_000_000;
// Track a short EWMA so recent measurements outweigh old startup noise.
const EWMA_PREVIOUS_WEIGHT: u64 = 4;
const EWMA_NEXT_WEIGHT: u64 = 1;
const EWMA_WEIGHT: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_NEXT_WEIGHT;

type Entries = DashMap<Key, Entry>;

/// The path the policy chose for a call: the strategy runs the matching serial or parallel body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Execution {
    Serial,
    Parallel,
}

/// Adaptive serial-vs-parallel decisions, shared cheaply across [`super::Rayon`] clones.
#[derive(Clone, Debug, Default)]
pub(super) struct Policy {
    entries: Arc<Entries>,
}

impl Policy {
    /// Runs `run` on the execution path preferred for this callsite and input size, occasionally
    /// timing the call so the decision tracks recent performance.
    pub(super) fn run<R>(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        run: impl FnOnce(Execution) -> R,
    ) -> R {
        // A single-threaded pool cannot benefit from rayon scheduling, so always run serial and
        // never spend a measurement on it.
        if parallelism <= 1 {
            return run(Execution::Serial);
        }

        let key = Key::new(caller, len, work, parallelism);
        let (execution, measure) = self.entries.entry(key).or_default().choose(parallelism);
        let start = measure.then(Instant::now);
        let result = run(execution);
        if let Some(start) = start {
            self.entries
                .entry(key)
                .or_default()
                .record(execution, start.elapsed());
        }
        result
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
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
    // Returns the path to prefer: the faster estimate, except that a measured serial estimate
    // at or over the budget biases to parallel (the tuner only arbitrates small cases). Ties
    // go to serial (equal wall time for fewer busy workers).
    const fn preferred(serial_ns: u64, parallel_ns: u64) -> Execution {
        if serial_ns >= SERIAL_SAMPLE_BUDGET_NS || parallel_ns < serial_ns {
            Execution::Parallel
        } else {
            Execution::Serial
        }
    }

    // Returns the path to run and whether the caller should time it and feed the elapsed duration
    // back to [`record`](Self::record).
    fn choose(&mut self, parallelism: usize) -> (Execution, bool) {
        // Seed the parallel estimate with the first call.
        let Some(parallel_ns) = self.parallel_ns else {
            return (Execution::Parallel, true);
        };

        // A serial pass of work that parallel finishes in `parallel_ns` can take up to
        // `parallel_ns * parallelism`. The projection is live: parallel keeps refreshing
        // whenever it executes, so a case that shrinks into the budget unlocks on its own.
        let projected_serial =
            parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX));
        let serial_affordable = projected_serial < SERIAL_SAMPLE_BUDGET_NS;

        self.since_probe = self.since_probe.saturating_add(1);

        // Seed the serial estimate at the probe boundary once its projected cost fits the
        // budget. Exactly one caller crosses the boundary, and a seed whose sample never
        // lands is simply offered again at the next boundary.
        let Some(serial_ns) = self.serial_ns else {
            if self.since_probe >= RESAMPLE_INTERVAL {
                self.since_probe = 0;
                if serial_affordable {
                    return (Execution::Serial, true);
                }
                return (Execution::Parallel, true);
            }
            return (
                Execution::Parallel,
                self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
            );
        };

        // Probe the losing path on an interval that doubles for each multiple of the winner's
        // wall time it is behind, so a close race is re-checked often while a blowout is
        // re-checked rarely. A parallel probe is always allowed because its cost is on the
        // order of the (in-budget) serial wall. A serial probe must fit the live projection.
        let preferred = Self::preferred(serial_ns, parallel_ns);
        let (winner_ns, loser_ns) = match preferred {
            Execution::Serial => (serial_ns, parallel_ns),
            Execution::Parallel => (parallel_ns, serial_ns),
        };
        let slowdown = loser_ns / winner_ns.max(1);
        let shift = u32::try_from(slowdown.saturating_sub(1))
            .unwrap_or(MAX_RESAMPLE_SHIFT)
            .min(MAX_RESAMPLE_SHIFT);
        let interval = RESAMPLE_INTERVAL << shift;

        if self.since_probe >= interval {
            self.since_probe = 0;
            match preferred {
                Execution::Serial => return (Execution::Parallel, true),
                Execution::Parallel if serial_affordable => return (Execution::Serial, true),
                Execution::Parallel => return (Execution::Parallel, true),
            }
        }

        (
            preferred,
            self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
        )
    }

    // The first sample of each path initializes its estimate, and every later sample blends
    // into the EWMA, so a single outlier (an error-aborted call, a contended pool) moves an
    // estimate by at most a fifth of the gap.
    fn record(&mut self, execution: Execution, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let estimate = match execution {
            Execution::Serial => &mut self.serial_ns,
            Execution::Parallel => &mut self.parallel_ns,
        };
        *estimate = Some(estimate.map_or(elapsed_ns, |current| update_ewma(current, elapsed_ns)));
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
        Entry, Execution, MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL, RESAMPLE_INTERVAL,
    };
    use std::time::Duration;

    const PARALLELISM: usize = 4;

    fn choose(entry: &mut Entry) -> (Execution, bool) {
        entry.choose(PARALLELISM)
    }

    fn preferred(entry: &Entry) -> Execution {
        Entry::preferred(entry.serial_ns.unwrap(), entry.parallel_ns.unwrap())
    }

    #[test]
    fn starts_parallel_then_seeds_serial_at_boundary() {
        let mut entry = Entry::default();

        assert_eq!(choose(&mut entry), (Execution::Parallel, true));
        entry.record(Execution::Parallel, Duration::from_micros(100));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                choose(&mut entry),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(choose(&mut entry), (Execution::Serial, true));
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
        // so a single outlier (a fast error-abort or a contended call) cannot swing the
        // projection that gates serial sampling.
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
        assert_eq!(preferred(&entry), Execution::Parallel);
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
        // Startup contention left parallel looking 30ms while serial measured 8ms, so serial
        // is preferred. The true parallel cost is 3ms: exponential probes blend the estimate
        // back down geometrically until the preference flips.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(30));
        entry.record(Execution::Serial, Duration::from_millis(8));
        assert_eq!(preferred(&entry), Execution::Serial);

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=2_000 {
            if preferred(&entry) == Execution::Parallel {
                flipped_at = Some(i - 1);
                break;
            }
            let (execution, measure) = choose(&mut entry);
            match execution {
                Execution::Parallel => {
                    assert!(measure);
                    probes += 1;
                    entry.record(Execution::Parallel, Duration::from_millis(3));
                }
                Execution::Serial => {
                    if measure {
                        entry.record(Execution::Serial, Duration::from_millis(8));
                    }
                }
            }
        }

        // The estimate converges 30 -> 24.6 -> 20.28 -> 16.82 -> 14.06 -> 11.85 -> 10.08 ->
        // 8.66 -> 7.53ms over eight probes whose intervals shrink as the ratio narrows.
        assert_eq!(probes, 8);
        assert_eq!(flipped_at, Some(1_600));
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
        assert_eq!(preferred(&entry), Execution::Parallel);

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
        // A garbage batch that error-aborts in microseconds can land on a serial probe, but
        // its sample blends into the EWMA and cannot flip the preference on its own.
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(800));
        entry.record(Execution::Serial, Duration::from_millis(3));
        assert_eq!(preferred(&entry), Execution::Parallel);

        entry.record(Execution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns, Some(2_404_000));
        assert_eq!(preferred(&entry), Execution::Parallel);
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
}
