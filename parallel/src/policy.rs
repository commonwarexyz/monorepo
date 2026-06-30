//! Adaptive execution policy for collection operations.
//!
//! Entries are keyed by callsite, input-size bucket, work-size bucket, and thread count so a
//! decision learned for one workload does not leak into another. The policy compares recent serial
//! and parallel timing samples and prefers parallel unless serial is clearly faster. It re-times
//! the preferred path every [`PREFERRED_SAMPLE_INTERVAL`] calls to keep its estimate current, and
//! probes the non-preferred path every [`RESAMPLE_INTERVAL`] calls in case the faster path has
//! changed.
//!
//! Timing is coarse by design: each measured call records a single wall-clock sample, and the
//! parallel sample also captures any time the job waits for a pool worker. On a shared pool under
//! load this can bias the parallel estimate upward and lean toward serial, but the periodic
//! resample bounds how long a stale decision persists, and both paths produce identical results,
//! so a misjudged call only costs throughput, never correctness.

use dashmap::DashMap;
use std::{
    panic::Location,
    sync::Arc,
    time::{Duration, Instant},
};

// Refresh the preferred path periodically so its EWMA does not go stale.
const PREFERRED_SAMPLE_INTERVAL: u32 = 10;
// Probe the non-preferred path on a longer interval in case conditions change.
const RESAMPLE_INTERVAL: u32 = 100;
// Track a short EWMA so recent measurements outweigh old startup noise.
const EWMA_PREVIOUS_WEIGHT: u64 = 4;
const EWMA_NEXT_WEIGHT: u64 = 1;
const EWMA_WEIGHT: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_NEXT_WEIGHT;
// Serial must take at most 90% of parallel's time before it becomes preferred.
const SERIAL_WIN_NUMERATOR: u64 = 90;
const SERIAL_WIN_DENOMINATOR: u64 = 100;
const SERIAL_SAMPLE_LIMIT_NS: u64 = 10_000_000;

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
        let (execution, measure) = self.entries.entry(key).or_default().choose();
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
    serial_ns: u64,
    parallel_ns: u64,
    serial_samples: u32,
    parallel_samples: u32,
    since_probe: u32,
}

impl Entry {
    // Returns the path to run and whether the caller should time it and feed the elapsed duration
    // back to [`record`](Self::record).
    fn choose(&mut self) -> (Execution, bool) {
        // Seed both sides before trusting the comparison.
        if self.parallel_samples == 0 {
            return (Execution::Parallel, true);
        }
        if self.serial_samples == 0 {
            if self.can_sample_serial() {
                return (Execution::Serial, true);
            }

            self.since_probe = self.since_probe.saturating_add(1);
            return (
                Execution::Parallel,
                self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
            );
        }

        let serial = u128::from(self.serial_ns) * u128::from(SERIAL_WIN_DENOMINATOR);
        let parallel = u128::from(self.parallel_ns) * u128::from(SERIAL_WIN_NUMERATOR);
        let preferred = if serial < parallel {
            Execution::Serial
        } else {
            Execution::Parallel
        };

        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe < RESAMPLE_INTERVAL {
            return (
                preferred,
                self.since_probe.is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
            );
        }
        self.since_probe = 0;

        // After enough calls, try the path that is currently losing.
        match preferred {
            Execution::Serial => (Execution::Parallel, true),
            Execution::Parallel if self.can_sample_serial() => (Execution::Serial, true),
            Execution::Parallel => (Execution::Parallel, true),
        }
    }

    fn record(&mut self, execution: Execution, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        match execution {
            Execution::Serial => {
                self.serial_ns = update_ewma(self.serial_ns, self.serial_samples, elapsed_ns);
                self.serial_samples = self.serial_samples.saturating_add(1);
            }
            Execution::Parallel => {
                self.parallel_ns = update_ewma(self.parallel_ns, self.parallel_samples, elapsed_ns);
                self.parallel_samples = self.parallel_samples.saturating_add(1);
            }
        }
    }

    const fn can_sample_serial(&self) -> bool {
        self.parallel_ns < SERIAL_SAMPLE_LIMIT_NS
    }
}

fn update_ewma(current: u64, samples: u32, next: u64) -> u64 {
    if samples == 0 {
        next
    } else {
        let weighted = u128::from(current) * u128::from(EWMA_PREVIOUS_WEIGHT)
            + u128::from(next) * u128::from(EWMA_NEXT_WEIGHT);
        (weighted / u128::from(EWMA_WEIGHT))
            .try_into()
            .unwrap_or(u64::MAX)
    }
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
    use super::{Entry, Execution, PREFERRED_SAMPLE_INTERVAL, RESAMPLE_INTERVAL};
    use std::time::Duration;

    #[test]
    fn starts_parallel_then_probes_serial() {
        let mut entry = Entry::default();

        assert_eq!(entry.choose(), (Execution::Parallel, true));
        entry.record(Execution::Parallel, Duration::from_micros(100));

        assert_eq!(entry.choose(), (Execution::Serial, true));
    }

    #[test]
    fn skips_initial_serial_probe_when_parallel_is_slow() {
        let mut entry = Entry::default();

        entry.record(Execution::Parallel, Duration::from_millis(10));

        for i in 1..PREFERRED_SAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(entry.choose(), (Execution::Parallel, true));
    }

    #[test]
    fn prefers_serial_with_margin() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(80));

        assert_eq!(entry.choose(), (Execution::Serial, false));
    }

    #[test]
    fn keeps_parallel_without_serial_margin() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(98));

        assert_eq!(entry.choose(), (Execution::Parallel, false));
    }

    #[test]
    fn updates_ewma_with_integer_math() {
        let mut entry = Entry::default();

        entry.record(Execution::Parallel, Duration::from_nanos(100));
        entry.record(Execution::Parallel, Duration::from_nanos(200));

        assert_eq!(entry.parallel_ns, 120);
    }

    #[test]
    fn resamples_other_execution() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(50));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (Execution::Serial, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(entry.choose(), (Execution::Parallel, true));
    }

    #[test]
    fn resamples_serial_when_parallel_wins() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(110));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(entry.choose(), (Execution::Serial, true));
    }

    #[test]
    fn skips_serial_resample_when_parallel_is_slow() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_millis(10));
        entry.record(Execution::Serial, Duration::from_millis(60));

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(entry.choose(), (Execution::Parallel, true));
    }

    #[test]
    fn refreshes_preferred_parallel_sample() {
        let mut entry = Entry::default();
        entry.record(Execution::Parallel, Duration::from_micros(100));
        entry.record(Execution::Serial, Duration::from_micros(110));

        for i in 1..PREFERRED_SAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (Execution::Parallel, i % PREFERRED_SAMPLE_INTERVAL == 0)
            );
        }
        assert_eq!(entry.choose(), (Execution::Parallel, true));
    }
}
