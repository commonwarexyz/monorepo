//! Adaptive execution policy for Rayon collection operations.
//!
//! Entries are keyed by callsite, input-size bucket, and thread count so a decision learned for
//! one workload does not leak into another. The policy compares recent serial and parallel timing
//! samples, prefers parallel unless serial is clearly faster, and periodically refreshes both
//! samples.

use parking_lot::{Mutex, MutexGuard};
use std::{collections::HashMap, panic::Location, time::Duration};

// Refresh the preferred path periodically so its EWMA does not go stale.
const PREFERRED_SAMPLE_INTERVAL: u32 = 8;
// Probe the non-preferred path on a longer interval in case conditions change.
const RESAMPLE_INTERVAL: u32 = 64;
// Track a short EWMA so recent measurements outweigh old startup noise.
const EWMA_PREVIOUS_WEIGHT: u64 = 4;
const EWMA_NEXT_WEIGHT: u64 = 1;
const EWMA_WEIGHT: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_NEXT_WEIGHT;
// Serial must take at most 95% of parallel's time before it becomes preferred.
const SERIAL_WIN_NUMERATOR: u64 = 95;
const SERIAL_WIN_DENOMINATOR: u64 = 100;

pub(super) type Entries = HashMap<Key, Entry>;

/// Identifies a stream of similar calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Key {
    file: &'static str,
    line: u32,
    column: u32,
    bucket: u8,
    parallelism: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Execution {
    Serial,
    Parallel,
}

/// Timing state for one [`Key`].
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Entry {
    serial_ns: u64,
    parallel_ns: u64,
    serial_samples: u32,
    parallel_samples: u32,
    since_probe: u32,
}

impl Entry {
    fn choose(&mut self) -> (Execution, bool) {
        // Seed both sides before trusting the comparison.
        if self.parallel_samples == 0 {
            return (Execution::Parallel, true);
        }
        if self.serial_samples == 0 {
            return (Execution::Serial, true);
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
                self.since_probe
                    .is_multiple_of(PREFERRED_SAMPLE_INTERVAL),
            );
        }
        self.since_probe = 0;

        // After enough calls, try the path that is currently losing.
        match preferred {
            Execution::Serial => (Execution::Parallel, true),
            Execution::Parallel => (Execution::Serial, true),
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
                self.parallel_ns =
                    update_ewma(self.parallel_ns, self.parallel_samples, elapsed_ns);
                self.parallel_samples = self.parallel_samples.saturating_add(1);
            }
        }
    }
}

fn update_ewma(current: u64, samples: u32, next: u64) -> u64 {
    // Integer math keeps the update cheap and deterministic.
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

fn entries(policy: &Mutex<Entries>) -> MutexGuard<'_, Entries> {
    policy.lock()
}

#[cfg(test)]
pub(super) fn len(policy: &Mutex<Entries>) -> usize {
    entries(policy).len()
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

const fn key(caller: &'static Location<'static>, len: usize, parallelism: usize) -> Key {
    Key {
        file: caller.file(),
        line: caller.line(),
        column: caller.column(),
        bucket: len_bucket(len),
        parallelism,
    }
}

pub(super) fn choose(
    policy: &Mutex<Entries>,
    caller: &'static Location<'static>,
    len: usize,
    parallelism: usize,
) -> (Key, Execution, bool) {
    let key = key(caller, len, parallelism);
    // A single-threaded pool cannot benefit from rayon scheduling.
    if parallelism <= 1 {
        return (key, Execution::Serial, false);
    }
    let mut entries = entries(policy);
    let (execution, measure) = entries.entry(key).or_default().choose();
    (key, execution, measure)
}

pub(super) fn record(
    policy: &Mutex<Entries>,
    key: Key,
    execution: Execution,
    elapsed: Duration,
) {
    entries(policy).entry(key).or_default().record(execution, elapsed);
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
