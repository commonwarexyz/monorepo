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

/// The path the policy chose for a call: the strategy runs the matching serial or parallel body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Execution {
    Serial,
    Parallel,
}

/// The path the policy chose for a call with multiple parallel arms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Choice {
    Serial,
    Parallel(u8),
}

/// The largest number of parallel arms a call may offer.
pub(super) const MAX_PARALLEL_ARMS: usize = 2;

/// Adaptive serial-vs-parallel decisions, shared cheaply across [`super::Rayon`] clones.
#[derive(Clone, Debug, Default)]
pub(super) struct Policy {
    entries: Arc<Entries>,
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

    /// Like [`Self::try_run`], but choosing among `arms` parallel bodies as
    /// well as the serial body.
    pub(super) fn try_run_n<R, E>(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        work: usize,
        parallelism: usize,
        arms: usize,
        run: impl FnOnce(Choice) -> Result<R, E>,
    ) -> Result<R, E> {
        if parallelism <= 1 {
            return run(Choice::Serial);
        }

        let key = Key::new(caller, len, work, parallelism);
        let (choice, measure) = self
            .entries
            .entry(key)
            .or_default()
            .choose_n(parallelism, arms);
        let start = measure.then(Instant::now);
        let result = run(choice);
        if let (Some(start), Ok(_)) = (start, &result) {
            let mut entry = self.entries.entry(key).or_default();
            entry.record_choice(choice, start.elapsed());
        }
        result
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
        self.entries
            .get(&key)
            .map(|e| (e.serial_ns, e.parallel_ns[0]))
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
    parallel_ns: [Option<u64>; MAX_PARALLEL_ARMS],
    since_probe: u32,
    /// Alternates which losing path the boundary probes when several exist.
    probe_flip: bool,
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
        let (choice, measure) = self.choose_n(parallelism, 1);
        let execution = match choice {
            Choice::Serial => Execution::Serial,
            Choice::Parallel(_) => Execution::Parallel,
        };
        (execution, measure)
    }

    // Multi-arm form of [`choose`](Self::choose): picks among the serial path
    // and `arms` parallel paths.
    fn choose_n(&mut self, parallelism: usize, arms: usize) -> (Choice, bool) {
        debug_assert!((1..=MAX_PARALLEL_ARMS).contains(&arms));

        // Seed each parallel estimate with the first calls. Saturating the probe counter
        // keeps the entry due for an immediate boundary, so the next seed is offered as
        // soon as an estimate lands (when the projection allows) instead of waiting a full
        // interval that a low-frequency callsite may never reach.
        for arm in 0..arms {
            if self.parallel_ns[arm].is_none() {
                self.since_probe = u32::MAX;
                return (Choice::Parallel(arm as u8), true);
            }
        }

        // The best parallel arm stands in for "parallel" everywhere below; ties go to the
        // lower arm index.
        let (best_arm, parallel_ns) = (0..arms)
            .filter_map(|arm| self.parallel_ns[arm].map(|ns| (arm as u8, ns)))
            .min_by_key(|(arm, ns)| (*ns, *arm))
            .expect("all arms are seeded above");

        // The projection gates serial in both sampling and preference: a case whose projection
        // exceeds the budget never runs serial. It is live: parallel keeps refreshing whenever
        // it executes, so a case that shrinks into the budget unlocks on its own.
        let can_sample_serial =
            Self::projected_serial(parallel_ns, parallelism) < SERIAL_SAMPLE_BUDGET_NS;

        // Until serial is sampled, the best parallel arm is preferred by default and the
        // boundary doubles as the seed slot. Once the estimates exist, the boundary probes a
        // losing path on an interval that doubles for each multiple of the winner's wall time
        // the closest loser is behind, so a close race is re-checked often while a blowout is
        // re-checked rarely.
        let losers = |preferred: Choice| {
            let mut losers: [Option<Choice>; MAX_PARALLEL_ARMS] = [None; MAX_PARALLEL_ARMS];
            let mut count = 0;
            for arm in 0..arms {
                if preferred != Choice::Parallel(arm as u8) {
                    losers[count] = Some(Choice::Parallel(arm as u8));
                    count += 1;
                }
            }
            if preferred != Choice::Serial && can_sample_serial {
                losers[count] = Some(Choice::Serial);
                count += 1;
            }
            (losers, count)
        };
        let estimate = |choice: Choice| match choice {
            Choice::Serial => self.serial_ns,
            Choice::Parallel(arm) => self.parallel_ns[arm as usize],
        };
        let (preferred, interval) = self.serial_ns.map_or(
            (Choice::Parallel(best_arm), RESAMPLE_INTERVAL),
            |serial_ns| {
                let preferred = match Self::preferred(serial_ns, parallel_ns, parallelism) {
                    Execution::Serial => Choice::Serial,
                    Execution::Parallel => Choice::Parallel(best_arm),
                };
                let winner_ns = estimate(preferred).expect("preferred path is sampled");
                let (candidates, count) = losers(preferred);
                let closest_ns = candidates[..count]
                    .iter()
                    .filter_map(|loser| estimate(loser.expect("loser slots are filled")))
                    .min()
                    .unwrap_or(winner_ns);
                let slowdown = closest_ns / winner_ns.max(1);
                let shift = slowdown
                    .saturating_sub(1)
                    .min(u64::from(MAX_RESAMPLE_SHIFT)) as u32;
                (preferred, RESAMPLE_INTERVAL << shift)
            },
        );

        // Exactly one caller crosses the boundary, and a serial seed whose sample never lands
        // is simply offered again at the next boundary. A serial seed or probe must fit the
        // live projection. A parallel probe is always allowed: it pays the true parallel wall
        // (including any pool queueing), which the capped interval amortizes. When several
        // losers exist the boundary alternates among them.
        self.since_probe = self.since_probe.saturating_add(1);
        if self.since_probe >= interval {
            self.since_probe = 0;
            // An unsampled serial estimate takes the boundary as its seed.
            if self.serial_ns.is_none() && can_sample_serial {
                return (Choice::Serial, true);
            }
            let (candidates, count) = losers(preferred);
            let probe = match count {
                0 => preferred,
                _ => {
                    self.probe_flip = !self.probe_flip;
                    let index = if self.probe_flip { 0 } else { count - 1 };
                    candidates[index].expect("loser slots are filled")
                }
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
        let choice = match execution {
            Execution::Serial => Choice::Serial,
            Execution::Parallel => Choice::Parallel(0),
        };
        self.record_choice(choice, elapsed);
    }

    fn record_choice(&mut self, choice: Choice, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let estimate = match choice {
            Choice::Serial => &mut self.serial_ns,
            Choice::Parallel(arm) => &mut self.parallel_ns[arm as usize],
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
        Choice, Entry, Execution, Policy, MAX_RESAMPLE_SHIFT, PREFERRED_SAMPLE_INTERVAL,
        RESAMPLE_INTERVAL,
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

        assert_eq!(entry.parallel_ns[0], Some(12_000_000));
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

        assert_eq!(entry.parallel_ns[0], Some(120));
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
                entry.parallel_ns[0].unwrap(),
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
                entry.parallel_ns[0].unwrap(),
                PARALLELISM
            ),
            Execution::Serial
        );

        let mut probes = 0;
        let mut flipped_at = None;
        for i in 1..=1_000 {
            if Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns[0].unwrap(),
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
                entry.parallel_ns[0].unwrap(),
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
                entry.parallel_ns[0].unwrap(),
                PARALLELISM
            ),
            Execution::Parallel
        );

        entry.record(Execution::Serial, Duration::from_micros(20));

        assert_eq!(entry.serial_ns, Some(2_404_000));
        assert_eq!(
            Entry::preferred(
                entry.serial_ns.unwrap(),
                entry.parallel_ns[0].unwrap(),
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
    fn seeds_both_arms_then_prefers_best() {
        let mut entry = Entry::default();

        // Both parallel arms are seeded before anything else, in order.
        assert_eq!(entry.choose_n(PARALLELISM, 2), (Choice::Parallel(0), true));
        entry.record_choice(Choice::Parallel(0), Duration::from_micros(400));
        assert_eq!(entry.choose_n(PARALLELISM, 2), (Choice::Parallel(1), true));
        entry.record_choice(Choice::Parallel(1), Duration::from_micros(100));

        // The serial seed follows at the next boundary (projection fits).
        assert_eq!(entry.choose_n(PARALLELISM, 2), (Choice::Serial, true));
        entry.record_choice(Choice::Serial, Duration::from_micros(300));

        // The fastest arm is preferred over both the slower arm and serial.
        assert_eq!(entry.choose_n(PARALLELISM, 2).0, Choice::Parallel(1));
    }

    #[test]
    fn boundary_probes_alternate_losers() {
        let mut entry = Entry::default();
        // Losers within 2x of the winner keep the probe interval at its base.
        entry.record_choice(Choice::Parallel(0), Duration::from_micros(150));
        entry.record_choice(Choice::Parallel(1), Duration::from_micros(100));
        entry.record_choice(Choice::Serial, Duration::from_micros(180));

        // Both losers (arm 0 and serial) are probed over successive
        // boundaries while arm 1 stays preferred in between.
        let mut probed = std::collections::HashSet::new();
        for _ in 0..3 {
            for _ in 1..RESAMPLE_INTERVAL {
                let (choice, _) = entry.choose_n(PARALLELISM, 2);
                assert_eq!(choice, Choice::Parallel(1));
            }
            let (probe, measure) = entry.choose_n(PARALLELISM, 2);
            assert!(measure);
            assert_ne!(probe, Choice::Parallel(1));
            probed.insert(probe);
        }
        assert!(probed.contains(&Choice::Serial));
        assert!(probed.contains(&Choice::Parallel(0)));
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
}
