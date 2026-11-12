//! Joint algorithm and execution choices for sorts whose equal-element order is unspecified.

use super::{
    Cadence, Estimate, Key, PREFERRED_SAMPLE_INTERVAL, Placement, Policy, RunExecution, RunPlan,
    RunSample, SERIAL_SAMPLE_BUDGET_NS, nanos,
};
use dashmap::DashMap;
use std::{panic::Location, sync::Arc};

/// The sorting algorithm used by a chosen path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SortAlgorithm {
    Unstable,
    Stable,
}

/// A complete sort decision, retained until its measured execution finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SortPlan {
    pub(crate) algorithm: SortAlgorithm,
    pub(crate) run: RunPlan,
}

/// Sort measurements shared across copies of the strategy.
#[derive(Clone, Debug, Default)]
pub(super) struct SortPolicy {
    entries: Arc<DashMap<SortKey, SortEntry>>,
}

/// Element size separates generic callers sorting differently sized records.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SortKey {
    run: Key,
    element_size: usize,
}

impl SortKey {
    const fn new(
        caller: &'static Location<'static>,
        len: usize,
        element_size: usize,
        parallelism: usize,
    ) -> Self {
        Self {
            run: Key::new(caller, len, len, parallelism),
            element_size,
        }
    }
}

impl Policy {
    /// Chooses an algorithm and execution mode within the caller's fixed placement.
    pub(crate) fn choose_sort(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        element_size: usize,
        parallelism: usize,
        placement: Placement,
    ) -> SortPlan {
        self.sorts
            .entries
            .entry(SortKey::new(caller, len, element_size, parallelism))
            .or_default()
            .choose(parallelism <= 1, placement)
    }

    /// Records the path captured by `plan`, regardless of subsequent policy decisions.
    pub(crate) fn record_sort(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        element_size: usize,
        parallelism: usize,
        plan: SortPlan,
        sample: RunSample,
    ) {
        self.sorts
            .entries
            .entry(SortKey::new(caller, len, element_size, parallelism))
            .or_default()
            .record(plan, sample);
    }

    #[cfg(test)]
    pub(crate) fn sort_len(&self) -> usize {
        self.sorts.entries.len()
    }

    /// Serial and parallel wall estimates, in unstable-then-stable order.
    #[cfg(test)]
    pub(crate) fn sort_estimates(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        element_size: usize,
        parallelism: usize,
        placement: Placement,
    ) -> Option<[(Option<u64>, Option<u64>); 2]> {
        self.sorts
            .entries
            .get(&SortKey::new(caller, len, element_size, parallelism))
            .map(|entry| {
                std::array::from_fn(|algorithm| {
                    (
                        entry.serial[algorithm].get(),
                        entry.parallel[placement][algorithm].wall.get(),
                    )
                })
            })
    }
}

/// Path order also breaks timing ties: serial first, then unstable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Path {
    SerialUnstable,
    SerialStable,
    ParallelUnstable,
    ParallelStable,
}

impl Path {
    const ALL: [Self; 4] = [
        Self::SerialUnstable,
        Self::SerialStable,
        Self::ParallelUnstable,
        Self::ParallelStable,
    ];

    // Parallel samples establish whether each serial algorithm fits the sampling budget.
    const SEED: [Self; 4] = [
        Self::ParallelUnstable,
        Self::ParallelStable,
        Self::SerialUnstable,
        Self::SerialStable,
    ];

    const fn algorithm(self) -> SortAlgorithm {
        match self {
            Self::SerialUnstable | Self::ParallelUnstable => SortAlgorithm::Unstable,
            Self::SerialStable | Self::ParallelStable => SortAlgorithm::Stable,
        }
    }

    const fn execution(self) -> RunExecution {
        match self {
            Self::SerialUnstable | Self::SerialStable => RunExecution::Serial,
            Self::ParallelUnstable | Self::ParallelStable => RunExecution::Parallel,
        }
    }

    const fn plan(self, placement: Placement, measure: bool) -> SortPlan {
        SortPlan {
            algorithm: self.algorithm(),
            run: RunPlan {
                execution: self.execution(),
                placement: match self.execution() {
                    RunExecution::Serial => Placement::Wide,
                    RunExecution::Parallel => placement,
                },
                measure,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ParallelTiming {
    wall: Estimate,
    busy: Estimate,
}

#[derive(Clone, Copy, Debug, Default)]
struct SortEntry {
    /// Serial work always runs on the caller, so its estimates are shared across placements.
    serial: [Estimate; 2],
    parallel: [[ParallelTiming; 2]; 2],
    /// Wide, Local, and serial-only callers each advance their own challenger schedule.
    choices: [SortChoice; 3],
}

impl SortEntry {
    fn choose(&mut self, serial_only: bool, placement: Placement) -> SortPlan {
        let wall = Path::ALL.map(|path| match path.execution() {
            RunExecution::Serial => self.serial[path.algorithm() as usize].get(),
            RunExecution::Parallel => self.parallel[placement][path.algorithm() as usize]
                .wall
                .get(),
        });
        let probe = Path::ALL.map(|path| match path.execution() {
            RunExecution::Serial => {
                serial_only
                    || self.parallel[placement][path.algorithm() as usize]
                        .busy
                        .get()
                        .is_some_and(|busy| busy < SERIAL_SAMPLE_BUDGET_NS)
            }
            RunExecution::Parallel => !serial_only,
        });

        let context = if serial_only { 2 } else { placement as usize };
        // A call whose sample never arrives leaves the path unseeded, so another call retries it.
        if let Some(path) = Path::SEED
            .into_iter()
            .find(|&path| probe[path as usize] && wall[path as usize].is_none())
        {
            // Recheck a losing seed promptly so a cold first sample does not set its backoff.
            self.choices[context].cadences[path as usize].saturate();
            return path.plan(placement, true);
        }

        let preferred = Path::ALL
            .into_iter()
            .filter(|&path| {
                probe[path as usize]
                    && wall[path as usize].is_some_and(|wall| {
                        serial_only
                            || path.execution() == RunExecution::Parallel
                            || wall < SERIAL_SAMPLE_BUDGET_NS
                    })
            })
            .min_by_key(|&path| wall[path as usize])
            .expect("every sort has a measured eligible path after seeding");
        let (path, measure) = self.choices[context].choose(preferred, &wall, &probe);
        path.plan(placement, measure)
    }

    fn record(&mut self, plan: SortPlan, sample: RunSample) {
        let algorithm = plan.algorithm as usize;
        match plan.run.execution {
            RunExecution::Serial => self.serial[algorithm].record(nanos(sample.wall)),
            RunExecution::Parallel => {
                let timing = &mut self.parallel[plan.run.placement][algorithm];
                timing.wall.record(nanos(sample.wall));
                timing.busy.record(nanos(sample.busy));
            }
        }
    }
}

/// Each challenger gets its own cadence so unrelated comparisons do not share confirmations.
#[derive(Clone, Copy, Debug, Default)]
struct SortChoice {
    cadences: [Cadence<Path>; 4],
    next: usize,
    since_measure: u32,
}

impl SortChoice {
    fn choose(
        &mut self,
        preferred: Path,
        wall: &[Option<u64>; 4],
        probe: &[bool; 4],
    ) -> (Path, bool) {
        self.since_measure += 1;
        let measure = self.since_measure >= PREFERRED_SAMPLE_INTERVAL;
        if measure {
            self.since_measure = 0;
        }

        // Only one challenger's cadence advances per call. An eligible losing path is visited
        // within four calls, or three while the preferred path is unchanged. Its capped cadence
        // therefore keeps it discoverable even when preferences change between calls.
        for _ in 0..Path::ALL.len() {
            let challenger = Path::ALL[self.next];
            self.next = (self.next + 1) % Path::ALL.len();
            if challenger == preferred || !probe[challenger as usize] {
                continue;
            }
            let (path, _) = self.cadences[challenger as usize].arbitrate(
                preferred,
                challenger,
                wall[preferred as usize].expect("preferred path is measured"),
                wall[challenger as usize].expect("eligible challenger is measured"),
                true,
            );
            return (path, measure || path != preferred);
        }
        (preferred, measure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MAX_RESAMPLE_SHIFT, RESAMPLE_INTERVAL};
    use std::time::Duration;

    const PLACEMENT: Placement = Placement::Local;
    const PARALLELISM: usize = 4;
    const MAX_GAP: usize = (3 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT)) as usize;

    const fn path(plan: SortPlan) -> Path {
        match (plan.algorithm, plan.run.execution) {
            (SortAlgorithm::Unstable, RunExecution::Serial) => Path::SerialUnstable,
            (SortAlgorithm::Stable, RunExecution::Serial) => Path::SerialStable,
            (SortAlgorithm::Unstable, RunExecution::Parallel) => Path::ParallelUnstable,
            (SortAlgorithm::Stable, RunExecution::Parallel) => Path::ParallelStable,
        }
    }

    const fn sample(wall: u64, busy: u64) -> RunSample {
        RunSample {
            wall: Duration::from_nanos(wall),
            busy: Duration::from_nanos(busy),
        }
    }

    fn record(entry: &mut SortEntry, plan: SortPlan, costs: [u64; 4], busy: [u64; 2]) {
        entry.record(
            plan,
            sample(costs[path(plan) as usize], busy[plan.algorithm as usize]),
        );
    }

    fn seeded(costs: [u64; 4], busy: [u64; 2]) -> SortEntry {
        let mut entry = SortEntry::default();
        for expected in Path::SEED {
            let plan = entry.choose(false, PLACEMENT);
            assert_eq!(path(plan), expected);
            assert!(plan.run.measure);
            record(&mut entry, plan, costs, busy);
        }
        entry
    }

    fn warmed(costs: [u64; 4], busy: [u64; 2]) -> SortEntry {
        let mut entry = seeded(costs, busy);
        for _ in Path::ALL {
            let plan = entry.choose(false, PLACEMENT);
            if plan.run.measure {
                record(&mut entry, plan, costs, busy);
            }
        }
        entry
    }

    #[test]
    fn sort_rechecks_a_cold_seed_before_backing_off() {
        for cold in Path::ALL {
            let mut costs = [100; 4];
            costs[cold as usize] = 1_000_000;
            let mut entry = seeded(costs, [100; 2]);
            costs[cold as usize] = 10;

            let mut retried = false;
            for _ in Path::ALL {
                let plan = entry.choose(false, PLACEMENT);
                if path(plan) == cold {
                    assert!(plan.run.measure);
                    retried = true;
                }
                if plan.run.measure {
                    record(&mut entry, plan, costs, [100; 2]);
                }
            }
            assert!(retried, "{cold:?} retained its cold seed");
            let estimate = match cold.execution() {
                RunExecution::Serial => entry.serial[cold.algorithm() as usize],
                RunExecution::Parallel => entry.parallel[PLACEMENT][cold.algorithm() as usize].wall,
            };
            assert_eq!(estimate.get(), Some(10));
            assert_eq!(path(entry.choose(false, PLACEMENT)), cold);
        }
    }

    #[test]
    fn sort_rechecks_cold_busy_time_before_excluding_serial() {
        let mut entry = SortEntry::default();
        let costs = [10, 100, 1_000_000, 1_000];
        let busy = [SERIAL_SAMPLE_BUDGET_NS, 1_000];
        for expected in [
            Path::ParallelUnstable,
            Path::ParallelStable,
            Path::SerialStable,
        ] {
            let plan = entry.choose(false, PLACEMENT);
            assert_eq!(path(plan), expected);
            record(&mut entry, plan, costs, busy);
        }

        let mut serial_seeded = false;
        for _ in 0..Path::ALL.len() + 1 {
            let plan = entry.choose(false, PLACEMENT);
            if path(plan) == Path::SerialUnstable {
                assert!(plan.run.measure);
                serial_seeded = true;
                break;
            }
            if plan.run.measure {
                record(&mut entry, plan, [10, 100, 1_000, 1_000], [1_000; 2]);
            }
        }
        assert!(serial_seeded, "cold busy time kept serial ineligible");

        // Serial execution carries Wide in its plan, but this caller's Local cadence is primed.
        assert_eq!(
            entry.choices[PLACEMENT as usize].cadences[Path::SerialUnstable as usize].since_probe,
            u32::MAX
        );
        assert_eq!(
            entry.choices[Placement::Wide as usize].cadences[Path::SerialUnstable as usize]
                .since_probe,
            0
        );
    }

    #[test]
    fn sort_learns_every_joint_winner() {
        for winner in Path::ALL {
            let mut costs = [1_000; 4];
            costs[winner as usize] = 100;
            let mut entry = warmed(costs, [1_000; 2]);
            assert_eq!(path(entry.choose(false, PLACEMENT)), winner);

            let mut wins = 0;
            for _ in 0..1_000 {
                let plan = entry.choose(false, PLACEMENT);
                wins += usize::from(path(plan) == winner);
                if plan.run.measure {
                    record(&mut entry, plan, costs, [1_000; 2]);
                }
            }
            assert!(wins >= 990, "{winner:?} won {wins} calls");
        }
    }

    #[test]
    fn sort_ties_prefer_serial_then_unstable() {
        let mut entry = warmed([100; 4], [100; 2]);
        assert_eq!(path(entry.choose(false, PLACEMENT)), Path::SerialUnstable);

        for timing in &mut entry.parallel[PLACEMENT] {
            timing.busy = Estimate::Live(SERIAL_SAMPLE_BUDGET_NS);
        }
        assert_eq!(path(entry.choose(false, PLACEMENT)), Path::ParallelUnstable);
    }

    #[test]
    fn sort_serial_only_learns_both_algorithms_without_budget_gating() {
        let mut entry = SortEntry::default();
        for expected in [Path::SerialUnstable, Path::SerialStable] {
            let plan = entry.choose(true, Placement::Wide);
            assert_eq!(path(plan), expected);
            assert_eq!(plan.run.placement, Placement::Wide);
            record(
                &mut entry,
                plan,
                [2 * SERIAL_SAMPLE_BUDGET_NS, SERIAL_SAMPLE_BUDGET_NS, 0, 0],
                [0; 2],
            );
        }
        let retry = entry.choose(true, Placement::Wide);
        assert_eq!(path(retry), Path::SerialUnstable);
        assert!(retry.run.measure);
        entry.record(retry, sample(2 * SERIAL_SAMPLE_BUDGET_NS, 0));
        assert_eq!(
            path(entry.choose(true, Placement::Wide)),
            Path::SerialStable
        );
        assert!(
            entry
                .parallel
                .iter()
                .flatten()
                .all(|p| p.wall.get().is_none())
        );
    }

    #[test]
    fn sort_serial_budget_is_per_algorithm_and_recovers() {
        let mut entry = SortEntry::default();
        let costs = [10, 50, 1_000, 1_000];
        let busy = [SERIAL_SAMPLE_BUDGET_NS, 1_000];
        for expected in [
            Path::ParallelUnstable,
            Path::ParallelStable,
            Path::SerialStable,
        ] {
            let plan = entry.choose(false, PLACEMENT);
            assert_eq!(path(plan), expected);
            record(&mut entry, plan, costs, busy);
        }
        for _ in 0..MAX_GAP {
            let plan = entry.choose(false, PLACEMENT);
            assert_ne!(path(plan), Path::SerialUnstable);
            if plan.run.measure {
                record(&mut entry, plan, costs, busy);
            }
        }
        assert!(
            entry.serial[SortAlgorithm::Unstable as usize]
                .get()
                .is_none()
        );

        // The serial seed becomes eligible once this algorithm's parallel busy time falls.
        for _ in 0..10 {
            entry.record(
                Path::ParallelUnstable.plan(PLACEMENT, true),
                sample(1_000, 1_000),
            );
        }
        let plan = entry.choose(false, PLACEMENT);
        assert_eq!(path(plan), Path::SerialUnstable);
        assert!(plan.run.measure);
        record(&mut entry, plan, costs, [1_000; 2]);

        // Each other path can still be due one early follow-up before normal backoff.
        let mut wins = 0;
        for _ in 0..100 {
            let plan = entry.choose(false, PLACEMENT);
            wins += usize::from(path(plan) == Path::SerialUnstable);
            if plan.run.measure {
                record(&mut entry, plan, costs, [1_000; 2]);
            }
        }
        assert!(wins >= 97, "recovered serial path won only {wins} calls");
    }

    #[test]
    fn sort_slow_serial_can_be_probed_but_cannot_win() {
        let costs = [2 * SERIAL_SAMPLE_BUDGET_NS, 1_000, 100, 1_000];
        let mut entry = warmed(costs, [1_000; 2]);
        assert_eq!(path(entry.choose(false, PLACEMENT)), Path::ParallelUnstable);

        let choice = &mut entry.choices[PLACEMENT as usize];
        choice.next = Path::SerialUnstable as usize;
        choice.cadences[Path::SerialUnstable as usize].saturate();
        let plan = entry.choose(false, PLACEMENT);
        assert_eq!(path(plan), Path::SerialUnstable);
        assert!(plan.run.measure);
        // Repeated cheap samples can restore a path whose live estimate exceeded the budget.
        for _ in 0..100 {
            entry.record(plan, sample(10, 10));
        }
        assert_eq!(path(entry.choose(false, PLACEMENT)), Path::SerialUnstable);
    }

    #[test]
    fn sort_samples_the_winner_and_bounds_every_challenger() {
        let winner = Path::ParallelUnstable;
        let mut costs = [SERIAL_SAMPLE_BUDGET_NS * 100; 4];
        costs[winner as usize] = 100;
        let mut entry = warmed(costs, [100; 2]);
        for cadence in &mut entry.choices[PLACEMENT as usize].cadences {
            cadence.boundary = Some((winner, MAX_RESAMPLE_SHIFT));
            cadence.confirmations = MAX_RESAMPLE_SHIFT;
        }

        let mut seen = [0; 4];
        let mut winner_samples = 0;
        for _ in 0..MAX_GAP {
            let plan = entry.choose(false, PLACEMENT);
            seen[path(plan) as usize] += 1;
            if plan.run.measure {
                winner_samples += usize::from(path(plan) == winner);
                record(&mut entry, plan, costs, [100; 2]);
            }
        }
        assert!(seen.into_iter().all(|count| count > 0));
        assert!(winner_samples >= MAX_GAP / PREFERRED_SAMPLE_INTERVAL as usize - 3);
    }

    #[test]
    fn sort_bounds_probes_when_the_preferred_path_changes() {
        let mut choice = SortChoice::default();
        let target = Path::SerialUnstable;
        let limit = 4 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT) as usize;
        let mut sampled = false;
        for _ in 0..limit {
            // Always prefer a different path from the cursor's next challenger. No cursor slot
            // is skipped, so the continuously losing target gets one opportunity in four calls.
            let preferred = if Path::ALL[choice.next] == Path::SerialStable {
                Path::ParallelUnstable
            } else {
                Path::SerialStable
            };
            let mut wall = [Some(1_000_000); 4];
            wall[preferred as usize] = Some(1);
            let (path, measure) = choice.choose(preferred, &wall, &[true; 4]);
            if path == target {
                assert!(measure);
                sampled = true;
                break;
            }
        }
        assert!(sampled);
    }

    #[test]
    fn sort_recovers_after_the_joint_winner_changes() {
        for old in Path::ALL {
            for new in Path::ALL {
                let mut costs = [1_000; 4];
                costs[old as usize] = 100;
                let mut entry = warmed(costs, [1_000; 2]);
                costs[old as usize] = 1_000;
                costs[new as usize] = 10;
                for _ in 0..MAX_GAP * 2 {
                    let plan = entry.choose(false, PLACEMENT);
                    if plan.run.measure {
                        record(&mut entry, plan, costs, [1_000; 2]);
                    }
                }
                let wins = (0..100)
                    .filter(|_| path(entry.choose(false, PLACEMENT)) == new)
                    .count();
                assert!(wins >= 95, "{old:?} -> {new:?} won {wins} calls");
            }
        }
    }

    #[test]
    fn sort_placements_share_serial_estimates_but_not_probe_progress() {
        let mut entry = warmed([500, 500, 100, 200], [1_000; 2]);
        for (path, wall) in [(Path::ParallelUnstable, 1_000), (Path::ParallelStable, 50)] {
            entry.record(path.plan(Placement::Wide, true), sample(wall, 1_000));
        }
        assert_eq!(path(entry.choose(false, PLACEMENT)), Path::ParallelUnstable);
        assert_eq!(
            path(entry.choose(false, Placement::Wide)),
            Path::ParallelStable
        );
        let before = entry.choices[Placement::Wide as usize]
            .cadences
            .map(|cadence| cadence.since_probe);
        for _ in 0..100 {
            entry.choose(false, PLACEMENT);
        }
        let after = entry.choices[Placement::Wide as usize]
            .cadences
            .map(|cadence| cadence.since_probe);
        assert_eq!(before, after);

        // Serial plans carry Wide for execution, but a Local caller advances its Local cadence.
        entry.serial[SortAlgorithm::Stable as usize] = Estimate::Live(1);
        let plan = entry.choose(false, PLACEMENT);
        assert_eq!(path(plan), Path::SerialStable);
        assert_eq!(plan.run.placement, Placement::Wide);
        assert_eq!(
            after,
            entry.choices[Placement::Wide as usize]
                .cadences
                .map(|cadence| cadence.since_probe)
        );
    }

    #[test]
    fn sort_policy_is_shared_and_separates_workload_keys() {
        let policy = Policy::default();
        let cloned = policy.clone();
        let caller = Location::caller();
        let first = policy.choose_sort(caller, 256, 8, PARALLELISM, PLACEMENT);
        policy.record_sort(caller, 256, 8, PARALLELISM, first, sample(100, 100));
        assert_eq!(
            path(cloned.choose_sort(caller, 300, 8, PARALLELISM, PLACEMENT)),
            Path::ParallelStable,
        );
        assert_eq!(policy.sort_len(), 1);

        for (len, size, threads) in [(512, 8, PARALLELISM), (256, 16, PARALLELISM), (256, 8, 2)] {
            assert_eq!(
                path(policy.choose_sort(caller, len, size, threads, PLACEMENT)),
                Path::ParallelUnstable,
            );
        }
        let other_caller = Location::caller();
        policy.choose_sort(other_caller, 256, 8, PARALLELISM, PLACEMENT);
        assert_eq!(policy.sort_len(), 5);
        assert_eq!(Policy::default().sort_len(), 0);
    }

    #[test]
    fn sort_missing_and_delayed_samples_keep_their_original_path() {
        let policy = Policy::default();
        let caller = Location::caller();
        let first = policy.choose_sort(caller, 256, 8, PARALLELISM, PLACEMENT);
        let delayed = policy.choose_sort(caller, 256, 8, PARALLELISM, PLACEMENT);
        assert_eq!(first, delayed);
        assert_eq!(
            policy.sort_estimates(caller, 256, 8, PARALLELISM, PLACEMENT),
            Some([(None, None), (None, None)]),
        );

        policy.record_sort(caller, 256, 8, PARALLELISM, first, sample(100, 100));
        let stable = policy.choose_sort(caller, 256, 8, PARALLELISM, PLACEMENT);
        assert_eq!(path(stable), Path::ParallelStable);
        policy.record_sort(caller, 256, 8, PARALLELISM, stable, sample(10, 10));
        policy.record_sort(caller, 256, 8, PARALLELISM, delayed, sample(50, 50));
        assert_eq!(
            policy.sort_estimates(caller, 256, 8, PARALLELISM, PLACEMENT),
            Some([(None, Some(50)), (None, Some(10))]),
        );
    }
}
