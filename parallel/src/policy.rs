//! Adaptive execution policies for collection operations and spawned jobs.
//!
//! Entries are keyed by callsite, input-size bucket, work-size bucket, and planning parallelism
//! so a decision learned for one workload does not leak into another. The policy compares recent
//! wall-clock estimates of each path and picks whichever is faster, with ties going to serial
//! (equal wall time for fewer busy workers).
//!
//! The tuner only arbitrates small cases. Choosing parallel for work that is better run serially
//! costs microseconds of dispatch overhead, while running big work serially forfeits the pool's
//! entire speedup. Serial is therefore gated by a live estimate in both of its roles.
//!
//! Sampling serial (the seed and every probe) requires the projected serial cost to fit under
//! [`SERIAL_SAMPLE_BUDGET_NS`]. The projection multiplies each parallel run's wall time by the
//! parallelism it planned with. Preferring serial in steady state requires both the projected and
//! the measured serial cost to fit under the same budget. Big cases therefore always run parallel
//! and never pay a serial sample.
//!
//! Every gate reads a live quantity, so no state is absorbing. The projection comes from the
//! parallel samples, and parallel records one every [`PREFERRED_SAMPLE_INTERVAL`] calls while it is
//! preferred and at every probe otherwise.
//!
//! Within the budget, the losing path is probed on an interval that grows exponentially with how
//! badly it lost and with how long the preference has held. A loser within 2x of the winner is
//! first probed every [`RESAMPLE_INTERVAL`] calls, and each additional multiple of the winner's
//! wall time doubles that interval.
//!
//! The interval also doubles with each consecutive probe slot that confirms the ordering. A slot
//! confirms when the same path is still preferred and the gap adds no fewer doublings than at the
//! previous slot, so movement that stays within the same whole multiple of the winner's wall time
//! still confirms.
//!
//! A flip of the preferred path, or a gap that drops a doubling, resets that count at once. A close
//! race that holds therefore backs off toward the cap, and a reset returns the interval to what the
//! gap alone sets. The interval never exceeds `RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT` calls,
//! whatever the two counts.
//!
//! Probes are never suppressed by the loser's own stale estimate, so an estimate poisoned by
//! transient conditions (pool contention at startup) converges back to the truth over a handful of
//! probes. After a path's first sample initializes its estimate, every later sample blends into the
//! EWMA, so a single outlier moves an established estimate by at most a fifth of the gap.
//!
//! Placement decides whether a parallel run or an offloaded job uses the shared pool or the local
//! pool. The local pool is confined to the submitting thread's last-level cache domain. Only a
//! caller outside the strategy's pools chooses a placement. A worker of any of them keeps every
//! placed call in its own pool, so the timing of the outermost call (a run's wall time or a job's
//! round trip) covers the placed calls nested in its work.
//!
//! Each entry learns its placement as a [`Choice`]. The choice seeds the shared pool and then the
//! local pool, prefers the faster, and probes the slower on the intervals above.
//!
//! Each pool has its own cadence for the serial-versus-parallel decision. A caller compares serial
//! against the pool it would use, on that pool's cadence. A worker compares against its own pool, a
//! caller without a local pool against the shared pool, and a caller with a choice of pools against
//! the preferred one.
//!
//! For a run, a caller with a choice consults the placement first on every call. A seed of an
//! unmeasured pool or a probe of the slower one takes the call as a timed parallel run. Placement
//! probes leave both execution cadences unchanged. The slower pool's probe interval follows its
//! loss to the faster of the preferred pool and serial, so it is probed even while serial wins, and
//! no more often than its loss to serial warrants. Serial counts only while it could be preferred:
//! once the budget gates it out, the slower pool races the preferred pool alone.
//!
//! Spawned jobs compare inline against a pool's hand-off overhead as runs compare serial against a
//! pool's wall time, but a caller with a choice decides in the other order. It first decides
//! between inline and the preferred pool's hand-off, on a cadence kept for such callers, and
//! consults the placement only for a job it offloads. The placement then weighs the pools against
//! each other alone, and the caller times the job when the placement seeds or probes a pool.
//!
//! While inline wins, a spawning caller with a choice therefore offloads only at its cadence's
//! probes, and the placement counts its own probe interval only in those offloads. The two capped
//! intervals compound, so a pool that has become faster can wait up to their product, in calls, for
//! its next probe.
//!
//! A worker keeps its job in its own pool and decides on a cadence and overhead estimate kept for
//! workers, since its round trip is not a hand-off.
//!
//! A caller outside the pools without a local pool offloads to the shared pool without consulting
//! the placement, on a cadence of its own. Its round trips train the shared pool's hand-off
//! overhead, which it compares inline against, but not the placement, which only callers with a
//! choice consult and train.
//!
//! Every caller on one cadence makes the same comparison, so each probe and sample slot lands on a
//! caller that can act on it. A caller confined to one pool decides against that pool, so a
//! preference learned by callers with a choice never commits it to a run there that serial would
//! beat within the budget.
//!
//! The pools' parallel estimates are shared. The runs of a confined caller keep the estimate of its
//! pool current for callers with a choice, and a call site reached both ways blends the timings of
//! both.
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
// Probe the losing path this often when its estimate is within 2x of the winner's and the ordering
// has no confirmations.
const RESAMPLE_INTERVAL: u32 = 100;
// Each additional multiple of the winner's wall time and each confirmation of the ordering doubles
// the probe interval, up to this shift (100 << 5 = 3,200 calls). The cap keeps every path
// discoverable while the interval amortizes the cost of a mispriced probe across thousands of
// calls. A parallel probe pays any pool queueing in full.
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
    /// The parallel body. A run executes it on the calling thread, and the body hands the strategy
    /// the work to distribute. A collection operation executes it on a pool.
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

/// The pools a run's caller may use, each with the parallelism it plans with there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pools {
    /// Only this placement takes part in the decision. A worker decides against its own pool,
    /// where its placed calls and joins run. A caller outside the pools decides against the
    /// shared pool when it has no local pool or nothing to place. A run with nothing to place
    /// keeps its body on the caller.
    Fixed(Placement, usize),
    /// The shared pool or the caller's local pool, with the local pool's planning parallelism.
    Either(usize),
}

/// The pool an offloaded job runs on, as its round trip is recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnPool {
    /// The submitting worker's own pool. Its round trip is not a hand-off, so it feeds the
    /// overhead estimate kept for workers and teaches the placement nothing.
    Own,
    /// The shared pool, taken by a caller outside the pools that has no local pool, and the pool a
    /// fixed plan names. A timed round trip feeds the shared pool's hand-off overhead, which such a
    /// caller compares inline against, and teaches the placement nothing, since the caller never
    /// consults it.
    Shared,
    /// The pool the placement chose, seeded, or probed for a caller with a local pool. Its round
    /// trip feeds that pool's hand-off overhead and the placement.
    Placed(Placement),
}

/// The decisions for one spawned job and whether the caller should time it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpawnPlan {
    /// Whether the job runs inline or on a pool.
    pub(super) execution: SpawnExecution,
    /// The pool an offloaded job runs on. An inline job records no round trip, so its pool is not
    /// consulted.
    pub(super) pool: SpawnPool,
    /// Whether the caller times the job and reports the samples.
    pub(super) measure: bool,
}

impl SpawnPlan {
    /// A plan with no learned choices: `execution`, untimed. Its pool is the shared one, where a
    /// submitter outside the pools runs an offloaded job; a worker keeps the job in its own pool
    /// whatever the plan says.
    pub(super) const fn fixed(execution: SpawnExecution) -> Self {
        Self {
            execution,
            pool: SpawnPool::Shared,
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
    /// `pools` reports the pools the caller may use. It is called before every adaptive
    /// decision, since the decision depends on them. Looking the local pool up may build it.
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
            parallelism,
            measure: false,
        };

        // A strategy configured for serial execution cannot benefit from rayon scheduling, so
        // always run serial and never spend a measurement on it.
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, work, parallelism);

        // A caller decides between serial and the pool it would use, on that pool's cadence. A
        // caller with a choice of pools consults the placement first. The lookup runs before the
        // entry is locked, since it may build the local pool.
        let local_parallelism = match pools() {
            Pools::Fixed(placement, pool_parallelism) => {
                (plan.execution, plan.measure) = self
                    .run_entries
                    .entry(key)
                    .or_default()
                    .choose(placement, parallelism);
                if plan.execution == RunExecution::Parallel {
                    plan.placement = placement;
                    plan.parallelism = pool_parallelism;
                }
                return plan;
            }
            Pools::Either(local_parallelism) => local_parallelism,
        };

        // The placement goes first and weighs the slower pool against the preferred pool and, while
        // serial could run, against serial. A seed or probe takes the call as a timed parallel run.
        // Probes leave both execution cadences unchanged, so placement and execution probes never
        // displace each other's boundary.
        let mut entry = self.run_entries.entry(key).or_default();
        let preferred = entry.placement.preferred();
        let serial_ns = entry.serial_ns.get();
        let rival_ns = entry.serial_rival_ns(preferred, parallelism);
        let placement = entry.placement.choose(rival_ns);
        if placement == preferred {
            (plan.execution, plan.measure) = entry.choose(preferred, parallelism);
            if plan.execution != RunExecution::Parallel {
                return plan;
            }
        } else {
            // Until serial is measured, a pool's first sample leaves its serial comparison due.
            if serial_ns.is_none() && entry.placement.estimate(placement).is_none() {
                entry.cadences[placement as usize].saturate();
            }
            (plan.execution, plan.measure) = (RunExecution::Parallel, true);
        }
        plan.placement = placement;
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

    /// Plans a spawned job, including whether the caller should time it and report the samples to
    /// [`Self::record_spawn_inline`], [`Self::record_spawn_job`], and
    /// [`Self::record_spawn_round_trip`].
    ///
    /// The policy prefers running the job inline on the calling task when its measured wall is no
    /// greater than both the hand-off overhead of offloading it and [`SPAWN_INLINE_BUDGET_NS`], and
    /// prefers offloading it otherwise.
    ///
    /// A worker of one of the strategy's pools (`own_pool`) keeps its job in that pool and decides
    /// on a cadence and overhead estimate kept for workers. Its calls therefore neither consume the
    /// probes that let outside callers place a job nor blend its own-pool round trips into their
    /// hand-off overhead.
    ///
    /// A caller outside the pools without a local pool compares inline against the shared pool's
    /// hand-off overhead, on a cadence kept for such callers, and its round trips train that
    /// overhead alone. A caller with a local pool compares inline against the preferred pool's
    /// hand-off overhead, on a cadence of its own, and consults the placement only for a job it
    /// offloads. The placement weighs the pools against each other alone, and a seed of an
    /// unmeasured pool or a probe of the slower one is timed.
    ///
    /// `can_local` reports whether the caller has a local pool, so it is called for every job from
    /// outside the pools and never for a worker's job. The lookup may build the local pool.
    pub(super) fn choose_spawn(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
        own_pool: bool,
        can_local: impl FnOnce() -> bool,
    ) -> SpawnPlan {
        // A single worker cannot overlap a hand-off, so always inline (nothing to measure).
        let mut plan = SpawnPlan::fixed(SpawnExecution::Inline);
        if parallelism <= 1 {
            return plan;
        }
        let key = Key::new(caller, len, len, parallelism);

        // Classify the caller before locking the entry, since `can_local` may build the local pool.
        let spawner = if own_pool {
            Spawner::Worker
        } else if can_local() {
            Spawner::Either
        } else {
            Spawner::Shared
        };
        let mut entry = self.spawn_entries.entry(key).or_default();
        (plan.execution, plan.measure) = entry.choose(spawner, SPAWN_INLINE_BUDGET_NS);
        match spawner {
            Spawner::Worker => plan.pool = SpawnPool::Own,

            // Once the job is offloaded, inline is out of the race, so the placement weighs the
            // pools without a rival. A pool other than the preferred one is a seed or probe, and
            // its round trip trains the placement only if timed. Callers without a local pool may
            // already have measured the shared pool's hand-off without training the placement, so
            // a seed is told by the placement's own estimate rather than by the execution seed.
            Spawner::Either if plan.execution == SpawnExecution::Offload => {
                let preferred = entry.placement.preferred();
                let placement = entry.placement.choose(None);
                plan.pool = SpawnPool::Placed(placement);
                plan.measure |=
                    placement != preferred || entry.placement.estimate(placement).is_none();
            }
            Spawner::Shared | Spawner::Either => {}
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
    /// The round trip minus the job feeds the hand-off overhead estimate of the pool that ran the
    /// job, or the overhead estimate kept for workers when the job stayed in the submitter's own
    /// pool. A job the placement chose also records the whole round trip for the placement; a job
    /// on the shared pool from a caller without a choice does not.
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
                SpawnPool::Shared => entry.overhead_ns[Placement::Wide as usize].record(overhead),
                SpawnPool::Placed(placement) => {
                    entry.overhead_ns[placement as usize].record(overhead);
                    entry.placement.record(placement, nanos(round_trip));
                }
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
    /// count, and a choose-created but never-recorded entry has no estimates.
    #[cfg(test)]
    pub(super) fn spawn_recorded(
        &self,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> bool {
        let key = Key::new(caller, len, len, parallelism);
        self.spawn_entries.get(&key).is_some_and(|entry| {
            entry
                .overhead_ns
                .iter()
                .any(|overhead_ns| overhead_ns.get().is_some())
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

    /// The shared-pool and local-pool estimates, in nanoseconds, of the run entry for this call
    /// site, or `None` when the entry does not exist.
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
/// A boundary whose probe is disallowed counts like any other. It still measures the preferred
/// path, and when the preference held and the gap did not shrink, nothing contradicts the ordering.
/// Once the probe is allowed again, it comes within the capped interval.
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

impl<P> Default for Cadence<P> {
    fn default() -> Self {
        Self {
            since_probe: 0,
            boundary: None,
            confirmations: 0,
        }
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
    // The parallel wall time on each pool, shared by callers with a choice and confined callers. A
    // caller with a choice compares serial against the preferred pool alone, so a probe of the
    // slower pool never raises the estimate it compares against. A confined caller compares serial
    // against its own pool.
    placement: Choice,
    // The serial cost projected from local runs. Domain pools may differ in width, so each run's
    // wall time is multiplied by the parallelism it planned with before it blends in.
    local_serial_ns: Estimate,
    // The cadences on which serial is arbitrated against each pool, indexed by placement. Every
    // caller on one cadence compares serial against the same pool, so each probe lands on a
    // caller that can act on it.
    cadences: [Cadence<RunExecution>; 2],
}

impl RunEntry {
    // A serial pass of work that parallel finishes in `parallel_ns` can take up to
    // `parallel_ns * parallelism`.
    fn projected_serial(parallel_ns: u64, parallelism: usize) -> u64 {
        parallel_ns.saturating_mul(u64::try_from(parallelism).unwrap_or(u64::MAX))
    }

    // The parallel estimate a caller with a choice decides on: the preferred pool's wall time, or
    // `None` until the shared pool is measured.
    #[cfg(test)]
    const fn parallel_ns(&self) -> Option<u64> {
        self.placement.estimate(self.placement.preferred())
    }

    // The estimate of `placement`'s pool and the serial cost projected from it, or `None` until
    // that pool is measured. The shared pool always plans with `parallelism`.
    fn estimates(&self, placement: Placement, parallelism: usize) -> Option<(u64, u64)> {
        let parallel_ns = self.placement.estimate(placement)?;
        let projected_ns = match placement {
            Placement::Wide => Self::projected_serial(parallel_ns, parallelism),
            Placement::Local => self.local_serial_ns.get()?,
        };
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

    // The measured serial wall time while serial could still be preferred over `placement`'s pool:
    // both it and the serial cost projected from that pool fit the budget. Serial outside the
    // budget is never preferred, so it is no rival to the pools and must not pace their probes.
    fn serial_rival_ns(&self, placement: Placement, parallelism: usize) -> Option<u64> {
        let serial_ns = self.serial_ns.get()?;
        let (_, projected_ns) = self.estimates(placement, parallelism)?;
        (serial_ns < SERIAL_SAMPLE_BUDGET_NS && projected_ns < SERIAL_SAMPLE_BUDGET_NS)
            .then_some(serial_ns)
    }

    // Returns the path to run, serial or `placement`'s pool, and whether the caller should time it
    // and report the elapsed time to [`Policy::record_run_placed`]. The decision is made on that
    // pool's cadence.
    fn choose(&mut self, placement: Placement, parallelism: usize) -> (RunExecution, bool) {
        let serial_ns = self.serial_ns;
        let estimates = self.estimates(placement, parallelism);
        let cadence = &mut self.cadences[placement as usize];

        // Seed this pool's estimate with its first call. Until serial is measured, saturating the
        // pool's cadence keeps it due for an immediate boundary, so its next call offers the serial
        // seed as soon as the parallel estimate lands (when the projection allows). Once serial is
        // measured, the seed leaves the cadence fresh, since the boundary could only probe a path
        // that is already priced.
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

    // Records a serial run, or a parallel run on the shared pool.
    #[cfg(test)]
    fn record(&mut self, execution: RunExecution, elapsed: Duration) {
        match execution {
            RunExecution::Serial => self.serial_ns.record(nanos(elapsed)),
            RunExecution::Parallel => self.placement.record(Placement::Wide, nanos(elapsed)),
        }
    }

    // Records the wall time of a parallel run on `placement` and, for the local pool, the serial
    // cost it projects at the `parallelism` it planned with.
    fn record_parallel(&mut self, placement: Placement, parallelism: usize, elapsed: Duration) {
        self.placement.record(placement, nanos(elapsed));
        if placement == Placement::Local {
            self.local_serial_ns
                .record(Self::projected_serial(nanos(elapsed), parallelism));
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
///
/// Runs confined to one pool record into that pool's estimate without consulting the choice, so
/// either estimate may exist before the first consultation.
#[derive(Clone, Copy, Debug, Default)]
struct Choice {
    /// Timings on the shared pool.
    wide_ns: Estimate,
    /// Timings on the local pool.
    local_ns: Estimate,
    /// The schedule for probing the slower pool.
    cadence: Cadence<Placement>,
}

impl Choice {
    /// The faster pool once both are measured, and the shared pool until then or on a tie.
    const fn preferred(&self) -> Placement {
        match (self.wide_ns.get(), self.local_ns.get()) {
            (Some(wide_ns), Some(local_ns)) if local_ns < wide_ns => Placement::Local,
            _ => Placement::Wide,
        }
    }

    /// The estimate of `placement`'s pool, or `None` until that pool is measured.
    const fn estimate(&self, placement: Placement) -> Option<u64> {
        match placement {
            Placement::Wide => self.wide_ns.get(),
            Placement::Local => self.local_ns.get(),
        }
    }

    /// Returns the pool to use.
    ///
    /// A pool without an estimate is timed first, the shared pool before the local pool. After that
    /// the faster pool is preferred and the slower one is probed on the choice's own [`Cadence`].
    /// The probe interval grows with the slower pool's loss to the faster of the preferred pool and
    /// `rival_ns`. A caller that could still take a path outside the pools passes that path's
    /// measured wall time as `rival_ns`, and a caller with no such path or no measurement of it
    /// passes `None`.
    fn choose(&mut self, rival_ns: Option<u64>) -> Placement {
        let (Some(wide_ns), Some(local_ns)) = (self.wide_ns.get(), self.local_ns.get()) else {
            // Saturating the cadence keeps the choice due for a boundary while it seeds, so the
            // call after the seeds probes the loser.
            self.cadence.saturate();
            let placement = if self.wide_ns.get().is_none() {
                Placement::Wide
            } else {
                Placement::Local
            };
            return placement;
        };

        let (preferred, loser, winner_ns, loser_ns) = match self.preferred() {
            Placement::Local => (Placement::Local, Placement::Wide, local_ns, wide_ns),
            Placement::Wide => (Placement::Wide, Placement::Local, wide_ns, local_ns),
        };
        let winner_ns = rival_ns.map_or(winner_ns, |rival_ns| rival_ns.min(winner_ns));
        self.cadence
            .arbitrate(preferred, loser, winner_ns, loser_ns, true)
            .0
    }

    /// Folds `sample_ns`, in nanoseconds, into the estimate of `placement`.
    fn record(&mut self, placement: Placement, sample_ns: u64) {
        match placement {
            Placement::Wide => self.wide_ns.record(sample_ns),
            Placement::Local => self.local_ns.record(sample_ns),
        }
    }
}

/// A population of spawning callers with its own execution cadence. Every caller in one population
/// compares inline against the same hand-off overhead, so each probe lands on a caller that can act
/// on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Spawner {
    /// A worker of one of the strategy's pools. It keeps its job in that pool.
    Worker,
    /// A caller outside the pools without a local pool. It offloads to the shared pool.
    Shared,
    /// A caller outside the pools with a local pool. It offloads to the pool the placement prefers
    /// unless the placement seeds or probes the other.
    Either,
}

/// Timing state for one spawn [`Key`].
///
/// Since caller overlap cannot be observed, the policy prefers inline only when the job wall is no
/// greater than both the round-trip overhead EWMA of the pool it would offload to and
/// [`SPAWN_INLINE_BUDGET_NS`]. The overhead is everything an offloaded run costs around the job
/// itself (hand-off setup, queueing, worker wake, result send, task wake, and the observing poll),
/// so a caller that waits on the result inlines whenever that is measured cheaper.
///
/// A caller that polls late inflates its overhead samples with overlap slack. That biases the
/// decision toward inline, and the budget bounds what the bias can place on the calling task.
///
/// The job wall is tracked per execution path. The worker-measured wall carries the penalty of
/// migrating the job to another core, so the decision prefers the inline-measured wall once one
/// exists. While offload is preferred, its probe boundary runs inline whenever the live worker wall
/// fits the budget, so an entry seeded into offload can still observe the inline wall.
#[derive(Clone, Copy, Debug, Default)]
struct SpawnEntry {
    // The hand-off overhead on each pool, indexed by placement: the time from spawn entry to
    // observed result of an offloaded run, minus the job's own wall time. A caller compares inline
    // against the pool it would offload to, so a probe of the slower pool never moves the overhead
    // that a caller preferring the faster one compares against.
    overhead_ns: [Estimate; 2],
    // The job's own wall time on a pool worker.
    job_ns: Estimate,
    // The job's own wall time inline on the calling task.
    inline_ns: Estimate,
    // The round-trip overhead of jobs that workers keep in their own pools. Such a worker may run
    // the job itself while it waits, so its overhead is not a hand-off's.
    own_overhead_ns: Estimate,
    // The cadences on which each [`Spawner`] arbitrates inline against its hand-off overhead,
    // indexed by spawner. Only a caller with a local pool places its offloads, so the probes of
    // workers and of callers without one must not consume its offload slots.
    cadences: [Cadence<SpawnExecution>; 3],
    // Which pool a caller with a local pool offloads to. It is consulted only for such a caller's
    // offloaded job, and only those jobs train it. The pool changes the job's wall as well as the
    // overhead, so the choice compares whole round trips.
    placement: Choice,
}

impl SpawnEntry {
    // Decides, on `spawner`'s cadence, whether its call runs inline or offloaded and whether the
    // caller should time it. A worker compares inline against the overhead kept for workers, a
    // caller without a local pool against the shared pool's, and a caller with one against the
    // preferred pool's. `budget` caps the job wall eligible for inlining.
    fn choose(&mut self, spawner: Spawner, budget: u64) -> (SpawnExecution, bool) {
        let overhead_ns = match spawner {
            Spawner::Worker => self.own_overhead_ns,
            Spawner::Shared => self.overhead_ns[Placement::Wide as usize],
            Spawner::Either => self.overhead_ns[self.placement.preferred() as usize],
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

    /// The pools of a caller outside the strategy's pools with a two-worker local pool.
    const EITHER: Pools = Pools::Either(2);

    /// The pools of a caller confined to `placement`'s pool: the strategy's parallelism on the
    /// shared pool, and two workers on a local pool.
    const fn confined(placement: Placement) -> Pools {
        match placement {
            Placement::Wide => Pools::Fixed(Placement::Wide, PARALLELISM),
            Placement::Local => Pools::Fixed(Placement::Local, 2),
        }
    }

    /// The pool other than `placement`'s.
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
            measure,
        }
    }

    /// The placement a plan's pool stands for, as the wall-time closures of the spawn tests key on
    /// it: a worker's own pool has none, and the shared pool counts as the wide placement whether
    /// or not the caller chose it.
    const fn placement_of(pool: SpawnPool) -> Option<Placement> {
        match pool {
            SpawnPool::Own => None,
            SpawnPool::Shared => Some(Placement::Wide),
            SpawnPool::Placed(placement) => Some(placement),
        }
    }

    fn choose(entry: &mut RunEntry) -> (RunExecution, bool) {
        entry.choose(entry.placement.preferred(), PARALLELISM)
    }

    /// The path `entry` prefers between serial and its preferred pool, projecting serial from that
    /// pool at [`PARALLELISM`].
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
        // A probe's sample blends like any other, so one probe moves a stale estimate by a
        // fifth of the gap rather than trusting a single measurement outright.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(25));
        entry.record(RunExecution::Serial, Duration::from_millis(100));

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
    fn recovers_from_poisoned_estimate() {
        // Startup contention left parallel looking 2ms while serial measured 1ms, so serial
        // is preferred. The projection is still under budget (2ms x 4 = 8ms). The true
        // parallel cost is 0.5ms: probes blend the estimate down geometrically until the
        // preference flips.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_millis(2));
        entry.record(RunExecution::Serial, Duration::from_millis(1));
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
        // A serial estimate poisoned over the budget (e.g. one contended stall) must not
        // lock serial out forever: the probe gate reads the live projection, not the stale
        // estimate.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(500));
        entry.record(RunExecution::Serial, Duration::from_millis(15));
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
    fn poisoned_probe_cannot_flip_preference() {
        // A spuriously fast serial sample (e.g. from a contended probe) blends into the EWMA
        // and cannot flip the preference on its own.
        let mut entry = RunEntry::default();
        entry.record(RunExecution::Parallel, Duration::from_micros(800));
        entry.record(RunExecution::Serial, Duration::from_millis(3));
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
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        // A 2us job behind a 50us round-trip overhead.
        entry.job_ns.record(2_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000);

        // The seed leaves the entry due for an immediate boundary, which re-measures offload.
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000);

        // The job costs less than the overhead and fits the budget, so it runs inline.
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_keeps_offloading_a_job_bigger_than_the_overhead() {
        // A 50us job behind a 5us round-trip overhead: offloading is cheaper under any polling.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(50_000);
        entry.overhead_ns[Placement::Wide as usize].record(5_000);

        // The seed leaves the entry due for a boundary, which probes inline (the worker wall
        // fits the budget) to observe the inline wall.
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(50_000);

        // The inline wall confirms the job is bigger than the overhead, so offload holds until
        // the next (backed-off) boundary.
        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS) {
                (SpawnExecution::Offload, measure) => {
                    if measure {
                        entry.job_ns.record(50_000);
                        entry.overhead_ns[Placement::Wide as usize].record(5_000);
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
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(25_000);
        entry.overhead_ns[Placement::Wide as usize].record(10_000);

        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, true)
        );
        entry.inline_ns.record(8_000);

        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, false)
        );
    }

    #[test]
    fn spawn_budget_caps_inline_when_the_overhead_is_inflated() {
        // A contended pool measured the round-trip overhead at 50ms. The 2ms job is cheaper, but its
        // EWMA exceeds the inline budget, so it remains offloaded.
        let mut entry = SpawnEntry::default();
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
        entry.job_ns.record(2_000_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000_000);

        for _ in 0..(2 * RESAMPLE_INTERVAL) {
            match entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS) {
                (SpawnExecution::Offload, measure) => {
                    if measure {
                        entry.job_ns.record(2_000_000);
                        entry.overhead_ns[Placement::Wide as usize].record(50_000_000);
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
            policy.choose_spawn(location, 64, 1, false, || false),
            plan_of(SpawnExecution::Inline, SpawnPool::Shared, false)
        );
    }

    #[test]
    fn spawn_inline_ewma_crossing_the_overhead_revokes_inline() {
        // A converged-inline entry whose inline wall grows: the flip must come from the inline
        // EWMA while the worker wall stays low, pinning that the decision prefers the inline
        // wall once one exists.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000);
        entry.inline_ns.record(2_000);
        assert!(matches!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));

        // One grown sample blends the inline EWMA over the 50us overhead.
        entry.inline_ns.record(500_000);
        assert_eq!(entry.inline_ns.get(), Some(101_600));
        assert!(matches!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, _)
        ));
    }

    #[test]
    fn spawn_entries_bucket_by_len() {
        let policy = Policy::default();
        let location = Location::caller();

        let _ = policy.choose_spawn(location, 1, PARALLELISM, false, || false);
        let _ = policy.choose_spawn(location, 2, PARALLELISM, false, || false);
        let _ = policy.choose_spawn(location, 3, PARALLELISM, false, || false);

        assert_eq!(policy.spawn_len(), 2);
    }

    #[test]
    fn spawn_records_feed_choose() {
        // Policy-level wiring for the three spawn record paths: the worker and future samples
        // seed the entry, and the probe's inline sample drives the flip.
        let policy = Policy::default();
        let location = Location::caller();

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || false),
            plan_of(SpawnExecution::Offload, SpawnPool::Shared, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, Duration::from_micros(25));
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, SpawnPool::Shared, true),
            Duration::from_micros(10),
            Duration::ZERO,
        );

        // The boundary probes inline (the worker wall fits the budget).
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || false),
            plan_of(SpawnExecution::Inline, SpawnPool::Shared, true)
        );

        // The probe's inline wall beats the overhead, so the entry flips inline: recording it
        // anywhere but the inline estimate would leave the entry offloaded.
        policy.record_spawn_inline(location, 64, PARALLELISM, Duration::from_micros(8));
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || false),
            plan_of(SpawnExecution::Inline, SpawnPool::Shared, false)
        );
    }

    #[test]
    fn choice_seeds_both_pools_then_prefers_the_faster() {
        let mut choice = Choice::default();

        // Each pool is seeded once, in order, and the seeds leave the choice due for an
        // immediate boundary that probes the loser.
        assert_eq!(choice.choose(None), Placement::Wide);
        choice.record(Placement::Wide, 100_000);
        assert_eq!(choice.choose(None), Placement::Local);
        choice.record(Placement::Local, 50_000);
        assert_eq!(choice.choose(None), Placement::Wide);
        choice.record(Placement::Wide, 100_000);

        // The loser is twice as slow, so it is probed at double the base interval.
        let interval = RESAMPLE_INTERVAL << 1;
        for _ in 1..interval {
            assert_eq!(choice.choose(None), Placement::Local);
        }
        assert_eq!(choice.choose(None), Placement::Wide);
    }

    #[test]
    fn choice_ties_go_to_the_shared_pool() {
        let mut choice = Choice::default();

        // With equal estimates and the cadence between boundaries, the call uses the shared pool.
        choice.record(Placement::Wide, 50_000);
        choice.record(Placement::Local, 50_000);
        choice.cadence.since_probe = 1;

        assert_eq!(choice.choose(None), Placement::Wide);
    }

    #[test]
    fn spawn_placement_is_learned_only_with_a_local_pool() {
        // A call without a local pool records its round trip as the shared pool's hand-off, which
        // such callers compare inline against, and leaves the placement unmeasured. The job is far
        // bigger than the hand-off, so every caller offloads it.
        let policy = Policy::default();
        let location = Location::caller();
        let job = Duration::from_millis(2);
        let overhead = Duration::from_micros(10);

        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || false),
            plan_of(SpawnExecution::Offload, SpawnPool::Shared, true)
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(SpawnExecution::Offload, SpawnPool::Shared, true),
            job + overhead,
            job,
        );
        assert_eq!(
            policy.spawn_placement_estimates(location, 64, PARALLELISM),
            Some((None, None)),
            "a caller without a local pool must not train the placement"
        );

        // The first caller with a local pool finds the shared hand-off measured but the placement
        // not, so its offload seeds the shared pool for the placement, timed although its own
        // cadence is between samples.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Wide),
                true
            )
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Wide),
                true,
            ),
            job + overhead,
            job,
        );

        // The next offload seeds the local pool. The local job runs in half the time, and the
        // placement compares whole round trips, so the local pool wins.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Local),
                true
            )
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job / 2);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Local),
                true,
            ),
            job / 2 + overhead,
            job / 2,
        );

        // The local round trip was faster, so the seed boundary probes the shared pool once
        // and then the local pool is preferred between probes.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Wide),
                true
            )
        );
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Local),
                false
            )
        );

        // A caller without a local pool still uses the shared pool without consulting the
        // placement, on its own cadence. Its seed left that cadence due for a boundary. The job
        // exceeds the inline budget, so that boundary re-measures offload and leaves inline
        // unprobed.
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || false),
            plan_of(SpawnExecution::Offload, SpawnPool::Shared, true)
        );
    }

    /// Drives one call through the run policy and returns its execution path and pool. `pools`
    /// are the pools the caller may use. `wall` gives the time each path and pool takes, and
    /// the call records it only when its plan is measured.
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
        // Workers of the local pool seed that pool and then serial, which wins. A caller confined
        // to the shared pool then seeds it, twice as slow as serial. Serial is already priced, so
        // the seed leaves no boundary due: the caller runs serial from its next call on and probes
        // the shared pool once the interval its loss sets has passed.
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
        // preference untouched. Serial is probed on its own cadence and never becomes preferred.
        // It is within 2x of the local pool, and every probe confirms the local pool, so its
        // probes back off from the base interval.
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
            "the shared pool must keep being probed, probed {wide_probes} times"
        );
        assert!(
            serial_runs <= steady_probes(calls, 0),
            "serial must only ever be probed, ran {serial_runs}"
        );
        assert_eq!(parallel_local, calls - wide_probes - serial_runs);
    }

    #[test]
    fn run_serial_projection_uses_the_local_parallelism() {
        // A local sample is projected onto a serial run with the local pool's parallelism, so a
        // narrow local pool under a wide strategy still lets serial be sampled. A 200 us run on a
        // 2-worker local pool projects to 400 us and fits the budget, while the strategy's 64-way
        // parallelism would project 12.8 ms and never sample serial. This holds for a caller with a
        // choice and for a worker of the local pool alike.
        for pools in [EITHER, confined(Placement::Local)] {
            let policy = Policy::default();
            let location = Location::caller();
            let parallelism = 64;
            let mut serial_runs = 0;
            for _ in 0..(RESAMPLE_INTERVAL * 4) {
                let plan = policy.choose_run(location, 10, 10, parallelism, || pools);
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
                "{pools:?}: serial must be sampled once the local projection fits"
            );
        }
    }

    #[test]
    fn run_serial_projection_prices_each_local_run_at_its_own_parallelism() {
        // Workers of an 8-worker and a 2-worker domain pool share the local estimate. Every run
        // does 16 ms of work, 2 ms on the wider pool and 8 ms on the narrower, so serial projects
        // past the budget whichever pool ran last and must never run. The narrower pool runs every
        // third call, so its samples land at rotating points of the cadence.
        let policy = Policy::default();
        let location = Location::caller();
        let parallelism = 8;
        for call in 0..10 * RESAMPLE_INTERVAL {
            let width = if call % 3 == 0 { 2 } else { 8 };
            let plan = policy.choose_run(location, 10, 10, parallelism, || {
                Pools::Fixed(Placement::Local, width)
            });
            assert_eq!(
                plan.execution,
                RunExecution::Parallel,
                "call {call}: serial must never run"
            );
            if plan.measure {
                let wall = Duration::from_millis(16 / Widen::widen(plan.parallelism));
                policy.record_run_placed(location, 10, 10, parallelism, plan, wall);
            }
        }
    }

    #[test]
    fn run_serial_projection_follows_recent_local_runs() {
        // The local pool's first run plans with 64 workers and projects past the budget, and
        // every later run plans with two and projects well under it. The projection must follow
        // the recent runs back under the budget, so serial is still sampled.
        let policy = Policy::default();
        let location = Location::caller();
        let parallelism = 64;
        let mut serial_runs = 0;
        for call in 0..4 * RESAMPLE_INTERVAL {
            let width = if call == 0 { 64 } else { 2 };
            let plan = policy.choose_run(location, 10, 10, parallelism, || {
                Pools::Fixed(Placement::Local, width)
            });
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
            "serial must be sampled once narrow runs age out the wide one"
        );
    }

    /// Records one timed run per sample: its execution, the pool of a parallel run, and its wall
    /// time in microseconds. Local runs plan with two workers.
    fn record_samples(
        policy: &Policy,
        location: &'static Location<'static>,
        samples: &[(RunExecution, Placement, u64)],
    ) {
        for &(execution, placement, wall) in samples {
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
    }

    /// Seeds one run entry with serial between the two pools: `preferred` beats serial, and the
    /// other pool is nine times slower than serial.
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

    /// Wall times in microseconds of serial, of a parallel run on `pool`, and of one on the
    /// other pool.
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

    /// The most probes of a pool over `calls` calls when that pool is at least
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

    /// Calls within which probes rediscover a pool that is remembered as nine times slower than
    /// serial but has since become faster, and the cadence backs off to the cap again.
    ///
    /// Each probe closes a fifth of the gap, so the pool overtakes serial at the thirteenth probe
    /// when it runs at half of serial's wall and at the fourteenth at six tenths. A probe that
    /// brings the pool a whole multiple of serial's wall closer resets the confirmations, so the
    /// intervals follow the gap. Only probes that leave the gap's count unchanged back off.
    ///
    /// At six tenths the gap's count before each probe runs 5, 5, 4, 3, 3, 2, 1, 1, 1, and then 0
    /// five times, so the probes come 3,200, 3,200, 1,600, 800, 800, 400, 200, 200, 400, 100, 100,
    /// 200, 400, and 800 calls apart, 12,400 calls in all. At half of serial's wall the thirteen
    /// probes take 11,600 calls.
    ///
    /// The flip restarts the confirmations. The pool keeps gaining on serial afterwards, so the gap
    /// never shrinks while the count climbs back. With a gap of `g` doublings the intervals run
    /// `RESAMPLE_INTERVAL << g` twice and then double up to half the cap, so those below the cap
    /// sum to at most one capped interval. Five capped intervals cover the 15,600 calls this takes
    /// at six tenths.
    const DISCOVERY: u32 = 5 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT);

    /// Calls in which a cadence at the cap crosses exactly one boundary.
    const SETTLED: u32 = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;

    /// Drives a caller confined to `pool` through [`DISCOVERY`] calls, then returns how many of
    /// the next [`SETTLED`] run on that pool.
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
        // The entry prefers the other pool over serial, and the caller's pool is nine times slower
        // than serial. A confined caller must run serial except for its own cadence's probes of
        // that pool, and must leave both pool estimates intact so a caller with a choice uses the
        // preferred pool at once.
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
                        assert_eq!(placement, pool, "a confined caller must stay in its pool");
                        pool_runs += 1;
                    }
                }
            }
            assert!(
                pool_runs <= loser_probes(calls),
                "{pool:?}: the caller must use its pool only for probes, ran {pool_runs} there and \
                 {serial_runs} serial"
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
        // Callers with a choice and callers confined to the shared pool share the entry. Each
        // must get the decision that is right for it, with no relearning in between, each paying
        // only its own cadences' probes.
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

            // Only the caller with the pool advances the run cadence and the placement, so it
            // pays their probes of serial and of the shared pool over its own calls. Serial is
            // within 2x of the local pool and every probe confirms the local pool, so its probes
            // back off from the base interval. The shared pool loses by more than the capped
            // margin.
            assert!(
                with_pool_other <= steady_probes(calls / 2, 0) + loser_probes(calls / 2),
                "parity {parity}: the caller with the pool must leave it only for probes, ran \
                 {with_pool_local} local and {with_pool_other} elsewhere"
            );

            // The caller without it runs serial apart from its own cadence's probes.
            assert!(
                without_pool_wide <= loser_probes(calls / 2),
                "parity {parity}: the caller without the pool must run serial apart from its \
                 probes, ran {without_pool_serial} serial and {without_pool_wide} wide"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_rediscovers_it_once_faster() {
        // The entry prefers the other pool and remembers the caller's pool as nine times slower
        // than serial, but the caller's pool actually beats serial. A confined caller must find
        // that out through its own cadence's probes and then run on its pool.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, other(pool));
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 100, 50, 80));
            assert!(
                pool_runs >= SETTLED - 1,
                "{pool:?}: the caller must settle on the pool, ran {pool_runs} of {SETTLED} there"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_notices_serial_slowing_down() {
        // The entry prefers the other pool and serial beats the caller's pool as remembered, but
        // serial has slowed past that pool. A confined caller times its own serial runs, so it
        // finds that out and moves to its pool.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();
            seed_preferred(&policy, location, other(pool));
            let pool_runs =
                pool_runs_once_settled(&policy, location, pool, walls(pool, 200, 150, 80));
            assert!(
                pool_runs >= SETTLED - 1,
                "{pool:?}: the caller must settle on the pool, ran {pool_runs} of {SETTLED} there"
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_is_decided_on_its_own_cadence_while_serial_wins() {
        // As remembered, serial beats the other pool and the other pool beats the caller's pool, so
        // the run cadence prefers serial. A confined caller decides on its own cadence. Its probes
        // find that its pool has become faster than serial, and the caller moves to it.
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
                "{pool:?}: the caller must settle on the pool, ran {pool_runs} of {SETTLED} there"
            );
        }
    }

    #[test]
    fn run_with_a_choice_rediscovers_a_pool_while_serial_wins() {
        // Serial beats the preferred pool, so the run cadence keeps a caller with a choice on
        // serial. The other pool is remembered as nine times slower than serial but is actually the
        // fastest path. The placement probes that pool on its own interval over the caller's calls,
        // and twelve probes bring it past the preferred pool. One more probe on that pool's run
        // cadence then brings it past serial. Both stages fit within the `DISCOVERY` calls a
        // confined caller takes to rediscover its pool and back off again.
        //
        // Once there, it leaves the pool only for the run cadence's probes of serial and the
        // placement's probes of the pool it preferred before. Both cadences are back at the cap, so
        // over `SETTLED` calls the placement probes exactly once. The run cadence skips that call
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
                "{pool:?}: the caller must settle on the pool, ran {pool_runs} of {SETTLED} there"
            );
        }
    }

    #[test]
    fn run_with_a_choice_probes_pools_that_lose_to_serial_on_the_capped_interval() {
        // Serial is ten times faster than the preferred pool, and the other pool is only half
        // again slower than that. Both pools lose to serial by more than the capped margin, so a
        // caller with a choice probes each of them once per capped interval at most, however
        // close the pools are to each other.
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
                "{pool:?}: each pool must be probed at most once per capped interval, ran \
                 {parallel_runs} parallel"
            );
        }
    }

    #[test]
    fn run_with_a_choice_paces_pool_probes_without_serial_once_the_budget_gates_it() {
        // Serial is sixty times faster than either pool, but serial projected from the preferred
        // pool exceeds the budget, so serial never runs and the preferred pool is the only path
        // the other pool races. The pools are within a whole multiple of each other, so the other
        // pool's first probe comes after one plain resample interval and later ones back off only
        // with confirmations. Serial's wall time must not stretch that interval to the cap.
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
                "{pool:?}: the other pool's first probe must come after one resample interval"
            );
            assert!(
                other_runs.len() <= Widen::widen(steady_probes(calls, 0)),
                "{pool:?}: the other pool must back off only with confirmations, probed {} times",
                other_runs.len()
            );
        }
    }

    #[test]
    fn run_confined_to_one_pool_keeps_big_work_there() {
        // The entry prefers the other pool and serial beats the caller's pool, but serial
        // projected from that pool's estimate at that pool's parallelism exceeds the budget the
        // tuner arbitrates within. A confined caller therefore stays on its pool, where the
        // tuner leaves big work, and never samples serial.
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
        // A confined caller decides on its own cadence however the placement stands, and pays
        // exactly that cadence's probes. Its pool is remembered as nine times slower than serial
        // but is actually faster, so its probes find that out, and afterwards serial is probed on
        // that cadence alone.
        for pool in [Placement::Wide, Placement::Local] {
            let policy = Policy::default();
            let location = Location::caller();

            // The first call seeds the caller's pool, and the boundary it leaves due seeds serial.
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
        // A worker of a domain pool seeds and keeps using that pool, planning with its width,
        // although a caller with a choice would seed the shared pool first. Its samples land in
        // the local estimate alone, so the first caller with a choice still seeds the shared
        // pool.
        let policy = Policy::default();
        let location = Location::caller();
        let local = confined(Placement::Local);
        let plan = policy.choose_run(location, 10, 10, PARALLELISM, || local);
        assert_eq!(
            plan,
            RunPlan {
                execution: RunExecution::Parallel,
                placement: Placement::Local,
                parallelism: 2,
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
        // Callers with a choice and callers confined to the shared pool share one entry, and the
        // callers with a choice prefer the local pool. With steady wall times the estimates never
        // move, so each population must make the same decisions, probes and samples included, as
        // when it calls alone. A caller never advances the cadence of a pool it does not decide on.
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
        // Workers of a domain pool time their runs on their own cadence, into the local estimate
        // that a caller with a choice decides on. When the local pool slows past the shared one,
        // that caller moves to the shared pool on its next call without timing the local pool
        // itself.
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
        // A caller with the pool on an entry that prefers the shared pool decides on the run
        // cadence once per call, so over a settled window it pays that cadence's serial probes and
        // the placement's probes of the local pool, and no more.
        //
        // Each cadence starts fresh, and serial and the local pool both trail the shared pool
        // within 2x. Every probe confirms the shared pool, so each cadence probes 100, 200, 400,
        // and 800 calls into its own count. The run cadence skips the placement's four probes, so
        // its boundaries slip by at most four calls and both sets land within the window.
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
                run_with(&policy, location, EITHER, wall)
                    != (RunExecution::Parallel, Placement::Wide)
            })
            .count();
        let other = u32::try_from(other).unwrap();
        assert_eq!(
            other,
            2 * steady_probes(settled, 0),
            "the caller must leave the shared pool for exactly its probes, ran {other} of \
             {settled} elsewhere"
        );
    }

    #[test]
    fn run_interleaved_callers_keep_the_local_estimate_live() {
        // Serial projects over the budget, so it never runs, and every call is parallel and
        // advances a cadence. Only timed local runs refresh the local estimate. Whatever rhythm the
        // callers without the pool keep with the one that has it, the placement must keep timing
        // that caller's local runs, so the estimate follows the local pool when it slows down.
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

            // The caller with the pool runs on it apart from the placement's probes of the shared
            // pool. The shared pool is within 2x of the local one, and every probe confirms the
            // local pool, so those probes back off from the base interval over that caller's calls.
            let with_pool = calls / period;
            assert!(
                local_runs >= with_pool - steady_probes(with_pool, 0),
                "period {period} phase {phase}: the caller must keep the local pool, ran \
                 {local_runs} local"
            );
            let (_, parallel_ns) = policy.get_entry(location, 10, 10, PARALLELISM).unwrap();
            assert!(
                parallel_ns.unwrap() >= 7_900_000,
                "period {period} phase {phase}: the local estimate must follow the slower pool, \
                 {parallel_ns:?}"
            );
        }
    }

    #[test]
    fn run_interleaved_callers_rediscover_a_faster_local_pool() {
        // Serial and the local pool both speed up. Callers without the pool sample serial on every
        // tenth call of their cadence. When the caller with the pool makes one call in ten, serial
        // overtakes the local estimate before that caller has refreshed it, and the run cadence
        // prefers serial.
        //
        // That caller's probes of parallel must keep landing on it at whatever phase of the others'
        // calls it runs, so the local pool is timed again and preferred once more. In a strict
        // alternation both estimates refresh apace, and the caller with the pool must keep it.
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

            // By the settled half the run cadence prefers the local pool over serial, and the
            // placement prefers it over the shared pool by more than the capped margin. Both gaps
            // only grow as the local estimate falls, so neither count resets. After its first
            // boundary in the window, such a cadence has intervals no shorter than a fresh
            // cadence's from the second on. It therefore crosses at most one boundary more than a
            // fresh cadence over as many calls.
            assert!(
                local_runs
                    >= with_pool
                        - (steady_probes(with_pool, 0) + 1)
                        - (loser_probes(with_pool) + 1),
                "period {period} phase {phase}: the caller must keep the local pool, ran \
                 {local_runs} of {with_pool} local"
            );
        }
    }

    #[test]
    fn run_backs_off_a_stable_close_race_until_it_flips() {
        // Serial beats the shared pool by a sixth of the pool's wall. The race is within 2x, so the
        // gap alone would re-check it every `RESAMPLE_INTERVAL` calls. A caller confined to that
        // pool decides it on the pool's fresh cadence.
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

        // Serial then slows to twice the pool's wall. It stays preferred for ten calls, until its
        // next sample flips the preference to the pool. The confirmations were of serial, and the
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
        // Serial beats the shared pool by a sixth, and a steady race backs a caller confined to
        // that pool off to the cap. The last of its 6,400 calls is a boundary with five
        // confirmations.
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
        // preference to the pool. The pool's next sample, ten calls later, raises its estimate to
        // 146 us and flips it back. Both flips land before the base interval ends.
        assert!((0..10).all(|_| run(300, 120) == RunExecution::Serial));
        assert!((0..10).all(|_| run(300, 250) == RunExecution::Parallel));

        // The flips cleared the confirmations, so the pool is probed when the base interval ends.
        let probes: Vec<_> = (21..=RESAMPLE_INTERVAL)
            .filter(|_| run(140, 146) == RunExecution::Parallel)
            .collect();
        assert_eq!(probes, [RESAMPLE_INTERVAL]);
    }

    #[test]
    fn run_rediscovers_a_stale_pool_while_a_noisy_close_race_backs_off() {
        // A caller confined to the shared pool remembers it as nine times slower than serial, but
        // it actually takes half of serial's wall. Each probe closes a fifth of the gap, so the
        // pool overtakes serial at the thirteenth.
        //
        // While the pool trails by several multiples of serial's wall, most probes bring it a
        // multiple closer and reset the confirmations, so the intervals follow the gap. Inside the
        // last multiple the remaining probes confirm and back off from the base interval. The
        // caller settles on the pool the call after the thirteenth probe, 11,601 calls in, where
        // the gap alone would take 10,501.
        let pools = confined(Placement::Wide);
        let policy = Policy::default();
        let location = Location::caller();
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 900),
                (RunExecution::Serial, Placement::Wide, 100),
            ],
        );
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
            "the caller must rediscover the pool within {DISCOVERY} calls"
        );
        assert_eq!(
            pool_runs,
            [
                3_200, 6_400, 8_000, 8_800, 9_200, 9_600, 9_800, 10_000, 10_100, 10_200, 10_400,
                10_800, 11_600, 11_601
            ]
        );

        // A close race whose loser moves within one multiple still backs off. Serial wins in 100 us
        // and the pool's probes alternate between 110 and 190 us. Every probe moves the pool's
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
        local_pool: bool,
        job: impl Fn(Option<Placement>) -> Duration,
        overhead: impl Fn(Option<Placement>) -> Duration,
    ) -> SpawnPlan {
        let plan = policy.choose_spawn(location, 64, PARALLELISM, worker, || local_pool);
        if plan.measure {
            match plan.execution {
                SpawnExecution::Inline => {
                    policy.record_spawn_inline(location, 64, PARALLELISM, job(None));
                }
                SpawnExecution::Offload => {
                    let placement = placement_of(plan.pool);
                    let job = job(placement);
                    policy.record_spawn_job(location, 64, PARALLELISM, job);
                    policy.record_spawn_round_trip(
                        location,
                        64,
                        PARALLELISM,
                        plan,
                        job + overhead(placement),
                        job,
                    );
                }
            }
        }
        plan
    }

    #[test]
    fn spawn_workers_leave_outside_callers_their_probes() {
        // Outside callers and pool workers alternate at one site, in both phases. Inline wins
        // for both (a 40 us job against a 60 us hand-off), but the local pool would win for an
        // outside caller (5 us job, 5 us hand-off), so the outside callers must still sample it.
        let job = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 5 } else { 40 })
        };
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 5 } else { 60 })
        };
        for worker_first in [false, true] {
            let policy = Policy::default();
            let location = Location::caller();
            for i in 0..20_002 {
                let worker = (i % 2 == 0) == worker_first;
                spawn_call(&policy, location, worker, true, job, overhead);
            }
            let estimates = policy.spawn_placement_estimates(location, 64, PARALLELISM);
            assert!(
                estimates.unwrap().1.is_some(),
                "an outside caller must seed the local pool (worker first: {worker_first}): \
                 {estimates:?}"
            );
        }
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
            let job = |_: Option<Placement>| Duration::from_micros(15);
            let (mut calls, mut offloads) = (0, 0);
            for i in 0..30_000 {
                let worker = pattern[i % pattern.len()];
                let overhead =
                    move |_: Option<Placement>| Duration::from_micros(if worker { 1 } else { 30 });
                let plan = spawn_call(&policy, location, worker, false, job, overhead);
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
        let job = |_: Option<Placement>| Duration::from_micros(1);
        let overhead = |_: Option<Placement>| Duration::from_micros(3);
        let mut inline = 0;
        for _ in 0..1_000 {
            let plan = spawn_call(&policy, location, true, false, job, overhead);
            inline += usize::from(plan.execution == SpawnExecution::Inline);
        }
        assert!(
            inline > 900,
            "a worker-only site must settle inline: inlined {inline} of 1000"
        );
    }

    #[test]
    fn spawn_callers_without_a_local_pool_leave_callers_with_one_their_probes() {
        // Outside callers with and without a local pool alternate at one site, in both phases.
        // Inline wins against the shared pool (a 40 us job against a 60 us hand-off), but the
        // local pool wins against inline (a 5 us job behind a 5 us hand-off).
        let job = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 5 } else { 40 })
        };
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 5 } else { 60 })
        };
        let calls = 20_000;
        let per_caller = calls / 2;
        for with_pool_first in [true, false] {
            let policy = Policy::default();
            let location = Location::caller();

            // Two callers without a local pool seed the shared pool and re-measure it at the
            // boundary the seed leaves due.
            for _ in 0..2 {
                assert_eq!(
                    spawn_call(&policy, location, false, false, job, overhead),
                    plan_of(SpawnExecution::Offload, SpawnPool::Shared, true)
                );
            }

            // The callers then alternate.
            let (mut local_offloads, mut wide_offloads) = (0, 0);
            for call in 0..calls {
                let local_pool = (call % 2 == 0) == with_pool_first;
                let plan = spawn_call(&policy, location, false, local_pool, job, overhead);
                if local_pool {
                    local_offloads += u32::from(
                        plan.execution == SpawnExecution::Offload
                            && plan.pool == SpawnPool::Placed(Placement::Local),
                    );
                } else {
                    wide_offloads += u32::from(plan.execution == SpawnExecution::Offload);
                }
            }

            // The caller with the pool starts on a fresh cadence of its own and inlines, since
            // inline beats the shared pool's hand-off within 2x. Its first probe, a base interval
            // in, offloads and seeds the shared pool for the placement, which the callers without
            // a pool never train. Its second probe, another base interval in, seeds the local
            // pool, and that seed leaves the placement due to probe the shared pool on the next
            // offload.
            //
            // From then on the caller offloads to the local pool apart from its probes of inline
            // and of the shared pool. Inline is eight times slower than the local hand-off, and the
            // shared round trip is ten times the local one, so both lose by more than the capped
            // margin.
            assert!(
                local_offloads >= per_caller - 2 * RESAMPLE_INTERVAL - 2 * loser_probes(per_caller),
                "a caller with a local pool must seed it and offload there (with pool first: \
                 {with_pool_first}): {local_offloads} of {per_caller} calls"
            );

            // The caller without it inlines, apart from its own probes of the shared pool. Its
            // cadence starts the alternation at a boundary, and each probe confirms inline.
            assert!(
                wide_offloads <= steady_probes(per_caller, 0),
                "a caller without a local pool must keep inlining (with pool first: \
                 {with_pool_first}): offloaded {wide_offloads} of {per_caller} calls"
            );
        }
    }

    #[test]
    fn spawn_overhead_follows_the_preferred_pool() {
        // A caller with a local pool offloads there, since a 5 us job behind a 5 us hand-off
        // beats the 40 us inline wall, while the shared pool's hand-off takes 10 ms. A probe of
        // the shared pool must not raise the overhead that the caller compares inline against,
        // or the caller would inline until its next probe of offload, thousands of calls later.
        let policy = Policy::default();
        let location = Location::caller();
        let job = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 5 } else { 40 })
        };
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) {
                5
            } else {
                10_000
            })
        };
        let local_offload = |plan: SpawnPlan| {
            plan.execution == SpawnExecution::Offload
                && plan.pool == SpawnPool::Placed(Placement::Local)
        };

        // The site settles on the local pool, offloading there between samples.
        let settled = (0..RESAMPLE_INTERVAL).any(|_| {
            let plan = spawn_call(&policy, location, false, true, job, overhead);
            local_offload(plan) && !plan.measure
        });
        assert!(settled, "the faster local pool must become preferred");

        // The placement probes the slower shared pool within its capped interval.
        let probed = (0..RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT).any(|_| {
            let plan = spawn_call(&policy, location, false, true, job, overhead);
            plan.execution == SpawnExecution::Offload
                && plan.pool == SpawnPool::Placed(Placement::Wide)
        });
        assert!(probed, "the slower shared pool must be probed");

        // The calls after the probe keep offloading to the local pool, apart from at most one
        // probe of inline.
        let local_offloads = (0..RESAMPLE_INTERVAL)
            .filter(|_| local_offload(spawn_call(&policy, location, false, true, job, overhead)))
            .count();
        assert!(
            local_offloads >= Widen::widen(RESAMPLE_INTERVAL) - 1,
            "a shared-pool probe must leave the caller offloading to the local pool: \
             {local_offloads} of {RESAMPLE_INTERVAL} calls"
        );
    }

    #[test]
    fn spawn_with_a_local_pool_places_only_its_offloads() {
        // Inline beats both pools: a 1 us job against hand-offs of 50 us on the shared pool and
        // 400 us on the local pool.
        let policy = Policy::default();
        let location = Location::caller();
        let job = |_: Option<Placement>| Duration::from_micros(1);
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 400 } else { 50 })
        };
        let cap = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;

        // The first call seeds the shared pool. The boundary that seed leaves due probes offload,
        // and the placement spends that offload seeding the local pool.
        let seeds: Vec<_> = (0..2)
            .map(|_| spawn_call(&policy, location, false, true, job, overhead))
            .collect();
        assert_eq!(
            seeds,
            [
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Wide),
                    true
                ),
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Local),
                    true
                ),
            ]
        );

        // Inline wins by more than the capped margin, so the caller offloads only on its cadence's
        // probes, one per capped interval. Its inline jobs never consult the placement, so the
        // boundary the local seed left due waits for the first offload. That offload probes the
        // slower local pool. The offloads after it use the preferred shared pool until a capped
        // interval of offloads, not of calls, has passed.
        let offloads: Vec<_> = (1..=3 * cap)
            .filter_map(|call| {
                let plan = spawn_call(&policy, location, false, true, job, overhead);
                (plan.execution == SpawnExecution::Offload).then_some((call, plan))
            })
            .collect();
        let local = plan_of(
            SpawnExecution::Offload,
            SpawnPool::Placed(Placement::Local),
            true,
        );
        let wide = plan_of(
            SpawnExecution::Offload,
            SpawnPool::Placed(Placement::Wide),
            true,
        );
        assert_eq!(offloads, [(cap, local), (2 * cap, wide), (3 * cap, wide)]);
    }

    #[test]
    fn spawn_placement_times_its_seeds_and_probes_and_weighs_only_the_pools() {
        // Offload beats inline on either pool: a job that takes 30 us inline, and 100 us on a
        // worker after migrating, behind hand-offs of 20 us on the shared pool and 10 us on the
        // local pool. Offloads between samples are untimed, but one that the placement spends on
        // seeding or probing a pool must be timed so its round trip trains the placement.
        let policy = Policy::default();
        let location = Location::caller();
        let job = |p: Option<Placement>| Duration::from_micros(if p.is_none() { 30 } else { 100 });
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(if p == Some(Placement::Local) { 10 } else { 20 })
        };

        // The first call seeds the shared pool, and the boundary it leaves due probes inline. The
        // next offload is untimed for the caller's cadence, so only the placement's seed of the
        // local pool times it. That seed leaves the placement due for a boundary, so the offload
        // after it probes the slower shared pool and is timed too. Later offloads use the local
        // pool untimed until the next sample.
        let plans: Vec<_> = (0..400)
            .map(|_| spawn_call(&policy, location, false, true, job, overhead))
            .collect();
        assert_eq!(
            plans[..5],
            [
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Wide),
                    true
                ),
                plan_of(SpawnExecution::Inline, SpawnPool::Shared, true),
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Local),
                    true
                ),
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Wide),
                    true
                ),
                plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Local),
                    false
                ),
            ]
        );

        // The shared round trip is within 2x of the local one, so with the pools weighed against
        // each other alone the placement probes the shared pool again a base interval of offloads
        // later, and then backs off as each probe confirms the local pool. Inline is four times
        // faster than the shared round trip, so weighing the pools against it as well would push
        // the second probe out by three doublings. Every probe is timed.
        let wide_calls: Vec<_> = (1..)
            .zip(&plans)
            .filter(|(_, plan)| {
                plan.execution == SpawnExecution::Offload
                    && plan.pool == SpawnPool::Placed(Placement::Wide)
            })
            .map(|(call, plan)| {
                assert!(
                    plan.measure,
                    "call {call}: a shared-pool offload must be timed"
                );
                call
            })
            .collect();
        assert_eq!(wide_calls, [1, 4, 104, 304]);
    }

    #[test]
    fn spawn_populations_keep_independent_cadences() {
        // Workers, outside callers without a local pool, and outside callers with one share one
        // entry. Every job takes 20 us wherever it runs and each hand-off takes the same time on
        // every call, so the estimates never move. Each population must make the same decisions,
        // probes and samples included, as when it calls alone. No population advances another's
        // cadence.
        let job = |_: Option<Placement>| Duration::from_micros(20);
        let overhead = |p: Option<Placement>| {
            Duration::from_micros(match p {
                None => 15,
                Some(Placement::Wide) => 30,
                Some(Placement::Local) => 10,
            })
        };
        let location = Location::caller();
        let seeded = || {
            let policy = Policy::default();
            policy.record_spawn_inline(location, 64, PARALLELISM, job(None));
            policy.record_spawn_job(location, 64, PARALLELISM, job(None));
            for pool in [
                SpawnPool::Own,
                SpawnPool::Placed(Placement::Wide),
                SpawnPool::Placed(Placement::Local),
            ] {
                let plan = SpawnPlan {
                    pool,
                    ..plan_of(
                        SpawnExecution::Offload,
                        SpawnPool::Placed(Placement::Wide),
                        true,
                    )
                };
                let placement = placement_of(pool);
                let round_trip = job(placement) + overhead(placement);
                policy.record_spawn_round_trip(
                    location,
                    64,
                    PARALLELISM,
                    plan,
                    round_trip,
                    job(placement),
                );
            }
            policy
        };

        // Each population is a worker flag and a local-pool flag.
        let populations = [(true, false), (false, false), (false, true)];
        let calls = 10 * RESAMPLE_INTERVAL;
        let alone: Vec<Vec<SpawnPlan>> = populations
            .iter()
            .map(|&(worker, local_pool)| {
                let policy = seeded();
                (0..calls)
                    .map(|_| spawn_call(&policy, location, worker, local_pool, job, overhead))
                    .collect()
            })
            .collect();
        for (plans, population) in alone.iter().zip(&populations) {
            assert!(
                plans
                    .iter()
                    .any(|plan| plan.execution != plans[0].execution),
                "{population:?} must probe its losing path within {calls} calls"
            );
        }

        // The populations then call in turn on one entry.
        let policy = seeded();
        let mut together = vec![Vec::new(); populations.len()];
        for _ in 0..calls {
            for (plans, &(worker, local_pool)) in together.iter_mut().zip(&populations) {
                plans.push(spawn_call(
                    &policy, location, worker, local_pool, job, overhead,
                ));
            }
        }
        for ((together, alone), population) in together.iter().zip(&alone).zip(&populations) {
            let diverged = together
                .iter()
                .zip(alone)
                .position(|(call, own)| call != own);
            assert_eq!(
                diverged, None,
                "{population:?} must decide as it does alone"
            );
        }
    }

    #[test]
    fn spawn_recorded_observes_own_pool_round_trip_before_job_recording() {
        let policy = Policy::default();
        let location = Location::caller();
        let plan = policy.choose_spawn(location, 64, PARALLELISM, true, || {
            panic!("a worker must not look up a local pool")
        });
        assert_eq!(
            plan,
            SpawnPlan {
                execution: SpawnExecution::Offload,
                pool: SpawnPool::Own,
                measure: true,
            }
        );
        assert!(!policy.spawn_recorded(location, 64, PARALLELISM));

        // The awaiting future can record the round trip before the worker records its job.
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
            policy.spawn_placement_estimates(location, 64, PARALLELISM),
            Some((None, None))
        );
    }

    #[test]
    fn spawn_placement_forced_by_a_worker_is_not_learned() {
        // A job that ran in a worker's own pool must change neither pool's estimate. With the
        // shared pool measured, the local side stays unmeasured, and the next call with a local
        // pool still seeds it.
        let policy = Policy::default();
        let location = Location::caller();
        let job = Duration::from_millis(2);
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Wide),
                true
            )
        );
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        policy.record_spawn_round_trip(
            location,
            64,
            PARALLELISM,
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Wide),
                true,
            ),
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
                pool: SpawnPool::Own,
                ..plan_of(
                    SpawnExecution::Offload,
                    SpawnPool::Placed(Placement::Local),
                    true,
                )
            },
            job * 2,
            job,
        );
        assert_eq!(
            policy.spawn_placement_estimates(location, 64, PARALLELISM),
            estimates
        );
        assert_eq!(
            policy.choose_spawn(location, 64, PARALLELISM, false, || true),
            plan_of(
                SpawnExecution::Offload,
                SpawnPool::Placed(Placement::Local),
                true
            )
        );
    }

    #[test]
    fn pools_are_asked_for_every_run_and_every_job_from_outside_the_pools() {
        // Looking the local pool up may build it. A run asks for its pools on every call, and a
        // job from outside the strategy's pools asks for the local pool on every call, since
        // each decision depends on them. A worker keeps its job in its own pool and never asks.
        let policy = Policy::default();
        let location = Location::caller();

        // Serial beats both pools and the job beats both offload round trips by wide margins,
        // so both entries prefer the path that needs no pool.
        record_samples(
            &policy,
            location,
            &[
                (RunExecution::Parallel, Placement::Wide, 1_000),
                (RunExecution::Parallel, Placement::Local, 1_000),
                (RunExecution::Serial, Placement::Wide, 10),
            ],
        );
        let job = Duration::from_micros(1);
        policy.record_spawn_inline(location, 64, PARALLELISM, job);
        policy.record_spawn_job(location, 64, PARALLELISM, job);
        for placement in [Placement::Wide, Placement::Local] {
            policy.record_spawn_round_trip(
                location,
                64,
                PARALLELISM,
                plan_of(SpawnExecution::Offload, SpawnPool::Placed(placement), true),
                Duration::from_micros(50),
                job,
            );
        }

        let mut serial_runs = 0;
        let mut inline_jobs = 0;
        for _ in 0..1_000 {
            let mut looked_up = false;
            let plan = policy.choose_run(location, 10, 10, PARALLELISM, || {
                looked_up = true;
                EITHER
            });
            assert!(looked_up, "a run must ask for its pools");
            serial_runs += usize::from(plan.execution == RunExecution::Serial);

            let mut looked_up = false;
            let plan = policy.choose_spawn(location, 64, PARALLELISM, false, || {
                looked_up = true;
                true
            });
            assert!(
                looked_up,
                "a job from outside the pools must ask for the local pool"
            );
            inline_jobs += usize::from(plan.execution == SpawnExecution::Inline);

            let mut looked_up = false;
            policy.choose_spawn(location, 64, PARALLELISM, true, || {
                looked_up = true;
                true
            });
            assert!(!looked_up, "a worker's job must not ask for the local pool");
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
        entry.overhead_ns[Placement::Wide as usize].record(50_000);
        entry.inline_ns.record(2_000);

        // The latest inline sample exceeds the overhead, but the EWMA remains below it.
        entry.inline_ns.record(100_000);
        assert_eq!(entry.inline_ns.get(), Some(21_600));
        assert!(matches!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Inline, _)
        ));
    }

    #[test]
    fn spawn_recovers_after_a_transient_slow_run() {
        // A spike poisoned the inline estimate but left the worker wall intact. Boundary probes of
        // inline are gated on the live worker wall, so probe samples blend the inline estimate back
        // down and inline execution returns.
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
        entry.job_ns.record(2_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000);
        entry.inline_ns.record(15_000_000);

        let limit = 18 * (RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT) + 3_600;
        let mut calls: u32 = 0;
        loop {
            calls += 1;
            assert!(
                calls <= limit,
                "inline execution must recover within {limit} calls"
            );
            match entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS) {
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
                        entry.overhead_ns[Placement::Wide as usize].record(50_000);
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
        entry.overhead_ns[Placement::Wide as usize].record(50_000);

        for i in 1..RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        // The boundary hands one call back to the pool so the overhead estimate stays live.
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
    }

    #[test]
    fn spawn_probe_interval_is_capped() {
        // Inline wins by 25x, so the offload probe backs off to the capped interval while the
        // measure cadence continues, matching the serial-vs-parallel entries.
        let mut entry = SpawnEntry::default();
        entry.job_ns.record(2_000);
        entry.overhead_ns[Placement::Wide as usize].record(50_000);

        let interval = RESAMPLE_INTERVAL << MAX_RESAMPLE_SHIFT;
        for i in 1..interval {
            assert_eq!(
                entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
                (
                    SpawnExecution::Inline,
                    i.is_multiple_of(PREFERRED_SAMPLE_INTERVAL)
                ),
                "call {i}"
            );
        }
        assert_eq!(
            entry.choose(Spawner::Shared, SPAWN_INLINE_BUDGET_NS),
            (SpawnExecution::Offload, true)
        );
    }
}
