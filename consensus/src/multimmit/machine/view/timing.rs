//! View timing: the measured network delay and production interval, and the per-view timers
//! derived from them.
//!
//! No timer rests on a configured latency. Two quantities are measured at run time:
//!
//! - `delta_hat`, the one-way delay, from the round trips of this node's own blocks, each ending
//!   when the endorsing vote arrives at this node rather than when this node gets to read it
//!   ([`RoundTrip`]);
//! - `theta_hat`, the time a producer takes per block, from the intervals between consecutive
//!   accepted heights of every chain ([`Cadence`]).
//!
//! The vote interval `eta` is a configured send rate and the cap `N` a size in blocks. Producers
//! build at the configured production interval `theta`, which no timer reads: a chain's measured
//! interval `theta_hat` stands in for it. From them:
//!
//! | timer | value | role |
//! |---|---|---|
//! | `D_stop` | `2 delta_hat + theta_hat + eta` | a chain silent this long is declared final (rule (i)) |
//! | `t_late` | `theta_hat + delta_hat` | a chain neither capped nor declared this long after all but `f` chains are is declared final (rule (ii)) |
//! | `t_max` | `N theta_hat + 2 delta_hat + eta` | every chain not capped is declared final (rule (iii)) |
//! | `t_quiet` | `2 delta_hat + eta` | a leader silent this long at entry is skipped (optimisation (B)) |
//! | `t_grace` | adaptive in `[2.5 delta_hat, 2 t_max]` | the least wait for a leader block before a leaderless final vote |
//!
//! `t_quiet` exceeds `eta + delta`, the longest a correct leader that keeps voting stays unheard,
//! even where the delay is below the vote interval.
//!
//! Every value, the estimates included, is capped at the configured timer ceiling: a robustness
//! backstop that bounds how long manipulated measurements can make a node wait, not a latency
//! estimate. A view's timers are fixed when it is entered, so a view runs under one set of values.
//!
//! `t_grace` adapts to evidence about the leader's delay: a valid proposal for a view that arrives
//! after this node's leaderless final vote for it shows the grace was too short, and doubles it; a
//! vote for a leader block halves it. Liveness needs only `t_grace >= 2 delta` from some view on
//! after GST, which the doubling guarantees while the timer ceiling exceeds `2 delta`.

use crate::{
    multimmit::{config::Profile, machine::input::Now, types::ChainId},
    types::Height,
};
use commonware_cryptography::Digest;
use std::{collections::VecDeque, time::Duration};

/// Microseconds per millisecond. Production intervals are kept in microseconds, so heights
/// accepted within one millisecond share their interval without rounding it to zero.
const MICROS_PER_MILLI: u64 = 1_000;

/// Returns `duration` in whole milliseconds, saturating.
pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Appends `sample` to `samples`, dropping the oldest sample beyond `window`.
fn record(samples: &mut VecDeque<u64>, window: usize, sample: u64) {
    if samples.len() == window {
        samples.pop_front();
    }
    samples.push_back(sample);
}

/// Returns the upper median of `values`, reordering them, or `None` when there are none.
fn upper_median(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let middle = values.len() / 2;
    Some(*values.select_nth_unstable(middle).1)
}

/// Measures the one-way network delay the view timers derive from.
pub(crate) trait DeltaEstimator: Send {
    /// Records that this node produced its own block at `height` at `at`.
    fn produced(&mut self, height: Height, at: Now);

    /// Records that this node's own blocks at or below `height` have `n - f` distinct endorsers
    /// as of `at`, the arrival at this node of the vote that completed them.
    fn confirmed(&mut self, height: Height, at: Now);

    /// Returns the one-way delay estimate in milliseconds, or `None` before any measurement.
    fn estimate(&self) -> Option<u64>;
}

/// The percentile of round trips the default estimator reports.
const PERCENTILE: usize = 90;

/// The default [`DeltaEstimator`]: the round trip of this node's own blocks.
///
/// A sample is the time from producing a block to the arrival at this node of the network message
/// carrying the `n - f`-th distinct validator's vote endorsing it: the delay out to that
/// validator, up to one vote interval `eta` until its next vote update, and the delay back. Every
/// validator produces continuously, so samples arrive at a steady rate whoever leads. The estimate
/// is `(RTT - eta) / 2` for `RTT` the 90th percentile of the most recent samples (older samples
/// drop out of the window).
///
/// Ending a sample at arrival keeps out the time the vote then waits in this node's queues for
/// decoding, verification, and reading, which grows with this node's load rather than with the
/// network delay. A sample still includes the endorser's processing between receiving the block
/// and sending its vote, and this node's own delay between producing the block and sending it.
///
/// Faulty validators cannot shorten a sample below the round trip to the `n - 2f`-th fastest
/// correct validator; the caller clamps the estimate from below, so they cannot drive it to zero
/// either.
pub(crate) struct RoundTrip {
    /// Own blocks not yet confirmed, lowest height first, with their production times.
    pending: VecDeque<(Height, Now)>,
    /// The most recent round trips in milliseconds, oldest first.
    samples: VecDeque<u64>,
    /// The bound on `samples`.
    window: usize,
    /// The bound on `pending`; the oldest unconfirmed block is dropped beyond it.
    outstanding: usize,
    /// The vote interval `eta` in milliseconds.
    vote: u64,
}

impl RoundTrip {
    /// Creates an estimator keeping `window` samples, tracking at most `outstanding` unconfirmed
    /// blocks, and removing the vote interval `vote` (in milliseconds) from each round trip.
    pub(crate) fn new(window: usize, outstanding: usize, vote: u64) -> Self {
        let window = window.max(1);
        Self {
            pending: VecDeque::new(),
            samples: VecDeque::with_capacity(window),
            window,
            outstanding: outstanding.max(1),
            vote,
        }
    }
}

impl DeltaEstimator for RoundTrip {
    fn produced(&mut self, height: Height, at: Now) {
        if self.pending.len() == self.outstanding {
            self.pending.pop_front();
        }
        self.pending.push_back((height, at));
    }

    fn confirmed(&mut self, height: Height, at: Now) {
        while let Some(&(produced, since)) = self.pending.front() {
            if produced > height {
                break;
            }
            self.pending.pop_front();
            record(&mut self.samples, self.window, at.saturating_since(since));
        }
    }

    fn estimate(&self) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.iter().copied().collect::<Vec<_>>();
        sorted.sort_unstable();
        // Nearest rank: the smallest sample at or above the percentile.
        let rank = (sorted.len() * PERCENTILE).div_ceil(100).max(1);
        Some(sorted[rank - 1].saturating_sub(self.vote) / 2)
    }
}

/// One chain's production samples.
#[derive(Default)]
struct ChainCadence {
    /// The most recent per-height intervals in microseconds, oldest first.
    samples: VecDeque<u64>,
    /// When the acceptances before the latest ones were made.
    previous: Option<Now>,
    /// When the latest acceptances were made, and how many heights they accepted.
    latest: Option<(Now, u64)>,
}

impl ChainCadence {
    /// Returns the upper median of the samples in microseconds, reordering a copy in `scratch`.
    fn interval(&self, scratch: &mut Vec<u64>) -> Option<u64> {
        scratch.clear();
        scratch.extend(self.samples.iter().copied());
        upper_median(scratch)
    }
}

/// Measures the production interval `theta_hat` from the acceptances of every chain.
///
/// Per chain, a sample is the time between two consecutive acceptances, shared evenly among the
/// heights accepted together (an adoption or a catch-up accepts several at once). A chain's
/// interval is the median of its most recent samples, so a producer's occasional pause, waiting
/// for the next view to release more heights, does not count while it is rarer than its blocks.
///
/// `theta_hat` is the upper median of the chains' intervals, with a chain that has no sample yet
/// counting at the seed: while fewer than half of the chains have faulty or slow producers, it lies
/// within the range of the other chains' intervals and the seed.
pub(crate) struct Cadence {
    chains: Vec<ChainCadence>,
    /// The bound on each chain's samples.
    window: usize,
    /// The interval of a chain without samples, in microseconds.
    seed: u64,
}

impl Cadence {
    /// Creates an estimator over `chains` chains keeping `window` samples per chain, with
    /// `seed` the interval of a chain not yet sampled.
    pub(crate) fn new(chains: usize, window: usize, seed: Duration) -> Self {
        Self {
            chains: (0..chains).map(|_| ChainCadence::default()).collect(),
            window: window.max(1),
            seed: u64::try_from(seed.as_micros()).unwrap_or(u64::MAX),
        }
    }

    /// Records that this node accepted the next height of `chain` at `at`.
    pub(crate) fn accepted(&mut self, chain: ChainId, at: Now) {
        let window = self.window;
        let Some(cadence) = self.chains.get_mut(chain.index()) else {
            return;
        };
        let interval = |since: Now, heights: u64| {
            at.saturating_since(since).saturating_mul(MICROS_PER_MILLI) / heights
        };
        match &mut cadence.latest {
            Some((time, heights)) if *time == at => {
                *heights += 1;
                // The first height of this batch recorded its sample; the batch shares it.
                if let (Some(previous), Some(sample)) =
                    (cadence.previous, cadence.samples.back_mut())
                {
                    *sample = interval(previous, *heights);
                }
            }
            latest => {
                cadence.previous = latest.map(|(time, _)| time);
                *latest = Some((at, 1));
                if let Some(previous) = cadence.previous {
                    record(&mut cadence.samples, window, interval(previous, 1));
                }
            }
        }
    }

    /// Returns `theta_hat` in microseconds.
    pub(crate) fn estimate(&self) -> u64 {
        let mut scratch = Vec::with_capacity(self.window);
        let mut intervals = self
            .chains
            .iter()
            .map(|cadence| cadence.interval(&mut scratch).unwrap_or(self.seed))
            .collect::<Vec<_>>();
        upper_median(&mut intervals).unwrap_or(self.seed)
    }

    /// Returns `chain`'s interval in microseconds, or `None` before its first sample.
    #[cfg(test)]
    pub(crate) fn chain_interval(&self, chain: ChainId) -> Option<u64> {
        self.chains.get(chain.index())?.interval(&mut Vec::new())
    }
}

/// The timers of one view, in milliseconds, fixed when the view is entered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewTimers {
    /// The delay estimate `delta_hat`.
    pub(crate) delta: u64,
    /// The production interval estimate `theta_hat`, rounded up.
    pub(crate) production: u64,
    /// `D_stop`: the silence after which a chain is declared final.
    pub(crate) stop: u64,
    /// `t_late`: how long after `tquorum` a chain neither capped nor declared is declared final.
    pub(crate) late: u64,
    /// `t_max`: the time after entry from which every chain not capped is declared final.
    pub(crate) max: u64,
    /// `t_quiet`: the leader silence that skips the leader at entry.
    pub(crate) quiet: u64,
    /// `t_grace`: the least wait before a leaderless final vote.
    pub(crate) grace: u64,
}

/// The view layer's timing state: the delay and production estimators and the adaptive grace.
pub(crate) struct Timing {
    delay: Box<dyn DeltaEstimator>,
    production: Cadence,
    /// The vote interval `eta`.
    vote: u64,
    /// The cap `N`.
    cap: u64,
    /// The delay estimate before any sample.
    delta_seed: u64,
    /// The least delay estimate.
    delta_floor: u64,
    /// The ceiling on every timer and estimate.
    ceiling: u64,
    /// The current grace `t_grace`, before clamping to the next view's range.
    grace: u64,
    /// The grace's range `[2.5 delta_hat, 2 t_max]` under the latest timers.
    grace_floor: u64,
    grace_ceiling: u64,
}

impl Timing {
    /// Creates the timing of `profile` with the default estimators and the grace at its floor.
    pub(crate) fn new<D: Digest>(profile: &Profile<D>) -> Self {
        let tuning = profile.tuning();
        let codec = profile.codec();
        let samples = tuning.delta_samples.get();
        let vote = millis(tuning.vote_interval);
        let mut timing = Self {
            delay: Box::new(RoundTrip::new(
                samples,
                usize::try_from(codec.window().flow())
                    .unwrap_or(usize::MAX)
                    .saturating_mul(2),
                vote,
            )),
            production: Cadence::new(codec.chains(), samples, tuning.theta_initial),
            vote,
            cap: u64::from(codec.window().cap()),
            delta_seed: millis(tuning.delta_initial),
            delta_floor: millis(tuning.delta_min),
            ceiling: millis(tuning.timer_ceiling),
            grace: 0,
            grace_floor: 0,
            grace_ceiling: 0,
        };
        timing.grace = timing.timers().grace;
        timing
    }

    /// Returns the delay estimator, to feed it measurements.
    pub(crate) fn estimator(&mut self) -> &mut dyn DeltaEstimator {
        self.delay.as_mut()
    }

    /// Returns the production estimator, to feed it acceptances.
    pub(crate) const fn cadence(&mut self) -> &mut Cadence {
        &mut self.production
    }

    /// Returns the vote interval `eta` in milliseconds.
    pub(crate) const fn vote_interval(&self) -> u64 {
        self.vote
    }

    /// Returns the timers of a view entered now, from `delta_hat` (the seed before any sample,
    /// and at least the configured floor) and `theta_hat`, with the grace clamped to
    /// `[2.5 delta_hat, 2 t_max]` and every value capped at the timer ceiling.
    pub(crate) fn timers(&mut self) -> ViewTimers {
        let ceiling = self.ceiling;
        let delta = self
            .delay
            .estimate()
            .unwrap_or(self.delta_seed)
            .max(self.delta_floor)
            .min(ceiling);
        let production = self
            .production
            .estimate()
            .min(ceiling.saturating_mul(MICROS_PER_MILLI));
        // A round trip plus one vote interval: the longest a correct validator that keeps voting
        // stays unheard, and the tail every timer below waits for.
        let settle = delta.saturating_mul(2).saturating_add(self.vote);
        let bound = self
            .cap
            .saturating_mul(production)
            .div_ceil(MICROS_PER_MILLI)
            .saturating_add(settle)
            .min(ceiling);
        let production = production.div_ceil(MICROS_PER_MILLI);
        self.grace_floor = (delta.saturating_mul(5) / 2).min(ceiling);
        self.grace_ceiling = bound.saturating_mul(2).min(ceiling).max(self.grace_floor);
        self.grace = self.grace.clamp(self.grace_floor, self.grace_ceiling);
        ViewTimers {
            delta,
            production,
            stop: production.saturating_add(settle).min(ceiling),
            late: production.saturating_add(delta).min(ceiling),
            max: bound,
            quiet: settle.min(ceiling),
            grace: self.grace,
        }
    }

    /// Doubles the grace, up to `2 t_max`: a valid proposal arrived after this node's
    /// leaderless final vote for its view.
    pub(crate) fn widen(&mut self) {
        self.grace = self.grace.saturating_mul(2).min(self.grace_ceiling);
    }

    /// Halves the grace, down to its floor: this node voted for a leader block.
    pub(crate) fn narrow(&mut self) {
        self.grace = (self.grace / 2).max(self.grace_floor);
    }
}
