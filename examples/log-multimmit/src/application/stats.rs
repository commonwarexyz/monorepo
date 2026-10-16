//! Running totals of this producer's block latencies, shared with the progress reporter.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// One latency's sample count and summed milliseconds.
#[derive(Default)]
struct Totals {
    samples: AtomicU64,
    millis: AtomicU64,
}

impl Totals {
    fn record(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
    }

    fn mean(&self) -> Option<u64> {
        let samples = self.samples.load(Ordering::Relaxed);
        (samples > 0).then(|| self.millis.load(Ordering::Relaxed) / samples)
    }
}

/// Latencies of this node's own blocks since the process started: from the start of a block's
/// construction to its header signature, and to its delivery in the total order, and the views
/// a block carrying input waits from its signature to its first finality.
///
/// For blocks carrying input, it also keeps the time from header signature to first finality
/// and to ordered delivery, and how many became final within the finality goal captured at
/// signing.
///
/// The application records samples; the progress reporter reads the summaries. Clones share
/// totals.
#[derive(Clone, Default)]
pub struct ProductionStats(Arc<Shared>);

#[derive(Default)]
struct Shared {
    signed: Totals,
    ordered: Totals,
    /// Views waited, summed in place of milliseconds.
    waited: Totals,
    /// Blocks final in the view they were signed in.
    final_in_view: AtomicU64,
    signed_finalized: Totals,
    signed_ordered: Totals,
    /// Blocks final with a known goal, with those final within it summed in place of
    /// milliseconds.
    goal: Totals,
}

impl ProductionStats {
    /// Records a block signed `millis` after its construction started.
    pub fn signed(&self, millis: u64) {
        self.0.signed.record(millis);
    }

    /// Records a block ordered `millis` after its construction started.
    pub fn ordered(&self, millis: u64) {
        self.0.ordered.record(millis);
    }

    /// Records a block first final `views` views after the view its header was signed in.
    pub fn finalized(&self, views: u64) {
        self.0.waited.record(views);
        if views == 0 {
            self.0.final_in_view.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a block first final `millis` after its header signature, and whether that was
    /// within the finality goal, if known.
    pub fn signed_finalized(&self, millis: u64, within_goal: Option<bool>) {
        self.0.signed_finalized.record(millis);
        if let Some(met) = within_goal {
            self.0.goal.record(u64::from(met));
        }
    }

    /// Records a block ordered `millis` after its header signature.
    pub fn signed_ordered(&self, millis: u64) {
        self.0.signed_ordered.record(millis);
    }

    /// Returns the mean construction-to-signature latency in milliseconds, if any block was signed.
    pub fn mean_signed(&self) -> Option<u64> {
        self.0.signed.mean()
    }

    /// Returns the mean construction-to-ordering latency in milliseconds, if any block was ordered.
    pub fn mean_ordered(&self) -> Option<u64> {
        self.0.ordered.mean()
    }

    /// Returns the mean signature-to-finality latency in milliseconds, if any block was final.
    pub fn mean_signed_finalized(&self) -> Option<u64> {
        self.0.signed_finalized.mean()
    }

    /// Returns the mean signature-to-ordering latency in milliseconds, if any block was ordered.
    pub fn mean_signed_ordered(&self) -> Option<u64> {
        self.0.signed_ordered.mean()
    }

    /// Returns the percentage of blocks final within the goal, if any was final with a known goal.
    pub fn within_goal_pct(&self) -> Option<u64> {
        let goal = &self.0.goal;
        let samples = goal.samples.load(Ordering::Relaxed);
        (samples > 0).then(|| goal.millis.load(Ordering::Relaxed) * 100 / samples)
    }

    /// Returns how many of this node's blocks were signed.
    pub fn signed_blocks(&self) -> u64 {
        self.0.signed.samples.load(Ordering::Relaxed)
    }

    /// Returns the percentage of finalized blocks final in the view they were signed in, and the
    /// mean views they waited in hundredths of a view, if any was finalized.
    pub fn views_waited(&self) -> Option<(u64, u64)> {
        let waited = &self.0.waited;
        let samples = waited.samples.load(Ordering::Relaxed);
        (samples > 0).then(|| {
            (
                self.0.final_in_view.load(Ordering::Relaxed) * 100 / samples,
                waited.millis.load(Ordering::Relaxed) * 100 / samples,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn means_cover_every_sample_and_are_absent_before_one() {
        let stats = ProductionStats::default();
        assert_eq!(stats.mean_signed(), None);
        assert_eq!(stats.mean_ordered(), None);
        assert_eq!(stats.views_waited(), None);
        assert_eq!(stats.mean_signed_finalized(), None);
        assert_eq!(stats.mean_signed_ordered(), None);
        assert_eq!(stats.within_goal_pct(), None);
        let shared = stats.clone();
        shared.signed(10);
        shared.signed(30);
        shared.ordered(500);
        shared.finalized(0);
        shared.finalized(0);
        shared.finalized(0);
        shared.finalized(2);
        assert_eq!(stats.mean_signed(), Some(20));
        assert_eq!(stats.mean_ordered(), Some(500));
        assert_eq!(stats.signed_blocks(), 2);
        assert_eq!(stats.views_waited(), Some((75, 50)));
    }

    #[test]
    fn signed_latencies_and_goal_share_cover_their_samples() {
        let stats = ProductionStats::default();
        stats.signed_finalized(100, Some(true));
        stats.signed_finalized(300, Some(false));
        stats.signed_finalized(200, Some(true));
        stats.signed_finalized(400, Some(true));
        // Finality without a known goal counts toward the latency but not the goal share.
        stats.signed_finalized(500, None);
        stats.signed_ordered(700);
        assert_eq!(stats.mean_signed_finalized(), Some(300));
        assert_eq!(stats.mean_signed_ordered(), Some(700));
        assert_eq!(stats.within_goal_pct(), Some(75));
    }
}
