//! The pure expectations-aware checker, adapted from the zksync-os-server chaos
//! rig's watcher.
//!
//! The runner feeds the checker one synchronous observation at a time; the
//! checker carries state between observations and panics (with a stable
//! `chaos:` prefix and the offending observation embedded) on the first
//! finding. Cross-referencing the schedule's published [`Expectations`] is what
//! turns raw observations into verdicts: "the schedule took quorum away" is
//! always distinguishable from "the chain stalled and nobody knows why".
//!
//! Checks (cross-node agreement and every certificate-level invariant are NOT
//! here: the runner runs the `crate::invariants` suite at every step boundary,
//! and this checker covers only what that suite is structurally blind to):
//! - **Finalized digest stability**: an already-observed `(node, view)`
//!   finalization digest must never change. Journal replay and resolver
//!   backfill legitimately RE-report views (which is why no monotonicity is
//!   asserted anywhere here), but a re-report must carry the same payload;
//!   invariants extraction keeps one certificate per reporter and view, so a
//!   same-reporter overwrite is invisible to it.
//! - **Progress without quorum**: once the settle margin after losing the
//!   liveness expectation has passed, the finalization tip is frozen; any
//!   advance past the freeze baseline is a safety finding. The tip is GLOBAL
//!   (max over every node, dead or alive) so redistribution of pre-loss
//!   progress (backfill, replay, rejoin) can never exceed it, and the baseline
//!   additionally covers the highest view with any recorded vote or certificate
//!   activity, since votes stored before the loss can still legally assemble
//!   into certificates after it.
//! - **Liveness stall**: the committee was expected live for the whole window,
//!   yet the global tip never advanced. The finding names the laggards.

use super::schedule::Condition;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

/// What the schedule currently believes about the cluster: the checker's ground
/// truth for "is a stall a finding or self-inflicted".
#[derive(Debug, Clone)]
pub(crate) struct Expectations {
    pub(crate) conditions: Vec<Condition>,
    pub(crate) expect_liveness: bool,
    /// When `expect_liveness` last changed (deterministic runtime time).
    pub(crate) since: SystemTime,
}

/// One synchronous observation of the cluster, snapshotted from the
/// finalization clock and the mock reporters.
#[derive(Debug, Clone)]
pub(crate) struct Poll {
    /// Per-node max-folded finalization frontier (the clock's view).
    pub(crate) latest_views: Vec<u64>,
    /// Highest view with any recorded vote or certificate activity across all
    /// reporters.
    pub(crate) activity_frontier: u64,
    /// Per-node finalized `(view, payload digest)` pairs, sorted by view.
    pub(crate) finalized: Vec<Vec<(u64, Sha256Digest)>>,
}

impl Poll {
    /// The global finalization tip: the highest frontier over every node, dead
    /// or alive.
    fn global_tip(&self) -> u64 {
        self.latest_views.iter().copied().max().unwrap_or(0)
    }
}

/// The pure check engine: state carried between observations, no I/O.
pub(crate) struct Checker {
    /// Every finalized digest ever observed, per node and view.
    digests: Vec<HashMap<u64, Sha256Digest>>,
    /// Highest global tip ever observed, and when it last advanced.
    tip: u64,
    tip_advanced_at: SystemTime,
    /// The frozen baseline captured once the settle margin after losing the
    /// liveness expectation passed. `None` while liveness is expected.
    forbidden_baseline: Option<u64>,
    settle_margin: Duration,
    liveness_window: Duration,
}

impl Checker {
    /// One-line internal state summary for the decision log (diagnostics only).
    pub(crate) fn debug_state(&self) -> String {
        format!(
            "tip={} tip_advanced_at={:?} baseline={:?}",
            self.tip, self.tip_advanced_at, self.forbidden_baseline
        )
    }

    pub(crate) fn new(
        validators: usize,
        start: SystemTime,
        settle_margin: Duration,
        liveness_window: Duration,
    ) -> Self {
        Self {
            digests: vec![HashMap::new(); validators],
            tip: 0,
            tip_advanced_at: start,
            forbidden_baseline: None,
            settle_margin,
            liveness_window,
        }
    }

    pub(crate) fn observe(&mut self, now: SystemTime, expectations: &Expectations, poll: &Poll) {
        // Digest stability over the finalized maps.
        for (node, finalized) in poll.finalized.iter().enumerate() {
            for (view, digest) in finalized {
                if let Some(previous) = self.digests[node].get(view) {
                    assert!(
                        previous == digest,
                        "chaos: finalized digest changed at node {node} view {view}: {previous:?} -> {digest:?}; conditions={:?}",
                        expectations.conditions,
                    );
                } else {
                    self.digests[node].insert(*view, *digest);
                }
            }
        }

        // Fold the global tip before the quorum check so an advance past an
        // already-frozen baseline is caught in the same observation.
        let observed_tip = poll.global_tip();
        if observed_tip > self.tip {
            self.tip = observed_tip;
            self.tip_advanced_at = now;
        }

        // Progress without quorum: once the settle margin after losing the
        // liveness expectation has passed, the tip is frozen; any advance is a
        // safety finding.
        if expectations.expect_liveness {
            self.forbidden_baseline = None;
        } else if elapsed(now, expectations.since) >= self.settle_margin {
            match self.forbidden_baseline {
                None => {
                    self.forbidden_baseline = Some(self.tip.max(poll.activity_frontier));
                }
                Some(baseline) => {
                    assert!(
                        self.tip <= baseline,
                        "chaos: progress without quorum: tip advanced {baseline} -> {} while below quorum; latest_views={:?} conditions={:?}",
                        self.tip,
                        poll.latest_views,
                        expectations.conditions,
                    );
                }
            }
        }

        // Liveness stall: expected live for a whole window, yet the tip never
        // advanced within it.
        if expectations.expect_liveness
            && elapsed(now, expectations.since) >= self.liveness_window
            && elapsed(now, self.tip_advanced_at) >= self.liveness_window
        {
            let laggards: Vec<usize> = poll
                .latest_views
                .iter()
                .enumerate()
                .filter(|(_, view)| **view < self.tip)
                .map(|(index, _)| index)
                .collect();
            panic!(
                "chaos: liveness stall: no finalization past view {} for {:?} while the committee was expected live; laggards={laggards:?} latest_views={:?} conditions={:?}",
                self.tip, self.liveness_window, poll.latest_views, expectations.conditions,
            );
        }
    }
}

/// Elapsed deterministic time, saturating at zero (the runtime clock is
/// monotone; a same-instant comparison yields zero).
fn elapsed(now: SystemTime, since: SystemTime) -> Duration {
    now.duration_since(since).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: Duration = Duration::from_secs(10);
    const WINDOW: Duration = Duration::from_secs(60);

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn digest(tag: u8) -> Sha256Digest {
        Sha256Digest::from([tag; 32])
    }

    fn expectations(expect_liveness: bool, since: SystemTime) -> Expectations {
        Expectations {
            conditions: vec![Condition::Healthy; 4],
            expect_liveness,
            since,
        }
    }

    fn poll(latest_views: Vec<u64>, finalized: Vec<Vec<(u64, Sha256Digest)>>) -> Poll {
        Poll {
            latest_views,
            activity_frontier: 0,
            finalized,
        }
    }

    #[test]
    #[should_panic(expected = "chaos: finalized digest changed")]
    fn a_changed_digest_is_a_finding() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let expect = expectations(true, at(0));
        let first = poll(vec![5, 0, 0, 0], vec![vec![(5, digest(1))], vec![], vec![], vec![]]);
        checker.observe(at(1), &expect, &first);
        let second = poll(vec![5, 0, 0, 0], vec![vec![(5, digest(2))], vec![], vec![], vec![]]);
        checker.observe(at(2), &expect, &second);
    }

    #[test]
    fn re_reported_views_with_stable_digests_are_not_findings() {
        // Journal replay and backfill re-report old views; only a payload
        // change is a finding.
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let expect = expectations(true, at(0));
        let observed = poll(
            vec![5, 5, 0, 0],
            vec![vec![(5, digest(1))], vec![(5, digest(1))], vec![], vec![]],
        );
        checker.observe(at(1), &expect, &observed);
        checker.observe(at(2), &expect, &observed);
    }

    #[test]
    #[should_panic(expected = "chaos: progress without quorum")]
    fn tip_advance_after_the_settle_margin_is_a_finding() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        // Quorum lost at t=100; the baseline freezes once the margin passes.
        let below = expectations(false, at(100));
        checker.observe(at(100), &below, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
        checker.observe(at(111), &below, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
        checker.observe(at(112), &below, &poll(vec![12, 10, 10, 0], vec![vec![]; 4]));
    }

    #[test]
    fn in_flight_progress_within_the_settle_margin_is_tolerated() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let below = expectations(false, at(100));
        checker.observe(at(100), &below, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
        // Still inside the margin: certificates already in flight may land.
        checker.observe(at(105), &below, &poll(vec![12, 10, 10, 0], vec![vec![]; 4]));
        // Frozen at 12 from here; no further advance, no finding.
        checker.observe(at(111), &below, &poll(vec![12, 12, 12, 0], vec![vec![]; 4]));
        checker.observe(at(130), &below, &poll(vec![12, 12, 12, 0], vec![vec![]; 4]));
    }

    #[test]
    fn the_activity_frontier_excuses_certificates_assembled_from_stored_votes() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let below = expectations(false, at(100));
        let mut observed = poll(vec![10, 10, 10, 0], vec![vec![]; 4]);
        observed.activity_frontier = 15;
        checker.observe(at(111), &below, &observed);
        // Votes recorded before the loss may still complete certificates up to
        // the activity frontier.
        checker.observe(at(120), &below, &poll(vec![15, 10, 10, 0], vec![vec![]; 4]));
    }

    #[test]
    fn regained_quorum_disarms_the_freeze() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let below = expectations(false, at(100));
        checker.observe(at(111), &below, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
        let restored = expectations(true, at(112));
        checker.observe(at(120), &restored, &poll(vec![20, 20, 20, 0], vec![vec![]; 4]));
    }

    #[test]
    #[should_panic(expected = "chaos: liveness stall")]
    fn a_quiet_window_under_expected_liveness_is_a_finding() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let expect = expectations(true, at(0));
        checker.observe(at(1), &expect, &poll(vec![10, 10, 10, 8], vec![vec![]; 4]));
        checker.observe(at(62), &expect, &poll(vec![10, 10, 10, 8], vec![vec![]; 4]));
    }

    #[test]
    fn tip_advances_rearm_the_stall_window() {
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let expect = expectations(true, at(0));
        checker.observe(at(1), &expect, &poll(vec![10, 10, 10, 10], vec![vec![]; 4]));
        checker.observe(at(50), &expect, &poll(vec![11, 10, 10, 10], vec![vec![]; 4]));
        checker.observe(at(100), &expect, &poll(vec![12, 11, 11, 11], vec![vec![]; 4]));
        checker.observe(at(140), &expect, &poll(vec![12, 12, 12, 12], vec![vec![]; 4]));
    }

    #[test]
    fn a_fresh_liveness_expectation_gets_a_full_window() {
        // Quorum was just restored: the window counts from the flip, not from
        // the last pre-outage finalization.
        let mut checker = Checker::new(4, at(0), MARGIN, WINDOW);
        let below = expectations(false, at(0));
        checker.observe(at(30), &below, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
        let restored = expectations(true, at(90));
        checker.observe(at(120), &restored, &poll(vec![10, 10, 10, 0], vec![vec![]; 4]));
    }
}
