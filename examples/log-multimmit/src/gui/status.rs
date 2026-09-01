//! Engine health derived from periodic inspections.

use crate::progress::Summary;
use std::time::{Duration, Instant};

/// Age after which the last inspection marks the engine unresponsive.
pub(super) const STATUS_STALE_AFTER: Duration = Duration::from_secs(2);

/// Whether the engine answers inspections.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum EngineHealth {
    /// No inspection has completed yet.
    Starting,
    /// The last inspection is recent.
    Responsive,
    /// The last inspection is older than [`STATUS_STALE_AFTER`].
    Unresponsive,
    /// The engine stopped.
    Stopped,
}

/// Engine status at one instant, for rendering.
#[derive(Clone)]
pub(super) struct EngineSnapshot {
    pub(super) health: EngineHealth,
    /// Time since the last completed inspection.
    pub(super) age: Option<Duration>,
    /// The last completed inspection.
    pub(super) summary: Option<Summary>,
}

/// The engine's inspection history, owned by the UI loop.
#[derive(Default)]
pub(super) struct EngineStatus {
    stopped: bool,
    last_response: Option<Instant>,
    summary: Option<Summary>,
}

impl EngineStatus {
    /// Records one completed inspection.
    pub(super) fn observed(&mut self, summary: Summary, now: Instant) {
        self.stopped = false;
        self.last_response = Some(now);
        self.summary = Some(summary);
    }

    /// Marks the engine stopped while retaining its last inspection.
    pub(super) const fn stopped(&mut self) {
        self.stopped = true;
    }

    pub(super) fn health(&self, now: Instant) -> EngineHealth {
        if self.stopped {
            return EngineHealth::Stopped;
        }
        let Some(last_response) = self.last_response else {
            return EngineHealth::Starting;
        };
        if now.saturating_duration_since(last_response) >= STATUS_STALE_AFTER {
            return EngineHealth::Unresponsive;
        }
        EngineHealth::Responsive
    }

    pub(super) fn snapshot(&self, now: Instant) -> EngineSnapshot {
        EngineSnapshot {
            health: self.health(now),
            age: self
                .last_response
                .map(|last_response| now.saturating_duration_since(last_response)),
            summary: self.summary.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::Chain;

    fn summary() -> Summary {
        Summary {
            view: 11,
            finality_floor: 7,
            retired: 5,
            live: true,
            cached_artifacts: 8,
            outbox_effects: 7,
            verification_jobs: 5,
            resolution_jobs: 3,
            producer: None,
            chains: vec![Chain {
                chain: 0,
                finalized: 22,
                certified: 33,
                known: 34,
            }],
        }
    }

    #[test]
    fn engine_health_distinguishes_stalls_from_stops() {
        let mut status = EngineStatus::default();
        let now = Instant::now();
        assert_eq!(status.health(now), EngineHealth::Starting);
        status.observed(summary(), now);
        assert_eq!(status.health(now), EngineHealth::Responsive);
        assert_eq!(
            status.health(now + STATUS_STALE_AFTER),
            EngineHealth::Unresponsive
        );
        status.stopped();
        assert_eq!(
            status.health(now + STATUS_STALE_AFTER),
            EngineHealth::Stopped
        );
        let snapshot = status.snapshot(now + STATUS_STALE_AFTER);
        assert_eq!(snapshot.age, Some(STATUS_STALE_AFTER));
        assert_eq!(snapshot.summary.unwrap().view, 11);
    }
}
