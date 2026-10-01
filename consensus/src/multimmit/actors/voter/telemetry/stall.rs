//! Detection of a local producer stuck at its DA pipeline limit.

use crate::multimmit::machine::ProducerProgress;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// When the local producer became blocked, and whether that stall was reported.
#[derive(Clone, Copy)]
struct Blocked {
    since: SystemTime,
    reported: bool,
}

/// Tracks the local producer's DA pipeline state and warns once per sustained stall.
#[derive(Default)]
pub(crate) struct ProducerStallMonitor {
    last: Option<ProducerProgress>,
    blocked: Option<Blocked>,
}

impl ProducerStallMonitor {
    /// Records the producer's latest progress, starting or ending a stall on a state change.
    pub(crate) fn observe(&mut self, progress: ProducerProgress, now: SystemTime) {
        if self.last == Some(progress) {
            return;
        }
        let blocked = progress.pipeline_blocked();
        match (self.blocked, blocked) {
            (None, true) => {
                self.blocked = Some(Blocked {
                    since: now,
                    reported: false,
                });
            }
            (Some(stall), false) => {
                if stall.reported {
                    info!(
                        chain = progress.chain().get(),
                        produced = progress.produced().get(),
                        certified = progress.certified().get(),
                        "local producer resumed after DA pipeline stall"
                    );
                }
                self.blocked = None;
            }
            (None, false) | (Some(_), true) => {}
        }
        debug!(
            chain = progress.chain().get(),
            produced = progress.produced().get(),
            certified = progress.certified().get(),
            da_quorum = progress.da_quorum(),
            wake = progress.wake(),
            timer_armed = progress.timer_armed(),
            build_pending = progress.build_pending(),
            production_credit = progress.production_credit(),
            pipeline_blocked = blocked,
            "local producer DA state changed"
        );
        self.last = Some(progress);
    }

    /// Warns once when the producer has been blocked for at least `threshold`.
    ///
    /// Returns whether this call reported the stall.
    pub(crate) fn report(&mut self, now: SystemTime, threshold: Duration) -> bool {
        let (Some(progress), Some(stall)) = (self.last, self.blocked.as_mut()) else {
            return false;
        };
        if stall.reported {
            return false;
        }
        let blocked_for = now.duration_since(stall.since).unwrap_or_default();
        if blocked_for < threshold {
            return false;
        }
        warn!(
            chain = progress.chain().get(),
            produced = progress.produced().get(),
            certified = progress.certified().get(),
            da_quorum = progress.da_quorum(),
            production_credit = progress.production_credit(),
            blocked_for_ms = blocked_for.as_millis(),
            "local producer stalled at DA pipeline limit"
        );
        stall.reported = true;
        true
    }
}
