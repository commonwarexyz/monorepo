//! Scheduling-gap accounting for the expiry-storm peer.

use std::{
    io,
    time::{Duration, Instant},
};

/// Tracks time between runs of the always-runnable fairness peer.
pub(crate) struct PeerGap {
    /// Most recent time the peer observed scheduling progress.
    previous_run: Instant,
    /// Largest interval observed after timer callbacks began.
    maximum: Duration,
}

impl PeerGap {
    /// Starts tracking from the peer's initialized and acknowledged state.
    pub(crate) const fn new(previous_run: Instant) -> Self {
        Self {
            previous_run,
            maximum: Duration::ZERO,
        }
    }

    /// Records one run and returns whether every callback has completed.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        callbacks_started: bool,
        callbacks_completed: bool,
    ) -> bool {
        if callbacks_started {
            self.maximum = self
                .maximum
                .max(now.saturating_duration_since(self.previous_run));
        }
        self.previous_run = now;
        callbacks_completed
    }

    /// Returns the largest scheduling gap observed after callbacks began.
    pub(crate) const fn maximum(&self) -> Duration {
        self.maximum
    }
}

/// Returns dispatch lateness while rejecting an early timer callback.
pub(crate) fn dispatch_lateness(observed: Duration, target: Duration) -> io::Result<Duration> {
    observed.checked_sub(target).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "storm timer fired before its requested deadline",
        )
    })
}

#[cfg(test)]
#[path = "peer_gap_tests.rs"]
mod tests;
