use prometheus_client::metrics::histogram::Histogram;
use std::time::Instant;

/// Trait providing convenience methods for `Histogram`.
pub trait HistogramExt {
    fn guard(&self) -> HistogramGuard<'_>;
}

impl HistogramExt for Histogram {
    fn guard(&self) -> HistogramGuard<'_> {
        HistogramGuard {
            histogram: self,
            start: Instant::now(),
            recorded: false,
        }
    }
}

/// Records the duration (in seconds) of a scope.
///
/// The duration is recorded when the guard is dropped, unless canceled or manually recorded.
pub struct HistogramGuard<'a> {
    start: Instant,
    histogram: &'a Histogram,
    recorded: bool,
}

impl HistogramGuard<'_> {
    /// Manually record and prevent automatic recording
    pub fn observe(&mut self) {
        self.record();
    }

    /// Cancel automatic recording
    pub fn cancel(&mut self) {
        self.recorded = true;
    }

    /// Records the duration
    fn record(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        self.histogram.observe(duration);
        self.recorded = true;
    }
}

impl Drop for HistogramGuard<'_> {
    fn drop(&mut self) {
        if !self.recorded {
            self.record();
        }
    }
}
