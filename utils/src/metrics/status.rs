//! Recording metrics with a status.

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter as DefaultCounter, family::Family},
};

/// Metric label that indicates status.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Label {
    /// The value of the label.
    status: Status,
}

/// Possible values for the status label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Status {
    /// Processed successfully.
    Success,
    /// Processing failed.
    Failure,
    /// Input was malformed or invalid in some way. Indicates a client error.
    Invalid,
    /// Input was valid, but intentionally not processed.
    /// For example due to a rate limit, being a duplicate, etc.
    Dropped,
}

/// A counter metric with a status label.
pub type Counter = Family<Label, DefaultCounter>;

/// Trait providing convenience methods for `Counter`.
pub trait CounterExt {
    fn guard(&self, status: Status) -> CounterGuard;
    fn inc(&self, status: Status);
    fn inc_with_bool(&self, ok: bool);
}

impl CounterExt for Counter {
    /// Create a new CounterGuard with a given status.
    fn guard(&self, status: Status) -> CounterGuard {
        CounterGuard {
            metric: self.clone(),
            status,
        }
    }

    /// Increment the metric with a given status.
    fn inc(&self, status: Status) {
        self.get_or_create(&Label { status }).inc();
    }

    /// Increment the metric as success if true, else as failure.
    fn inc_with_bool(&self, ok: bool) {
        self.inc(if ok { Status::Success } else { Status::Failure });
    }
}

/// Increments a `Counter` metric when dropped.
///
/// Can be used to ensure that counters are incremented regardless of the control flow. For example,
/// if a function returns early, the metric will still be incremented.
pub struct CounterGuard {
    /// The metric to increment.
    metric: Counter,

    /// The status at which the metric is set to be incremented.
    status: Status,
}

impl CounterGuard {
    /// Modify the status at which the metric will be incremented.
    pub fn set(&mut self, status: Status) {
        self.status = status;
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.metric.inc(self.status);
    }
}
