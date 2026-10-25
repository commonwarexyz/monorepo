//! Metric handles that an [`Index`](super::Index) updates as it changes.
//!
//! A full index counts on its registered metrics directly. The index inside a parallel
//! snapshot-build worker counts on [`Batched`] handles that publish to the full index's metrics in
//! batches. Both implement these traits, so one implementation of the index serves either.

use commonware_runtime::telemetry::metrics::{Batched, Counter, Gauge, GaugeValue, raw};

/// A gauge that an index raises and lowers as keys and values come and go.
pub trait GaugeHandle: Send + Sync {
    /// Increase the gauge by one.
    fn inc(&mut self);

    /// Decrease the gauge by one.
    fn dec(&mut self);

    /// Decrease the gauge by `value`.
    fn dec_by(&mut self, value: GaugeValue);

    /// The gauge's value as seen through this handle.
    fn get(&self) -> GaugeValue;
}

/// A counter that an index raises as it prunes values or spills partitions.
pub trait CounterHandle: Send + Sync {
    /// Increase the counter by one.
    fn inc(&mut self);

    /// Increase the counter by `value`.
    fn inc_by(&mut self, value: u64);

    /// The counter's value as seen through this handle.
    fn get(&self) -> u64;
}

impl GaugeHandle for Gauge {
    fn inc(&mut self) {
        self.metric().inc();
    }

    fn dec(&mut self) {
        self.metric().dec();
    }

    fn dec_by(&mut self, value: GaugeValue) {
        self.metric().dec_by(value);
    }

    fn get(&self) -> GaugeValue {
        self.metric().get()
    }
}

impl CounterHandle for Counter {
    fn inc(&mut self) {
        self.metric().inc();
    }

    fn inc_by(&mut self, value: u64) {
        self.metric().inc_by(value);
    }

    fn get(&self) -> u64 {
        self.metric().get()
    }
}

impl GaugeHandle for Batched<raw::Gauge> {
    fn inc(&mut self) {
        Self::inc(self);
    }

    fn dec(&mut self) {
        Self::dec(self);
    }

    fn dec_by(&mut self, value: GaugeValue) {
        Self::dec_by(self, value);
    }

    fn get(&self) -> GaugeValue {
        Self::get(self)
    }
}

impl CounterHandle for Batched<raw::Counter> {
    fn inc(&mut self) {
        Self::inc(self);
    }

    fn inc_by(&mut self, value: u64) {
        Self::inc_by(self, value);
    }

    fn get(&self) -> u64 {
        Self::get(self)
    }
}
