//! Metric handles that publish one writer's updates to a shared metric in batches.

use super::{GaugeValue, Registered, raw};
use std::num::NonZeroU32;

mod sealed {
    /// The operations a [`super::Batched`] handle needs from its metric.
    pub trait Sealed: Clone {
        /// The metric's value type. It also represents the change between two values.
        type Value: Copy + Default + PartialEq;

        /// The change from `from` to `to`, wrapping on overflow.
        fn change(from: Self::Value, to: Self::Value) -> Self::Value;

        /// Add `change` to the metric.
        fn apply(&self, change: Self::Value);
    }
}

/// A metric that a [`Batched`] handle can publish to. It is sealed and implemented for
/// [`raw::Counter`] and [`raw::Gauge`].
pub trait Batchable: sealed::Sealed {}

impl Batchable for raw::Counter {}

impl Batchable for raw::Gauge {}

impl sealed::Sealed for raw::Counter {
    type Value = u64;

    fn change(from: u64, to: u64) -> u64 {
        to.wrapping_sub(from)
    }

    fn apply(&self, change: u64) {
        self.inc_by(change);
    }
}

impl sealed::Sealed for raw::Gauge {
    type Value = GaugeValue;

    fn change(from: GaugeValue, to: GaugeValue) -> GaugeValue {
        to.wrapping_sub(from)
    }

    fn apply(&self, change: GaugeValue) {
        self.inc_by(change);
    }
}

/// A metric handle that publishes one writer's updates to a shared metric in batches.
///
/// The handle keeps the writer's total and adds the total's change since the previous publication
/// to the shared metric after every `size` updates and when the handle is dropped. The shared
/// metric includes each update made before the writer's latest publication exactly once, and none
/// made after it.
///
/// Writers that update one shared metric directly contend on its cache line with every update.
/// Giving each writer its own handle limits that to one update of the shared metric per batch.
pub struct Batched<M: Batchable> {
    /// A clone of the shared metric that shares its value but not its registration.
    shared: M,

    /// The writer's total.
    value: M::Value,

    /// The writer's total at creation or at the latest publication. `shared` already includes
    /// every update up to it.
    published: M::Value,

    /// Updates made since the latest publication.
    pending: u32,

    /// Updates per batch.
    size: NonZeroU32,
}

impl<M: Batchable> Batched<M> {
    /// Create a handle that publishes to `shared`'s metric after every `size` updates. The
    /// writer's total starts at zero, and every update counts toward a batch, including one that
    /// leaves the total unchanged.
    ///
    /// The handle does not hold `shared`'s registration, so the metric leaves the registry when
    /// the last [`Registered`] handle to it is dropped. This handle does not publish to a fresh
    /// metric registered under the same name afterwards.
    pub fn new(shared: &Registered<M>, size: NonZeroU32) -> Self {
        Self {
            shared: shared.metric().clone(),
            value: M::Value::default(),
            published: M::Value::default(),
            pending: 0,
            size,
        }
    }

    /// The writer's total, including updates not yet published.
    pub const fn get(&self) -> M::Value {
        self.value
    }

    /// Add the writer's change since the previous publication to the shared metric, and start a
    /// new batch.
    fn publish(&mut self) {
        if self.value != self.published {
            self.shared.apply(M::change(self.published, self.value));
            self.published = self.value;
        }
        self.pending = 0;
    }

    /// Record the writer's new total and publish once this update completes a batch.
    fn update(&mut self, value: M::Value) {
        self.value = value;
        self.pending += 1;
        if self.pending == self.size.get() {
            self.publish();
        }
    }
}

impl<M: Batchable> Drop for Batched<M> {
    fn drop(&mut self) {
        self.publish();
    }
}

impl Batched<raw::Counter> {
    /// Increase the writer's total by one.
    pub fn inc(&mut self) {
        self.update(self.value.wrapping_add(1));
    }

    /// Increase the writer's total by `value`.
    pub fn inc_by(&mut self, value: u64) {
        self.update(self.value.wrapping_add(value));
    }
}

impl Batched<raw::Gauge> {
    /// Increase the writer's total by one.
    pub fn inc(&mut self) {
        self.update(self.value.wrapping_add(1));
    }

    /// Decrease the writer's total by one.
    pub fn dec(&mut self) {
        self.update(self.value.wrapping_sub(1));
    }

    /// Increase the writer's total by `value`.
    pub fn inc_by(&mut self, value: GaugeValue) {
        self.update(self.value.wrapping_add(value));
    }

    /// Decrease the writer's total by `value`.
    pub fn dec_by(&mut self, value: GaugeValue) {
        self.update(self.value.wrapping_sub(value));
    }

    /// Set the writer's total to `value`.
    pub fn set(&mut self, value: GaugeValue) {
        self.update(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Metrics as _, Runner as _, deterministic,
        telemetry::metrics::{MetricsExt as _, has_metric_value, metric_samples},
    };
    use commonware_utils::NZU32;

    #[test]
    fn test_counter_publishes_full_batches() {
        // Updates reach the shared metric only as each batch of three fills.
        let shared = Registered::detached(raw::Counter::default());
        let mut batched = Batched::new(&shared, NZU32!(3));
        batched.inc();
        batched.inc();
        assert_eq!(shared.get(), 0);
        assert_eq!(batched.get(), 2);
        batched.inc();
        assert_eq!(shared.get(), 3);
        batched.inc();
        batched.inc();
        assert_eq!(shared.get(), 3);
        batched.inc();
        assert_eq!(shared.get(), 6);

        // Dropping the handle publishes a partial batch.
        batched.inc_by(5);
        assert_eq!(shared.get(), 6);
        assert_eq!(batched.get(), 11);
        drop(batched);
        assert_eq!(shared.get(), 11);
    }

    #[test]
    fn test_gauge_publishes_net_change() {
        // Updates that cancel out publish nothing when their batch fills.
        let shared = Registered::detached(raw::Gauge::default());
        let mut batched = Batched::new(&shared, NZU32!(2));
        batched.inc();
        batched.dec();
        assert_eq!(shared.get(), 0);

        // A net decrease publishes a negative change.
        batched.dec_by(3);
        batched.inc();
        assert_eq!(shared.get(), -2);

        // The second `set(5)` leaves the total unchanged but still completes the batch, so the
        // change since the previous publication reaches the shared metric.
        batched.set(5);
        batched.set(5);
        assert_eq!(shared.get(), 5);
    }

    #[test]
    fn test_handles_publish_independently() {
        // The first handle publishes its updates.
        let shared = Registered::detached(raw::Gauge::default());
        let mut first = Batched::new(&shared, NZU32!(1));
        first.inc_by(3);
        assert_eq!(shared.get(), 3);

        // A handle created after another writer has published adds only its own updates.
        let mut second = Batched::new(&shared, NZU32!(1));
        second.inc_by(4);
        assert_eq!(second.get(), 4);
        assert_eq!(shared.get(), 7);

        // Dropping a handle publishes the updates it has not yet published.
        let mut third = Batched::new(&shared, NZU32!(2));
        third.inc();
        assert_eq!(shared.get(), 7);
        drop(third);
        assert_eq!(shared.get(), 8);
    }

    #[test]
    fn test_registration_stays_with_owner() {
        deterministic::Runner::default().start(|context| async move {
            // Publications reach the registered metric while its owner holds the registration.
            let shared = context.gauge("keys", "Number of keys");
            let mut batched = Batched::new(&shared, NZU32!(1));
            batched.inc_by(5);
            assert!(has_metric_value(&context.encode(), "keys", 5));

            // Dropping the owner's handle unregisters the metric even though the batched handle
            // still publishes to it. Registering the name again creates a new metric that later
            // publications do not reach.
            drop(shared);
            assert!(metric_samples(&context.encode(), "keys").next().is_none());
            let fresh = context.gauge("keys", "Number of keys");
            batched.inc();
            assert_eq!(fresh.get(), 0);
        });
    }
}
