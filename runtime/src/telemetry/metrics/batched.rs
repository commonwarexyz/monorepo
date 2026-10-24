//! Metric handles that publish one writer's updates to a shared metric in batches.

use super::{GaugeValue, Registered, raw};

mod sealed {
    /// The operations a [`super::Batched`] handle needs from its metric.
    pub trait Sealed: Clone + Default {
        /// The metric's value type. It also represents the change between two values.
        type Value: Copy + PartialEq;

        /// The change from `from` to `to`, wrapping on overflow.
        fn change(from: Self::Value, to: Self::Value) -> Self::Value;

        /// The metric's current value.
        fn value(&self) -> Self::Value;

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

    fn value(&self) -> u64 {
        self.get()
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

    fn value(&self) -> GaugeValue {
        self.get()
    }

    fn apply(&self, change: GaugeValue) {
        self.inc_by(change);
    }
}

/// A metric handle that publishes one writer's updates to a shared metric in batches.
///
/// [`Self::new`] creates an unregistered metric for the writer to update through [`Self::local`].
/// Each [`Self::flush`] adds that metric's change since the previous flush to the shared metric.
/// Writers that update one shared metric directly contend on its cache line with every update.
/// Giving each writer its own handle limits that to one update of the shared metric per flush.
///
/// The shared metric includes each update made before the writer's latest flush exactly once, and
/// none made after it. The handle never flushes on its own, so dropping it discards the updates
/// made since its last flush.
pub struct Batched<M: Batchable> {
    /// The metric the writer updates. Its value is the writer's total.
    local: Registered<M>,

    /// A clone of the shared metric that shares its value but not its registration.
    shared: M,

    /// The value of `local` at creation or at the latest flush. `shared` already includes every
    /// update up to it.
    published: M::Value,
}

impl<M: Batchable> Batched<M> {
    /// Create a handle that publishes to `shared`'s metric. It does not hold `shared`'s
    /// registration, so the metric leaves the registry when the last [`Registered`] handle to it
    /// is dropped. Registering the same name again then creates a new metric that this handle does
    /// not publish to.
    pub fn new(shared: &Registered<M>) -> Self {
        let local = Registered::detached(M::default());
        let published = local.value();
        Self {
            local,
            shared: shared.metric().clone(),
            published,
        }
    }

    /// The metric the writer updates. Its value is the writer's total, including updates not yet
    /// flushed, and its clones share that value.
    pub const fn local(&self) -> &Registered<M> {
        &self.local
    }

    /// Add the local metric's change since the previous flush to the shared metric.
    pub fn flush(&mut self) {
        let value = self.local.value();
        if value != self.published {
            self.shared.apply(M::change(self.published, value));
            self.published = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Metrics as _, Runner as _, deterministic,
        telemetry::metrics::{MetricsExt as _, has_metric_value, metric_samples},
    };

    #[test]
    fn test_counter_publishes_each_update_once() {
        let shared = Registered::detached(raw::Counter::default());
        let mut batched = Batched::new(&shared);
        let local = batched.local().clone();

        // Updates reach the shared metric only when flushed.
        local.inc_by(3);
        assert_eq!(shared.get(), 0);
        batched.flush();
        assert_eq!(shared.get(), 3);

        // Each flush publishes only the updates since the previous one. The local metric keeps the
        // writer's total.
        batched.flush();
        assert_eq!(shared.get(), 3);
        local.inc();
        batched.flush();
        assert_eq!(shared.get(), 4);
        assert_eq!(local.get(), 4);
    }

    #[test]
    fn test_gauge_publishes_net_change() {
        let shared = Registered::detached(raw::Gauge::default());
        let mut batched = Batched::new(&shared);
        let local = batched.local().clone();

        // Updates that cancel out publish nothing.
        local.inc();
        local.dec();
        batched.flush();
        assert_eq!(shared.get(), 0);

        // A net decrease publishes a negative change. Setting the local metric publishes its change
        // since the previous flush.
        local.dec_by(2);
        batched.flush();
        assert_eq!(shared.get(), -2);
        local.set(5);
        batched.flush();
        assert_eq!(shared.get(), 5);
    }

    #[test]
    fn test_handles_publish_independently() {
        // The first handle publishes its updates.
        let shared = Registered::detached(raw::Gauge::default());
        let mut first = Batched::new(&shared);
        first.local().inc_by(3);
        first.flush();
        assert_eq!(shared.get(), 3);

        // A handle created after another writer has published adds only its own updates.
        let mut second = Batched::new(&shared);
        second.local().inc_by(4);
        second.flush();
        assert_eq!(shared.get(), 7);

        // Dropping a handle discards the updates made after its last flush.
        second.local().inc();
        drop(second);
        assert_eq!(shared.get(), 7);
    }

    #[test]
    fn test_registration_stays_with_owner() {
        deterministic::Runner::default().start(|context| async move {
            // Flushes reach the registered metric while its owner holds the registration.
            let shared = context.gauge("keys", "Number of keys");
            let mut batched = Batched::new(&shared);
            batched.local().inc_by(5);
            batched.flush();
            assert!(has_metric_value(&context.encode(), "keys", 5));

            // Dropping the owner's handle unregisters the metric even though the batched handle
            // still publishes to it. Registering the name again creates a new metric that later
            // flushes do not reach.
            drop(shared);
            assert!(metric_samples(&context.encode(), "keys").next().is_none());
            let fresh = context.gauge("keys", "Number of keys");
            batched.local().inc();
            batched.flush();
            assert_eq!(fresh.get(), 0);
        });
    }
}
