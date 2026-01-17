//! Utilities for collecting and reporting telemetry data.

use std::{
    any::{Any, TypeId},
    borrow::Cow,
    collections::HashMap,
};

use prometheus_client::registry::{Metric, Registry};

pub mod metrics;
pub mod traces;

/// They key to cache a metric in the registry.
///
/// Inludes the [`TypeId`] of the metric to be able to register metrics of
/// different type but under the same name.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Key<'a> {
    name: Cow<'a, str>,
    type_id: TypeId,
}

#[derive(Debug, Default)]
pub(crate) struct MetricsRegistry {
    registered: HashMap<Key<'static>, Box<dyn Any + Send + Sync>>,
    inner: Registry,
}

impl MetricsRegistry {
    /// Returns a metric of type `M` if it was previously registered under `name.`
    ///
    /// If it does not already exist, registers `metric` under `name` with `help`
    /// message and returns a clone of it.
    pub(crate) fn get_or_register<M: Clone + Metric>(
        &mut self,
        name: &str,
        help: &str,
        metric: M,
    ) -> M {
        if let Some(metric) = self.get::<M>(name) {
            return metric;
        }
        self.register(name.to_string(), help.to_string(), metric.clone());
        metric
    }

    /// Returns a metric of type `M` if it was previously registered under `name.`
    ///
    /// If it does not already exist, calls `metric` to construct the metric prior
    /// to registering it under `name` with a `help` message and returns a clone of it.
    pub(crate) fn get_or_register_with<M: Clone + Metric>(
        &mut self,
        name: &str,
        help: &str,
        metric: impl FnOnce() -> M,
    ) -> M {
        if let Some(metric) = self.get::<M>(name) {
            return metric;
        }
        let metric = metric();
        self.register(name.to_string(), help.to_string(), metric.clone());
        metric
    }

    /// Returns a reference to the inner prometheus registry.
    ///
    /// This bypasses the layer in front of the prometheus registry and allows
    /// writing to it directly.
    pub(crate) fn write_through(&mut self) -> &mut Registry {
        &mut self.inner
    }

    /// Returns a metric of type `M` registered under `name` from the registry.
    ///
    /// Returns `None` if no such metric exists.
    fn get<M: Clone + Metric>(&self, name: &str) -> Option<M> {
        self.registered
            .get(&Key {
                name: Cow::Borrowed(&name),
                type_id: TypeId::of::<M>(),
            })
            .and_then(|boxed| boxed.downcast_ref::<M>())
            .cloned()
    }

    /// Registers and caches `metric` under `name` in the registry.
    fn register<M: Clone + Metric>(&mut self, name: String, help: String, metric: M) {
        self.inner.register(name.clone(), help, metric.clone());
        self.registered.insert(
            Key {
                name: Cow::Owned(name),
                type_id: TypeId::of::<M>(),
            },
            Box::new(metric),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicU64};

    use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

    use super::MetricsRegistry;

    #[test]
    fn registering_different_metric_types_under_same_name_works() {
        let mut metrics_registry = MetricsRegistry::default();
        metrics_registry.get_or_register(
            "raindrops",
            "counting raindrops",
            Counter::<u64, AtomicU64>::default(),
        );
        metrics_registry.get_or_register(
            "raindrops",
            "counting raindrops",
            Gauge::<i64, AtomicI64>::default(),
        );

        assert!(metrics_registry.get::<Counter>("raindrops").is_some());
        assert!(metrics_registry.get::<Gauge>("raindrops").is_some());
    }
}
