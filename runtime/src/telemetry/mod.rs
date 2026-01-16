//! Utilities for collecting and reporting telemetry data.

use std::{any::Any, collections::HashMap};

use prometheus_client::registry::{Metric, Registry};

pub mod metrics;
pub mod traces;

#[derive(Debug, Default)]
pub(crate) struct MetricsRegistry {
    registered: HashMap<String, Box<dyn Any + Send + Sync>>,
    inner: Registry,
}

impl MetricsRegistry {
    /// Registers `metric` on the registry under `name` and with a `help` explainer.
    ///
    /// If a metric under `name` was previously registered, drops `metric` and
    /// instead returns the already registered item.
    pub(crate) fn get_or_register<M: Clone + Metric>(
        &mut self,
        name: String,
        help: String,
        metric: M,
    ) -> M {
        if let Some(metric) = self
            .registered
            .get(&name)
            .and_then(|boxed| boxed.downcast_ref::<M>())
            .cloned()
        {
            return metric;
        }
        self.inner.register(name.clone(), help, metric.clone());
        self.registered
            .insert(name.clone(), Box::new(metric.clone()));
        metric
    }

    /// Returns a reference to the inner prometheus registry.
    ///
    /// This bypasses the layer in front of the prometheus registry and allows
    /// writing to it directly.
    pub(crate) fn write_through(&mut self) -> &mut Registry {
        &mut self.inner
    }
}
