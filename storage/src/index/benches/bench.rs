use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    telemetry::metrics::{Metric, Registered, Registration},
    Metrics, Name, Supervisor,
};
use criterion::criterion_main;

mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;
mod insert;
mod insert_and_prune;
mod lookup;
mod lookup_miss;

pub(crate) type Digest = <Sha256 as Hasher>::Digest;

#[derive(Clone)]
pub(crate) struct DummyMetrics;

impl Supervisor for DummyMetrics {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: impl std::fmt::Display) -> Self {
        Self
    }

    fn name(&self) -> Name {
        Name::default()
    }
}

impl Metrics for DummyMetrics {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        _: N,
        _: H,
        metric: M,
    ) -> Registered<M> {
        Registered::with_registration(metric, Registration::from(()))
    }

    fn encode(&self) -> String {
        "".into()
    }
}

criterion_main!(
    hashmap_iteration::benches,
    hashmap_insert_fixed::benches,
    hashmap_insert::benches,
    insert::benches,
    insert_and_prune::benches,
    lookup::benches,
    lookup_miss::benches,
);
