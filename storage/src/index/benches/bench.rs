use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{metrics::Metric, Metrics};
use criterion::criterion_main;

mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;
mod insert;
mod lookup;
mod lookup_miss;

pub(crate) type Digest = <Sha256 as Hasher>::Digest;

#[derive(Clone)]
pub(crate) struct DummyMetrics;

impl Metrics for DummyMetrics {
    fn label(&self) -> String {
        "".into()
    }

    fn with_label(&self, _: &str) -> Self {
        Self
    }

    fn with_attribute(&self, _: &str, _: impl std::fmt::Display) -> Self {
        Self
    }

    fn with_span(&self) -> Self {
        Self
    }

    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        _: N,
        _: H,
        metric: M,
    ) -> commonware_runtime::Registered<M> {
        commonware_runtime::Registered::detached(metric)
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
    lookup::benches,
    lookup_miss::benches,
);
