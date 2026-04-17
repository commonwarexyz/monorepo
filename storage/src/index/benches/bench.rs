use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{Name, Observer, Supervisor};
use criterion::criterion_main;
use prometheus_client::registry::Metric;

mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;
mod insert;
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

impl Observer for DummyMetrics {
    fn with_scope(self) -> Self {
        Self
    }

    fn with_span(self) -> Self {
        Self
    }

    fn register<M: Metric + Clone>(&self, _: &str, _: &str, default: M) -> M {
        default
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
