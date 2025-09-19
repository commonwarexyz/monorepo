use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::Metrics;
use commonware_storage::{index::Index, translator::TwoCap};
use criterion::{criterion_group, Criterion};
use prometheus_client::registry::Metric;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

#[cfg(test)]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(not(test))]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

#[derive(Clone)]
struct DummyMetrics;

impl Metrics for DummyMetrics {
    fn label(&self) -> String {
        "".to_string()
    }

    fn with_label(&self, _: &str) -> Self {
        Self
    }

    fn encode(&self) -> String {
        "".to_string()
    }

    fn register<N: Into<String>, H: Into<String>>(&self, _: N, _: H, _: impl Metric) {}
}

fn bench_insert(c: &mut Criterion) {
    for items in N_ITEMS {
        let label = format!("{}/items={}", module_path!(), items,);
        c.bench_function(&label, |b| {
            b.iter_custom(move |iters| {
                // Setup items
                let mut rng = StdRng::seed_from_u64(0);
                let mut kvs = Vec::with_capacity(items);
                for i in 0..items {
                    kvs.push((Sha256::hash(&i.to_be_bytes()), i as u64));
                }

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Shuffle items and setup Index
                    kvs.shuffle(&mut rng);
                    let mut index = Index::init(DummyMetrics, TwoCap);

                    // Run benchmark
                    let start = Instant::now();
                    for (k, v) in &kvs {
                        index.insert(k, *v);
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
