use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Metrics;
use commonware_storage::{
    index::{Index, Ordered, Unordered},
    translator::TwoCap,
};
use criterion::{criterion_group, Criterion};
use prometheus_client::registry::Metric;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
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
    for variant in ["ordered", "unordered"] {
        for items in N_ITEMS {
            let label = format!("{}/variant={variant} items={items}", module_path!());
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
                        let start = Instant::now();
                        if variant == "ordered" {
                            let mut index = Ordered::init(DummyMetrics, TwoCap);
                            run_benchmark(&mut index, &kvs);
                        } else {
                            let mut index = Unordered::init(DummyMetrics, TwoCap);
                            run_benchmark(&mut index, &kvs);
                        };
                        total += start.elapsed();
                    }
                    total
                });
            });
        }
    }
}

fn run_benchmark<I: Index<Value = u64>>(
    index: &mut I,
    kvs: &Vec<(<Sha256 as Hasher>::Digest, u64)>,
) {
    for (k, v) in kvs {
        index.insert(k, *v);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
