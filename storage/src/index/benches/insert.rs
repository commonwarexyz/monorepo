use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Metrics;
use commonware_storage::{
    index::{ordered, partitioned, unordered, Unordered},
    translator::{FourCap, TwoCap},
};
use criterion::{criterion_group, Criterion};
use prometheus_client::registry::Metric;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

#[derive(Debug, Clone, Copy)]
enum Variant {
    Ordered,
    Unordered,
    PartitionedUnordered1, // 1-byte prefix
    PartitionedUnordered2, // 2-byte prefix
    PartitionedOrdered1,   // 1-byte prefix
    PartitionedOrdered2,   // 2-byte prefix
}

impl Variant {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::Unordered => "unordered",
            Self::PartitionedUnordered1 => "partitioned_unordered_1",
            Self::PartitionedUnordered2 => "partitioned_unordered_2",
            Self::PartitionedOrdered1 => "partitioned_ordered_1",
            Self::PartitionedOrdered2 => "partitioned_ordered_2",
        }
    }
}

const VARIANTS: [Variant; 6] = [
    Variant::Ordered,
    Variant::Unordered,
    Variant::PartitionedUnordered1,
    Variant::PartitionedUnordered2,
    Variant::PartitionedOrdered1,
    Variant::PartitionedOrdered2,
];

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
        // Setup items
        let mut rng = StdRng::seed_from_u64(0);
        let mut kvs = Vec::with_capacity(items);
        for i in 0..items {
            kvs.push((Sha256::hash(&i.to_be_bytes()), i as u64));
        }
        // Shuffle items and setup Index
        kvs.shuffle(&mut rng);
        for variant in VARIANTS {
            let label = format!(
                "{}/variant={} items={}",
                module_path!(),
                variant.name(),
                items,
            );
            c.bench_function(&label, |b| {
                let kvs_data = kvs.clone();
                b.iter_custom(move |iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        match variant {
                            Variant::Ordered => {
                                let mut index = ordered::Index::new(DummyMetrics, FourCap);
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::Unordered => {
                                let mut index = unordered::Index::new(DummyMetrics, FourCap);
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedUnordered1 => {
                                // For apples to apples behavior (in terms of # of collision) we'd
                                // ideally like a "ThreeCap" translator when there is a 1-byte
                                // prefix, but that's not currently a thing.
                                let mut index = partitioned::unordered::Index::<_, _, 1>::new(
                                    DummyMetrics,
                                    FourCap,
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedUnordered2 => {
                                let mut index = partitioned::unordered::Index::<_, _, 2>::new(
                                    DummyMetrics,
                                    TwoCap,
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedOrdered1 => {
                                let mut index = partitioned::ordered::Index::<_, _, 1>::new(
                                    DummyMetrics,
                                    FourCap,
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedOrdered2 => {
                                let mut index = partitioned::ordered::Index::<_, _, 2>::new(
                                    DummyMetrics,
                                    TwoCap,
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                        };
                    }
                    total
                });
            });
        }
    }
}

fn run_benchmark<I: Unordered<Value = u64>>(
    index: &mut I,
    kvs: &[(<Sha256 as Hasher>::Digest, u64)],
) -> Duration {
    let start = Instant::now();
    for (k, v) in kvs {
        index.insert(k, *v);
    }
    start.elapsed()
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
