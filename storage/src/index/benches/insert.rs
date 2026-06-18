use super::DummyMetrics;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{ordered, partitioned, unordered, Unordered},
    translator::{Cap, EightCap, Hashed},
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

#[cfg(not(any(full_bench, huge_bench)))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(all(full_bench, not(huge_bench)))]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];
// The huge tier targets the P=3 regime (16.8M partitions): 20M keys gives ~1.2 entries per
// partition and 100M gives ~6, so the per-partition sorted runs are actually exercised. It needs
// ~12 GB of RAM, so it sits behind its own cfg.
#[cfg(huge_bench)]
const N_ITEMS: [usize; 2] = [20_000_000, 100_000_000];

/// Key count at or above which the index is large enough for partitioning to pay off: only then do
/// the P=3 variant and the heavy-occupancy-sensitive baselines run (see [`Variant::runs_at`]).
const HUGE: usize = 2_000_000;

#[derive(Debug, Clone, Copy)]
enum Variant {
    Ordered,
    Unordered,
    PartitionedOrdered1,
    PartitionedOrdered2,
    PartitionedOrdered3,
    PartitionedUnordered1,
    PartitionedUnordered2,
    HashedUnordered,
    HashedPartitionedUnordered1,
    HashedPartitionedUnordered2,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::Unordered => "unordered",
            Self::PartitionedOrdered1 => "partitioned_ordered_1",
            Self::PartitionedOrdered2 => "partitioned_ordered_2",
            Self::PartitionedOrdered3 => "partitioned_ordered_3",
            Self::PartitionedUnordered1 => "partitioned_unordered_1",
            Self::PartitionedUnordered2 => "partitioned_unordered_2",
            Self::HashedUnordered => "hashed_unordered",
            Self::HashedPartitionedUnordered1 => "hashed_partitioned_unordered_1",
            Self::HashedPartitionedUnordered2 => "hashed_partitioned_unordered_2",
        }
    }

    /// Whether this variant should run at the given key count. Ordered P=3 (sorted struct-of-arrays)
    /// only runs at huge sizes, below which its 16.8M-partition allocation dominates. At huge sizes
    /// we keep the flat baselines, the unordered hashmap shards (cheap at low P), and ordered P=3,
    /// dropping the deep-occupancy ordered P=1/P=2 and the hashed variants.
    const fn runs_at(&self, items: usize) -> bool {
        match self {
            Self::PartitionedOrdered3 => items >= HUGE,
            Self::Unordered
            | Self::Ordered
            | Self::PartitionedUnordered1
            | Self::PartitionedUnordered2 => true,
            _ => items < HUGE,
        }
    }
}

const VARIANTS: [Variant; 10] = [
    Variant::Ordered,
    Variant::Unordered,
    Variant::PartitionedOrdered1,
    Variant::PartitionedOrdered2,
    Variant::PartitionedOrdered3,
    Variant::PartitionedUnordered1,
    Variant::PartitionedUnordered2,
    Variant::HashedUnordered,
    Variant::HashedPartitionedUnordered1,
    Variant::HashedPartitionedUnordered2,
];

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
            if !variant.runs_at(items) {
                continue;
            }
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
                                let mut index = ordered::Index::new(DummyMetrics, EightCap);
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::Unordered => {
                                let mut index = unordered::Index::new(DummyMetrics, EightCap);
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedOrdered1 => {
                                let mut index = partitioned::ordered::Index::<_, _, 1>::new(
                                    DummyMetrics,
                                    Cap::<7>::new(),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedOrdered2 => {
                                let mut index = partitioned::ordered::Index::<_, _, 2>::new(
                                    DummyMetrics,
                                    Cap::<6>::new(),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedOrdered3 => {
                                let mut index = partitioned::ordered::Index::<_, _, 3>::new(
                                    DummyMetrics,
                                    Cap::<5>::new(),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedUnordered1 => {
                                let mut index = partitioned::unordered::Index::<_, _, 1>::new(
                                    DummyMetrics,
                                    Cap::<7>::new(),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::PartitionedUnordered2 => {
                                let mut index = partitioned::unordered::Index::<_, _, 2>::new(
                                    DummyMetrics,
                                    Cap::<6>::new(),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::HashedUnordered => {
                                let mut index = unordered::Index::new(
                                    DummyMetrics,
                                    Hashed::from_seed(0, EightCap),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::HashedPartitionedUnordered1 => {
                                let mut index = partitioned::unordered::Index::<_, _, 1>::new(
                                    DummyMetrics,
                                    Hashed::from_seed(0, Cap::<7>::new()),
                                );
                                total += run_benchmark(&mut index, &kvs_data);
                            }
                            Variant::HashedPartitionedUnordered2 => {
                                let mut index = partitioned::unordered::Index::<_, _, 2>::new(
                                    DummyMetrics,
                                    Hashed::from_seed(0, Cap::<6>::new()),
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
