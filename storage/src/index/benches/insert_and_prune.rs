use super::DummyMetrics;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{unordered, Unordered},
    translator::FourCap,
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 4] = [10_000, 50_000, 100_000, 500_000];

fn bench_insert_and_prune(c: &mut Criterion) {
    for items in N_ITEMS {
        let mut rng = StdRng::seed_from_u64(0);
        let mut kvs = Vec::with_capacity(items);
        for i in 0..items {
            kvs.push((Sha256::hash(&i.to_be_bytes()), i as u64));
        }
        kvs.shuffle(&mut rng);

        c.bench_function(&format!("{}/items={items}", module_path!()), |b| {
            let kvs_data = kvs.clone();
            b.iter_custom(move |iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut index = unordered::Index::new(DummyMetrics, FourCap);
                    total += run_benchmark(&mut index, &kvs_data);
                }
                total
            });
        });
    }
}

fn run_benchmark<I: Unordered<Value = u64>>(
    index: &mut I,
    kvs: &[(<Sha256 as Hasher>::Digest, u64)],
) -> Duration {
    // Seed the index with initial values.
    for (k, v) in kvs {
        index.insert(k, *v);
    }

    // Overwrite every key using insert_and_prune: prune the old value, insert the new one.
    let start = Instant::now();
    for (k, v) in kvs {
        index.insert_and_prune(k, *v + 1, |old| *old == *v);
    }
    start.elapsed()
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert_and_prune
}
