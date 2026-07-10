use commonware_utils::{cache::Clock, TestRng};
use criterion::{criterion_group, Criterion};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks the steady-state insert path under churn: a full cache with a
/// working set twice the capacity, so most inserts miss and evict (CLOCK sweep,
/// index remove + insert, slot reuse).
fn bench_insert(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let working = (capacity as u64) * 2;
        let mut cache: Clock<u64, u64> = Clock::new(NonZeroUsize::new(capacity).unwrap());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut rng = TestRng::new(capacity as u64);
        let keys: Vec<u64> = (0..1024).map(|_| rng.random_range(0..working)).collect();
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
            b.iter(|| {
                for k in &keys {
                    cache.put(black_box(*k), black_box(*k));
                }
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert,
}
