use commonware_utils::cache::Clock;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks the cache-hit read path: a full cache, all lookups present.
fn bench_get(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let mut cache: Clock<u64, u64> = Clock::new(NonZeroUsize::new(capacity).unwrap());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut rng = StdRng::seed_from_u64(capacity as u64);
        let keys: Vec<u64> = (0..1024)
            .map(|_| rng.gen_range(0..capacity as u64))
            .collect();
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
            b.iter(|| {
                for k in &keys {
                    black_box(cache.get(black_box(k)));
                }
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get,
}
