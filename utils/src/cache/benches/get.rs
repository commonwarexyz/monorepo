use commonware_utils::{TestRng, cache::Cache};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks the cache-hit read path: a full cache, all lookups present.
fn bench_get(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let capacity = NonZeroUsize::new(capacity).unwrap();
        let mut cache = Cache::new(capacity);
        for i in 0..capacity.get() as u64 {
            cache.put(i, i);
        }
        let mut rng = TestRng::new(capacity.get() as u64);
        let keys: Vec<u64> = (0..1024)
            .map(|_| rng.random_range(0..capacity.get() as u64))
            .collect();

        c.bench_function(
            &format!("{}/capacity={}", module_path!(), capacity.get()),
            |b| {
                b.iter(|| {
                    for k in &keys {
                        black_box(cache.get(black_box(k)));
                    }
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get,
}
