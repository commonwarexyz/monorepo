use commonware_utils::{
    TestRng,
    cache::{Cache, Clock2QPlus, Policy, Sieve},
};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

fn bench<P>(
    c: &mut Criterion,
    policy: &str,
    capacity: usize,
    keys: &[u64],
    mut cache: Cache<u64, u64, P>,
) where
    P: Policy<u64>,
{
    for i in 0..capacity as u64 {
        cache.put(i, i);
    }
    c.bench_function(
        &format!("{}/policy={policy} capacity={capacity}", module_path!()),
        |b| {
            b.iter(|| {
                for k in keys {
                    black_box(cache.get(black_box(k)));
                }
            });
        },
    );
}

/// Benchmarks the cache-hit read path: a full cache, all lookups present.
fn bench_get(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let capacity = NonZeroUsize::new(capacity).unwrap();
        let mut rng = TestRng::new(capacity.get() as u64);
        let keys: Vec<u64> = (0..1024)
            .map(|_| rng.random_range(0..capacity.get() as u64))
            .collect();

        bench(
            c,
            "clock",
            capacity.get(),
            &keys,
            Cache::<u64, u64>::new(capacity),
        );

        bench(
            c,
            "clock2q-plus",
            capacity.get(),
            &keys,
            Cache::<u64, u64, Clock2QPlus<u64>>::new(capacity),
        );

        bench(
            c,
            "sieve",
            capacity.get(),
            &keys,
            Cache::<u64, u64, Sieve>::new(capacity),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get,
}
