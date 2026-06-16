use ahash::RandomState as AHashState;
use commonware_utils::cache::Clock;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::hash_map::RandomState as SipHashState, hash::BuildHasher, hint::black_box,
    num::NonZeroUsize,
};

/// Benchmarks the cache-hit read path: a full cache, all lookups present. Run
/// for both the default DoS-resistant hasher (SipHash) and a fast hasher (ahash)
/// to show how much of the read cost is hashing the key.
fn bench_get_with<S: BuildHasher>(c: &mut Criterion, hasher: &str, make: impl Fn() -> S) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let mut cache: Clock<u64, u64, S> =
            Clock::with_hasher(NonZeroUsize::new(capacity).unwrap(), make());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut rng = StdRng::seed_from_u64(capacity as u64);
        let keys: Vec<u64> = (0..1024)
            .map(|_| rng.gen_range(0..capacity as u64))
            .collect();
        c.bench_function(
            &format!("{}/hasher={hasher} capacity={capacity}", module_path!()),
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

fn bench_get(c: &mut Criterion) {
    bench_get_with(c, "siphash", SipHashState::new);
    bench_get_with(c, "ahash", || AHashState::with_seeds(1, 2, 3, 4));
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get,
}
