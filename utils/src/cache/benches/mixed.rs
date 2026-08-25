use commonware_utils::{
    TestRng,
    cache::{Cache, Clock2QPlus, Policy, Sieve},
};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

fn bench<P>(c: &mut Criterion, policy: &str, capacity: usize, mut cache: Cache<u64, u64, P>)
where
    P: Policy<u64>,
{
    for i in 0..capacity as u64 {
        cache.put(i, i);
    }
    let mut rng = TestRng::new(capacity as u64);

    // Each round reads 8 live slots, then installs one fresh key. Stable slots
    // let the benchmark update the live key set after each eviction.
    let rounds: Vec<[usize; 8]> = (0..1024)
        .map(|_| {
            let mut reads = [0usize; 8];
            for slot in &mut reads {
                *slot = rng.random_range(0..capacity);
            }
            reads
        })
        .collect();
    let mut keys: Vec<u64> = (0..capacity as u64).collect();
    let mut next = capacity as u64;

    c.bench_function(
        &format!("{}/policy={policy} capacity={capacity}", module_path!()),
        |b| {
            b.iter(|| {
                for reads in &rounds {
                    for &slot in reads {
                        black_box(cache.get(black_box(&keys[slot])));
                    }
                    let key = next;
                    next = next
                        .checked_add(1)
                        .expect("benchmark keys must not overflow");
                    let (slot, value) = cache.get_or_insert_mut(black_box(key), || unreachable!());
                    *value = key;
                    keys[slot] = key;
                }
            });
        },
    );
}

/// Benchmarks a read-heavy mix under churn with 8 hits per fresh insertion.
fn bench_mixed(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let capacity = NonZeroUsize::new(capacity).unwrap();
        bench(c, "clock", capacity.get(), Cache::<u64, u64>::new(capacity));
        bench(
            c,
            "clock2q-plus",
            capacity.get(),
            Cache::<u64, u64, Clock2QPlus<u64>>::new(capacity),
        );
        bench(
            c,
            "sieve",
            capacity.get(),
            Cache::<u64, u64, Sieve>::new(capacity),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mixed,
}
