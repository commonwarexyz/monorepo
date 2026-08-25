use commonware_utils::cache::{Cache, Clock2QPlus, Policy};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroUsize};

const INSERTS_PER_ITERATION: usize = 1024;

fn bench<P>(c: &mut Criterion, policy: &str, capacity: usize, mut cache: Cache<u64, u64, P>)
where
    P: Policy<u64>,
{
    for i in 0..capacity as u64 {
        cache.put(i, i);
    }
    let mut next = capacity as u64;
    c.bench_function(
        &format!("{}/policy={policy} capacity={capacity}", module_path!()),
        |b| {
            b.iter_batched(
                || {
                    let start = next;
                    next = next
                        .checked_add(INSERTS_PER_ITERATION as u64)
                        .expect("benchmark keys must not overflow");
                    start..next
                },
                |keys| {
                    for key in keys {
                        cache.put(black_box(key), black_box(key));
                    }
                },
                BatchSize::SmallInput,
            );
        },
    );
}

/// Benchmarks the steady-state insert path under churn. Every key is fresh, so
/// each insertion into the full cache invokes the policy's eviction path.
fn bench_insert(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let capacity = NonZeroUsize::new(capacity).unwrap();
        bench(c, "clock", capacity.get(), Cache::<u64, u64>::new(capacity));
        bench(
            c,
            "clock2q-plus",
            capacity.get(),
            Cache::<u64, u64, Clock2QPlus<u64>>::new(capacity),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert,
}
