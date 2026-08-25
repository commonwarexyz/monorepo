use commonware_utils::cache::Cache;
use criterion::{BatchSize, Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroUsize};

const INSERTS_PER_ITERATION: usize = 1024;

/// Benchmarks the steady-state insert path under churn. Every key is fresh, so
/// each insertion into the full cache evicts a CLOCK resident.
fn bench_insert(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let mut cache: Cache<u64, u64> = Cache::new(NonZeroUsize::new(capacity).unwrap());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut next = capacity as u64;
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
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
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert,
}
