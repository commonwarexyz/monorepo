use commonware_utils::cache::Cache;
use criterion::{BatchSize, Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks reuse after bulk invalidation, excluding setup and removal.
fn bench_refill(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
            b.iter_batched_ref(
                || {
                    let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
                    cache.prefill(|| 0);
                    for key in 0..capacity as u64 {
                        cache.put(key, key);
                    }
                    cache.retain(|key, _| key % 2 == 0);
                    assert_eq!(cache.len(), capacity / 2);
                    cache
                },
                |cache| {
                    for key in (1..capacity as u64).step_by(2) {
                        let (slot, value) =
                            cache.get_or_insert_mut(black_box(key), || unreachable!());
                        *value = key;
                        black_box(slot);
                    }
                },
                BatchSize::PerIteration,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_refill,
}
