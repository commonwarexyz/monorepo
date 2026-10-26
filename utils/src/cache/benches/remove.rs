use commonware_utils::{Widen, cache::Cache};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const REMOVES_PER_ITERATION: u64 = 4096;

/// Benchmarks removing a run of consecutive keys by key from a full cache: once with every key
/// resident and once with keys that were never cached.
fn bench_remove(c: &mut Criterion) {
    for capacity in [1usize << 18, 1 << 23] {
        let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
        let pages: u64 = Widen::widen(capacity);
        for page in 0..pages {
            cache.put((0u64, page), page);
        }
        let span = pages - REMOVES_PER_ITERATION;
        for resident in [true, false] {
            let blob = u64::from(!resident);
            let mut next = 0u64;
            c.bench_function(
                &format!("{}/capacity={capacity} resident={resident}", module_path!()),
                |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let start = next % span;
                            next += REMOVES_PER_ITERATION;
                            let pages = start..start + REMOVES_PER_ITERATION;
                            let begin = Instant::now();
                            for page in pages.clone() {
                                black_box(cache.remove(&(blob, page)));
                            }
                            elapsed += begin.elapsed();

                            // Restore the removed keys so the cache stays full.
                            if resident {
                                for page in pages {
                                    cache.put((0, page), page);
                                }
                            }
                        }
                        elapsed
                    })
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_remove,
}
