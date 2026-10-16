use commonware_utils::cache::Cache;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const REMOVES_PER_ITERATION: u64 = 4096;

/// Benchmarks removing a run of consecutive keys from a full cache, as a page cache does when it
/// drops a region of a blob: once with every key resident and once with none (keys evicted
/// earlier or never cached).
fn bench_remove(c: &mut Criterion) {
    for capacity in [1usize << 18, 1 << 23] {
        let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
        for page in 0..capacity as u64 {
            cache.put((0u64, page), page);
        }
        let span = capacity as u64 - REMOVES_PER_ITERATION;
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
