use commonware_utils::{Widen, cache::Cache};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

/// Entries removed in each timed iteration.
const REMOVES_PER_ITERATION: usize = 4096;

/// Benchmarks removing a run of entries from a full cache. Removal by key runs once with every key
/// resident and once with keys that were never cached, and removal by slot runs over resident
/// slots.
fn bench_remove(c: &mut Criterion) {
    for capacity in [1usize << 18, 1 << 23] {
        let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
        let pages: u64 = Widen::widen(capacity);
        for page in 0..pages {
            cache.put((0u64, page), page);
        }
        let removes: u64 = Widen::widen(REMOVES_PER_ITERATION);
        let span = pages - removes;
        for resident in [true, false] {
            let blob = u64::from(!resident);
            let mut next = 0u64;
            c.bench_function(
                &format!(
                    "{}/capacity={capacity} by=key resident={resident}",
                    module_path!()
                ),
                |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let start = next % span;
                            next += removes;
                            let pages = start..start + removes;
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

        let mut next = 0usize;
        c.bench_function(
            &format!(
                "{}/capacity={capacity} by=slot resident=true",
                module_path!()
            ),
            |b| {
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        let start = next % (capacity - REMOVES_PER_ITERATION);
                        next += REMOVES_PER_ITERATION;
                        let slots = start..start + REMOVES_PER_ITERATION;
                        let keys: Vec<(u64, u64)> = slots
                            .clone()
                            .map(|slot| {
                                *cache
                                    .key_at(slot)
                                    .expect("a full cache must fill every slot")
                            })
                            .collect();
                        let begin = Instant::now();
                        for slot in slots {
                            black_box(cache.remove_at(slot));
                        }
                        elapsed += begin.elapsed();

                        // Restore the removed keys so the cache stays full.
                        for (blob, page) in keys {
                            cache.put((blob, page), page);
                        }
                    }
                    elapsed
                })
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_remove,
}
