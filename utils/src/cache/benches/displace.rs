use commonware_utils::cache::Cache;
use criterion::{BatchSize, Criterion, criterion_group};
use std::{collections::VecDeque, hint::black_box, num::NonZeroUsize};

const INSERTS_PER_ITERATION: usize = 1024;

/// Benchmarks admitting fresh keys into a full cache by displacing a caller-chosen stale
/// resident, as a page cache does when a new page takes over a retired one, against the
/// policy's own eviction. Every inserted key is fresh and never read.
///
/// With `stale=resident`, each insert names the oldest Main resident and the new key joins the
/// back of that order, so Main keeps its size and every displacement finds its key. With
/// `stale=absent`, the named key was never cached, so the insert pays a failed lookup and falls
/// back to evicting the Small tail. `stale=none` is the plain insert.
fn bench_displace(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        for mode in ["resident", "absent", "none"] {
            let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
            for i in 0..capacity as u64 {
                cache.put(i, i);
            }

            // Warm-up fills Small before Main, so Main holds the later keys in admission order.
            let small = capacity / 10;
            let mut main: VecDeque<u64> = (small as u64..capacity as u64).collect();
            let mut next = capacity as u64;
            let mut absent = u64::MAX;

            c.bench_function(
                &format!("{}/capacity={capacity} stale={mode}", module_path!()),
                |b| {
                    b.iter_batched(
                        || {
                            (0..INSERTS_PER_ITERATION)
                                .map(|_| {
                                    let key = next;
                                    next += 1;
                                    let stale = match mode {
                                        "resident" => {
                                            main.push_back(key);
                                            Some(main.pop_front().expect("Main is never empty"))
                                        }
                                        "absent" => {
                                            absent -= 1;
                                            Some(absent)
                                        }
                                        _ => None,
                                    };
                                    (key, stale)
                                })
                                .collect::<Vec<_>>()
                        },
                        |pairs| {
                            for (key, stale) in pairs {
                                match stale {
                                    Some(stale) => cache.get_or_insert_mut_displacing(
                                        black_box(key),
                                        black_box(&stale),
                                        || key,
                                    ),
                                    None => cache.get_or_insert_mut(black_box(key), || key),
                                };
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_displace,
}
