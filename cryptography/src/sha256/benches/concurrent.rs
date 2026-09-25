//! Hash independent inputs on several threads at once.
//!
//! Every thread owns its inputs and runs the same operation. The reported time
//! is per operation on one thread, so perfect scaling matches `threads=1`.

use commonware_cryptography::{Hasher, Sha256};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::{
    hint::black_box,
    sync::Barrier,
    time::{Duration, Instant},
};

/// Thread counts to measure.
const THREADS: [usize; 3] = [1, 4, 16];

/// Run `op` `iters` times on each of `threads` threads, starting together.
fn measure(threads: usize, iters: u64, op: impl Fn(usize) + Sync) -> Duration {
    let barrier = Barrier::new(threads + 1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|thread| {
                let (barrier, op) = (&barrier, &op);
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..iters {
                        op(thread);
                    }
                })
            })
            .collect();
        barrier.wait();
        let start = Instant::now();
        for handle in handles {
            handle.join().unwrap();
        }
        start.elapsed()
    })
}

/// Random bytes for every thread.
fn inputs(threads: usize, count: usize, len: usize) -> Vec<Vec<Vec<u8>>> {
    let mut sampler = test_rng();
    (0..threads)
        .map(|_| {
            (0..count)
                .map(|_| {
                    let mut message = vec![0u8; len];
                    sampler.fill_bytes(&mut message);
                    message
                })
                .collect()
        })
        .collect()
}

fn bench_concurrent(c: &mut Criterion) {
    let max = THREADS[THREADS.len() - 1];
    let mut group = c.benchmark_group(module_path!());
    group.sample_size(20);

    let nodes = inputs(max, 2, 72);
    for threads in THREADS {
        for (shape, split) in [("bmt", &[32usize, 64][..]), ("mmr", &[8, 40, 72][..])] {
            let parts: Vec<[Vec<&[u8]>; 2]> = nodes
                .iter()
                .map(|pair| {
                    core::array::from_fn(|i| {
                        let mut start = 0;
                        split
                            .iter()
                            .map(|&end| {
                                let part = &pair[i][start..end];
                                start = end;
                                part
                            })
                            .collect()
                    })
                })
                .collect();
            group.bench_function(
                format!("op=hash_pair shape={shape} threads={threads}"),
                |b| {
                    b.iter_custom(|iters| {
                        measure(threads, iters, |thread| {
                            let [left, right] = &parts[thread];
                            black_box(Sha256::hash_pair(black_box(left), black_box(right)));
                        })
                    })
                },
            );
        }
    }

    for len in [256, 4096, 65_536, 1_048_576, 16_777_216] {
        let messages = inputs(max, 1, len);
        for threads in THREADS {
            group.bench_function(format!("op=hash len={len} threads={threads}"), |b| {
                b.iter_custom(|iters| {
                    measure(threads, iters, |thread| {
                        black_box(Sha256::hash(&[black_box(&messages[thread][0])]));
                    })
                })
            });
        }
    }

    for len in [64, 256, 4096, 65_536] {
        let batches = inputs(max, 16, len);
        for threads in THREADS {
            group.bench_function(
                format!("op=hash_many count=16 len={len} threads={threads}"),
                |b| {
                    b.iter_custom(|iters| {
                        measure(threads, iters, |thread| {
                            black_box(Sha256::hash_many(black_box(&batches[thread])));
                        })
                    })
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_concurrent);
