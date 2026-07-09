use commonware_utils::{cache::Clock, TestRng};
use criterion::{criterion_group, Criterion};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks a read-heavy mix under churn: 8 hits per miss insert, so resident
/// entries keep their reference bits set and every eviction sweep must clear a
/// run of bits before finding a victim (the CLOCK worst case).
fn bench_mixed(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let mut cache: Clock<u64, u64> = Clock::new(NonZeroUsize::new(capacity).unwrap());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut rng = TestRng::new(capacity as u64);
        // Each round reads 8 keys biased to the resident range, then inserts one
        // key from far outside it (a guaranteed miss that evicts).
        let rounds: Vec<([u64; 8], u64)> = (0..1024)
            .map(|round| {
                let mut reads = [0u64; 8];
                for slot in &mut reads {
                    *slot = rng.random_range(0..capacity as u64);
                }
                (reads, u64::MAX - round)
            })
            .collect();
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
            b.iter(|| {
                for (reads, insert) in &rounds {
                    for k in reads {
                        black_box(cache.get(black_box(k)));
                    }
                    cache.put(black_box(*insert), black_box(*insert));
                }
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mixed,
}
