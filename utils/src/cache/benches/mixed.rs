use commonware_utils::{TestRng, cache::Cache};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::{hint::black_box, num::NonZeroUsize};

/// Benchmarks a read-heavy mix under churn: 8 hits per miss insert, so resident
/// entries keep their reference bits set and every eviction sweep must clear a
/// run of bits before finding a victim (the CLOCK worst case).
fn bench_mixed(c: &mut Criterion) {
    for capacity in [1usize << 10, 1 << 14, 1 << 18] {
        let mut cache: Cache<u64, u64> = Cache::new(NonZeroUsize::new(capacity).unwrap());
        for i in 0..capacity as u64 {
            cache.put(i, i);
        }
        let mut rng = TestRng::new(capacity as u64);
        // Each round reads 8 live slots, then installs one fresh key. Stable
        // slots let the benchmark update the live key set after each eviction.
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
        c.bench_function(&format!("{}/capacity={capacity}", module_path!()), |b| {
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
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mixed,
}
