use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, RngExt as _, SeedableRng};
use std::{collections::HashMap, hint::black_box};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 1] = [100_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 3] = [100_000, 1_000_000, 10_000_000];

struct MockIndex {
    section: u64,
    _offset: u32,
    _len: u32,
}

fn bench_hashmap_iteration(c: &mut Criterion) {
    for n in N_ITEMS {
        for k in [4, 8, 16, 32] {
            c.bench_function(&format!("{}/n={} k={}", module_path!(), n, k), |b| {
                b.iter_batched(
                    || {
                        let mut map = HashMap::with_capacity(n);
                        let mut rng = StdRng::seed_from_u64((n as u64) ^ (k as u64));
                        let mut key = vec![0; k];

                        // Populate the HashMap with dummy data
                        for _ in 0..n {
                            rng.fill(&mut key[..]);
                            let value = MockIndex {
                                section: rng.random(),
                                _offset: rng.random(),
                                _len: rng.random(),
                            };
                            map.insert(key.clone(), value);
                        }
                        map
                    },
                    |map| {
                        for (_, value) in map {
                            let _ = black_box(value.section);
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_hashmap_iteration
}
