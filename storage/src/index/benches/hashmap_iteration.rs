use commonware_utils::TestRng;
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::{collections::HashMap, hint::black_box};

struct MockIndex {
    section: u64,
    _offset: u32,
    _len: u32,
}

fn n_items() -> &'static [usize] {
    if commonware_bench::full() {
        &[100_000, 1_000_000, 10_000_000]
    } else {
        &[100_000]
    }
}

fn bench_hashmap_iteration(c: &mut Criterion) {
    for &n in n_items() {
        for k in [4, 8, 16, 32] {
            c.bench_function(&format!("{}/n={} k={}", module_path!(), n, k), |b| {
                b.iter_batched(
                    || {
                        let mut map = HashMap::with_capacity(n);
                        let mut rng = TestRng::new((n as u64) ^ (k as u64));
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
