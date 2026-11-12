use commonware_utils::TestRng;
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::collections::HashMap;

struct MockIndex {
    _section: u64,
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

fn bench_hashmap_insert(c: &mut Criterion) {
    for &n in n_items() {
        for k in [4, 8, 16, 32] {
            c.bench_function(&format!("{}/n={} k={}", module_path!(), n, k), |b| {
                b.iter_batched(
                    || {
                        // Perform all random ops
                        let mut vec: Vec<(Vec<u8>, u64, u32, u32)> = Vec::with_capacity(n);
                        let mut rng = TestRng::new((n as u64) ^ (k as u64));
                        let mut key = vec![0; k];

                        // Populate vec with dummy data
                        for _ in 0..n {
                            rng.fill(&mut key[..]);
                            let section = rng.random();
                            let offset = rng.random();
                            let len = rng.random();
                            vec.push((key.clone(), section, offset, len));
                        }
                        vec
                    },
                    |v| {
                        let mut map = HashMap::new();

                        // Populate the HashMap with dummy data
                        for (key, section, offset, len) in v {
                            let value = MockIndex {
                                _section: section,
                                _offset: offset,
                                _len: len,
                            };
                            map.insert(key, value);
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
    targets = bench_hashmap_insert
}
