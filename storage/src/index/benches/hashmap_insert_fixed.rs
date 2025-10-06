use criterion::{criterion_group, BatchSize, Criterion};
use rand::Rng;
use std::collections::HashMap;

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 1] = [100_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 3] = [100_000, 1_000_000, 10_000_000];

struct MockIndex {
    _section: u64,
    _offset: u32,
    _len: u32,
    _next: Option<Box<MockIndex>>,
}

fn benchmark_hashmap_insert_fixed(c: &mut Criterion) {
    for n in N_ITEMS {
        c.bench_function(&format!("{}/n={} k={}", module_path!(), n, 4), |b| {
            b.iter_batched(
                || {
                    // Perform all random ops
                    let mut vec: Vec<([u8; 4], u64, u32, u32)> = Vec::with_capacity(n);
                    let mut rng = rand::thread_rng();

                    // Populate vec with dummy data
                    for _ in 0..n {
                        let key: [u8; 4] = rng.gen();
                        let section = rng.gen();
                        let offset = rng.gen();
                        let len = rng.gen();
                        vec.push((key, section, offset, len));
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
                            _next: None,
                        };
                        map.insert(key, value);
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_hashmap_insert_fixed
}
