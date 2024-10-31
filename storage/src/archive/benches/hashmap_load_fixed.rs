use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::Rng;
use std::collections::HashMap;

struct MockIndex {
    _section: u64,
    _offset: usize,
    _next: Option<Box<MockIndex>>,
}

fn benchmark_hashmap_load_fixed(c: &mut Criterion) {
    for n in [100_000, 1_000_000, 10_000_000, 100_000_000] {
        c.bench_function(&format!("load_fixed: n={} k={}", n, 4), |b| {
            b.iter_batched(
                || {
                    // Perform all random ops
                    let mut vec: Vec<([u8; 4], u64, usize)> = Vec::with_capacity(n);
                    let mut rng = rand::thread_rng();

                    // Populate vec with dummy data
                    for _ in 0..n {
                        let key: [u8; 4] = rng.gen();
                        let section = rng.gen();
                        let offset = rng.gen();
                        vec.push((key, section, offset));
                    }
                    vec
                },
                |v| {
                    let mut map = HashMap::new();

                    // Populate the HashMap with dummy data
                    for (key, section, offset) in v {
                        let value = MockIndex {
                            _section: section,
                            _offset: offset,
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
    targets = benchmark_hashmap_load_fixed
}
criterion_main!(benches);
