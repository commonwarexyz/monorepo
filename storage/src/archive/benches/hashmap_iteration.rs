use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::Rng;
use std::collections::HashMap;

struct MockIndex {
    section: u64,
    _offset: u32,
    _len: u32,
    _next: Option<Box<MockIndex>>,
}

fn benchmark_hashmap_iteration(c: &mut Criterion) {
    for n in [100_000, 1_000_000, 10_000_000, 100_000_000] {
        for k in [4, 8, 16, 32] {
            c.bench_function(&format!("iteration: n={} k={}", n, k), |b| {
                b.iter_batched(
                    || {
                        let mut map = HashMap::with_capacity(n);
                        let mut rng = rand::thread_rng();
                        let mut key = vec![0; k];

                        // Populate the HashMap with dummy data
                        for _ in 0..n {
                            rng.fill(&mut key[..]);
                            let value = MockIndex {
                                section: rng.gen(),
                                _offset: rng.gen(),
                                _len: rng.gen(),
                                _next: None,
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
    targets = benchmark_hashmap_iteration
}
criterion_main!(benches);
