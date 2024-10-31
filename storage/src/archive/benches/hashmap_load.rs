use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use std::collections::HashMap;

struct MockIndex {
    _section: u64,
    _offset: usize,
    _next: Option<Box<MockIndex>>,
}

fn benchmark_hashmap_load(c: &mut Criterion) {
    for n in &[100_000, 1_000_000, 10_000_000, 100_000_000] {
        for k in [4, 8, 16, 32] {
            c.bench_function(&format!("load: n={} k={}", n, k), |b| {
                b.iter(|| {
                    let mut map = HashMap::new();
                    let mut rng = rand::thread_rng();

                    // Populate the HashMap with dummy data
                    for _ in 0..*n {
                        let key: Vec<u8> = (0..k).map(|_| rng.gen()).collect();
                        let value = MockIndex {
                            _section: rng.gen(),
                            _offset: rng.gen(),
                            _next: None,
                        };
                        map.insert(key, value);
                    }
                })
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_hashmap_load
}
criterion_main!(benches);
