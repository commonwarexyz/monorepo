use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use std::collections::HashMap;

fn benchmark_map_iteration(c: &mut Criterion) {
    for n in &[100_000, 1_000_000, 10_000_000, 100_000_000] {
        for k in &[4, 8, 16, 32] {
            c.bench_function(format!("n={} k={}", n, k), |b| {
                b.iter_batched(
                    || {
                        let mut map = HashMap::with_capacity(*n);
                        let mut rng = rand::thread_rng();

                        // Populate the HashMap with dummy data
                        for _ in 0..*n {
                            let key: Vec<u8> = (0..k).map(|_| rng.gen()).collect();
                            let value = Index {
                                section: rng.gen(),
                                offset: rng.gen(),
                                next: None,
                            };
                            map.insert(key, value);
                        }
                        map
                    },
                    |map| {
                        for (_, value) in &map {
                            let _ = black_box(value.section);
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, benchmark_map_iteration);
criterion_main!(benches);
