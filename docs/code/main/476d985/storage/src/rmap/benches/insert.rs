use commonware_storage::rmap::RMap;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

fn bench_insert(c: &mut Criterion) {
    for items in [10_000, 50_000, 100_000, 500_000, 1_000_000] {
        let label = format!("{}/items={}", module_path!(), items,);
        c.bench_function(&label, |b| {
            b.iter_custom(move |iters| {
                // Setup items
                let mut rng = StdRng::seed_from_u64(0);
                let mut indices = Vec::with_capacity(items);
                for i in 0..items {
                    indices.push(i as u64);
                }

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Shuffle items and setup RMap
                    indices.shuffle(&mut rng);
                    let mut rmap = RMap::new();

                    // Run benchmark
                    let start = Instant::now();
                    for i in &indices {
                        rmap.insert(*i);
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert
}
