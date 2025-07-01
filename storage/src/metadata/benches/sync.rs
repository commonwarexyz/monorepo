//! Benchmark for syncing `Metadata` with overlapping keys.

use super::utils::{get_random_kvs, init};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::time::{Duration, Instant};

fn bench_sync(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for &num_keys in &[100, 1_000, 10_000] {
        for &modified_pct in &[0, 5, 25, 50, 75, 100] {
            let label = format!(
                "{}/keys={} modified_pct={}",
                module_path!(),
                num_keys,
                modified_pct
            );

            // Generate key-value pairs for the benchmark
            let initial_kvs = get_random_kvs(num_keys);
            let mut second_kvs = initial_kvs.clone();
            if modified_pct > 0 {
                let modified_count = (num_keys * modified_pct) / 100;
                let mut rng = StdRng::seed_from_u64(0);
                let mut indices: Vec<usize> = (0..num_keys).collect();
                indices.shuffle(&mut rng);
                for &idx in indices.iter().take(modified_count) {
                    let mut val = vec![0; 100];
                    rng.fill(&mut val[..]);
                    second_kvs[idx].1 = val;
                }
            }

            // Run the benchmark
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(|iters| {
                    let initial_kvs = initial_kvs.clone();
                    let second_kvs = second_kvs.clone();
                    async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let mut metadata = init(ctx.clone()).await;

                            // Put initial state
                            for (k, v) in &initial_kvs {
                                metadata.put(k.clone(), v.clone());
                            }

                            // Sync twice to ensure both blobs populated
                            metadata.sync().await.unwrap();
                            metadata.sync().await.unwrap();

                            // Update some keys
                            for (k, v) in &second_kvs {
                                metadata.put(k.clone(), v.clone());
                            }

                            // Sync new data
                            let start = Instant::now();
                            metadata.sync().await.unwrap();
                            total += start.elapsed();

                            metadata.destroy().await.unwrap();
                        }
                        total
                    }
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sync
}
