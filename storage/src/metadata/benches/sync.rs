//! Benchmark for syncing `Metadata` with overlapping keys.

use super::utils::{get_metadata, get_random_kvs, Key, Val};
use commonware_runtime::benchmarks::tokio;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_sync(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for &num_keys in &[100, 1_000] {
        for &overlap_pct in &[0, 25, 50, 75, 100] {
            let label = format!(
                "{}/keys={} overlap_pct={}",
                module_path!(),
                num_keys,
                overlap_pct
            );

            // Generate key-value pairs for the benchmark
            let initial_kvs = get_random_kvs(num_keys, 0);
            let overlap_count = (num_keys * overlap_pct) / 100;

            let mut second_kvs: Vec<(Key, Val)> = initial_kvs
                .iter()
                .take(overlap_count)
                .map(|(k, _)| {
                    let new_val = get_random_kvs(1, k.to_u64()).pop().unwrap().1;
                    (k.clone(), new_val)
                })
                .collect();

            if num_keys > overlap_count {
                let new_kvs = get_random_kvs(num_keys - overlap_count, num_keys as u64);
                second_kvs.extend(new_kvs);
            }

            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(|iters| {
                    let initial_kvs = initial_kvs.clone();
                    let second_kvs = second_kvs.clone();
                    async move {
                        let ctx = commonware_runtime::benchmarks::context::get::<
                            commonware_runtime::tokio::Context,
                        >();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let mut metadata = get_metadata(ctx.clone()).await;

                            // Sync 1: Initial state
                            for (k, v) in &initial_kvs {
                                metadata.put(k.clone(), v.clone());
                            }
                            metadata.sync().await.unwrap();

                            // Sync 2: Benchmarked operation
                            let start = Instant::now();
                            for (k, v) in &second_kvs {
                                metadata.put(k.clone(), v.clone());
                            }
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
