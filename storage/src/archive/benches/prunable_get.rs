//! Random key-lookup benchmark for Archive.

use super::utils::{
    append_random, compression_label, create_benchmark_label, get_archive,
    read_concurrent_indices_prunable, read_concurrent_keys_prunable, read_serial_indices_prunable,
    read_serial_keys_prunable, select_indices, select_keys,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::Instant;

/// Items pre-loaded into the archive.
const ITEMS: u64 = 250_000;

fn bench_prunable_get(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        // Create a shared on-disk archive once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let keys = builder.start(|ctx| async move {
            let mut a = get_archive(ctx, compression).await;
            let keys = append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
            keys
        });

        // Run the benchmarks.
        let runner = tokio::Runner::new(cfg.clone());
        for mode in ["serial", "concurrent"] {
            for pattern in ["key", "index"] {
                for reads in [1_000, 10_000, 50_000] {
                    let label = create_benchmark_label(
                        module_path!(),
                        &[
                            ("mode", mode.to_string()),
                            ("pattern", pattern.to_string()),
                            ("comp", compression_label(compression)),
                            ("reads", reads.to_string()),
                        ],
                    );
                    c.bench_function(&label, |b| {
                        let keys = keys.clone();
                        b.to_async(&runner).iter_custom(move |iters| {
                            let keys = keys.clone();
                            async move {
                                let ctx = context::get::<commonware_runtime::tokio::Context>();
                                let archive = get_archive(ctx, compression).await;
                                if pattern == "key" {
                                    let selected_keys = select_keys(&keys, reads, ITEMS);
                                    let start = Instant::now();
                                    for _ in 0..iters {
                                        match mode {
                                            "serial" => {
                                                read_serial_keys_prunable(&archive, &selected_keys)
                                                    .await
                                            }
                                            "concurrent" => {
                                                read_concurrent_keys_prunable(
                                                    &archive,
                                                    selected_keys.clone(),
                                                )
                                                .await
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                    start.elapsed()
                                } else {
                                    let selected_indices = select_indices(reads, ITEMS);
                                    let start = Instant::now();
                                    for _ in 0..iters {
                                        match mode {
                                            "serial" => {
                                                read_serial_indices_prunable(
                                                    &archive,
                                                    &selected_indices,
                                                )
                                                .await
                                            }
                                            "concurrent" => {
                                                read_concurrent_indices_prunable(
                                                    &archive,
                                                    &selected_indices,
                                                )
                                                .await
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                    start.elapsed()
                                }
                            }
                        });
                    });
                }
            }
        }

        // Clean up shared artifacts.
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let a = get_archive(ctx, compression).await;
            a.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prunable_get
}
