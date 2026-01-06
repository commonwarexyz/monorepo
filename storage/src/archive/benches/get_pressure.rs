//! Benchmark for Archive get operations under cache pressure.
//!
//! Uses a tiny buffer pool (10 pages = 160KB) with a larger working set
//! to simulate realistic cache contention scenarios.

use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::PoolRef,
    tokio::Config,
    Runner,
};
use commonware_storage::{
    archive::{prunable, Archive as ArchiveTrait, Identifier},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use criterion::{criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{hint::black_box, num::NonZeroUsize, time::Instant};

const WRITE_BUFFER: usize = 1024 * 1024;
const ITEMS_PER_SECTION: u64 = 1_024;
const REPLAY_BUFFER: usize = 1024 * 1024;
const PAGE_SIZE: NonZeroUsize = NZUsize!(16_384);

/// Tiny cache: 10 pages = 160KB (will cause many cache misses)
const TINY_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

/// Items pre-loaded (will exceed cache size significantly)
const ITEMS: u64 = 50_000;

type Key = FixedBytes<64>;
type Val = FixedBytes<32>;

type PressureArchive = prunable::Archive<TwoCap, commonware_runtime::tokio::Context, Key, Val>;

async fn init_archive(
    ctx: commonware_runtime::tokio::Context,
    compression: Option<u8>,
) -> PressureArchive {
    let cfg = prunable::Config {
        translator: TwoCap,
        index_partition: "archive_bench_pressure_index".into(),
        index_buffer_pool: PoolRef::new(PAGE_SIZE, TINY_CACHE_SIZE),
        value_partition: "archive_bench_pressure_value".into(),
        compression,
        codec_config: (),
        items_per_section: NZU64!(ITEMS_PER_SECTION),
        write_buffer: NZUsize!(WRITE_BUFFER),
        replay_buffer: NZUsize!(REPLAY_BUFFER),
    };
    prunable::Archive::init(ctx, cfg).await.unwrap()
}

async fn append_random(archive: &mut PressureArchive, count: u64) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 32];

    for i in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        rng.fill_bytes(&mut val_buf);
        archive.put(i, key, Val::new(val_buf)).await.unwrap();
    }
    archive.sync().await.unwrap();
}

fn select_indices(reads: usize) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_indices.push(rng.gen_range(0..ITEMS));
    }
    selected_indices
}

async fn read_serial_indices(a: &PressureArchive, indices: &[u64]) {
    for idx in indices {
        black_box(a.get(Identifier::Index(*idx)).await.unwrap().unwrap());
    }
}

async fn read_concurrent_indices(a: &PressureArchive, indices: &[u64]) {
    let mut futs = Vec::with_capacity(indices.len());
    for idx in indices {
        futs.push(a.get(Identifier::Index(*idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

fn bench_get_pressure(c: &mut Criterion) {
    let cfg = Config::default();
    for compression in [Some(3)] {
        // Create a shared on-disk archive once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        builder.start(|ctx| async move {
            let mut a = init_archive(ctx, compression).await;
            append_random(&mut a, ITEMS).await;
            a.sync().await.unwrap();
        });

        // Run the benchmarks.
        let runner = tokio::Runner::new(cfg.clone());
        for mode in ["serial", "concurrent"] {
            for reads in [1_000, 5_000] {
                let label = format!(
                    "{}/mode={} pattern=index comp={} reads={} cache=tiny",
                    module_path!(),
                    mode,
                    compression
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "off".into()),
                    reads
                );
                c.bench_function(&label, |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let archive = init_archive(ctx, compression).await;
                        let selected_indices = select_indices(reads);
                        let start = Instant::now();
                        for _ in 0..iters {
                            match mode {
                                "serial" => read_serial_indices(&archive, &selected_indices).await,
                                "concurrent" => {
                                    read_concurrent_indices(&archive, &selected_indices).await
                                }
                                _ => unreachable!(),
                            }
                        }
                        start.elapsed()
                    });
                });
            }
        }

        // Clean up shared artifacts.
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let a = init_archive(ctx, compression).await;
            a.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get_pressure
}
