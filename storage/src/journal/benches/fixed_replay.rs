use super::write_random_journal;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{black_box, criterion_group, Criterion};
use futures::{pin_mut, StreamExt};
use std::time::{Duration, Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 100_000;

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 1_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Replay all items in the given `journal`.
async fn bench_run(journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>) {
    let concurrency = (ITEMS_TO_WRITE / ITEMS_PER_BLOB) as usize;
    let stream = journal
        .replay(concurrency)
        .await
        .expect("failed to replay journal");
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => {
                black_box(item);
            }
            Err(err) => panic!("Failed to read item: {}", err),
        }
    }
}

/// Benchmark the replaying of ITEMS_TO_WRITE (and then ITEMS_TO_WRITE*2)
/// items from a journal containing exactly that number of items.
fn bench_fixed_replay(c: &mut Criterion) {
    let executor = tokio::Executor::default();

    c.bench_function(
        &format!("{}/items={}", module_path!(), ITEMS_TO_WRITE),
        |b| {
            b.to_async(&executor).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut j = write_random_journal::<ITEM_SIZE>(
                    ctx.clone(),
                    PARTITION,
                    ITEMS_PER_BLOB,
                    ITEMS_TO_WRITE,
                )
                .await;

                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    bench_run(&mut j).await;
                    duration += start.elapsed();
                }
                j.destroy().await.unwrap();

                duration
            });
        },
    );

    c.bench_function(
        &format!("{}/items={}", module_path!(), ITEMS_TO_WRITE * 2),
        |b| {
            b.to_async(&executor).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut j = write_random_journal::<ITEM_SIZE>(
                    ctx.clone(),
                    PARTITION,
                    ITEMS_PER_BLOB,
                    ITEMS_TO_WRITE * 2,
                )
                .await;

                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    bench_run(&mut j).await;
                    duration += start.elapsed();
                }
                j.destroy().await.unwrap();

                duration
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_replay
}
