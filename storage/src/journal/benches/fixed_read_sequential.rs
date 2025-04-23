use super::append_random_journal;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{black_box, criterion_group, Criterion};
use std::time::{Duration, Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 100_000;

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 1_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Sequentially read `items_to_read` items in the given `journal` starting from item 0.
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: u64) {
    for pos in 0..items_to_read {
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Benchmark the sequential read of ITEMS_TO_WRITE (and then ITEMS_TO_WRITE*2)
/// items from a journal containing exactly that number of items.
fn bench_fixed_read_sequential(c: &mut Criterion) {
    let executor = tokio::Executor::default();

    c.bench_function(
        &format!("{}/items={}", module_path!(), ITEMS_TO_WRITE),
        |b| {
            b.to_async(&executor).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let j = append_random_journal::<ITEM_SIZE>(
                    ctx.clone(),
                    PARTITION,
                    ITEMS_PER_BLOB,
                    ITEMS_TO_WRITE,
                )
                .await;
                let sz = j.size().await.unwrap();
                assert_eq!(sz, ITEMS_TO_WRITE);

                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    bench_run(&j, ITEMS_TO_WRITE).await;
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
                let j = append_random_journal::<ITEM_SIZE>(
                    ctx.clone(),
                    PARTITION,
                    ITEMS_PER_BLOB,
                    ITEMS_TO_WRITE * 2,
                )
                .await;
                let sz = j.size().await.unwrap();
                assert_eq!(sz, ITEMS_TO_WRITE * 2);

                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    bench_run(&j, ITEMS_TO_WRITE * 2).await;
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
    targets = bench_fixed_read_sequential
}
