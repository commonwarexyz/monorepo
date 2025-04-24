use super::append_random_data;
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

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Replay all items in the given `journal`.
async fn bench_run(journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: u64) {
    let concurrency = (items_to_read / ITEMS_PER_BLOB) as usize;
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

/// Benchmark the replaying of items from a journal containing exactly that
/// number of items.
fn bench_fixed_replay(c: &mut Criterion) {
    let executor = tokio::Executor::default();
    for items in [1_000, 10_000, 100_000, 500_000] {
        c.bench_function(
            &format!("{}/items={} size={}", module_path!(), items, ITEM_SIZE),
            |b| {
                b.to_async(&executor).iter_custom(|iters| async move {
                    // Append random data to the journal
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut j = append_random_data::<ITEM_SIZE>(
                        ctx.clone(),
                        PARTITION,
                        ITEMS_PER_BLOB,
                        items,
                    )
                    .await;
                    let sz = j.size().await.unwrap();
                    assert_eq!(sz, items);

                    // Run the benchmark
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        bench_run(&mut j, items).await;
                        duration += start.elapsed();
                    }

                    // Destroy the journal after appending to avoid polluting the next iteration
                    j.destroy().await.unwrap();

                    duration
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_replay
}
