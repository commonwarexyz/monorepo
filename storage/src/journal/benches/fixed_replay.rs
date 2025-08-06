use super::{append_random_data, get_journal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context, Runner},
    Runner as _,
};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::{sequence::FixedBytes, NZUsize};
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
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, buffer: usize) {
    let stream = journal
        .replay(NZUsize!(buffer), 0)
        .await
        .expect("failed to replay journal");
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => {
                black_box(item);
            }
            Err(err) => panic!("Failed to read item: {err}"),
        }
    }
}

/// Benchmark the replaying of items from a journal containing exactly that
/// number of items.
fn bench_fixed_replay(c: &mut Criterion) {
    for items in [1_000, 10_000, 100_000, 500_000] {
        // Create a config we can use across all benchmarks (with a fixed `storage_directory`), allowing the
        // same test file to be re-used.
        let cfg = Config::default();

        // Generate a large temp journal with random data.
        let runner = Runner::new(cfg.clone());
        runner.start(|ctx| async move {
            // Create a large temp journal with random data.
            let mut j = get_journal(ctx, PARTITION, ITEMS_PER_BLOB).await;
            append_random_data::<ITEM_SIZE>(&mut j, items).await;
            j.close().await.unwrap();
        });

        // Run the benchmarks
        let runner = tokio::Runner::new(cfg.clone());
        for buffer in [128, 16_384, 65_536, 1_048_576] {
            c.bench_function(
                &format!(
                    "{}/items={} buffer={} size={}",
                    module_path!(),
                    items,
                    buffer,
                    ITEM_SIZE
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let j = get_journal(ctx.clone(), PARTITION, ITEMS_PER_BLOB).await;
                        let mut duration = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            bench_run(&j, buffer).await;
                            duration += start.elapsed();
                        }

                        duration
                    });
                },
            );
        }

        // Clean up the temp journal
        let runner = Runner::new(cfg);
        runner.start(|context| async move {
            let j = get_journal::<ITEM_SIZE>(context, PARTITION, ITEMS_PER_BLOB).await;
            j.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_replay
}
