use crate::{append_fixed_random_data, get_variable_journal, ITEMS_PER_BLOB, ITEM_SIZE};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context, Runner},
    Runner as _,
};
use commonware_storage::journal::contiguous::variable::Journal;
use commonware_utils::{sequence::FixedBytes, NZUsize};
use criterion::{criterion_group, Criterion};
use futures::{pin_mut, StreamExt};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "variable_test_partition";

/// Replay all items in the given `journal`.
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, buffer: usize) {
    let stream = journal
        .replay(0, NZUsize!(buffer))
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

/// Benchmark the replaying of items from a variable journal containing exactly that
/// number of items.
fn bench_variable_replay(c: &mut Criterion) {
    for items in [1_000, 10_000, 100_000, 500_000] {
        // Create a config we can use across all benchmarks (with a fixed `storage_directory`),
        // allowing the same test file to be re-used.
        let cfg = Config::default();

        // Generate a large temp journal with random data.
        let runner = Runner::new(cfg.clone());
        runner.start(|ctx| async move {
            let mut j = get_variable_journal(ctx, PARTITION, ITEMS_PER_BLOB).await;
            append_fixed_random_data::<_, ITEM_SIZE>(&mut j, items).await;
            j.sync().await.unwrap();
        });

        // Run the benchmarks.
        let runner = tokio::Runner::new(cfg.clone());
        for buffer in [16_384, 65_536, 1_048_576] {
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
                        let j = get_variable_journal(ctx.clone(), PARTITION, ITEMS_PER_BLOB).await;
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

        // Clean up the temp journal.
        let runner = Runner::new(cfg);
        runner.start(|context| async move {
            let j = get_variable_journal::<ITEM_SIZE>(context, PARTITION, ITEMS_PER_BLOB).await;
            j.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_replay
}
