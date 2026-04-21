use crate::{append_fixed_random_data, get_fixed_journal, ITEMS_PER_BLOB, ITEM_SIZE};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context, Runner},
    Runner as _, Supervisor,
};
use commonware_storage::journal::contiguous::{fixed::Journal, Reader as _};
use commonware_utils::{sequence::FixedBytes, NZUsize};
use criterion::{criterion_group, Criterion};
use futures::{pin_mut, StreamExt};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "test-partition";

/// Replay all items in the given `journal`.
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, buffer: usize) {
    let reader = journal.reader().await;
    let stream = reader
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
        let cfg = Config::default();
        let mut initialized = false;
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
                    // Setup: populate journal (once, on first sample).
                    if !initialized {
                        Runner::new(cfg.clone()).start(|ctx| async move {
                            let mut j = get_fixed_journal(ctx, PARTITION, ITEMS_PER_BLOB).await;
                            append_fixed_random_data::<_, ITEM_SIZE>(&mut j, items).await;
                            j.sync().await.unwrap();
                        });
                        initialized = true;
                    }

                    // Benchmark: measure replay time.
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let j = get_fixed_journal(ctx.child("journal"), PARTITION, ITEMS_PER_BLOB)
                            .await;
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

        // Cleanup: destroy journal.
        if initialized {
            Runner::new(cfg).start(|context| async move {
                let j = get_fixed_journal::<ITEM_SIZE>(context, PARTITION, ITEMS_PER_BLOB).await;
                j.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_replay
}
