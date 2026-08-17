use crate::{
    ITEM_SIZE, ITEMS_PER_BLOB, REPLAY_POLICIES, ReplayPolicy, append_fixed_random_data,
    get_variable_journal,
};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::journal::contiguous::{Contiguous as _, variable::Journal};
use commonware_utils::{NZUsize, sequence::FixedBytes};
use criterion::{Criterion, criterion_group};
use futures::{StreamExt, pin_mut};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "variable-test-partition";

/// Replay all items in the given `journal`.
async fn bench_run(
    journal: Journal<Context, FixedBytes<ITEM_SIZE>>,
    buffer: usize,
    policy: ReplayPolicy,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let (journal, reader) = journal.snapshot().await.unwrap();
    let stream = reader
        .replay(0, NZUsize!(buffer), policy.options())
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
    journal
}

/// Benchmark the replaying of items from a variable journal containing exactly that
/// number of items.
fn bench_variable_replay(c: &mut Criterion) {
    for items in [1_000, 10_000, 100_000, 500_000] {
        let cfg = Config::default();
        let runner = tokio::Runner::new(cfg.clone());
        for buffer in [16_384, 65_536, 1_048_576] {
            for policy in REPLAY_POLICIES {
                c.bench_function(
                    &format!(
                        "{}/items={} buffer={} size={} read_options={}",
                        module_path!(),
                        items,
                        buffer,
                        ITEM_SIZE,
                        policy.label()
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut duration = Duration::ZERO;
                            for _ in 0..iters {
                                // A fresh journal and page cache give both arms equivalent
                                // initial state before the one-pass replay.
                                let journal = get_variable_journal(
                                    ctx.child("storage"),
                                    PARTITION,
                                    ITEMS_PER_BLOB,
                                )
                                .await;
                                let journal =
                                    append_fixed_random_data::<_, ITEM_SIZE>(journal, items).await;

                                let start = Instant::now();
                                let journal = bench_run(journal, buffer, policy).await;
                                duration += start.elapsed();

                                journal.destroy().await.unwrap();
                            }
                            duration
                        });
                    },
                );
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_replay
}
