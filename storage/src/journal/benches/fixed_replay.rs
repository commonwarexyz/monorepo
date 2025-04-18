use super::{get_random_journal, write_random_journal};
use commonware_runtime::tokio::{Config as TConfig, Context, Executor};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{async_executor::AsyncExecutor, black_box, criterion_group, BatchSize, Criterion};
use futures::{pin_mut, StreamExt};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 100_000;

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 1_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

async fn bench_init(context: Context) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    write_random_journal::<ITEM_SIZE>(
        context.clone(),
        PARTITION,
        ITEMS_PER_BLOB,
        ITEMS_TO_WRITE,
        false,
    )
    .await
}

async fn bench_setup(context: Context) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    get_random_journal::<ITEM_SIZE>(context, PARTITION, ITEMS_PER_BLOB).await
}

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
    let runtime_cfg = TConfig::default();
    let (executor, context) = Executor::init(runtime_cfg.clone());
    executor.block_on(async {
        let journal = bench_init(context.clone()).await;
        let sz = journal.size().await.unwrap();
        assert_eq!(sz, ITEMS_TO_WRITE);
    });

    c.bench_function(
        &format!("{}/items={}", module_path!(), ITEMS_TO_WRITE),
        |b| {
            b.to_async(&executor).iter_batched(
                || bench_setup(context.clone()),
                |journal| async {
                    let mut j = journal.await;
                    bench_run(&mut j).await;
                },
                BatchSize::SmallInput,
            );
        },
    );

    // Repeat the benchmark only with double the number of items.
    executor.block_on(async {
        let journal = bench_init(context.clone()).await;
        let sz = journal.size().await.unwrap();
        assert_eq!(sz, ITEMS_TO_WRITE * 2);
    });

    c.bench_function(
        &format!("{}/items={}", module_path!(), ITEMS_TO_WRITE * 2),
        |b| {
            b.to_async(&executor).iter_batched(
                || bench_setup(context.clone()),
                |journal| async {
                    let mut j = journal.await;
                    bench_run(&mut j).await;
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_replay
}
