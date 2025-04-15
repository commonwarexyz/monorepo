use super::{get_random_journal, write_random_journal};
use commonware_runtime::tokio::{Config as TConfig, Context, Executor};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{async_executor::AsyncExecutor, black_box, criterion_group, BatchSize, Criterion};

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

/// Sequentially read `items_to_read` items in the given `journal` starting from item 0.
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: u64) {
    for pos in 0..items_to_read {
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Benchmark the sequential read of ITEMS_TO_WRITE (and then ITEMS_TO_WRITE*2)
/// items from a journal containing exactly that number of items.
fn bench_fixed_read_sequential(c: &mut Criterion) {
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
                    let j = journal.await;
                    bench_run(&j, ITEMS_TO_WRITE).await;
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
                    let j = journal.await;
                    bench_run(&j, ITEMS_TO_WRITE * 2).await;
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_read_sequential
}
