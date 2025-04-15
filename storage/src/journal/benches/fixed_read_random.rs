use super::{get_random_journal, write_random_journal};
use commonware_runtime::tokio::{Config as TConfig, Context, Executor};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{async_executor::AsyncExecutor, black_box, criterion_group, BatchSize, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 10_000;

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 5_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

async fn bench_init(context: Context) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    write_random_journal::<ITEM_SIZE>(
        context.clone(),
        PARTITION,
        ITEMS_PER_BLOB,
        ITEMS_TO_WRITE,
        true,
    )
    .await
}

async fn bench_setup(context: Context) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let journal = get_random_journal::<ITEM_SIZE>(context, PARTITION, ITEMS_PER_BLOB).await;
    assert_eq!(journal.size().await.unwrap(), ITEMS_TO_WRITE);

    journal
}

/// Read `items_to_read` random items from the given `journal`, awaiting each
/// result before continuing.
async fn bench_run_serial(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: usize) {
    let mut rng = StdRng::seed_from_u64(0);

    for _ in 0..items_to_read {
        let pos = rng.gen_range(0..ITEMS_TO_WRITE);
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Concurrently read (via try_join_all) `items_to_read` random items from the given `journal`.
async fn bench_run_concurrent(
    journal: &Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) {
    let mut rng = StdRng::seed_from_u64(0);

    let mut futures = Vec::with_capacity(items_to_read);
    for _ in 0..items_to_read {
        let pos = rng.gen_range(0..ITEMS_TO_WRITE);
        futures.push(journal.read(pos));
    }
    try_join_all(futures).await.expect("failed to read data");
}

fn bench_fixed_read_random(c: &mut Criterion) {
    let runtime_cfg = TConfig::default();
    let (executor, context) = Executor::init(runtime_cfg.clone());
    executor.block_on(async {
        let journal = bench_init(context.clone()).await;
        let sz = journal.size().await.unwrap();
        assert_eq!(sz, ITEMS_TO_WRITE);
    });

    for n in [100, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        c.bench_function(&format!("{}/serial/items={}", module_path!(), n), |b| {
            b.to_async(&executor).iter_batched(
                || bench_setup(context.clone()),
                |journal| async {
                    let j = journal.await;
                    bench_run_serial(&j, n).await;
                },
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}/concurrent/items={}", module_path!(), n), |b| {
            b.to_async(&executor).iter_batched(
                || bench_setup(context.clone()),
                |journal| async {
                    let j = journal.await;
                    bench_run_concurrent(&j, n).await;
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_read_random
}
