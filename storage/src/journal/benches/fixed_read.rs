use commonware_runtime::tokio::{Blob, Config as TConfig, Context, Executor};
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::array::FixedBytes;
use criterion::{async_executor::AsyncExecutor, black_box, criterion_group, BatchSize, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 10000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Number of items to write to the journal during setup before invoking the benchmark.
const ITEMS_TO_WRITE: u64 = 10000000;

/// Setup the benchmark by writing ITEMS_TO_WRITE random items to a journal of items with ITEM_SIZE
/// bytes each. The journal is configured to use ITEMS_PER_BLOB items per blob.
async fn bench_init(context: Context) -> Journal<Blob, Context, FixedBytes<ITEM_SIZE>> {
    let journal_config = JConfig {
        partition: PARTITION.to_string(),
        items_per_blob: ITEMS_PER_BLOB,
    };

    // Initialize the journal.
    let mut journal = Journal::init(context, journal_config).await.unwrap();
    let sz = journal.size().await.unwrap();
    assert_eq!(sz, 0);

    // Append ITEMS_TO_WRITE random items to the journal
    let mut rng = StdRng::seed_from_u64(0);
    let mut arr = [0; ITEM_SIZE];
    for _ in 0..ITEMS_TO_WRITE {
        rng.fill_bytes(&mut arr);
        journal
            .append(FixedBytes::new(arr))
            .await
            .expect("failed to append data");
    }
    journal.sync().await.unwrap();

    journal
}

async fn bench_setup(context: Context) -> Journal<Blob, Context, FixedBytes<ITEM_SIZE>> {
    let journal_config = JConfig {
        partition: PARTITION.to_string(),
        items_per_blob: ITEMS_PER_BLOB,
    };

    Journal::init(context, journal_config).await.unwrap()
}

async fn bench_run_serial(
    journal: &Journal<Blob, Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) {
    let mut rng = StdRng::seed_from_u64(0);

    for _ in 0..items_to_read {
        let pos = rng.gen_range(0..ITEMS_TO_WRITE);
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

async fn bench_run_parallel(
    journal: &Journal<Blob, Context, FixedBytes<ITEM_SIZE>>,
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

fn bench_fixed_read(c: &mut Criterion) {
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

        c.bench_function(&format!("{}/parallel/items={}", module_path!(), n), |b| {
            b.to_async(&executor).iter_batched(
                || bench_setup(context.clone()),
                |journal| async {
                    let j = journal.await;
                    bench_run_parallel(&j, n).await;
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_fixed_read
}
