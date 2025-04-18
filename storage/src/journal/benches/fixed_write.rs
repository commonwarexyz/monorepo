use commonware_runtime::tokio::{Config as TConfig, Context, Executor};
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::array::FixedBytes;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 10_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Number of items to write to the journal in each benchmark iteration.
const ITEMS_TO_WRITE: usize = 500_000;

async fn bench_setup(context: Context) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let partition = "test_partition";

    let journal_config = JConfig {
        partition: partition.to_string(),
        items_per_blob: ITEMS_PER_BLOB,
    };

    let mut j = Journal::init(context, journal_config).await.unwrap();
    // Ensure each sample starts writing from position 0.
    j.prune(0).await.unwrap();

    j
}

async fn bench_run(journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>) {
    let mut rng = StdRng::seed_from_u64(0);
    // Append a ton of random items to the journal
    let mut arr = [0; ITEM_SIZE];
    for _ in 0..ITEMS_TO_WRITE {
        rng.fill_bytes(&mut arr);
        journal
            .append(FixedBytes::new(arr))
            .await
            .expect("failed to append data");
    }
}

fn bench_fixed_write(c: &mut Criterion) {
    let runtime_cfg = TConfig::default();
    let (executor, context) = Executor::init(runtime_cfg.clone());

    c.bench_function(module_path!(), |b| {
        b.to_async(&executor).iter_batched(
            || bench_setup(context.clone()),
            |journal| async {
                let mut j = journal.await;
                bench_run(&mut j).await;
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_write
}
