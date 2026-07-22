use crate::{
    HOT_PAGE_CACHE_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, append_fixed_random_data, get_variable_journal,
};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    tokio::{Config, Context, Runner},
};
use commonware_storage::journal::contiguous::{Contiguous as _, variable::Journal};
use commonware_utils::{NZU64, sequence::FixedBytes, test_rng};
use criterion::{Criterion, criterion_group};
use futures::future::try_join_all;
use rand::RngExt as _;
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "variable-random-test-partition";

/// Value of items_per_section to use in the journal config.
const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(10_000);

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 5_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Position stride that touches every data page when warming the page cache. Entries are
/// ITEM_SIZE bytes plus a one-byte length prefix, so consecutive warmed positions are at
/// most one page apart (and every offsets-journal page is touched along the way).
const WARM_STRIDE: usize = (PAGE_SIZE.get() as usize) / (ITEM_SIZE + 1);

/// Read positions spaced closely enough to touch every page, fully populating the
/// page cache before measurement in the hot-cache variants.
async fn warm_page_cache(
    journal: Journal<Context, FixedBytes<ITEM_SIZE>>,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let (journal, reader) = journal.snapshot().await.unwrap();
    for pos in (0..ITEMS_TO_WRITE).step_by(WARM_STRIDE) {
        black_box(reader.read(pos).await.expect("failed to read data"));
    }
    journal
}

/// Read `items_to_read` random items from the given `journal`, awaiting each
/// result before continuing.
async fn bench_run_serial(
    journal: Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let (journal, reader) = journal.snapshot().await.unwrap();
    let mut rng = test_rng();
    for _ in 0..items_to_read {
        let pos = rng.random_range(0..ITEMS_TO_WRITE);
        black_box(reader.read(pos).await.expect("failed to read data"));
    }
    journal
}

/// Concurrently read (via try_join_all) `items_to_read` random items from the given `journal`.
async fn bench_run_concurrent(
    journal: Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let (journal, reader) = journal.snapshot().await.unwrap();
    let mut rng = test_rng();
    let mut futures = Vec::with_capacity(items_to_read);
    for _ in 0..items_to_read {
        let pos = rng.random_range(0..ITEMS_TO_WRITE);
        futures.push(reader.read(pos));
    }
    try_join_all(futures).await.expect("failed to read data");
    journal
}

/// Batch-read `items_to_read` random items via `read_many`.
async fn bench_run_read_many(
    journal: Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let (journal, reader) = journal.snapshot().await.unwrap();
    let mut rng = test_rng();
    let mut positions: Vec<u64> = (0..items_to_read)
        .map(|_| rng.random_range(0..ITEMS_TO_WRITE))
        .collect();
    positions.sort_unstable();
    positions.dedup();
    black_box(
        reader
            .read_many(&positions)
            .await
            .expect("failed to read data"),
    );
    journal
}

fn bench_variable_read_random(c: &mut Criterion) {
    let cfg = Config::default();
    let mut initialized = false;
    let runner = tokio::Runner::new(cfg.clone());
    for mode in ["serial", "concurrent", "read_many"] {
        for items_to_read in [100, 1_000, 10_000, 100_000] {
            for cache in ["cold", "hot"] {
                let page_cache_size: NonZeroUsize = match cache {
                    "cold" => PAGE_CACHE_SIZE,
                    "hot" => HOT_PAGE_CACHE_SIZE,
                    _ => unreachable!(),
                };
                c.bench_function(
                    &format!(
                        "{}/mode={} items={} size={} cache={}",
                        module_path!(),
                        mode,
                        items_to_read,
                        ITEM_SIZE,
                        cache
                    ),
                    |b| {
                        // Setup: populate journal (once, on first sample).
                        if !initialized {
                            Runner::new(cfg.clone()).start(|ctx| async move {
                                let j = get_variable_journal(
                                    ctx,
                                    PARTITION,
                                    ITEMS_PER_SECTION,
                                    PAGE_CACHE_SIZE,
                                )
                                .await;
                                append_fixed_random_data::<_, ITEM_SIZE>(j, ITEMS_TO_WRITE).await;
                            });
                            initialized = true;
                        }

                        // Benchmark: measure read time.
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut j = get_variable_journal(
                                ctx.child("storage"),
                                PARTITION,
                                ITEMS_PER_SECTION,
                                page_cache_size,
                            )
                            .await;
                            if cache == "hot" {
                                j = warm_page_cache(j).await;
                            }
                            let mut duration = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                j = match mode {
                                    "serial" => bench_run_serial(j, items_to_read).await,
                                    "concurrent" => bench_run_concurrent(j, items_to_read).await,
                                    "read_many" => bench_run_read_many(j, items_to_read).await,
                                    _ => unreachable!(),
                                };
                                duration += start.elapsed();
                            }
                            duration
                        });
                    },
                );
            }
        }
    }

    // Cleanup: destroy journal.
    if initialized {
        Runner::new(cfg).start(|context| async move {
            let j = get_variable_journal::<ITEM_SIZE>(
                context,
                PARTITION,
                ITEMS_PER_SECTION,
                PAGE_CACHE_SIZE,
            )
            .await;
            j.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_read_random
}
