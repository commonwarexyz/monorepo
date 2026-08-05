//! Rewind-heavy churn: batches of appends synced, then half the section
//! rewound away, repeatedly. Sized under the segment target by default, so
//! the cleaner stays idle (the no-cleaner baseline); supervised bake-off runs
//! scale `cycles` up until rotation and cleaning engage.

use crate::utils::{Entry, init_file, init_segment, random_value};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

/// Value size for every churn append.
const SIZE: usize = 4_096;

/// Appends per cycle.
const APPENDS: u64 = 8;

/// Append-sync-rewind rounds per iteration.
const CYCLES: u64 = 8;

/// Section receiving the churn.
const SECTION: u64 = 1;

/// Index bytes of one entry.
const CHUNK: u64 = crate::utils::SegmentJournal::<SIZE>::CHUNK_SIZE as u64;

async fn run_file(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_file::<SIZE>(&ctx).await;
    let value = random_value::<SIZE>();
    let mut id = 0;
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..CYCLES {
            for _ in 0..APPENDS {
                (journal, _, _, _) = journal
                    .append(SECTION, Entry::new(id), &value)
                    .await
                    .expect("failed to append");
                id += 1;
            }
            journal = journal.sync(SECTION).await.expect("failed to sync");
            let entries = journal.size(SECTION).expect("failed to size") / CHUNK;
            journal = journal
                .rewind_section(SECTION, entries / 2 * CHUNK)
                .await
                .expect("failed to rewind");
        }
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

async fn run_segment(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_segment::<SIZE>(&ctx).await;
    let value = random_value::<SIZE>();
    let mut id = 0;
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..CYCLES {
            for _ in 0..APPENDS {
                (journal, _, _, _) = journal
                    .append(SECTION, Entry::new(id), &value)
                    .await
                    .expect("failed to append");
                id += 1;
            }
            journal = journal.sync().await.expect("failed to sync");
            let entries = journal.size(SECTION).expect("failed to size") / CHUNK;
            journal = journal
                .rewind_section(SECTION, entries / 2 * CHUNK)
                .await
                .expect("failed to rewind");
        }
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

fn bench_churn(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for backend in ["file", "segment"] {
        c.bench_function(
            &format!(
                "{}/size={} appends={} cycles={} backend={}",
                module_path!(),
                SIZE,
                APPENDS,
                CYCLES,
                backend
            ),
            |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    match backend {
                        "file" => run_file(iters).await,
                        _ => run_segment(iters).await,
                    }
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_churn
}
