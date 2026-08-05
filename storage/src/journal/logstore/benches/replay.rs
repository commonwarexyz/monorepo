//! Sequential replay of every index entry after a multi-section preload.

use crate::utils::{Entry, init_file, init_segment, random_value};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

/// Value size for every preloaded entry.
const SIZE: usize = 4_096;

/// Preloaded entries, spread over [SECTIONS] sections.
const ITEMS: u64 = 512;

/// Sections the preload spreads across.
const SECTIONS: u64 = 4;

/// Read-ahead handed to `replay`.
const BUFFER: usize = 64 * 1_024;

async fn run_file(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_file::<SIZE>(&ctx).await;
    let value = random_value::<SIZE>();
    for id in 0..ITEMS {
        (journal, _, _, _) = journal
            .append(id % SECTIONS, Entry::new(id), &value)
            .await
            .expect("failed to append");
    }
    journal = journal.sync_all().await.expect("failed to sync");

    let mut duration = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let mut replay = journal
            .replay(0, 0, NZUsize!(BUFFER))
            .await
            .expect("failed to replay");
        let mut replayed = 0;
        while let Some(item) = replay.next().await {
            item.expect("failed to read entry");
            replayed += 1;
        }
        assert_eq!(replayed, ITEMS);
        journal = replay.finish().expect("failed to finish");
        duration += start.elapsed();
    }
    journal.destroy().await.expect("failed to destroy");
    duration
}

async fn run_segment(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_segment::<SIZE>(&ctx).await;
    let value = random_value::<SIZE>();
    for id in 0..ITEMS {
        (journal, _, _, _) = journal
            .append(id % SECTIONS, Entry::new(id), &value)
            .await
            .expect("failed to append");
    }
    journal = journal.sync().await.expect("failed to sync");

    let mut duration = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let mut replay = journal
            .replay(0, 0, NZUsize!(BUFFER))
            .await
            .expect("failed to replay");
        let mut replayed = 0;
        while let Some(item) = replay.next().await {
            item.expect("failed to read entry");
            replayed += 1;
        }
        assert_eq!(replayed, ITEMS);
        journal = replay.finish().expect("failed to finish");
        duration += start.elapsed();
    }
    journal.destroy().await.expect("failed to destroy");
    duration
}

fn bench_replay(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for backend in ["file", "segment"] {
        c.bench_function(
            &format!(
                "{}/items={} size={} sections={} backend={}",
                module_path!(),
                ITEMS,
                SIZE,
                SECTIONS,
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
    targets = bench_replay
}
