//! Commit latency. Single-section rows append and sync one value per commit;
//! multi-section rows append one value to each of [SECTIONS] sections and then
//! sync once (the per-file backend syncs every touched section).

use crate::utils::{Entry, init_file, init_segment, random_value};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

/// Section receiving every single-section append.
const SECTION: u64 = 1;

/// Sections written by each multi-section batch.
const SECTIONS: u64 = 4;

async fn run_file<const N: usize>(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_file::<N>(&ctx).await;
    let value = random_value::<N>();
    let start = Instant::now();
    for id in 0..iters {
        (journal, _, _, _) = journal
            .append(SECTION, Entry::new(id), &value)
            .await
            .expect("failed to append");
        journal = journal.sync(SECTION).await.expect("failed to sync");
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

async fn run_segment<const N: usize>(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_segment::<N>(&ctx).await;
    let value = random_value::<N>();
    let start = Instant::now();
    for id in 0..iters {
        (journal, _, _, _) = journal
            .append(SECTION, Entry::new(id), &value)
            .await
            .expect("failed to append");
        journal = journal.sync().await.expect("failed to sync");
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

async fn run_file_multi<const N: usize>(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_file::<N>(&ctx).await;
    let value = random_value::<N>();
    let start = Instant::now();
    for id in 0..iters {
        for section in 1..=SECTIONS {
            (journal, _, _, _) = journal
                .append(section, Entry::new(id), &value)
                .await
                .expect("failed to append");
        }
        for section in 1..=SECTIONS {
            journal = journal.sync(section).await.expect("failed to sync");
        }
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

async fn run_segment_multi<const N: usize>(iters: u64) -> Duration {
    let ctx = context::get::<commonware_runtime::tokio::Context>();
    let mut journal = init_segment::<N>(&ctx).await;
    let value = random_value::<N>();
    let start = Instant::now();
    for id in 0..iters {
        for section in 1..=SECTIONS {
            (journal, _, _, _) = journal
                .append(section, Entry::new(id), &value)
                .await
                .expect("failed to append");
        }
        journal = journal.sync().await.expect("failed to sync");
    }
    let elapsed = start.elapsed();
    journal.destroy().await.expect("failed to destroy");
    elapsed
}

fn bench_size<const N: usize>(c: &mut Criterion, runner: &tokio::Runner) {
    for backend in ["file", "segment"] {
        c.bench_function(
            &format!("{}/size={} backend={}", module_path!(), N, backend),
            |b| {
                b.to_async(runner).iter_custom(move |iters| async move {
                    match backend {
                        "file" => run_file::<N>(iters).await,
                        _ => run_segment::<N>(iters).await,
                    }
                });
            },
        );
    }
}

fn bench_multi_size<const N: usize>(c: &mut Criterion, runner: &tokio::Runner) {
    for backend in ["file", "segment"] {
        c.bench_function(
            &format!(
                "{}/sections={} size={} backend={}",
                module_path!(),
                SECTIONS,
                N,
                backend
            ),
            |b| {
                b.to_async(runner).iter_custom(move |iters| async move {
                    match backend {
                        "file" => run_file_multi::<N>(iters).await,
                        _ => run_segment_multi::<N>(iters).await,
                    }
                });
            },
        );
    }
}

fn bench_commit(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    bench_size::<4_096>(c, &runner);
    bench_size::<65_536>(c, &runner);
    bench_size::<1_048_576>(c, &runner);
    bench_multi_size::<4_096>(c, &runner);
    bench_multi_size::<65_536>(c, &runner);
    bench_multi_size::<1_048_576>(c, &runner);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_commit
}
