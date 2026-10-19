//! Steady-state cost of appending one item and making it durable.

use crate::{get_fixed_journal, get_variable_journal};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use commonware_storage::journal::contiguous::Mutable;
use commonware_utils::{NZU64, sequence::FixedBytes};
use criterion::{Criterion, criterion_group};
use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

/// Partition used by this benchmark.
const PARTITION: &str = "append-sync-partition";

/// Size of each item in bytes.
const ITEM_SIZE: usize = 256;

/// Items per blob or section, so steady state includes starting new ones.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(64);

/// How a cycle makes its item durable.
#[derive(Clone, Copy)]
enum Mode {
    Sync,
    StartSync,
    Commit,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::StartSync => "start_sync",
            Self::Commit => "commit",
        }
    }
}

/// Append `item` and make it durable, awaiting a started sync's handle.
async fn cycle<J: Mutable<Item = FixedBytes<ITEM_SIZE>>>(
    journal: J,
    item: &FixedBytes<ITEM_SIZE>,
    mode: Mode,
) -> J {
    let (journal, _) = journal.append(item).await.unwrap();
    match mode {
        Mode::Sync => journal.sync().await.unwrap(),
        Mode::StartSync => {
            let (journal, handle) = journal.start_sync().await.unwrap();
            handle.await.unwrap();
            journal
        }
        Mode::Commit => journal.commit().await.unwrap(),
    }
}

/// Time `iters` cycles after populating both copies of the journal's checkpoint, then destroy it.
async fn run<J: Mutable<Item = FixedBytes<ITEM_SIZE>>>(
    mut journal: J,
    iters: u64,
    mode: Mode,
) -> Duration {
    let item = FixedBytes::new([0xAB; ITEM_SIZE]);
    for _ in 0..2 {
        journal = cycle(journal, &item, mode).await;
    }
    let mut elapsed = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        journal = cycle(journal, &item, mode).await;
        elapsed += start.elapsed();
    }
    journal.destroy().await.unwrap();
    elapsed
}

fn bench_append_sync(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for fixed in [true, false] {
        // `commit` makes items durable without updating the checkpoint, so it is a control.
        for mode in [Mode::Sync, Mode::StartSync, Mode::Commit] {
            let kind = if fixed { "fixed" } else { "variable" };
            c.bench_function(
                &format!("{}/journal={kind} mode={}", module_path!(), mode.name()),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let storage = ctx.child("storage");
                        if fixed {
                            let journal =
                                get_fixed_journal::<ITEM_SIZE>(storage, PARTITION, ITEMS_PER_BLOB)
                                    .await;
                            run(journal, iters, mode).await
                        } else {
                            let journal = get_variable_journal::<ITEM_SIZE>(
                                storage,
                                PARTITION,
                                ITEMS_PER_BLOB,
                            )
                            .await;
                            run(journal, iters, mode).await
                        }
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_append_sync
}
