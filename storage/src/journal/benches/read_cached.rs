use crate::{append_fixed_random_data, get_fixed_journal, get_variable_journal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::contiguous::{Contiguous, Mutable};
use commonware_utils::{NZU64, test_rng};
use criterion::{Criterion, criterion_group};
use rand::seq::SliceRandom as _;
use std::{
    hint::black_box,
    num::NonZeroU64,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "read-cached";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000);

/// Number of items in the journal. Small enough that every page fits in the page cache.
const ITEMS: u64 = 20_000;

/// Every position in the journal, in a fixed random order.
fn shuffled_positions() -> Vec<u64> {
    let mut positions: Vec<u64> = (0..ITEMS).collect();
    positions.shuffle(&mut test_rng());
    positions
}

/// Read every position in `positions`, awaiting each result before continuing.
async fn read_all<J: Contiguous>(journal: &J, positions: &[u64]) {
    for &pos in positions {
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Time `iters` passes of random reads over `journal` once every item is served from memory
/// (the page cache or the write buffer), then destroy it.
async fn time_reads<J: Mutable>(journal: J, iters: u64) -> Duration {
    let positions = shuffled_positions();
    read_all(&journal, &positions).await;
    for &pos in &positions {
        assert!(
            journal.try_read_sync(pos).is_some(),
            "position {pos} is not in memory"
        );
    }
    let start = Instant::now();
    for _ in 0..iters {
        read_all(&journal, &positions).await;
    }
    let elapsed = start.elapsed();
    journal.destroy().await.unwrap();
    elapsed
}

/// Benchmark random reads of a `journal` ("fixed" or "variable") of `SIZE`-byte items, all
/// served from memory.
fn bench_size<const SIZE: usize>(c: &mut Criterion, runner: &tokio::Runner, journal: &str) {
    c.bench_function(
        &format!("{}/journal={journal} size={SIZE}", module_path!()),
        |b| {
            b.to_async(runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                match journal {
                    "fixed" => {
                        let j = get_fixed_journal::<SIZE>(ctx, PARTITION, ITEMS_PER_BLOB).await;
                        time_reads(append_fixed_random_data::<_, SIZE>(j, ITEMS).await, iters).await
                    }
                    "variable" => {
                        let j = get_variable_journal::<SIZE>(ctx, PARTITION, ITEMS_PER_BLOB).await;
                        time_reads(append_fixed_random_data::<_, SIZE>(j, ITEMS).await, iters).await
                    }
                    _ => unreachable!(),
                }
            });
        },
    );
}

fn bench_read_cached(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    bench_size::<8>(c, &runner, "fixed");
    bench_size::<32>(c, &runner, "fixed");
    bench_size::<64>(c, &runner, "fixed");
    bench_size::<128>(c, &runner, "fixed");
    bench_size::<129>(c, &runner, "fixed");
    bench_size::<256>(c, &runner, "fixed");
    bench_size::<32>(c, &runner, "variable");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_read_cached
}
