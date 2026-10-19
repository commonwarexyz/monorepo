use crate::{append_fixed_random_data, get_fixed_journal, get_variable_journal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::contiguous::Contiguous;
use commonware_utils::{NZU64, test_rng};
use criterion::{Criterion, criterion_group};
use rand::seq::SliceRandom as _;
use std::{hint::black_box, num::NonZeroU64, time::Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "fixed-read-cached";

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

/// Benchmark random reads of a fixed journal of `SIZE`-byte items, all served from the page cache.
fn bench_fixed<const SIZE: usize>(c: &mut Criterion, runner: &tokio::Runner) {
    c.bench_function(
        &format!("{}/journal=fixed size={SIZE}", module_path!()),
        |b| {
            b.to_async(runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let j = get_fixed_journal::<SIZE>(ctx, PARTITION, ITEMS_PER_BLOB).await;
                let j = append_fixed_random_data::<_, SIZE>(j, ITEMS).await;
                let positions = shuffled_positions();
                read_all(&j, &positions).await;
                let start = Instant::now();
                for _ in 0..iters {
                    read_all(&j, &positions).await;
                }
                let elapsed = start.elapsed();
                j.destroy().await.unwrap();
                elapsed
            });
        },
    );
}

/// Benchmark random reads of a variable journal of `SIZE`-byte items, all served from the page
/// cache.
fn bench_variable<const SIZE: usize>(c: &mut Criterion, runner: &tokio::Runner) {
    c.bench_function(
        &format!("{}/journal=variable size={SIZE}", module_path!()),
        |b| {
            b.to_async(runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let j = get_variable_journal::<SIZE>(ctx, PARTITION, ITEMS_PER_BLOB).await;
                let j = append_fixed_random_data::<_, SIZE>(j, ITEMS).await;
                let positions = shuffled_positions();
                read_all(&j, &positions).await;
                let start = Instant::now();
                for _ in 0..iters {
                    read_all(&j, &positions).await;
                }
                let elapsed = start.elapsed();
                j.destroy().await.unwrap();
                elapsed
            });
        },
    );
}

fn bench_fixed_read_cached(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    bench_fixed::<8>(c, &runner);
    bench_fixed::<32>(c, &runner);
    bench_fixed::<64>(c, &runner);
    bench_fixed::<128>(c, &runner);
    bench_fixed::<129>(c, &runner);
    bench_fixed::<256>(c, &runner);
    bench_variable::<32>(c, &runner);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_read_cached
}
