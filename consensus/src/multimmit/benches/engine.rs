//! Whole-engine performance profile: a committee of complete engines (consensus actors over the
//! production machine, marshal, and a staging application) on the deterministic runtime.
//!
//! Criterion measures host wall time for a fixed amount of block and view work. Capture a
//! reproducible host baseline with:
//!
//! `cargo bench -p commonware-consensus --bench multimmit -- engine:: --save-baseline multimmit-engine-current`

use commonware_consensus::multimmit::test_utils::benchmarks::{
    ENGINE_BLOCKS_PER_CHAIN, ENGINE_NODES, ENGINE_VIEW_ADVANCE, engine_parameters,
    run_engine_profile,
};
use criterion::{Criterion, Throughput, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_block_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::block_throughput", module_path!()));
    group.throughput(Throughput::Elements(
        ENGINE_NODES as u64 * ENGINE_BLOCKS_PER_CHAIN,
    ));
    group.bench_function(engine_parameters(), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_engine_profile();
                elapsed += run.block_elapsed;
                black_box(run.report.delivered);
            }
            elapsed
        });
    });
    group.finish();
}

fn bench_view_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::view_throughput", module_path!()));
    group.throughput(Throughput::Elements(ENGINE_VIEW_ADVANCE));
    group.bench_function(engine_parameters(), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_engine_profile();
                elapsed += run.view_elapsed;
                // The throughput counts the target views, so every run must advance that far.
                assert!(run.report.views >= ENGINE_VIEW_ADVANCE);
                black_box(run.report.view_time);
            }
            elapsed
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_block_throughput, bench_view_throughput
}
