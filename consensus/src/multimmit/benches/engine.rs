//! Whole-engine performance profile.
//!
//! Criterion measures host wall time for fixed block and view work. The deterministic latency
//! limits are a unit test (`engine_profile_latency_stays_within_gates`), never host measurements.
//! Capture a reproducible host baseline with:
//!
//! `cargo bench -p commonware-consensus --bench multimmit -- engine::production --save-baseline multimmit-engine-current`

use commonware_consensus::multimmit::test_utils::benchmarks::{
    ENGINE_BLOCKS_PER_CHAIN, ENGINE_NODES, ENGINE_VIEW_ADVANCE, engine_parameters,
    run_engine_profile,
};
use criterion::{Criterion, Throughput, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_production_block_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::production_block_throughput", module_path!()));
    group.throughput(Throughput::Elements(
        ENGINE_NODES as u64 * ENGINE_BLOCKS_PER_CHAIN,
    ));
    group.bench_function(engine_parameters(false), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_engine_profile(false);
                elapsed += run.block_elapsed;
                black_box(run.report.blocks);
            }
            elapsed
        });
    });
    group.finish();
}

fn bench_production_view_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::production_view_throughput", module_path!()));
    group.throughput(Throughput::Elements(ENGINE_VIEW_ADVANCE));
    group.bench_function(engine_parameters(false), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_engine_profile(false);
                elapsed += run.view_elapsed;
                // The throughput counts the target views, so every run must advance exactly that far.
                assert_eq!(run.report.views, ENGINE_VIEW_ADVANCE);
                black_box(run.report.views);
            }
            elapsed
        });
    });
    group.finish();
}

fn bench_production_latency_gate(c: &mut Criterion) {
    c.bench_function(
        &format!(
            "{}::production_latency_gate/{}",
            module_path!(),
            engine_parameters(true)
        ),
        |b| b.iter(|| black_box(run_engine_profile(true).report)),
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_production_block_throughput,
        bench_production_view_throughput,
        bench_production_latency_gate
}
