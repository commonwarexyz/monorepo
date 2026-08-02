use commonware_consensus::multimmit::test_utils::benchmarks::{
    JournalScenario, MACHINE_SCALE_BLOCKS_PER_CHAIN, MACHINE_SCALE_COMPLETION_PROFILE,
    MACHINE_SCALE_PARTICIPANTS, MACHINE_SCALE_VIEWS, machine_scale_report, run_journal,
};
use commonware_runtime::{benchmarks::tokio, telemetry::metrics::raw::Histogram};
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_journal(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let scenarios = [
        (
            "append_serial/records=256",
            JournalScenario::AppendSerial256,
        ),
        (
            "append_pipelined/records=256",
            JournalScenario::AppendPipelined256,
        ),
        ("replay/records=1000", JournalScenario::Replay1000),
    ];
    for (label, scenario) in scenarios {
        c.bench_function(&format!("{}::{label}", module_path!()), |b| {
            b.to_async(&runner).iter_custom(|iterations| async move {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    elapsed += run_journal(scenario).await;
                }
                elapsed
            });
        });
    }
}

fn bench_machine_scale(c: &mut Criterion) {
    let profile = MACHINE_SCALE_COMPLETION_PROFILE;
    c.bench_function(
        &format!(
            "{}::machine_scale_logical_work/n={} bpc={} views={} cpu={} storage={} network={}",
            module_path!(),
            MACHINE_SCALE_PARTICIPANTS,
            MACHINE_SCALE_BLOCKS_PER_CHAIN,
            MACHINE_SCALE_VIEWS,
            profile.cpu_ticks,
            profile.storage_ticks,
            profile.network_ticks,
        ),
        |b| b.iter(|| black_box(machine_scale_report().checksum())),
    );
}

fn bench_metric_observation(c: &mut Criterion) {
    const OBSERVATIONS: usize = 1_024;
    const BUCKETS: [f64; 11] = [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];
    let histogram = Histogram::new(BUCKETS);
    c.bench_function(
        &format!(
            "{}::metric_observation/observations={} buckets={}",
            module_path!(),
            OBSERVATIONS,
            BUCKETS.len(),
        ),
        |b| {
            b.iter(|| {
                for sample in 0..OBSERVATIONS {
                    histogram.observe(black_box((sample % 500) as f64 / 1_000.0));
                }
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_journal, bench_machine_scale, bench_metric_observation
}
