//! Private-core scenarios: a validator's steady-state view cycle, the replay of its journal, and
//! an observer reading a deployment-scale vote stream.

use commonware_consensus::multimmit::test_utils::benchmarks::{
    MachineScenario, STREAM_CAP, STREAM_PARTICIPANTS, STREAM_TICKS, Script, Stream, run_machine,
    run_stream,
};
use criterion::{Criterion, Throughput, criterion_group};
use std::{collections::BTreeMap, time::Duration};

fn bench_scenarios(c: &mut Criterion) {
    // Signing the scripted artifacts dominates setup, so each committee size signs once.
    let mut scripts = BTreeMap::new();
    for scenario in MachineScenario::ALL {
        let script = scripts
            .entry(scenario.participants())
            .or_insert_with(|| Script::new(scenario.participants()));
        c.bench_function(&format!("{}::{scenario}", module_path!()), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| run_machine(scenario, script))
                    .sum::<Duration>()
            });
        });
    }
}

/// Measures the host time per vote update an observer reads, including its share of the headers
/// and certificates that arrive with the updates.
fn bench_stream(c: &mut Criterion) {
    let stream = Stream::new();
    let updates = run_stream(&stream).updates;
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(updates as u64));
    group.bench_function(
        format!(
            "vote_stream/n={STREAM_PARTICIPANTS} chains={STREAM_PARTICIPANTS} cap={STREAM_CAP} \
             ticks={STREAM_TICKS}"
        ),
        |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| run_stream(&stream).total())
                    .sum::<Duration>()
            });
        },
    );
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_scenarios, bench_stream
}
