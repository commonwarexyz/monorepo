//! Private-core scenarios and the committee-scale logical-work model.

use commonware_consensus::multimmit::test_utils::benchmarks::{
    MACHINE_SCALE_BLOCKS_PER_CHAIN, MACHINE_SCALE_COMPLETION_PROFILE, MACHINE_SCALE_PARTICIPANTS,
    MACHINE_SCALE_VIEWS, MachineScenario, machine_scale_report, run_machine,
};
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_scenarios(c: &mut Criterion) {
    for scenario in MachineScenario::ALL {
        c.bench_function(&format!("{}::{scenario}", module_path!()), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| run_machine(scenario))
                    .fold(Duration::ZERO, |total, elapsed| total + elapsed)
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_scenarios, bench_machine_scale
}
