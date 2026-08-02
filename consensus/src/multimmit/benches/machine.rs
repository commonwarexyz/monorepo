use commonware_consensus::multimmit::test_utils::benchmarks::{MachineScenario, run_machine};
use criterion::{Criterion, criterion_group};
use std::time::Duration;

fn bench_scenarios(c: &mut Criterion) {
    let scenarios = [
        (
            "poll/n=50 artifacts=64 budget=1",
            MachineScenario::Poll64Budget1,
        ),
        (
            "poll/n=50 artifacts=64 budget=1024",
            MachineScenario::Poll64Budget1024,
        ),
        (
            "poll/n=50 artifacts=256 budget=1",
            MachineScenario::Poll256Budget1,
        ),
        (
            "poll/n=50 artifacts=256 budget=1024",
            MachineScenario::Poll256Budget1024,
        ),
        (
            "obligation_discharge/n=6 obligations=1 retired=1",
            MachineScenario::Obligation1,
        ),
        (
            "obligation_discharge/n=6 obligations=64 retired=1",
            MachineScenario::Obligation64,
        ),
        (
            "ingress_admission/n=50 artifacts=1",
            MachineScenario::IngressAdmission,
        ),
        (
            "observe_duplicates/n=50 artifacts=40",
            MachineScenario::ObserveDuplicates,
        ),
    ];
    for (label, scenario) in scenarios {
        c.bench_function(&format!("{}::{label}", module_path!()), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| run_machine(scenario))
                    .fold(Duration::ZERO, |total, elapsed| total + elapsed)
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_scenarios
}
