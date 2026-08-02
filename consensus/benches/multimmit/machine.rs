use super::common;
use commonware_consensus::multimmit::test_utils::benchmarks::{
    AllocationCases, MachineScenario, idle_allocation_case, run_machine,
};
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn hot_path_allocation_counts() -> [usize; 4] {
    let mut cases = AllocationCases::new();
    let (_, duplicate) = common::count_allocations(|| cases.duplicate_ingress());
    let (_, sign) = common::count_allocations(|| cases.sign_completion());
    let (_, release) = common::count_allocations(|| cases.publication_release());
    let (_, reference) = common::count_allocations(|| cases.signature_reference());
    [duplicate, sign, release, reference]
}

fn bench_hot_path_allocations(c: &mut Criterion) {
    // The first self-admission lazily sizes its encoding scratch rather than reserving the
    // configured maximum at startup. Every later measured hot-path operation remains allocation
    // free.
    const BASELINE: [usize; 4] = [0, 1, 0, 0];
    assert_eq!(hot_path_allocation_counts(), BASELINE);
    c.bench_function(
        &format!(
            "{}::hot_path_allocations/cases=4 duplicate=0 sign=1 publication=0 reference=0 target=measured-deviation",
            module_path!()
        ),
        |b| {
            b.iter(|| {
                let counts = hot_path_allocation_counts();
                assert_eq!(counts, BASELINE);
                counts
            });
        },
    );
}

fn bench_idle_allocation_sanity(c: &mut Criterion) {
    c.bench_function(
        &format!(
            "{}::idle_allocation_sanity/cases=2 target=0",
            module_path!()
        ),
        |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let mut case = idle_allocation_case();
                    let started = Instant::now();
                    let (_, allocations) = common::count_allocations(|| case.run());
                    elapsed += started.elapsed();
                    assert_eq!(allocations, 0);
                }
                elapsed
            });
        },
    );
}

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
    targets = bench_hot_path_allocations, bench_idle_allocation_sanity, bench_scenarios
}
