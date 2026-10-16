//! Certificate verification: V-QCs and L-QCs checked against the committee.
//!
//! Verification expands the compact tally into every signer's content before checking the
//! aggregate, so staggered votes also pay for the expansion of their deviations.

use super::common::{Workload, bench_strategies, scenarios};
use commonware_consensus::multimmit::test_utils::benchmarks::ViewScenario;
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Verifies the view's V-QC.
struct VerifyVqc<'a, V: Variant> {
    view: &'a ViewScenario<V>,
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyVqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let verifier = self.view.verifier();
        assert!(black_box(verifier.verify_vqc(
            &mut self.rng,
            self.view.vqc(),
            strategy
        )));
    }
}

/// Verifies the view's L-QC.
struct VerifyLqc<'a, V: Variant> {
    view: &'a ViewScenario<V>,
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyLqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let verifier = self.view.verifier();
        assert!(black_box(verifier.verify_lqc::<_, Sha256, _>(
            &mut self.rng,
            self.view.lqc(),
            strategy
        )));
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for (participants, shape, view) in scenarios::<V>() {
        let label = |certificate: &str| {
            format!(
                "{}::verify_{certificate}/variant={variant} n={participants} votes={shape}",
                module_path!()
            )
        };
        bench_strategies(c, &label("vqc"), || VerifyVqc {
            view: &view,
            rng: test_rng(),
        });
        bench_strategies(c, &label("lqc"), || VerifyLqc {
            view: &view,
            rng: test_rng(),
        });
    }
}

fn bench_aggregate(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_aggregate
}
