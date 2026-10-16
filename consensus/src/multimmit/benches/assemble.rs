//! Certificate assembly: V-QCs and L-QCs built from verified votes.
//!
//! V-QC assembly includes encoding the resolution paths of the recorded tips.

use super::common::{Workload, bench_strategies, scenarios};
use commonware_consensus::multimmit::{
    scheme::bls12381::SignatureVerification, test_utils::benchmarks::ViewScenario,
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Assembles a V-QC from the view's verified final votes.
struct AssembleVqc<'a, V: Variant> {
    view: &'a ViewScenario<V>,
    rng: TestRng,
}

impl<V: Variant> Workload for AssembleVqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let vqc = self
            .view
            .verifier()
            .assemble_vqc(
                &mut self.rng,
                self.view.parent(),
                self.view.finals(),
                self.view.paths().to_vec(),
                SignatureVerification::Preverified,
                strategy,
            )
            .unwrap();
        black_box(vqc);
    }
}

/// Assembles an L-QC from the view's verified votes for its leader block.
struct AssembleLqc<'a, V: Variant> {
    view: &'a ViewScenario<V>,
    rng: TestRng,
}

impl<V: Variant> Workload for AssembleLqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let lqc = self
            .view
            .verifier()
            .assemble_lqc::<_, Sha256, _>(
                &mut self.rng,
                self.view.leader().clone(),
                self.view.votes(),
                SignatureVerification::Preverified,
                strategy,
            )
            .unwrap();
        black_box(lqc);
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for (participants, shape, view) in scenarios::<V>() {
        let label = |certificate: &str| {
            format!(
                "{}::assemble_{certificate}/variant={variant} n={participants} votes={shape}",
                module_path!()
            )
        };
        bench_strategies(c, &label("vqc"), || AssembleVqc {
            view: &view,
            rng: test_rng(),
        });
        bench_strategies(c, &label("lqc"), || AssembleLqc {
            view: &view,
            rng: test_rng(),
        });
    }
}

fn bench_assemble(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_assemble
}
