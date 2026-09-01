//! Batch verification of signed transaction blocks.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::Artifact;
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Batch-verifies attributed artifacts.
pub struct VerifyArtifacts<'a, V: Variant> {
    pub verifier: &'a MultimmitScheme<V>,
    pub artifacts: &'a [&'a Artifact<V, Digest>],
    pub rng: TestRng,
}

impl<V: Variant> Workload for VerifyArtifacts<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        black_box(self.verifier.verify_artifacts::<_, Sha256, _>(
            &mut self.rng,
            self.artifacts,
            &[],
            strategy,
        ));
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let blocks = fixture
        .ordinary_blocks()
        .into_iter()
        .map(Artifact::TransactionBlock)
        .collect::<Vec<_>>();
    let artifacts = blocks.iter().collect::<Vec<_>>();
    bench_strategies(
        c,
        &format!("{}/variant={variant} n={PARTICIPANTS}", module_path!()),
        || VerifyArtifacts {
            verifier: &fixture.verifier,
            artifacts: &artifacts,
            rng: test_rng(),
        },
    );
}

fn bench_ordinary(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_ordinary
}
