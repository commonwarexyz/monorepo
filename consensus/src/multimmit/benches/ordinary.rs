//! Batch verification of signed transaction blocks.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::{
    Artifact,
    mocks::{Bls, Fixture as Suite, Sas},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Batch-verifies attributed artifacts.
pub struct VerifyArtifacts<'a, S: Suite> {
    pub verifier: &'a MultimmitScheme<S>,
    pub artifacts: &'a [&'a Artifact<S, Digest>],
    pub rng: TestRng,
}

impl<S: Suite> Workload for VerifyArtifacts<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(self.verifier.verify_artifacts::<_, Sha256, _>(
            &mut self.rng,
            self.artifacts,
            &[],
            strategy,
        ));
    }
}

fn register<S: Suite>(c: &mut Criterion, suite: &str, variant: &str) {
    let fixture = Fixture::<S>::new();
    let blocks = fixture
        .ordinary_blocks()
        .into_iter()
        .map(Artifact::TransactionBlock)
        .collect::<Vec<_>>();
    let artifacts = blocks.iter().collect::<Vec<_>>();
    bench_strategies(
        c,
        &format!(
            "{}/suite={suite} variant={variant} n={PARTICIPANTS}",
            module_path!()
        ),
        || VerifyArtifacts {
            verifier: &fixture.verifier,
            artifacts: &artifacts,
            rng: test_rng(),
        },
    );
}

fn bench_ordinary(c: &mut Criterion) {
    register::<Bls<MinPk>>(c, "bls12381", "minpk");
    register::<Bls<MinSig>>(c, "bls12381", "minsig");
    register::<Sas<MinPk>>(c, "bls12381_sas", "minpk");
    register::<Sas<MinSig>>(c, "bls12381_sas", "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_ordinary
}
