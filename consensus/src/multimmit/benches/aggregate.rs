//! Certificate verification: V-QCs and L-QCs checked against the committee.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::{
    mocks::{Bls, Fixture as Suite, Sas},
    types::{Lqc, Vqc},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// The seed of the batch-verification randomness, fixed per benchmark.
const RNG_SEED: u64 = 0x0ddc_0ffe;

/// Verifies a V-QC.
struct VerifyVqc<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    vqc: &'a Vqc<S, Digest>,
    rng: TestRng,
}

impl<S: Suite> Workload for VerifyVqc<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .verify_vqc::<_, Sha256, _>(&mut self.rng, self.vqc, strategy)
                .unwrap(),
        );
    }
}

/// Verifies an L-QC.
struct VerifyLqc<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    lqc: &'a Lqc<S, Digest>,
    rng: TestRng,
}

impl<S: Suite> Workload for VerifyLqc<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .verify_lqc::<_, Sha256, _>(&mut self.rng, self.lqc, strategy)
                .unwrap(),
        );
    }
}

fn register<S: Suite>(c: &mut Criterion, suite: &str, variant: &str) {
    let fixture = Fixture::<S>::new();
    let (vqc, lqc) = fixture.certificates();

    bench_strategies(
        c,
        &format!(
            "{}/suite={suite} variant={variant} certificate=vqc n={PARTICIPANTS}",
            module_path!()
        ),
        || VerifyVqc {
            verifier: &fixture.verifier,
            vqc: &vqc,
            rng: TestRng::new(RNG_SEED),
        },
    );
    bench_strategies(
        c,
        &format!(
            "{}/suite={suite} variant={variant} certificate=lqc n={PARTICIPANTS}",
            module_path!()
        ),
        || VerifyLqc {
            verifier: &fixture.verifier,
            lqc: &lqc,
            rng: TestRng::new(RNG_SEED),
        },
    );
}

fn bench_aggregate(c: &mut Criterion) {
    register::<Bls<MinPk>>(c, "bls12381", "minpk");
    register::<Bls<MinSig>>(c, "bls12381", "minsig");
    register::<Sas<MinPk>>(c, "bls12381_sas", "minpk");
    register::<Sas<MinSig>>(c, "bls12381_sas", "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_aggregate
}
