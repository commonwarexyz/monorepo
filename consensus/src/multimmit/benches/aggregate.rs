//! Certificate verification: V-QCs and L-QCs checked against the committee.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::types::{Lqc, Vqc};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// The seed of the batch-verification randomness, fixed per benchmark.
const RNG_SEED: u64 = 0x0ddc_0ffe;

/// Verifies a V-QC.
struct VerifyVqc<'a, V: Variant> {
    verifier: &'a MultimmitScheme<V>,
    vqc: &'a Vqc<V, Digest>,
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyVqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        black_box(
            self.verifier
                .verify_vqc::<_, Sha256, _>(&mut self.rng, self.vqc, strategy)
                .unwrap(),
        );
    }
}

/// Verifies an L-QC.
struct VerifyLqc<'a, V: Variant> {
    verifier: &'a MultimmitScheme<V>,
    lqc: &'a Lqc<V, Digest>,
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyLqc<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        black_box(
            self.verifier
                .verify_lqc::<_, Sha256, _>(&mut self.rng, self.lqc, strategy)
                .unwrap(),
        );
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let (vqc, lqc) = fixture.certificates();

    bench_strategies(
        c,
        &format!(
            "{}/variant={variant} certificate=vqc n={PARTICIPANTS}",
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
            "{}/variant={variant} certificate=lqc n={PARTICIPANTS}",
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
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_aggregate
}
