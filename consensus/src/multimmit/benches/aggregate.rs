//! Certificate verification: V-QCs and L-QCs checked against the committee.
//!
//! `distinct` is how many different vote bodies the certificate's votes carry, and `known` is how
//! many of an L-QC's votes the verifier already checked individually and can discharge.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_sequential};
use commonware_consensus::multimmit::{
    Artifact,
    scheme::Verified,
    types::{Lqc, Vote, Vqc},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest,
};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// The seed of the batch-verification randomness, fixed per benchmark.
const RNG_SEED: u64 = 0x0ddc_0ffe;

/// Vote-body counts measured: unanimous, a few views of the producer chains, and one per voter.
const DISTINCT: [(usize, &str); 3] = [(1, "1"), (5, "5"), (PARTICIPANTS as usize, "all")];

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

/// Verifies an L-QC while discharging the votes the verifier already checked.
struct VerifyLqcKnown<'a, V: Variant> {
    verifier: &'a MultimmitScheme<V>,
    lqc: &'a Artifact<V, Digest>,
    known: &'a [Verified<'a, V, Digest>],
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyLqcKnown<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let verdicts = self.verifier.verify_artifacts::<_, Sha256, _>(
            &mut self.rng,
            &[self.lqc],
            &[self.known],
            strategy,
        );
        assert!(verdicts[0]);
        black_box(verdicts);
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    for (distinct, label) in DISTINCT {
        let (vqc, lqc) = fixture.certificates_among(distinct);
        bench_sequential(
            c,
            &format!(
                "{}/variant={variant} certificate=vqc n={PARTICIPANTS} distinct={label}",
                module_path!()
            ),
            VerifyVqc {
                verifier: &fixture.verifier,
                vqc: &vqc,
                rng: TestRng::new(RNG_SEED),
            },
        );
        bench_sequential(
            c,
            &format!(
                "{}/variant={variant} certificate=lqc n={PARTICIPANTS} distinct={label}",
                module_path!()
            ),
            VerifyLqc {
                verifier: &fixture.verifier,
                lqc: &lqc,
                rng: TestRng::new(RNG_SEED),
            },
        );
    }

    // Discharge a share of the L-QC's votes, with every body distinct.
    let leader = fixture.leader();
    let votes: Vec<Vote<V, Digest>> = fixture.votes(&leader);
    let lqc = Artifact::Lqc(
        fixture
            .verifier
            .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
            .unwrap(),
    );
    for percent in [0, 50, 100] {
        let known: Vec<_> = votes
            .iter()
            .take(votes.len() * percent / 100)
            .map(Verified::Vote)
            .collect();
        bench_sequential(
            c,
            &format!(
                "{}/variant={variant} certificate=lqc n={PARTICIPANTS} distinct=all known={percent}%",
                module_path!()
            ),
            VerifyLqcKnown {
                verifier: &fixture.verifier,
                lqc: &lqc,
                known: &known,
                rng: TestRng::new(RNG_SEED),
            },
        );
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
