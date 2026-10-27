//! Threshold recovery: DA certificates and nullifications from a quorum of shares.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::types::{DaVote, Nullify};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Recovers a DA certificate from a quorum of shares.
struct AssembleDaCertificate<'a, V: Variant> {
    verifier: &'a MultimmitScheme<V>,
    votes: &'a [DaVote<V, Digest>],
}

impl<V: Variant> Workload for AssembleDaCertificate<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        black_box(
            self.verifier
                .assemble_da_certificate(self.votes, strategy)
                .unwrap(),
        );
    }
}

/// Recovers a nullification from a quorum of shares.
struct AssembleNullification<'a, V: Variant> {
    verifier: &'a MultimmitScheme<V>,
    nullifies: &'a [Nullify<V>],
}

impl<V: Variant> Workload for AssembleNullification<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        black_box(
            self.verifier
                .assemble_nullification(self.nullifies, strategy)
                .unwrap(),
        );
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 1);
    let da_votes = fixture
        .signers
        .iter()
        .take(fixture.codec.da_quorum())
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let nullifies = fixture
        .nullifies()
        .into_iter()
        .take(fixture.codec.nullification_quorum())
        .collect::<Vec<_>>();

    bench_strategies(
        c,
        &format!(
            "{}/variant={variant} role=da n={PARTICIPANTS}",
            module_path!()
        ),
        || AssembleDaCertificate {
            verifier: &fixture.verifier,
            votes: &da_votes,
        },
    );
    bench_strategies(
        c,
        &format!(
            "{}/variant={variant} role=nullify n={PARTICIPANTS}",
            module_path!()
        ),
        || AssembleNullification {
            verifier: &fixture.verifier,
            nullifies: &nullifies,
        },
    );
}

fn bench_recover(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_recover
}
