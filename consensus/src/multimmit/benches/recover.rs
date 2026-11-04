//! Threshold recovery: DA certificates and nullifications from a quorum of shares.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_consensus::multimmit::{
    mocks::{Bls, Fixture as Suite},
    types::{DaVote, Nullify},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Recovers a DA certificate from a quorum of shares.
struct AssembleDaCertificate<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    votes: &'a [DaVote<S, Digest>],
}

impl<S: Suite> Workload for AssembleDaCertificate<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .assemble_da_certificate(&mut test_rng(), self.votes, strategy)
                .unwrap(),
        );
    }
}

/// Recovers a nullification from a quorum of shares.
struct AssembleNullification<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    nullifies: &'a [Nullify<S>],
}

impl<S: Suite> Workload for AssembleNullification<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .assemble_nullification(&mut test_rng(), self.nullifies, strategy)
                .unwrap(),
        );
    }
}

fn register<S: Suite>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<S>::new();
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
    register::<Bls<MinPk>>(c, "minpk");
    register::<Bls<MinSig>>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_recover
}
