//! Batch verification of threshold shares: DA votes and nullify shares.

use super::{
    common::{Fixture, PARTICIPANTS, bench_strategies},
    ordinary::VerifyArtifacts,
};
use commonware_consensus::multimmit::{
    Artifact,
    mocks::{Bls, Fixture as Suite},
};
use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};

fn register<S: Suite>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(0, 1);
    let da_votes = fixture
        .signers
        .iter()
        .map(|signer| Artifact::DaVote(signer.sign_da_vote(header.clone()).unwrap()))
        .collect::<Vec<_>>();
    let nullifies = fixture
        .nullifies()
        .into_iter()
        .map(Artifact::Nullify)
        .collect::<Vec<_>>();
    let da = da_votes.iter().collect::<Vec<_>>();
    let nullification = nullifies.iter().collect::<Vec<_>>();

    for (role, artifacts) in [("da", da), ("nullify", nullification)] {
        bench_strategies(
            c,
            &format!(
                "{}/variant={variant} role={role} n={PARTICIPANTS}",
                module_path!()
            ),
            || VerifyArtifacts {
                verifier: &fixture.verifier,
                artifacts: &artifacts,
                rng: test_rng(),
            },
        );
    }
}

fn bench_shares(c: &mut Criterion) {
    register::<Bls<MinPk>>(c, "minpk");
    register::<Bls<MinSig>>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_shares
}
