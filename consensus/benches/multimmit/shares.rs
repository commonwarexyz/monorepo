use super::common::{Fixture, PARTICIPANTS, rayon};
use commonware_consensus::multimmit::{mocks, scheme::Unverified};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 1);
    let da_votes = fixture
        .signers
        .iter()
        .map(|signer| mocks::sign_da_vote(signer, header.clone()).unwrap())
        .collect::<Vec<_>>();
    let nullifies = fixture.nullifies();
    let da = da_votes.iter().map(Unverified::DaVote).collect::<Vec<_>>();
    let nullification = nullifies
        .iter()
        .map(Unverified::Nullify)
        .collect::<Vec<_>>();
    let rayon = rayon();

    for (role, artifacts) in [("da", da), ("nullify", nullification)] {
        for (strategy, parallel) in [("sequential", false), ("rayon", true)] {
            c.bench_function(
                &format!(
                    "{}/variant={} role={} n={} strategy={}",
                    module_path!(),
                    variant,
                    role,
                    PARTICIPANTS,
                    strategy,
                ),
                |b| {
                    b.iter(|| {
                        let verdicts = if parallel {
                            fixture.verifier.verify_artifacts::<_, Sha256, _>(
                                &mut test_rng(),
                                &artifacts,
                                &rayon,
                            )
                        } else {
                            fixture.verifier.verify_artifacts::<_, Sha256, _>(
                                &mut test_rng(),
                                &artifacts,
                                &Sequential,
                            )
                        };
                        black_box(verdicts)
                    });
                },
            );
        }
    }
}

fn bench_shares(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_shares
}
