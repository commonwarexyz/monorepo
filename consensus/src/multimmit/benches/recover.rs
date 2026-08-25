use super::common::{Fixture, PARTICIPANTS, rayon};
use commonware_consensus::multimmit::mocks;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig, Variant};
use commonware_parallel::Sequential;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 1);
    let da_votes = fixture
        .signers
        .iter()
        .take(fixture.codec.da_quorum())
        .map(|signer| mocks::sign_da_vote(signer, header.clone()).unwrap())
        .collect::<Vec<_>>();
    let nullifies = fixture
        .nullifies()
        .into_iter()
        .take(fixture.codec.nullification_quorum())
        .collect::<Vec<_>>();
    let rayon = rayon();

    for (strategy, parallel) in [("sequential", false), ("rayon", true)] {
        c.bench_function(
            &format!(
                "{}/variant={} role=da n={} strategy={}",
                module_path!(),
                variant,
                PARTICIPANTS,
                strategy,
            ),
            |b| {
                b.iter(|| {
                    let certificate = if parallel {
                        fixture.verifier.assemble_da_certificate(&da_votes, &rayon)
                    } else {
                        fixture
                            .verifier
                            .assemble_da_certificate(&da_votes, &Sequential)
                    };
                    black_box(certificate.unwrap())
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/variant={} role=nullify n={} strategy={}",
                module_path!(),
                variant,
                PARTICIPANTS,
                strategy,
            ),
            |b| {
                b.iter(|| {
                    let certificate = if parallel {
                        fixture.verifier.assemble_nullification(&nullifies, &rayon)
                    } else {
                        fixture
                            .verifier
                            .assemble_nullification(&nullifies, &Sequential)
                    };
                    black_box(certificate.unwrap())
                });
            },
        );
    }
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
