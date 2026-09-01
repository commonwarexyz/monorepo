use super::common::{Fixture, PARTICIPANTS, rayon};
use commonware_codec::Encode as _;
use commonware_consensus::{
    multimmit::{
        mocks,
        types::{Tally, ViewMessage},
    },
    types::Attributable as _,
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Sequential;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Committee sizes measured: the shared fixture size and one at deployment scale.
const SIZES: [u32; 2] = [PARTICIPANTS, 50];

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for participants in SIZES {
        let fixture = Fixture::<V>::new_sized(participants);
        let leader = fixture.leader();
        let messages = fixture.view_messages(&leader);
        let votes = fixture.votes(&leader);
        let bodies = votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone()))
            .collect::<Vec<_>>();
        let rayon = rayon();

        for (strategy, parallel) in [("sequential", false), ("rayon", true)] {
            c.bench_function(
                &format!(
                    "{}/variant={variant} certificate=vqc n={participants} strategy={strategy}",
                    module_path!(),
                ),
                |b| {
                    b.iter(|| {
                        let certificate = if parallel {
                            mocks::assemble_vqc_preverified::<_, _, Sha256, _>(
                                &fixture.verifier,
                                leader.clone(),
                                &messages,
                                &rayon,
                            )
                        } else {
                            mocks::assemble_vqc_preverified::<_, _, Sha256, _>(
                                &fixture.verifier,
                                leader.clone(),
                                &messages,
                                &Sequential,
                            )
                        };
                        black_box(certificate.unwrap())
                    });
                },
            );
            c.bench_function(
                &format!(
                    "{}/variant={variant} certificate=lqc n={participants} strategy={strategy}",
                    module_path!(),
                ),
                |b| {
                    b.iter(|| {
                        let certificate = if parallel {
                            mocks::assemble_lqc_preverified::<_, _, Sha256, _>(
                                &fixture.verifier,
                                leader.clone(),
                                &votes,
                                &rayon,
                            )
                        } else {
                            mocks::assemble_lqc_preverified::<_, _, Sha256, _>(
                                &fixture.verifier,
                                leader.clone(),
                                &votes,
                                &Sequential,
                            )
                        };
                        black_box(certificate.unwrap())
                    });
                },
            );
        }

        // Stages inside one assembly, so a total can be attributed rather than guessed.
        c.bench_function(
            &format!(
                "{}/variant={variant} stage=tally n={participants}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    let tally = Tally::from_votes::<V, Sha256, _>(
                        &leader,
                        bodies.iter().cloned(),
                        fixture.codec,
                    );
                    black_box(tally.unwrap())
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/variant={variant} stage=validity n={participants}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    for (_, body) in &bodies {
                        black_box(body.valid_for::<Sha256, V>(&leader));
                    }
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/variant={variant} stage=transcript n={participants}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    for message in &messages {
                        match message {
                            ViewMessage::Vote(vote) => {
                                black_box(vote.body().encode());
                            }
                            ViewMessage::NoVote(novote) => {
                                black_box(novote.round().encode());
                            }
                        }
                    }
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/variant={variant} stage=clone n={participants}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    black_box(votes.clone());
                });
            },
        );
    }
}

fn bench_assemble(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_assemble
}
