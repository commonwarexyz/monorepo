//! Certificate assembly: V-QCs and L-QCs built from verified view messages.

use super::common::{Fixture, MultimmitScheme, PARTICIPANTS, Workload, bench_strategies};
use commonware_codec::Encode as _;
use commonware_consensus::{
    multimmit::{
        mocks::{Bls, Fixture as Suite},
        scheme::SignatureVerification,
        types::{DigestedLeader, LeaderBlock, Tally, ViewMessage, Vote},
    },
    types::Attributable as _,
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Committee sizes measured: the shared fixture size and one at deployment scale.
const SIZES: [u32; 2] = [PARTICIPANTS, 50];

/// Assembles a V-QC from verified view messages.
struct AssembleVqc<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    leader: &'a LeaderBlock<S, Digest>,
    messages: &'a [ViewMessage<S, Digest>],
}

impl<S: Suite> Workload for AssembleVqc<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .assemble_vqc_with::<_, Sha256, _>(
                    &mut test_rng(),
                    self.leader.clone(),
                    self.messages,
                    SignatureVerification::Preverified,
                    strategy,
                )
                .unwrap(),
        );
    }
}

/// Assembles an L-QC from verified votes.
struct AssembleLqc<'a, S: Suite> {
    verifier: &'a MultimmitScheme<S>,
    leader: &'a LeaderBlock<S, Digest>,
    votes: &'a [Vote<S, Digest>],
}

impl<S: Suite> Workload for AssembleLqc<'_, S> {
    fn run<St: Strategy>(&mut self, strategy: &St) {
        black_box(
            self.verifier
                .assemble_lqc_with::<_, Sha256, _>(
                    &mut test_rng(),
                    self.leader.clone(),
                    self.votes,
                    SignatureVerification::Preverified,
                    strategy,
                )
                .unwrap(),
        );
    }
}

fn register<S: Suite>(c: &mut Criterion, variant: &str) {
    for participants in SIZES {
        let fixture = Fixture::<S>::new_sized(participants);
        let leader = fixture.leader();
        let messages = fixture.view_messages(&leader);
        let votes = fixture.votes(&leader);
        let bodies = votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone()))
            .collect::<Vec<_>>();

        bench_strategies(
            c,
            &format!(
                "{}/variant={variant} certificate=vqc n={participants}",
                module_path!()
            ),
            || AssembleVqc {
                verifier: &fixture.verifier,
                leader: &leader,
                messages: &messages,
            },
        );
        bench_strategies(
            c,
            &format!(
                "{}/variant={variant} certificate=lqc n={participants}",
                module_path!()
            ),
            || AssembleLqc {
                verifier: &fixture.verifier,
                leader: &leader,
                votes: &votes,
            },
        );

        // Stages inside one assembly, so a total can be attributed rather than guessed.
        c.bench_function(
            &format!(
                "{}/variant={variant} stage=tally n={participants}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    let tally = Tally::from_votes(
                        DigestedLeader::new::<Sha256>(&leader),
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
                        black_box(body.valid_for(DigestedLeader::new::<Sha256>(&leader)));
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
    register::<Bls<MinPk>>(c, "minpk");
    register::<Bls<MinSig>>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_assemble
}
