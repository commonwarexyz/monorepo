//! White-box tests of the verifier internals.

use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            util::WorkerPanicked,
            verifier::{Config, Fatal, Verifier, actor::deliver, votes::VerifiedVotes},
            voter::{self, Endpoints},
        },
        machine::{
            Generation, Issued, JobId, Observation, VerificationItem, VerificationTicket, VerifyJob,
        },
        mocks::Committee,
        types::{Artifact, ChainId},
    },
    types::{Participant, Round, View},
};
use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinPk, ed25519};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::sync::Mutex;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::{Span, info_span};
use tracing_subscriber::prelude::*;

type Digest = <Sha256 as Hasher>::Digest;

type TestVerifier =
    Verifier<deterministic::Context, Sha256, ed25519::PublicKey, MinPk, Sequential, Sequential>;

fn verifier(context: deterministic::Context, committee: &Committee<MinPk>) -> TestVerifier {
    Verifier::new(
        context,
        Config {
            scheme: committee.verifier.clone(),
            strategy: Sequential,
            critical_strategy: Sequential,
            inflight_jobs: NonZeroUsize::new(2).unwrap(),
            mailbox_size: NonZeroUsize::new(4).unwrap(),
        },
    )
    .0
}

#[derive(Clone, Default)]
struct VerificationSpans(Arc<Mutex<Vec<Option<&'static str>>>>);

impl<S> tracing_subscriber::Layer<S> for VerificationSpans
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attrs.metadata().name() == "multimmit.batcher.verify" {
            self.0.lock().push(
                ctx.span(id)
                    .unwrap()
                    .parent()
                    .map(|span| span.metadata().name()),
            );
        }
    }
}

#[test]
fn verification_dispatch_wait_is_observed_when_first_polled() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let verifier = verifier(context.child("batcher"), &committee);
        let artifact = Artifact::Vqc(committee.vqc(View::new(1)));
        let id = JobId::new(0);
        let ticket = VerificationTicket::new(id, artifact.id::<Sha256>(), Observation::new(0, 0));
        let job = VerifyJob::new(
            Issued::new(id, Generation::new(0)),
            vec![VerificationItem::new(
                ticket,
                Arc::new(artifact),
                Vec::new(),
            )],
        );
        let verification = verifier.verification(
            Sequential,
            Span::none(),
            Round::new(committee.config.epoch(), View::new(1)),
            job,
            context.current(),
        );

        // Submission waits for the first poll, so the wait before it counts as dispatch time.
        context.sleep(Duration::from_millis(125)).await;
        assert!(
            context
                .encode()
                .contains("verification_dispatch_wait_count 0\n")
        );
        let (_, result) = verification.await;
        assert!(
            result
                .unwrap()
                .verdicts()
                .iter()
                .all(|verdict| verdict.valid())
        );
        let encoded = context.encode();
        assert!(
            encoded.contains("verification_dispatch_wait_count 1\n"),
            "{encoded}"
        );
        assert!(
            encoded.contains("verification_dispatch_wait_sum 0.125\n"),
            "{encoded}"
        );
    });
}

#[test]
fn verification_trace_levels_preserve_round_prerequisites() {
    for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
        let spans = VerificationSpans::default();
        let subscriber = tracing_subscriber::registry()
            .with(spans.clone())
            .with(tracing_subscriber::filter::LevelFilter::from_level(level));
        tracing::subscriber::with_default(subscriber, || {
            deterministic::Runner::default().start(|context| async move {
                let committee = Committee::<MinPk>::builder(40, 6).build();
                let verifier = verifier(context.child("batcher"), &committee);
                let proposal = committee.leader_block(View::new(1));
                let bulk = Artifact::TransactionBlock(
                    committee.signed_block(ChainId::new(0), Sha256::hash(&[b"bulk"])),
                );
                let cases = vec![
                    vec![bulk.clone()],
                    vec![Artifact::LeaderBlock(proposal.clone())],
                    vec![Artifact::Vote(
                        committee.vote(Participant::new(0), &proposal),
                    )],
                    vec![Artifact::Vqc(committee.vqc(View::new(1)))],
                    vec![Artifact::Lqc(committee.lqc(View::new(1)))],
                    vec![
                        bulk,
                        Artifact::NoVote(committee.novote(Participant::new(0), View::new(1))),
                    ],
                ];
                let root = info_span!(parent: None, "test.round");
                for (index, artifacts) in cases.into_iter().enumerate() {
                    let id = JobId::new(index as u64);
                    let items = artifacts
                        .into_iter()
                        .enumerate()
                        .map(|(item, artifact)| {
                            let ticket = VerificationTicket::new(
                                id,
                                artifact.id::<Sha256>(),
                                Observation::new(item as u64, 0),
                            );
                            VerificationItem::new(ticket, Arc::new(artifact), Vec::new())
                        })
                        .collect();
                    let job = VerifyJob::new(Issued::new(id, Generation::new(0)), items);
                    let before = spans.0.lock().len();
                    let (completion_parent, result) = verifier
                        .verification(
                            Sequential,
                            root.clone(),
                            Round::new(committee.config.epoch(), View::new(1)),
                            job,
                            context.current(),
                        )
                        .await;
                    assert!(
                        result
                            .unwrap()
                            .verdicts()
                            .iter()
                            .all(|verdict| verdict.valid())
                    );
                    assert_eq!(completion_parent.id(), root.id());
                    let recorded = spans.0.lock();
                    let visible = index != 0 || level == tracing::Level::DEBUG;
                    assert_eq!(
                        recorded.len() - before,
                        usize::from(visible),
                        "case {index} at {level}"
                    );
                    if visible {
                        assert_eq!(recorded.last(), Some(&Some("test.round")));
                    }
                }
            });
        });
    }
}

#[test]
fn verified_votes_retain_a_bounded_window_per_view() {
    let committee = Committee::<MinPk>::builder(7, 6).build();
    let vote = |view: u64, signer: usize| {
        Arc::new(Artifact::<MinPk, Digest>::Vote(committee.vote(
            Participant::from_usize(signer),
            &committee.leader_block(View::new(view)),
        )))
    };
    let mut cache = VerifiedVotes::<MinPk, Digest>::new(2);

    // Distinct votes accumulate up to the per-view bound of one vote and one novote each.
    for signer in 0..5 {
        cache.record(View::new(5), &vote(5, signer));
    }
    assert_eq!(cache.known(View::new(5)).len(), 4);
    assert!(cache.known(View::new(6)).is_empty());

    // A vote sixteen views ahead keeps view 5; one more evicts it.
    cache.record(View::new(21), &vote(21, 0));
    assert_eq!(cache.known(View::new(5)).len(), 4);
    cache.record(View::new(22), &vote(22, 0));
    assert!(cache.known(View::new(5)).is_empty());
    assert_eq!(cache.known(View::new(21)).len(), 1);
}

#[test]
fn a_panicked_worker_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let (voter, _inbox) = voter::Mailbox::<ed25519::PublicKey, MinPk, Digest>::new(
            &context.child("voter"),
            &context,
            NonZeroUsize::MIN,
        );
        let Endpoints { completions, .. } = voter.into_endpoints();
        assert!(matches!(
            deliver(&completions, (Span::none(), Err(WorkerPanicked))),
            Err(Fatal::WorkerPanicked(_))
        ));
    });
}
