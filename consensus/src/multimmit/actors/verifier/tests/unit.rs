//! White-box tests of the verifier internals.

use super::{job, update};
use crate::{
    Epochable as _,
    multimmit::{
        actors::verifier::{Config, Verifier},
        mocks::Committee,
        testing::PanickingHasher,
        types::{Artifact, ChainId},
    },
    types::{Round, View},
};
use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinPk, ed25519};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic,
    telemetry::metrics::metric_sum,
};
use commonware_utils::sync::Mutex;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::{Span, info_span};
use tracing_subscriber::prelude::*;

type TestVerifier<H = Sha256> =
    Verifier<deterministic::Context, H, ed25519::PublicKey, MinPk, Sequential, Sequential>;

fn verifier<H: Hasher>(
    context: deterministic::Context,
    committee: &Committee<MinPk>,
) -> TestVerifier<H> {
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

/// Records the parent span name of every verification worker span.
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
        if attrs.metadata().name() == "multimmit.verifier.verify" {
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
        let verifier = verifier::<Sha256>(context.child("verifier"), &committee);
        let job = job(0, vec![(Artifact::Vqc(committee.vqc(View::new(1))), None)]);
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
        assert!(result.verdicts().iter().all(|verdict| verdict.valid()));
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
                let verifier = verifier::<Sha256>(context.child("verifier"), &committee);
                let view = View::new(1);
                let bulk = (
                    Artifact::TransactionBlock(committee.genesis_child(ChainId::new(0), b"bulk")),
                    None,
                );
                // Only the first case is bulk-only, so only it traces below info level.
                let cases = vec![
                    vec![bulk.clone()],
                    vec![(Artifact::LeaderBlock(committee.leader_block(view)), None)],
                    vec![update(&committee, 0, view)],
                    vec![(Artifact::Vqc(committee.vqc(view)), None)],
                    vec![(Artifact::Lqc(committee.lqc(view)), None)],
                    vec![bulk, update(&committee, 0, view)],
                ];
                let root = info_span!(parent: None, "test.round");
                for (index, artifacts) in cases.into_iter().enumerate() {
                    let before = spans.0.lock().len();
                    let (completion_parent, result) = verifier
                        .verification(
                            Sequential,
                            root.clone(),
                            Round::new(committee.config.epoch(), view),
                            job(index as u64, artifacts),
                            context.current(),
                        )
                        .await;
                    assert!(result.verdicts().iter().all(|verdict| verdict.valid()));
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
fn a_panicked_worker_settles_every_item_invalid() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let verifier = verifier::<PanickingHasher>(context.child("verifier"), &committee);
        let view = View::new(1);
        // Checking an L-QC hashes its transcript, so the hasher panics inside the worker.
        let job = job(
            0,
            vec![
                update(&committee, 1, view),
                (Artifact::Lqc(committee.lqc(view)), None),
            ],
        );
        let (_, completion) = verifier
            .verification(
                Sequential,
                Span::none(),
                Round::new(committee.config.epoch(), view),
                job.clone(),
                context.current(),
            )
            .await;

        assert_eq!(completion.issued(), job.issued());
        assert_eq!(completion.verdicts().len(), 2);
        for (verdict, item) in completion.verdicts().iter().zip(job.items()) {
            assert_eq!(verdict.ticket(), item.ticket());
            assert!(!verdict.valid());
        }
        assert_eq!(
            metric_sum(&context.encode(), "verifier_worker_panics_total", &[]),
            1.0
        );
    });
}
