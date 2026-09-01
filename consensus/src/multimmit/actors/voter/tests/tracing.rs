//! Round span and trace-field tests.

use super::harness::{Attachments, NodeBuilder, assert_test_roots, next_block};
use crate::{
    multimmit::{
        actors::voter::telemetry::{round_span, round_timeout_span},
        config::Role,
        mocks::MockApplication,
        testing::{SpanRecorder, expect_before, expect_within},
        types::ChainId,
        wire::{DataMessage, Envelope},
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Runner as _, deterministic::Runner as DeterministicRunner,
    telemetry::traces::collector::TraceStorage,
};
use futures::task::noop_waker_ref;
use std::{future::Future as _, pin::pin, task::Context, time::Duration};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt as _;

#[test]
fn round_compare_fields_are_numeric() {
    let recorder = SpanRecorder::default();
    recorder.capture(|| {
        let round = Round::new(Epoch::new(42), View::new(1_964));
        let root = round_span(round.epoch(), round.view());
        let _timeout = round_timeout_span(&root, round);
    });

    for name in ["multimmit.voter.round", "multimmit.voter.round.timeout"] {
        let span = recorder.last(name).expect("the span was recorded");
        for field in ["epoch", "view"] {
            assert!(
                span.signed.contains(&field),
                "{name} records {field} as a signed integer"
            );
        }
    }
}

#[test]
fn round_spans_track_ingress_and_publication_boundaries() {
    let traces = TraceStorage::default();
    let recorder = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            commonware_runtime::telemetry::traces::collector::CollectingLayer::new(traces.clone()),
        )
        .with(recorder.clone());
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    executor.start(|context| async move {
        let seed = 76;
        let node = NodeBuilder::new(seed, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;

        expect_within(
            &context,
            Duration::from_secs(1),
            next_block(&node, &mut peer_data_rx),
            "local block was not published",
        )
        .await;

        let commitment = Sha256::hash(&[b"traced remote payload"]);
        let block = node.committee.signed_block(ChainId::new(1), commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block)).encode(),
            false,
        );

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                peer_data_rx.recv(),
                "remote block was not observed and verified",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload()
                && vote.header().body_digest() == commitment
            {
                break;
            }
        }

        let events = traces.get_by_level(Level::DEBUG);
        for operation in [
            "multimmit.voter.produce.complete",
            "multimmit.voter.custody.complete",
            "multimmit.voter.sign",
            "multimmit.voter.persist",
            "multimmit.voter.verify.process",
        ] {
            events
                .expect_event(|event| {
                    event.metadata.content == "test captured input dispatch"
                        && event
                            .spans
                            .first()
                            .is_some_and(|span| span.content == operation)
                })
                .unwrap();
        }
        events
            .expect_event(|event| {
                event.metadata.content == "test reporter received activity"
                    && event
                        .expect_span_at_index(0, |span| {
                            if span.content == "multimmit.voter.verify.process" {
                                Ok(())
                            } else {
                                Err("verification dequeue processing span is missing"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span_at_index(1, |span| {
                            if span.content == "multimmit.voter.verify"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("verify span is missing its round fields".to_string().into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span_at_index(2, |span| {
                            if span.content == "multimmit.voter.round"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("owning round is missing its round fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
            })
            .unwrap();
        events
            .expect_event(|event| {
                event.metadata.content == "durable publication installed"
                    && event.metadata.expect_field_exact("epoch", "76").is_ok()
                    && event.metadata.expect_field_exact("view", "1").is_ok()
                    && event
                        .expect_span(|span| {
                            span.content == "multimmit.voter.round"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                        })
                        .is_ok()
            })
            .unwrap();
        events
            .expect_event(|event| {
                event.metadata.content == "test relay received payload"
                    && event
                        .expect_span_at_index(0, |span| {
                            if span.content == "multimmit.voter.publish"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("publish span is missing its round fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
            })
            .unwrap();
    });
    assert_test_roots(&recorder);
}

#[test_traced]
fn ready_application_work_precedes_later_mailbox_traffic() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        // The first application build is held by a one-shot gate.
        let application = MockApplication::new();
        let mut build = application.gate_build();
        let node = NodeBuilder::new(49, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;

        build.wait_started().await;
        // Quiesce the voter before staging the race. Every completion pool self-wakes once on
        // its first poll, and an outstanding wake would let the voter run between the mailbox
        // enqueue and the build task's completion, leaving no ready application work to outrank.
        context.sleep(Duration::from_millis(1)).await;
        let inspector = node.inspector();
        let mut inspection = pin!(inspector.inspect());
        assert!(
            inspection
                .as_mut()
                .poll(&mut Context::from_waker(noop_waker_ref()))
                .is_pending(),
            "the query is queued before the build completes"
        );
        build.release();

        let inspection = inspection.await.expect("voter responds");
        assert!(
            inspection
                .producer()
                .is_some_and(|producer| producer.prepared() >= 1)
        );
    });
}
