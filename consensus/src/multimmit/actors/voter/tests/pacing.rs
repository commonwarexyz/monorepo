//! Pacing over the real voter, persistence, and network paths under a deterministic clock.

use super::harness::{Attachments, NodeBuilder};
use crate::{
    Viewable as _,
    multimmit::{
        actors::voter::actor::TestHooks,
        config::{Role, VotePacing},
        machine::SignRequest,
        testing::SpanRecorder,
        wire::{CertificateMessage, ConsensusMessage},
    },
    types::{Participant, View},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_p2p::{Recipients, Sender as _};
use commonware_runtime::{Clock as _, Runner as _, deterministic};
use std::time::Duration;

fn voted(hooks: &TestHooks<MinPk, Digest>, view: View) -> bool {
    hooks.durable_effects().values().flatten().any(|attempt| {
        attempt.effect.sign_requests().is_some_and(|requests| {
            requests
                .iter()
                .any(|request| matches!(request, SignRequest::Vote(body) if body.view() == view))
        })
    })
}

#[test]
fn vote_pacing_waits_releases_and_keeps_timeout_rescue() {
    for (lambda, cap_ms, submit_ms, check_ms, expected_before_check) in [
        (0., 100, 20, 50, true),
        (1., 100, 20, 50, false),
        (1., 1000, 400, 450, false),
    ] {
        let recorder = SpanRecorder::default();
        recorder.capture(|| {
            deterministic::Runner::timed(Duration::from_secs(3)).start(|context| async move {
                let hooks = TestHooks::default();
                let mut matrix = vec![vec![1000.; 6]; 6];
                matrix[1][0] = 1.;
                matrix[0][2] = 1.;
                let pacing =
                    VotePacing::new(matrix, lambda, Some(Duration::from_millis(cap_ms))).unwrap();
                let mut node = NodeBuilder::new(710, Role::Validator(Participant::new(0)), "paced")
                    .attachments(Attachments {
                        hooks: hooks.clone(),
                        ..Attachments::default()
                    })
                    .pacing(pacing)
                    .start(&context)
                    .await;
                let start = context.current();
                let (mut sender, _receiver) = node.peer(1, 1).await;
                context
                    .sleep_until(start + Duration::from_millis(submit_ms))
                    .await;
                let proposal = node.committee.leader_block(View::new(1));
                sender.send(
                    Recipients::One(node.me.clone()),
                    node.envelope(ConsensusMessage::Proposal {
                        block: Box::new(proposal),
                        parent: None,
                    })
                    .encode(),
                    true,
                );
                context
                    .sleep_until(start + Duration::from_millis(check_ms))
                    .await;
                assert_eq!(voted(&hooks, View::new(1)), expected_before_check);
                assert_eq!(
                    node.inspect().await.view(),
                    View::new(1),
                    "inspection remains responsive while pacing"
                );
                context
                    .sleep_until(
                        start + Duration::from_millis(if cap_ms == 1000 { 550 } else { 170 }),
                    )
                    .await;
                assert!(
                    voted(&hooks, View::new(1)),
                    "timer must release the ordinary or rescue vote"
                );
            })
        });
        let builds = recorder
            .spans()
            .iter()
            .filter(|span| span.name == "multimmit.vote.build")
            .count();
        assert_eq!(
            builds,
            usize::from(cap_ms != 1000),
            "timeout rescue must bypass the ordinary vote pass"
        );
    }
}

#[test]
fn view_change_cancels_a_paced_vote() {
    deterministic::Runner::timed(Duration::from_secs(3)).start(|context| async move {
        let hooks = TestHooks::default();
        let mut matrix = vec![vec![1000.; 6]; 6];
        matrix[1][0] = 1.;
        matrix[0][2] = 1.;
        let mut node = NodeBuilder::new(711, Role::Validator(Participant::new(0)), "cancel_paced")
            .attachments(Attachments {
                hooks: hooks.clone(),
                ..Attachments::default()
            })
            .pacing(VotePacing::new(matrix, 1., Some(Duration::from_millis(300))).unwrap())
            .start(&context)
            .await;
        let (mut sender, _receiver) = node.peer(1, 1).await;
        sender.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(node.committee.leader_block(View::new(1))),
                parent: None,
            })
            .encode(),
            true,
        );
        context.sleep(Duration::from_millis(50)).await;
        assert!(!voted(&hooks, View::new(1)));
        let (mut certificates, _receiver) = node.peer(1, 2).await;
        certificates.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Digest>::Nullification(
                node.committee.nullification(View::new(1)),
            ))
            .encode(),
            true,
        );
        context.sleep(Duration::from_millis(350)).await;
        assert!(node.inspect().await.view() >= View::new(2));
        assert!(
            !voted(&hooks, View::new(1)),
            "a stale release cannot vote in the abandoned view"
        );
    });
}
