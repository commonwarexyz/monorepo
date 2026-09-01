//! Inactivity timeout and timeout-batch tests.

use super::harness::{Node, NodeBuilder, voter_limits};
use crate::{
    Viewable as _,
    multimmit::{
        actors::voter::VoterLimits,
        config::Role,
        testing::expect_before,
        types::ChainId,
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope},
    },
    types::{Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    telemetry::metrics::metric_sum,
};
use std::time::Duration;
async fn inactivity_timeout_scenario(
    context: &DeterministicContext,
    active_peers: &[usize],
    expire: bool,
    target_view: u64,
    expected_early: bool,
) -> Node {
    let mut node = NodeBuilder::new(944, Role::Validator(Participant::new(0)), "inactivity")
        .limits(move |limits| {
            limits.voter = VoterLimits {
                skip_timeout: Some(Duration::from_secs(2)),
                ..voter_limits()
            }
        })
        .start(context)
        .await;
    context.sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metric_sum(
            &context.encode(),
            "inactivity_voter_view_timeouts_total",
            &[]
        ),
        0.0,
        "cold startup must retain the ordinary deadline"
    );

    let mut peers = Vec::new();
    for peer in 1..6 {
        peers.push(node.peer(peer, 1).await);
    }
    for &peer in active_peers {
        let (sender, _) = &mut peers[peer - 1];
        // Every payload names participant two; only transport identities count as activity.
        sender.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                node.committee.novote(Participant::new(2), View::new(1)),
            ))
            .encode(),
            true,
        );
    }
    context.sleep(Duration::from_millis(20)).await;
    if expire {
        context.sleep(Duration::from_secs(3)).await;
    }
    let (mut certificates, _receiver) = node.peer(1, 2).await;
    for view in 1..target_view {
        certificates.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                node.committee.nullification(View::new(view)),
            ))
            .encode(),
            true,
        );
        while node.inspect().await.view().get() <= view {
            context.sleep(Duration::from_millis(1)).await;
        }
    }
    context.sleep(Duration::from_millis(50)).await;
    let inspection = node.inspect().await;
    assert_eq!(inspection.view(), View::new(target_view));
    let metrics = context.encode();
    let armed = metric_sum(&metrics, "inactivity_voter_view_timer_armed", &[]);
    assert_eq!(armed, if expected_early { 0.0 } else { 1.0 }, "{metrics}");
    if expected_early {
        let deadline = context.current() + Duration::from_millis(100);
        let mut novote = false;
        let mut nullify = false;
        while !(novote && nullify) {
            let (_, bytes) = expect_before(
                context,
                deadline,
                peers[0].1.recv(),
                "early timeout did not publish both shares",
            )
            .await
            .unwrap();
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .unwrap();
            match envelope.into_payload() {
                ConsensusMessage::NoVote(vote) if vote.view() == View::new(target_view) => {
                    assert!(node.committee.verifier.verify_novote(&vote));
                    novote = true;
                }
                ConsensusMessage::Nullify(vote) if vote.view() == View::new(target_view) => {
                    assert!(node.committee.verifier.verify_nullify(&vote));
                    nullify = true;
                }
                _ => {}
            }
        }
    }
    node
}

#[test_traced]
fn inactivity_timeout_requires_a_recent_quorum_of_transport_peers() {
    for (peers, expire, expected) in [
        (vec![], false, false),
        (vec![1, 3, 4], false, false),
        (vec![1, 3, 4, 5], false, true),
        (vec![1, 3, 4, 5], true, false),
        (vec![1, 2, 3, 4, 5], false, false),
    ] {
        DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
            inactivity_timeout_scenario(&context, &peers, expire, 2, expected).await;
        });
    }
}

#[test_traced]
fn inactivity_timeout_never_skips_the_local_leader() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        inactivity_timeout_scenario(&context, &[1, 2, 3, 4, 5], false, 6, false).await;
    });
}

#[test_traced]
fn inactivity_timeout_revived_leader_keeps_its_next_deadline() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let mut node = inactivity_timeout_scenario(&context, &[1, 3, 4, 5], false, 2, true).await;
        let (mut revived, _receiver) = node.peer(2, 0).await;
        revived.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(
                node.committee
                    .signed_block(ChainId::new(2), Sha256::hash(&[b"revived leader"])),
            ))
            .encode(),
            false,
        );
        context.sleep(Duration::from_millis(20)).await;
        let (mut certificates, _receiver) = node.peer(3, 2).await;
        for view in 2..8 {
            certificates.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    node.committee.nullification(View::new(view)),
                ))
                .encode(),
                true,
            );
            while node.inspect().await.view().get() <= view {
                context.sleep(Duration::from_millis(1)).await;
            }
        }
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(node.inspect().await.view(), View::new(8));
        assert_eq!(
            metric_sum(&context.encode(), "inactivity_voter_view_timer_armed", &[]),
            1.0
        );
    });
}

#[test_traced]
fn inactivity_timeout_recovery_starts_without_peer_history() {
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    let (_, checkpoint) = runner.start_and_recover(|context| async move {
        inactivity_timeout_scenario(&context, &[1, 3, 4, 5], false, 2, true).await;
    });
    DeterministicRunner::from(checkpoint).start(|context| async move {
        let mut node = NodeBuilder::new(
            944,
            Role::Validator(Participant::new(0)),
            "recovered_inactivity",
        )
        .limits(move |limits| {
            limits.voter = VoterLimits {
                skip_timeout: Some(Duration::from_secs(2)),
                ..voter_limits()
            }
        })
        .start(&context)
        .await;
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(node.inspect().await.view(), View::new(2));
        let metrics = context.encode();
        assert_eq!(
            metric_sum(
                &metrics,
                "recovered_inactivity_voter_view_timeouts_total",
                &[]
            ),
            0.0
        );
        assert_eq!(
            metric_sum(&metrics, "recovered_inactivity_voter_view_timer_armed", &[]),
            1.0
        );
    });
}

#[test_traced]
fn timeout_signs_and_broadcasts_an_atomic_novote_nullify_batch() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(44, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        let (mut consensus_tx, mut consensus_rx) = node.peer(1, 1).await;
        let (_, mut certificate_rx) = node.peer(1, 2).await;

        // No leader traffic arrives, so the view timer fires and the batch publishes.
        let mut saw_novote = false;
        let mut saw_nullify = false;
        let mut nullified_view = None;
        let deadline = context.current() + Duration::from_secs(1);
        while !(saw_novote && saw_nullify) {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                consensus_rx.recv(),
                "timeout did not emit the atomic NoVote/Nullify batch",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            match envelope.into_payload() {
                ConsensusMessage::NoVote(vote) => {
                    assert!(node.committee.verifier.verify_novote(&vote));
                    saw_novote = true;
                }
                ConsensusMessage::Nullify(nullify) => {
                    assert!(node.committee.verifier.verify_nullify(&nullify));
                    nullified_view = Some(nullify.view().get());
                    saw_nullify = true;
                }
                _ => {}
            }
        }

        // The remaining threshold shares recover and durably forward one certificate.
        let view = nullified_view.expect("the timeout emitted a nullify share");
        for signer in 1..node.committee.codec().nullification_quorum() {
            consensus_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(ConsensusMessage::<MinPk, Sha256Digest>::Nullify(
                    node.committee
                        .nullify(Participant::from_usize(signer), View::new(view)),
                ))
                .encode(),
                true,
            );
        }
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                certificate_rx.recv(),
                "nullification shares did not produce a certificate",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if matches!(
                envelope.into_payload(),
                CertificateMessage::Nullification(_)
            ) {
                break;
            }
        }
        // The certificate leaves the process when its forwarding stages, so the durable
        // counter lands on the barrier acknowledgement that follows the wire message.
        let deadline = context.current() + Duration::from_secs(1);
        let metrics = loop {
            let metrics = context.encode();
            if metrics
                .lines()
                .any(|line| line == "primary_voter_nullifications_total 1")
            {
                break metrics;
            }
            assert!(
                context.current() < deadline,
                "durable nullification forwarding was not counted: {metrics}"
            );
            context.sleep(Duration::from_millis(10)).await;
        };
        assert!(
            metrics.lines().any(|line| {
                line.starts_with("primary_voter_nullification_recovery_latency_count ")
                    && line.ends_with(" 1")
            }),
            "nullification recovery latency was not observed: {metrics}"
        );
    });
}
