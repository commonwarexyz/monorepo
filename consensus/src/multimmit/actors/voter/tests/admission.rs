//! Live admission priority, verification isolation, validation pipelining, and inspection tests.

use super::harness::{
    Attachments, NodeBuilder, assert_test_roots, da_certificate, next_block, voter_limits,
};
use crate::{
    Epochable as _, Heightable as _,
    multimmit::{
        actors::voter::{Query, actor::TestHooks},
        config::Role,
        machine::{Generation, Lane, ResolutionCompletion, ResolutionJob},
        mocks::{Committee, MockApplication, cluster::start_network},
        testing::{SpanRecorder, expect_before, expect_within},
        types::{
            ChainId, DaVote, LeaderBlock, PathLimits, SignedTransactionBlock,
            TransactionBlockHeader, ViewProof,
        },
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope},
    },
    types::{Attributable as _, Height, Participant, Round, View},
};
use commonware_actor::mailbox;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Supervisor as _,
    deterministic::Runner as DeterministicRunner,
    telemetry::{metrics::metric_sum, traces::collector::TraceStorage},
};
use commonware_utils::channel::oneshot;
use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt as _;
#[test_traced]
fn inspection_overflow_does_not_retain_queries() {
    DeterministicRunner::default().start(|context| async move {
        let (sender, _queries): (mailbox::UnreliableSender<Query<Sha256Digest>>, _) =
            mailbox::new_unreliable(context.child("inspection_queries"), NonZeroUsize::MIN);
        let (first, _first_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::Inspect { responder: first })
                .accepted()
        );

        let (overflow, overflow_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::Inspect {
                    responder: overflow,
                })
                .is_rejected()
        );
        assert!(overflow_response.await.is_err());
    });
}

#[test]
fn work_quanta_refresh_round_without_reparenting_async_inputs() {
    let traces = TraceStorage::default();
    let recorder = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            commonware_runtime::telemetry::traces::collector::CollectingLayer::new(traces.clone()),
        )
        .with(recorder.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::new();
        let mut build = application.gate_build();
        application.permit_builds(0);
        let mut node = NodeBuilder::new(76, Role::Validator(Participant::new(0)), "quantum")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        build.wait_started().await;
        let (mut certificates, _) = node.peer(1, 2).await;
        certificates.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                node.committee.nullification(View::new(1)),
            ))
            .encode(),
            true,
        );
        while node.inspect().await.view() == View::new(1) {
            context.sleep(Duration::from_millis(1)).await;
        }
        build.release();
        while !traces
            .get_by_level(Level::DEBUG)
            .iter()
            .any(|event| event.metadata.content == "test production timer armed")
        {
            context.sleep(Duration::from_millis(1)).await;
        }
        certificates.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                node.committee.nullification(View::new(2)),
            ))
            .encode(),
            true,
        );
        while node.inspect().await.view() == View::new(2) {
            context.sleep(Duration::from_millis(1)).await;
        }
        loop {
            let events = traces.get_by_level(Level::DEBUG);
            if events.iter().any(|event| {
                event.metadata.content == "test captured input dispatch"
                    && event
                        .spans
                        .first()
                        .is_some_and(|span| span.content == "multimmit.voter.production.timeout")
            }) {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }

        let events = traces.get_by_level(Level::DEBUG);
        let mut worked_in_cycle = false;
        for event in events.iter() {
            match event.metadata.content.as_str() {
                "test core cycle started" => worked_in_cycle = false,
                "test machine-owned work" => {
                    let view = event
                        .metadata
                        .fields
                        .iter()
                        .find(|(name, _)| name == "view")
                        .expect("work records its owning view")
                        .1
                        .as_str();
                    assert!(!worked_in_cycle, "one semantic quantum per actor cycle");
                    worked_in_cycle = true;
                    let root = event.spans.last().expect("work has a round root");
                    assert_eq!(root.content, "multimmit.voter.round");
                    root.expect_field_exact("view", view).unwrap();
                }
                _ => {}
            }
        }
        events
            .expect_event(|event| {
                event.metadata.content == "test machine-owned work"
                    && event.metadata.expect_field_exact("view", "3").is_ok()
            })
            .unwrap();
        for (operation, view, current_view) in [
            ("multimmit.voter.produce.complete", "1", "2"),
            ("multimmit.voter.production.timeout", "2", "3"),
        ] {
            events
                .expect_event(|event| {
                    event.metadata.content == "test captured input dispatch"
                        && event
                            .metadata
                            .expect_field_exact("current_view", current_view)
                            .is_ok()
                        && event
                            .spans
                            .first()
                            .is_some_and(|span| span.content == operation)
                        && event.spans.last().is_some_and(|span| {
                            span.content == "multimmit.voter.round"
                                && span.expect_field_exact("view", view).is_ok()
                        })
                })
                .unwrap();
        }
    });
    assert_test_roots(&recorder);
}

#[test_traced]
fn live_admission_preserves_core_local_priority_under_peer_flood() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let hooks = TestHooks::default();
        let node = NodeBuilder::new(86, Role::Observer, "live_scheduler")
            .attachments(Attachments {
                hooks: hooks.clone(),
                ..Attachments::default()
            })
            .limits(move |limits| limits.inflight_verifications = NonZeroUsize::new(16).unwrap())
            .start(&context)
            .await;
        let (mut peer, _) = node.peer(1, 0).await;

        for ordinal in 0..64_u64 {
            let commitment = Sha256::hash(&[
                b"live scheduler flood".as_slice(),
                ordinal.to_be_bytes().as_slice(),
            ]);
            let block = node.committee.signed_block(ChainId::new(1), commitment);
            peer.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::Block(block)).encode(),
                false,
            );
        }

        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let services = hooks.services();
            let mut cycles = BTreeMap::<u64, (usize, usize)>::new();
            for (cycle, lane) in services {
                let counts = cycles.entry(cycle).or_default();
                match lane {
                    Lane::LocalCompletion => counts.0 += 1,
                    Lane::PeerObservation => counts.1 += 1,
                    _ => {}
                }
            }
            // Peer observations are admitted only at their co-scheduling budget while local
            // completions are serviced, so a peer flood never starves local priority. The full
            // local-versus-peer budget split is unit-tested in the core admission scheduler.
            let peer_held_to_budget = cycles
                .values()
                .all(|&(local, peer)| local == 0 || peer <= 2);
            let local_serviced_beside_a_capped_peer_batch = cycles
                .values()
                .any(|&(local, peer)| local >= 1 && peer == 2);
            if peer_held_to_budget && local_serviced_beside_a_capped_peer_batch {
                return;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!(
                        "live admission never held peer observations to their budget while \
                         servicing local completions: {cycles:?}"
                    );
                },
            }
        }
    });
}

#[test_traced]
fn an_invalid_da_share_is_discarded_and_the_quorum_still_certifies() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(81, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        // One registration per peer: re-registering the same channel drops the first receiver.
        let (mut culprit, mut data_rx) = node.peer(1, 0).await;
        let header = next_block(&node, &mut data_rx).await;

        // Participant one signs over a different header and sends the result for this one. The
        // share is structurally perfect, so admission accepts it and the quorum's single group
        // check is what discovers it.
        let elsewhere = node
            .committee
            .transaction_header(ChainId::new(0), Sha256::hash(&[b"another subject"]));
        let invalid = DaVote::new(
            header.clone(),
            node.committee
                .da_vote(Participant::new(1), elsewhere)
                .share()
                .clone(),
        );
        culprit.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaVote(invalid)).encode(),
            false,
        );
        for signer in 2..6 {
            let (mut peer, _) = node.peer(signer, 0).await;
            peer.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::DaVote(
                    node.committee
                        .da_vote(Participant::from_usize(signer), header.clone()),
                ))
                .encode(),
                false,
            );
        }

        // The honest remainder still forms a quorum, so the block certifies one attempt later.
        let deadline = context.current() + Duration::from_secs(5);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                data_rx.recv(),
                "an invalid share stalled the honest quorum",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaCertificate(certificate) = envelope.into_payload()
                && certificate.header() == &header
            {
                assert!(node.committee.verifier.verify_da_certificate(&certificate));
                break;
            }
        }

        assert!(node.blocker.blocked().is_empty());
        assert_eq!(
            metric_sum(
                &context.encode(),
                "primary_voter_da_recovery_fallbacks_total",
                &[]
            ),
            1.0,
            "one adversarial share costs exactly one attribution pass"
        );
    });
}

#[test_traced]
fn misattributed_da_shares_are_dropped_and_the_quorum_certifies_without_fallback() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(82, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        // One registration per peer: re-registering the same channel drops the first receiver.
        let (mut sender, mut data_rx) = node.peer(1, 0).await;
        let header = next_block(&node, &mut data_rx).await;

        // Participant one sends, ahead of the real votes, shares that name other signers and
        // carry bytes signed over a different header, for enough signers to deny a quorum if
        // they were kept. Ingress drops every one, since participant one is not their signer.
        let codec = node.committee.codec();
        let excluded = codec.participants() - codec.da_quorum() + 1;
        let elsewhere = node
            .committee
            .transaction_header(ChainId::new(0), Sha256::hash(&[b"another subject"]));
        for signer in 2..=excluded + 1 {
            let misattributed = DaVote::new(
                header.clone(),
                node.committee
                    .da_vote(Participant::from_usize(signer), elsewhere.clone())
                    .share()
                    .clone(),
            );
            sender.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::DaVote(misattributed)).encode(),
                false,
            );
        }
        for signer in 2..6 {
            let (mut peer, _) = node.peer(signer, 0).await;
            peer.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::DaVote(
                    node.committee
                        .da_vote(Participant::from_usize(signer), header.clone()),
                ))
                .encode(),
                false,
            );
        }

        // The honest shares form the quorum on the first attempt.
        let deadline = context.current() + Duration::from_secs(5);
        loop {
            let (_, bytes) = select! {
                result = data_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("misattributed shares stalled the honest quorum")
                },
            };
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaCertificate(certificate) = envelope.into_payload()
                && certificate.header() == &header
            {
                assert!(node.committee.verifier.verify_da_certificate(&certificate));
                break;
            }
        }

        assert!(node.blocker.blocked().is_empty());
        assert_eq!(
            metric_sum(
                &context.encode(),
                "primary_voter_da_recovery_fallbacks_total",
                &[]
            ),
            0.0,
            "no misattributed share reaches recovery"
        );
    });
}

#[test_traced]
fn invalid_verification_does_not_block_its_authenticated_source() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(76, Role::Observer, "primary")
            .start(&context)
            .await;
        let (mut peer_a, _) = node.peer(1, 0).await;
        let (mut peer_b, _) = node.peer(2, 0).await;

        let original_a0 = node
            .committee
            .signed_block(ChainId::new(0), Sha256::hash(&[b"original a0"]));
        let forged_a0 = SignedTransactionBlock::new(
            node.committee
                .transaction_header(ChainId::new(0), Sha256::hash(&[b"forged a0"])),
            original_a0.attestation().clone(),
        );
        let valid_b = node
            .committee
            .signed_block(ChainId::new(1), Sha256::hash(&[b"valid b"]));
        let original_a2 = node
            .committee
            .signed_block(ChainId::new(2), Sha256::hash(&[b"original a2"]));
        let forged_a2 = SignedTransactionBlock::new(
            node.committee
                .transaction_header(ChainId::new(2), Sha256::hash(&[b"forged a2"])),
            original_a2.attestation().clone(),
        );

        peer_a.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(forged_a0)).encode(),
            false,
        );
        peer_b.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(valid_b)).encode(),
            false,
        );
        peer_a.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(forged_a2)).encode(),
            false,
        );

        context.sleep(Duration::from_millis(50)).await;
        assert!(node.blocker.blocked().is_empty());
    });
}

#[test_traced]
fn relayed_double_vote_blocks_its_signer_not_the_relays() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(82, Role::Observer, "objective_equivocation")
            .start(&context)
            .await;
        let (mut first_relay, _) = node.peer(1, 1).await;
        let (mut second_relay, _) = node.peer(2, 1).await;
        let first_leader = node.committee.leader_block(View::new(1));
        let alternate = LeaderBlock::new(
            first_leader.block().round(),
            first_leader.block().parent(),
            Sha256::hash(&[b"alternate leader history"]),
            first_leader.block().proposals().to_vec(),
            node.committee.codec(),
        )
        .unwrap();
        let leader = node.committee.config.leader(View::new(1));
        let alternate = node.committee.signers[leader.get() as usize]
            .sign_leader_block(alternate)
            .unwrap();
        let signer = 3;

        first_relay.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Vote(
                node.committee.vote(Participant::from_usize(signer), &first_leader),
            ))
            .encode(),
            false,
        );
        second_relay.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Vote(
                node.committee.vote(Participant::from_usize(signer), &alternate),
            ))
            .encode(),
            false,
        );

        let deadline = context.current() + Duration::from_secs(1);
        while node.blocker.blocked().is_empty() {
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => panic!("verified double vote did not block its signer"),
            }
        }
        assert_eq!(
            node.blocker.blocked(),
            vec![node.committee.identities[signer].clone()],
        );
        // The voter counts the block under the batcher-labelled name the dashboard reads.
        assert_eq!(
            metric_sum(&context.encode(), "objective_equivocation_batcher_blocked_total", &[]),
            1.0,
        );
    });
}

#[test_traced]
fn accepted_inspection_loses_to_at_most_one_ready_event() {
    DeterministicRunner::default().start(|context| async move {
        let mut node = NodeBuilder::new(79, Role::Observer, "control_order")
            .start(&context)
            .await;
        let baseline = metric_sum(&context.encode(), "control_order_voter_stale_total", &[]);
        let view = View::new(1);
        for id in 0..8 {
            let job = ResolutionJob::issue(id, Generation::new(0), view);
            let completion = ResolutionCompletion::new(
                job.issued(),
                job.view(),
                ViewProof::Nullification(Box::new(node.committee.nullification(view))),
            );
            assert!(
                node.resolutions()
                    .resolved(
                        tracing::Span::none(),
                        tracing::Span::none(),
                        Round::new(node.committee.config.epoch(), view),
                        completion,
                    )
                    .accepted()
            );
        }

        let _ = node.inspect().await;
        let serviced =
            metric_sum(&context.encode(), "control_order_voter_stale_total", &[]) - baseline;
        assert!(
            (1.0..=2.0).contains(&serviced),
            "accepted inspection lost to {serviced} ready control events",
        );
    });
}

#[test_traced]
fn application_eventual_validity_restores_correct_chain_liveness() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        // The first remote verification is held by a one-shot gate.
        let application = MockApplication::builder()
            .gate_chain(ChainId::new(1))
            .build();
        let mut validation = application.gate_verification();
        let mut node = NodeBuilder::new(50, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;
        let (_, mut consensus_rx) = node.peer(1, 1).await;

        let remote_commitment = Sha256::hash(&[b"unavailable remote payload"]);
        let remote = node
            .committee
            .signed_block(ChainId::new(1), remote_commitment);
        let remote_header = remote.header().clone();
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(remote)).encode(),
            false,
        );
        validation.wait_started().await;

        let inspector = node.inspector();
        let _ = select! {
            result = inspector.inspect() => {
                result.expect("voter responds while validation is pending")
            },
            () = context.sleep(Duration::from_millis(100)) => {
                panic!("remote validation blocked voter control");
            },
        };

        let local = expect_within(
            &context,
            Duration::from_millis(250),
            next_block(&node, &mut data_rx),
            "remote validation blocked the eligible local build",
        )
        .await;
        assert_eq!(local.chain().get(), 0);

        let deadline = context.current() + Duration::from_secs(1);
        let mut saw_novote = false;
        let mut saw_nullify = false;
        while !(saw_novote && saw_nullify) {
            select! {
                result = consensus_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope =
                        Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
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
                            assert!(
                                node.committee
                                    .verifier
                                    .verify_nullify(&nullify)
                            );
                            saw_nullify = true;
                        }
                        _ => {}
                    }
                },
                () = context.sleep_until(deadline) => {
                    panic!("remote validation blocked the view timer");
                },
            }
        }

        validation.release();

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                data_rx.recv(),
                "eventually valid remote block did not receive a local DA vote",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical data envelope");
            let DataMessage::DaVote(vote) = envelope.into_payload() else {
                continue;
            };
            if vote.header() == &remote_header {
                assert_eq!(vote.signer(), Participant::new(0));
                break;
            }
        }

        let certificate = da_certificate(&node.committee, &remote_header);
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaCertificate(certificate))
                .encode(),
            false,
        );
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let inspection = node.inspect().await;
            let remote_chain = inspection
                .chain_progress()
                .iter()
                .find(|progress| progress.chain().get() == 1)
                .expect("remote chain is tracked");
            if remote_chain.certified() >= Height::new(1) {
                assert!(remote_chain.known() >= remote_chain.certified());
                break;
            }
            assert!(
                context.current() < deadline,
                "eventually valid remote chain did not certify"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

#[test_traced]
fn same_chain_validations_overlap_without_voting_past_pending_parent() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::builder()
            .gate_chain(ChainId::new(1))
            .build();
        let mut validations =
            application.gate_verification_heights([Height::new(1), Height::new(2)]);
        application.pause_building();
        let application_log = application.log();
        let limits = voter_limits();
        let node = NodeBuilder::new(
            111,
            Role::Validator(Participant::new(0)),
            "same_chain_validation_pipeline",
        )
        .attachments(Attachments {
            application,
            ..Attachments::default()
        })
        .limits(move |actor_limits| actor_limits.voter = limits)
        .start(&context)
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        let parent = node.committee.signed_block(
            ChainId::new(1),
            Sha256::hash(&[b"pipelined parent payload"]),
        );
        let parent_header = parent.header().clone();
        let child_header = TransactionBlockHeader::new(
            node.committee.config.epoch(),
            parent_header.chain(),
            parent_header.height().next(),
            parent_header.block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"pipelined child payload"]),
        )
        .expect("the child extends its live producer chain");
        let child = node.committee.signers[1]
            .sign_transaction_block(child_header.clone())
            .expect("the producer signs its child");
        let grandchild_header = TransactionBlockHeader::new(
            node.committee.config.epoch(),
            child_header.chain(),
            child_header.height().next(),
            child_header.block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"pipelined grandchild payload"]),
        )
        .expect("the grandchild extends its live producer chain");
        let grandchild = node.committee.signers[1]
            .sign_transaction_block(grandchild_header.clone())
            .expect("the producer signs its grandchild");

        for block in [child, grandchild] {
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::Block(block)).encode(),
                false,
            );
        }
        context.sleep(Duration::from_millis(10)).await;
        assert!(
            application_log.lock().verifications.is_empty(),
            "a descendant without an authenticated parent must not occupy validation capacity",
        );

        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(parent)).encode(),
            false,
        );
        let mut parent_validation = validations.remove(0);
        let mut child_validation = validations.remove(0);
        parent_validation.wait_started().await;
        child_validation.wait_started().await;
        assert_eq!(application_log.lock().verifications.len(), 2);

        child_validation.release();
        let deadline = context.current() + Duration::from_millis(100);
        while application_log.lock().verifications.len() < 3 {
            assert!(
                context.current() < deadline,
                "the completed child did not release the next same-chain request",
            );
            context.sleep(Duration::from_millis(1)).await;
        }
        let mut verification_heights = application_log
            .lock()
            .verifications
            .iter()
            .map(|(context, _)| context.height())
            .collect::<Vec<_>>();
        verification_heights.sort();
        assert_eq!(
            verification_heights,
            [
                parent_header.height(),
                child_header.height(),
                grandchild_header.height(),
            ],
            "validation dispatch follows producer ancestry even when descendants arrive first",
        );

        let deadline = context.current() + Duration::from_millis(100);
        loop {
            select! {
                result = data_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                        bytes,
                        &node.envelope_cfg(node.committee.codec()),
                    )
                    .expect("canonical data envelope");
                    if let DataMessage::DaVote(vote) = envelope.into_payload() {
                        assert!(
                            vote.header() != &child_header && vote.header() != &grandchild_header,
                            "a descendant cannot become DA-safe before its parent",
                        );
                    }
                },
                () = context.sleep_until(deadline) => break,
            }
        }

        parent_validation.release();

        let deadline = context.current() + Duration::from_secs(1);
        let mut voted = Vec::new();
        while voted.len() < 2 {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                data_rx.recv(),
                "the contiguous valid prefix did not receive DA votes",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical data envelope");
            let DataMessage::DaVote(vote) = envelope.into_payload() else {
                continue;
            };
            if vote.header() == &parent_header || vote.header() == &child_header {
                let height = vote.header().height();
                if !voted.contains(&height) {
                    voted.push(height);
                }
            }
        }
        assert_eq!(
            voted,
            [parent_header.height(), child_header.height()],
            "DA authority advances only across the contiguous valid prefix",
        );
    });
}

#[test_traced]
fn da_certificate_cancels_superseded_local_custody() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::builder()
            .gate_chain(ChainId::new(0))
            .build();
        let mut custody = application.gate_verification();
        let committee = Committee::<MinPk>::builder(109, 6)
            .limits(PathLimits::new(1, 1).unwrap())
            .build();
        let role = Role::Validator(Participant::new(0));
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let node = NodeBuilder::new(109, role, "cancel_custody")
            .network(committee, oracle, 0)
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        custody.wait_started().await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        let sibling = node
            .committee
            .transaction_header(ChainId::new(0), Sha256::hash(&[b"certified sibling"]));
        let certificate = da_certificate(&node.committee, &sibling);
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaCertificate(certificate))
                .encode(),
            false,
        );

        let replacement = expect_within(
            &context,
            Duration::from_secs(1),
            next_block(&node, &mut data_rx),
            "superseded custody prevented replacement production",
        )
        .await;
        assert_eq!(replacement.height(), sibling.height().next());
        assert_eq!(replacement.parent(), sibling.digest::<Sha256>());
    });
}

#[test_traced]
fn da_certificate_cancels_all_obsolete_pipelined_validations() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::builder()
            .gate_chain(ChainId::new(1))
            .build();
        let mut validations = application.gate_verifications(3);
        application.pause_building();
        let application_log = application.log();
        let limits = voter_limits();
        let node = NodeBuilder::new(
            83,
            Role::Validator(Participant::new(0)),
            "retire_validation",
        )
        .attachments(Attachments {
            application,
            ..Attachments::default()
        })
        .limits(move |actor_limits| actor_limits.voter = limits)
        .start(&context)
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        let first = node
            .committee
            .signed_block(ChainId::new(1), Sha256::hash(&[b"obsolete parent payload"]));
        let first_header = first.header().clone();
        let second_header = TransactionBlockHeader::new(
            node.committee.config.epoch(),
            first_header.chain(),
            first_header.height().next(),
            first_header.block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"obsolete child payload"]),
        )
        .expect("the child extends its live producer chain");
        let second = node.committee.signers[1]
            .sign_transaction_block(second_header.clone())
            .expect("the producer signs its child");
        let third_header = TransactionBlockHeader::new(
            node.committee.config.epoch(),
            second_header.chain(),
            second_header.height().next(),
            second_header.block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"surviving grandchild payload"]),
        )
        .expect("the grandchild extends its live producer chain");
        let third = node.committee.signers[1]
            .sign_transaction_block(third_header.clone())
            .expect("the producer signs its grandchild");

        for block in [first, second, third] {
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::Block(block)).encode(),
                false,
            );
        }
        let mut first_validation = validations.remove(0);
        let mut second_validation = validations.remove(0);
        let mut third_validation = validations.remove(0);
        first_validation.wait_started().await;
        second_validation.wait_started().await;
        assert_eq!(application_log.lock().verifications.len(), 2);

        let certificate = da_certificate(&node.committee, &second_header);
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaCertificate(certificate))
                .encode(),
            false,
        );

        third_validation.wait_started().await;
        first_validation.wait_cancelled().await;
        second_validation.wait_cancelled().await;
        third_validation.release();

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                data_rx.recv(),
                "the certified frontier did not release the surviving validation",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical data envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload()
                && vote.header() == &third_header
            {
                break;
            }
        }
    });
}
