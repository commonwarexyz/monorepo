//! Relay, reporter, and publication retry tests.

use super::harness::{
    Attachments, NodeBuilder, TestRelay, TestReporter, da_certificate, next_block, tuning,
    voter_limits,
};
use crate::{
    multimmit::{
        actors::voter::VoterLimits,
        config::Role,
        engine::{Config as EngineConfig, Engine, Planes},
        mocks::{
            Committee, MockApplication,
            cluster::{QUOTA, start_network},
        },
        testing::{expect_before, expect_within},
        types::{Activity, Artifact, ChainId},
        wire::{ConsensusMessage, DataMessage, Envelope},
    },
    types::{Attributable as _, Participant, View},
};
use commonware_actor::Feedback;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _, utils::mocks::NoopBlocker};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::{FaultConfig, Runner as DeterministicRunner},
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZUsize, probability};
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc, time::Duration};
#[test_traced]
fn mutable_journal_sync_failure_stops_production_engine() {
    let seed = 82;
    DeterministicRunner::timed(Duration::from_secs(10)).start(move |context| async move {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let me = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let control = oracle.control(me);
        let planes = Planes {
            data: control.register(0, QUOTA).await.unwrap(),
            consensus: control.register(1, QUOTA).await.unwrap(),
            certificates: control.register(2, QUOTA).await.unwrap(),
            resolver: control.register(3, QUOTA).await.unwrap(),
        };
        let application = MockApplication::new();
        application.pause_building();
        let engine_context = context.child("storage_failure_engine");
        let task_prefix = engine_context.name().label;
        let engine = Engine::<_, Sha256, _, _, _, _, _, _, _, _>::open(
            engine_context,
            EngineConfig {
                scheme: committee.signers[0].clone(),
                genesis: committee.config.genesis().clone(),
                tuning: tuning(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: TestReporter::default(),
                strategy: Sequential,
                critical_strategy: Sequential,
                blocker: NoopBlocker::default(),
                partition_prefix: "storage_failure_engine".to_owned(),
                page_cache: CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
                mailbox_size: NonZeroUsize::new(64).unwrap(),
            },
        )
        .await
        .expect("the production engine opens");
        let mut running = engine.start(planes);
        assert!(
            running.ready().await.is_ok(),
            "the production engine becomes ready"
        );
        assert!(
            count_running_tasks(&context, &task_prefix) > 0,
            "the production engine has no supervised tasks before fault injection"
        );
        let inspector = running.inspector().clone();

        *context.storage_fault_config().write() = FaultConfig {
            sync_rate: Some(probability!(1.0)),
            ..FaultConfig::default()
        };
        application.permit_builds(1);

        let mut joined = Box::pin(running.join());
        select! {
            result = &mut joined => {
                assert!(result.is_ok(), "the engine root stops on its own after the failure");
            },
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("the engine root did not stop after the mutable journal failure");
            },
        }
        assert!(
            inspector.inspect().await.is_none(),
            "the failed engine left its diagnostic mailbox open"
        );
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            count_running_tasks(&context, &task_prefix),
            0,
            "the joined engine left supervised descendants running"
        );
    });
}

#[test_traced]
fn dependency_blocked_artifact_is_not_reported_before_admission() {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let reporter = TestReporter::with_feedback(Feedback::Ok);
        let mut node = NodeBuilder::new(51, Role::Observer, "primary")
            .attachments(Attachments {
                reporter: reporter.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        let leader = node.committee.leader_block(View::new(1));
        let vote = node.committee.vote(Participant::new(1), &leader);
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Vote(vote)).encode(),
            true,
        );

        let deadline = context.current() + Duration::from_secs(2);
        loop {
            if node.inspect().await.waiting_artifacts() == 1 {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("vote never entered the dependency index");
                },
            }
        }

        let activities = reporter.activities();
        assert!(
            activities.is_empty(),
            "dependency-blocked activity was reported before admission: {activities:?}"
        );
    });
}

#[test_traced]
fn closed_relay_retries_exact_header_digest_without_publishing_header() {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let relay = TestRelay::with_feedback(Feedback::Closed);
        let node = NodeBuilder::new(52, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        select! {
            header = next_block(&node, &mut data_rx) => {
                panic!("closed relay allowed transaction header publication: {header:?}");
            },
            () = context.sleep(Duration::from_secs(1)) => {},
        }

        let broadcasts = relay.broadcasts();
        assert!(
            broadcasts.len() >= 2,
            "closed relay was not retried: {broadcasts:?}"
        );
        assert!(
            broadcasts
                .iter()
                .all(|(_, feedback)| *feedback == Feedback::Closed),
            "relay returned unexpected feedback: {broadcasts:?}"
        );
        let header_digests = broadcasts
            .iter()
            .map(|(header_digest, _)| *header_digest)
            .collect::<BTreeSet<_>>();
        assert!(
            header_digests.iter().all(|header_digest| {
                broadcasts
                    .iter()
                    .filter(|(attempted, _)| attempted == header_digest)
                    .count()
                    >= 2
            }),
            "a durable Relay obligation was not retried exactly: {broadcasts:?}"
        );
    });
}

#[test_traced]
fn closed_relay_does_not_withhold_consensus_transmissions() {
    // A dead relay endpoint may withhold transaction-block transmissions, but never the
    // consensus-critical artifacts sharing a publication with them: two relay-muted senders
    // exhaust the committee's fault budget and freeze every view.
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let relay = TestRelay::with_feedback(Feedback::Closed);
        let node = NodeBuilder::new(55, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (mut consensus_tx, mut consensus_rx) = node.peer(1, 1).await;

        let block = node.committee.leader_block(View::new(1));
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(block),
                parent: None,
            })
            .encode(),
            true,
        );

        let deadline = context.current() + Duration::from_secs(3);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                consensus_rx.recv(),
                "closed relay withheld the node's consensus transmissions",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if let ConsensusMessage::Vote(vote) = envelope.into_payload() {
                assert!(node.committee.verifier.verify_vote(&vote));
                break;
            }
        }
        assert!(
            relay
                .broadcasts()
                .iter()
                .all(|(_, feedback)| *feedback == Feedback::Closed),
            "the relay endpoint stayed closed for every attempt"
        );
    });
}

#[test_traced]
fn accepted_relay_attempt_precedes_exact_header_publication() {
    for (seed, feedback) in [(53, Feedback::Ok), (54, Feedback::Backoff)] {
        let executor = DeterministicRunner::timed(Duration::from_secs(10));
        executor.start(move |context| async move {
            let relay = TestRelay::with_feedback(feedback);
            let node = NodeBuilder::new(seed, Role::Validator(Participant::new(0)), "primary")
                .attachments(Attachments {
                    relay: relay.clone(),
                    ..Attachments::default()
                })
                .start(&context)
                .await;
            let (_, mut data_rx) = node.peer(1, 0).await;

            let header = expect_within(
                &context,
                Duration::from_secs(2),
                next_block(&node, &mut data_rx),
                "accepted relay attempt did not publish a header",
            )
            .await;

            let broadcasts = relay.broadcasts();
            let header_digest = header.digest::<Sha256>();
            assert_ne!(header_digest, header.body_digest());
            let Some((_, returned)) = broadcasts
                .iter()
                .find(|(attempted, _)| *attempted == header_digest)
            else {
                panic!("header was published before its exact relay attempt");
            };
            assert_eq!(*returned, feedback);
        });
    }
}

#[test_traced]
fn publication_retries_until_semantic_supersession() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = NodeBuilder::new(42, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        // The block is retried across the backoff schedule. The producer keeps building
        // within its window while work is pending, so later frames may carry newer blocks; the
        // retry is the frame that repeats this exact header.
        let header = next_block(&node, &mut data_rx).await;
        let mut retried = false;
        for _ in 0..8 {
            let again = next_block(&node, &mut data_rx).await;
            if again == header {
                retried = true;
                break;
            }
        }
        assert!(retried, "the exact block is retried until it is superseded");
        let metrics = context.encode();
        assert!(
            metrics.lines().any(|line| {
                line.contains("retransmitted_bytes_total")
                    && line.contains("plane=\"Data\"")
                    && !line.ends_with(" 0")
            }),
            "publication retries must count into the per-plane retry byte family: {metrics}",
        );

        // An admitted DA certificate for the header supersedes the block publication.
        let certificate = da_certificate(&node.committee, &header);
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                certificate,
            ))
            .encode(),
            false,
        );

        // Let the certificate be admitted and the in-flight frames settle. The producer keeps
        // building newer blocks, so supersession is about this exact header, not about the outbox
        // emptying.
        context.sleep(Duration::from_secs(2)).await;
        let (_, mut settled_rx) = node.peer(2, 0).await;
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            select! {
                result = settled_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope =
                        Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                            bytes,
                            &node.envelope_cfg(node.committee.codec()),
                        )
                        .expect("canonical envelope");
                    if let DataMessage::Block(sent) = envelope.into_payload() {
                        assert_ne!(
                            sent.header(),
                            &header,
                            "superseded block kept publishing"
                        );
                    }
                },
                () = context.sleep_until(deadline) => break,
            }
        }
    });
}

#[test_traced]
fn accepted_relay_is_reused_during_header_retries() {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let relay = TestRelay::default();
        let node = NodeBuilder::new(110, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let header = next_block(&node, &mut data_rx).await;
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            select! {
                again = next_block(&node, &mut data_rx) => {
                    if again == header {
                        break;
                    }
                },
                () = context.sleep_until(deadline) => {
                    panic!("the durable transaction header was not retried");
                },
            }
        }

        let digest = header.digest::<Sha256>();
        let attempts = relay
            .broadcasts()
            .into_iter()
            .filter(|(attempted, _)| *attempted == digest)
            .collect::<Vec<_>>();
        assert_eq!(
            attempts.len(),
            1,
            "header retries must reuse an accepted Relay broadcast: {attempts:?}"
        );
    });
}

#[test_traced]
fn outstanding_block_refreshes_relay_on_the_heartbeat() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let relay = TestRelay::default();
        let limits = VoterLimits {
            retry_initial: Duration::from_millis(70),
            retry_ceiling: Duration::from_millis(70),
            heartbeat: Duration::from_millis(200),
            ..voter_limits()
        };
        let node = NodeBuilder::new(111, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            })
            .limits(move |actor_limits| actor_limits.voter = limits)
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let digest = next_block(&node, &mut data_rx).await.digest::<Sha256>();
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let attempts = relay
                .broadcasts()
                .into_iter()
                .filter(|(attempted, _)| *attempted == digest)
                .count();
            if attempts >= 2 {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(25)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("an outstanding block was not refreshed through Relay");
                },
            }
        }
    });
}

#[test_traced]
fn reporter_feedback_does_not_block_remote_block_admission() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let reporter = TestReporter::with_feedback(Feedback::Closed);
        let application = MockApplication::new();
        application.pause_building();
        let node = NodeBuilder::new(43, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                application,
                reporter: reporter.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        // The producer of chain one sends its block; the DA share must come back to it alone.
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;
        let (_, mut other_rx) = node.peer(2, 0).await;

        let commitment = Sha256::hash(&[b"remote payload"]);
        let block = node.committee.signed_block(ChainId::new(1), commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block.clone())).encode(),
            false,
        );

        // The producer receives an attributed DA share from participant zero.
        loop {
            let (_, bytes) = peer_data_rx.recv().await.expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload() {
                assert_eq!(vote.signer().get(), 0);
                assert_eq!(vote.header().body_digest(), commitment);
                assert!(node.committee.verifier.verify_da_vote(&vote));
                break;
            }
        }
        let artifact = Artifact::TransactionBlock(block);
        let accepted = Activity::ProtocolAccepted {
            artifact_id: artifact.id::<Sha256>(),
            artifact: Arc::new(artifact),
        };
        let activities = reporter.activities();
        assert!(
            activities.contains(&accepted),
            "admitted block was not reported: {activities:?}"
        );

        // The share is a point-to-point send: another peer never sees it.
        select! {
            result = other_rx.recv() => {
                panic!("targeted send leaked to another peer: {result:?}");
            },
            () = context.sleep(Duration::from_millis(500)) => {},
        }
    });
}
