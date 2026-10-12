//! Attached observer, broadcast-parent, and recovery reissue tests.

use super::harness::{Attachments, NodeBuilder, TestRelay, next_block, profile, voter_limits};
use crate::{
    Viewable as _,
    multimmit::{
        actors::{
            testing::CoreDriver,
            voter::{VoterLimits, actor::TestHooks, persistence::TestGates},
        },
        config::Role,
        machine::{CoreState, Input, Inspection},
        mocks::{Committee, MockApplication, cluster::start_network},
        storage::{RecoveryConfig, partitions, recover},
        testing::{expect_before, expect_within},
        types::{Artifact, ViewMessage},
        wire::{CertificateMessage, ConsensusMessage, Envelope},
    },
    types::{Participant, View},
};
use commonware_actor::Feedback;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Storage as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::Runner as DeterministicRunner,
    mocks::{DeferredSync, PendingSyncs, next_pending_sync},
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZU64, NZUsize};
use std::time::Duration;

#[test_traced]
fn attached_observer_matches_the_synchronous_core() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = NodeBuilder::new(45, Role::Observer, "primary")
            .start(&context)
            .await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        // One leader block and a finalizing vote quorum, in one deterministic arrival order.
        let block = node.committee.leader_block(View::new(1));
        let votes = (0..node.committee.codec().view_quorum())
            .map(|signer| node.committee.vote(Participant::from_usize(signer), &block))
            .collect::<Vec<_>>();
        let mut artifacts = vec![Artifact::LeaderBlock(block.clone())];
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(block),
                parent: None,
            })
            .encode(),
            true,
        );
        for vote in &votes {
            artifacts.push(Artifact::Vote(vote.clone()));
            consensus_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(ConsensusMessage::Vote(vote.clone())).encode(),
                true,
            );
        }

        // Drive the synchronous Core over the identical cohort.
        let committee = Committee::<MinPk>::builder(45, 6).build();
        let mut core = CoreState::fresh(profile(&committee, Role::Observer)).unwrap();
        core.enqueue(Input::Start).unwrap();
        let mut driver = CoreDriver::new(&committee.verifier);
        driver.settle(&mut core);
        driver.observe(&mut core, artifacts);
        driver.settle(&mut core);
        let expected = core.machine().inspect();

        // The attached machine converges to the same normalized projection.
        let mut attached = node.inspect().await;
        for _ in 0..200 {
            if matches_protocol_projection(&attached, &expected) {
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
            attached = node.inspect().await;
        }
        assert!(
            matches_protocol_projection(&attached, &expected),
            "attached {attached:?} does not match pure {expected:?}"
        );
    });
}

#[test_traced]
fn updated_broadcast_parent_is_attached_to_a_live_proposal() {
    broadcast_parent_proposal(true);
}

#[test_traced]
fn exact_broadcast_parent_is_omitted_from_a_live_proposal() {
    broadcast_parent_proposal(false);
}

fn broadcast_parent_proposal(update_parent: bool) {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let seed = 79;
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let role = Role::Validator(Participant::new(3));
        let application = MockApplication::new();
        application.pause_building();
        let mut node = NodeBuilder::new(seed, role, "updated_parent")
            .network(Committee::<MinPk>::builder(seed, 6).build(), oracle, 3)
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (mut consensus_tx, mut consensus_rx) = node.peer(1, 1).await;
        let (mut certificate_tx, mut certificate_rx) = node.peer(1, 2).await;
        let block = committee.leader_block(View::new(1));
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(block.clone()),
                parent: None,
            })
            .encode(),
            true,
        );

        let messages = (0..6)
            .map(|signer| {
                ViewMessage::Vote(committee.vote(Participant::from_usize(signer), &block))
            })
            .collect::<Vec<_>>();
        let votes = messages[..committee.codec().view_quorum()]
            .iter()
            .map(|message| {
                let ViewMessage::Vote(vote) = message else {
                    unreachable!("the test uses only votes");
                };
                node.envelope(ConsensusMessage::Vote(vote.clone())).encode()
            })
            .collect::<Vec<_>>();
        for vote in &votes {
            consensus_tx.send(Recipients::One(node.me.clone()), vote.clone(), true);
        }
        let deadline = context.current() + Duration::from_secs(2);
        let mut published = None;
        while published.is_none() {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                certificate_rx.recv(),
                "the first V-QC was not published",
            )
            .await
            .expect("network stays up");
            let envelope = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical certificate envelope");
            if let CertificateMessage::Vqc(certificate) = envelope.into_payload() {
                published = Some(certificate);
            }
        }
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(node.inspect().await.view(), View::new(2));

        let updated = update_parent.then(|| {
            committee
                .verifier
                .assemble_vqc::<Sha256, _>(block.block().clone(), &messages, &Sequential)
                .expect("all participants form a fuller V-QC")
        });
        if let Some(parent) = &updated {
            assert_ne!(
                parent.id::<Sha256>(),
                published.as_ref().unwrap().id::<Sha256>()
            );
            certificate_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::Vqc(parent.clone()))
                    .encode(),
                true,
            );
            context.sleep(Duration::from_millis(100)).await;
        }

        certificate_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                committee.nullification(View::new(2)),
            ))
            .encode(),
            true,
        );
        // The proposal names its exact parent. A fuller certificate requires an attachment;
        // the first broadcast already supplies the unchanged parent.
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let (_, bytes) = select! {
                result = consensus_rx.recv() => result.expect("network stays up"),
                result = certificate_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope =
                        Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                            bytes,
                            &node.envelope_cfg(node.committee.codec()),
                        )
                        .expect("canonical certificate envelope");
                    if let CertificateMessage::Vqc(certificate) = envelope.into_payload()
                        && certificate.view() == View::new(1)
                    {
                        published = Some(certificate);
                    }
                    continue;
                },
                () = context.sleep_until(deadline) => panic!("the view-3 proposal never arrived"),
            };
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical consensus envelope");
            let ConsensusMessage::Proposal { block, parent } = envelope.into_payload() else {
                continue;
            };
            if block.view() != View::new(3) {
                continue;
            }
            let published = published.expect("a view-1 V-QC was published");
            let Some(updated) = &updated else {
                assert_eq!(block.block().parent(), published.id::<Sha256>());
                assert!(
                    parent.is_none(),
                    "the exact broadcast parent must be omitted"
                );
                break;
            };
            let parent = parent.expect("the fuller parent must accompany the proposal");
            assert_eq!(parent.as_ref(), updated);
            assert_eq!(block.block().parent(), parent.id::<Sha256>());
            assert_eq!(parent.leader(), published.leader());
            assert!(
                parent.tally().signers().count() >= published.tally().signers().count(),
                "the attached parent lost votes the broadcast certificate carried"
            );
            assert!(
                published.tally().signers().iter().all(|signer| parent
                    .tally()
                    .signers()
                    .iter()
                    .any(|s| s == signer)),
                "the attached parent is not a superset of the broadcast certificate"
            );
            break;
        }
    });
}

/// Compares protocol state, excluding scheduling-dependent outbox IDs and pending barriers.
fn matches_protocol_projection(
    left: &Inspection<Sha256Digest>,
    right: &Inspection<Sha256Digest>,
) -> bool {
    left.outbox().len() == right.outbox().len()
        && left.epoch() == right.epoch()
        && left.view() == right.view()
        && left.generation() == right.generation()
        && left.cursor() == right.cursor()
        && left.is_live() == right.is_live()
        && left.is_recovering() == right.is_recovering()
        && left.cached_artifacts() == right.cached_artifacts()
        && left.pending_artifacts() == right.pending_artifacts()
        && left.waiting_artifacts() == right.waiting_artifacts()
        && left.ready_artifacts() == right.ready_artifacts()
        && left.dropped_artifacts() == right.dropped_artifacts()
        && left.future_artifacts() == right.future_artifacts()
        && left.verification_jobs() == right.verification_jobs()
        && left.local_artifacts() == right.local_artifacts()
        && left.finality_floor() == right.finality_floor()
        && left.produced_blocks() == right.produced_blocks()
        && left.resolution_jobs() == right.resolution_jobs()
        && left.chain_progress() == right.chain_progress()
        && left.pools() == right.pools()
        && left.finality() == right.finality()
        && left.retained_artifact_references() == right.retained_artifact_references()
        && left.nullification_suffix() == right.nullification_suffix()
        && left.retired_view() == right.retired_view()
        && left.finality_floor() == right.finality_floor()
}

#[test_traced]
fn recovery_reissues_unsuperseded_publications() {
    // Run one validator until it has two distinct durable publications, then crash the whole
    // runtime uncleanly and recover only its synced storage.
    let seed = 46;
    let role = Role::Validator(Participant::new(0));
    let initial_relay = TestRelay::default();
    let first_relay = initial_relay.clone();
    let runner = DeterministicRunner::timed(Duration::from_secs(60));
    let (obligations, checkpoint) = runner.start_and_recover(move |context| async move {
        let node = NodeBuilder::new(seed, role, "first")
            .attachments(Attachments {
                relay: first_relay,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let mut obligations = Vec::new();
        while obligations.len() < 2 {
            let header = next_block(&node, &mut data_rx).await;
            if !obligations.contains(&header) {
                obligations.push(header);
            }
        }
        obligations
    });
    for header in &obligations {
        assert!(
            initial_relay
                .broadcasts()
                .iter()
                .any(|(attempted, _)| *attempted == header.digest::<Sha256>()),
            "initial publication was not relayed: {header:?}"
        );
    }

    // Close the first recovered attempt for both obligations. Each must remain installed, retry
    // Relay, and publish its original signed header only after Relay accepts it.
    let relay = TestRelay::scripted([Feedback::Closed, Feedback::Closed], Feedback::Ok);
    let runner = DeterministicRunner::from(checkpoint);
    runner.start(move |context| async move {
        let mut node = NodeBuilder::new(seed, role, "second")
            .attachments(Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() > 0);
        let expected = format!(
            "second_voter_produced_blocks {}",
            inspection.produced_blocks()
        );
        assert!(
            context.encode().lines().any(|line| line == expected),
            "recovered production gauge did not reflect machine state"
        );
        let (_, mut data_rx) = node.peer(1, 0).await;
        let deadline = context.current() + Duration::from_secs(2);
        let mut recovered = Vec::new();
        while recovered.len() < obligations.len() {
            let header = select! {
                header = next_block(&node, &mut data_rx) => header,
                () = context.sleep_until(deadline) => {
                    panic!("recovery did not republish every exact obligation: {recovered:?}");
                },
            };
            let Some(expected) = obligations
                .iter()
                .find(|expected| expected.digest::<Sha256>() == header.digest::<Sha256>())
            else {
                continue;
            };
            assert_eq!(
                &header, expected,
                "recovery reconstructed a different header"
            );
            if !recovered.contains(&header) {
                recovered.push(header);
            }
        }

        for expected in &obligations {
            let attempts = relay
                .broadcasts()
                .into_iter()
                .filter_map(|(attempted, feedback)| {
                    (attempted == expected.digest::<Sha256>()).then_some(feedback)
                })
                .collect::<Vec<_>>();
            assert_eq!(attempts.first(), Some(&Feedback::Closed));
            assert!(
                attempts.contains(&Feedback::Ok),
                "recovered obligation was not retried after Relay closed: {expected:?}"
            );
        }
    });
}

#[test_traced]
fn recovery_ready_waits_for_the_exact_drain_acknowledgement() {
    const RECOVERY_DELAY: Duration = Duration::from_millis(250);

    let seed = 83;
    let role = Role::Validator(Participant::new(0));
    let runner = DeterministicRunner::timed(Duration::from_secs(30));
    let (expected, checkpoint) = runner.start_and_recover(move |context| async move {
        let (node, ready) = NodeBuilder::new(seed, role, "recovery_source")
            .start_pending(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        ready.await.expect("source voter becomes ready");
        next_block(&node, &mut data_rx).await
    });

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let gates = TestGates::default();
        let mut drain = gates.arm_next_start_sync();
        let (node, ready) = NodeBuilder::new(seed, role, "recovery_target")
            .attachments(Attachments {
                hooks: TestHooks::default().with_gates(gates),
                ..Attachments::default()
            })
            .start_pending(&context)
            .await;
        let mut ready = Box::pin(ready);
        drain.wait_entered().await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        select! {
            result = &mut ready => panic!("ready resolved before recovery drain: {result:?}"),
            result = data_rx.recv() => panic!("recovered publication escaped before ready: {result:?}"),
            () = context.sleep(RECOVERY_DELAY) => {},
        }
        drain.release();
        ready.await.expect("recovered voter becomes ready");
        let recovered = expect_within(
            &context,
            Duration::from_secs(1),
            next_block(&node, &mut data_rx),
            "pre-ack recovery publication was not preserved",
        )
        .await;
        assert_eq!(recovered, expected);
    });
}

#[test_traced]
fn repeated_pre_ack_recovery_crashes_keep_the_suffix_bounded() {
    const SEED: u64 = 108;
    const RESTARTS: usize = 5;

    let role = Role::Validator(Participant::new(0));
    let runner = DeterministicRunner::timed(Duration::from_secs(30));
    let (_, mut checkpoint) = runner.start_and_recover(move |context| async move {
        let mut node = NodeBuilder::new(SEED, role, "bounded_recovery")
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let _ = next_block(&node, &mut data_rx).await;
        for _ in 0..100 {
            if node.inspect().await.pending_barrier().is_none() {
                node.crash(&context).await;
                return;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("the source generation did not become durable");
    });

    for _ in 0..RESTARTS {
        let gates = TestGates::default();
        let mut synced_generation = gates.arm_next_after_sync();
        let checkpoint_syncs = PendingSyncs::default();
        checkpoint_syncs.arm();
        let DeferredSync {
            release: release_startup_sync,
            blocked: startup_sync_blocked,
        } = next_pending_sync(&checkpoint_syncs);
        let runner = DeterministicRunner::from(checkpoint);
        let (_, next_checkpoint) = runner.start_and_recover(move |context| async move {
            let limits = VoterLimits {
                checkpoint_interval: NZU64!(1),
                ..voter_limits()
            };
            let mut starting = Box::pin(
                NodeBuilder::new(SEED, role, "bounded_recovery")
                    .attachments(Attachments {
                        checkpoint_syncs: checkpoint_syncs.clone(),
                        hooks: TestHooks::default().with_gates(gates),
                        ..Attachments::default()
                    })
                    .limits(move |actor_limits| actor_limits.voter = limits)
                    .start_pending(&context),
            );
            select! {
                result = startup_sync_blocked => {
                    result.expect("recovery compaction reaches the storage fence");
                },
                _ = &mut starting => {
                    panic!("recovery constructed actors before its compacted base was durable");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("recovery did not reach its actor-free storage fence");
                },
            }
            assert_eq!(
                count_running_tasks(&context, "bounded_recovery"),
                0,
                "an actor existed while recovery storage was fenced"
            );
            release_startup_sync
                .send(Ok(()))
                .expect("startup storage fence remains pending");
            checkpoint_syncs.unblock();
            let (node, ready) = starting.await;
            let mut ready = Box::pin(ready);
            select! {
                () = synced_generation.wait_entered() => {},
                result = &mut ready => {
                    panic!("recovery became ready before its generation acknowledgement: {result:?}");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("recovery generation did not reach the post-sync crash cut");
                },
            }
            node.crash(&context).await;
        });
        checkpoint = next_checkpoint;
    }

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let committee = Committee::<MinPk>::builder(SEED, 6).build();
        let mut store_context = context.child("bounded_recovery_stores");
        let recovered = Box::pin(recover::<_, Sha256, _, _, _, _>(
            &mut store_context,
            RecoveryConfig {
                profile: profile(&committee, role),
                partition_prefix: &format!("node_{SEED}"),
                scheme: &committee.signers[0],
                strategy: &Sequential,
                page_cache: CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
                checkpoint_interval: voter_limits().checkpoint_interval,
                inflight_application: NZUsize!(4),
            },
            &MockApplication::new(),
        ))
        .await
        .expect("stores recover after repeated pre-ack crashes");
        assert_eq!(
            recovered.replayed,
            Some(1),
            "each restart must replace, rather than extend, the replay suffix"
        );

        let sections = context
            .scan(&partitions(&format!("node_{SEED}")).journal)
            .await
            .expect("journal partition remains readable");
        assert!(
            sections.len() <= 2,
            "repeated recovery retained obsolete journal sections: {sections:?}"
        );
    });
}
