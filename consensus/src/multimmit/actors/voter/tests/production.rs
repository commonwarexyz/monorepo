//! Local block building, custody, checkpointing, and signed-publication tests.

use super::harness::{Attachments, NodeBuilder, da_certificate, next_block, voter_limits};
use crate::{
    Epochable as _,
    multimmit::{
        actors::voter::{VoterLimits, actor::TestHooks, persistence::TestGates},
        config::Role,
        mocks::{Committee, MockApplication},
        storage::partitions,
        testing::{expect_before, expect_within},
        types::{ChainId, Context},
        wire::{CertificateMessage, DataMessage, Envelope, EnvelopeConfig},
    },
    types::{Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_collect_traces, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Spawner as _, Storage as _, Supervisor as _,
    deterministic::Runner as DeterministicRunner, telemetry::traces::collector::TraceStorage,
};
use commonware_utils::NZU64;
use std::time::Duration;
use tracing::Level;
#[test_traced]
fn fresh_validator_requests_a_block_without_work_update() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let application = MockApplication::new();
        let mut build = application.gate_build();
        let log = application.log();
        let _node = NodeBuilder::new(61, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;

        select! {
            () = build.wait_started() => {},
            () = context.sleep(Duration::from_millis(250)) => {
                panic!("fresh validator did not autonomously request a block");
            },
        }
        assert_eq!(log.lock().proposed, 1);
        build.release();
    });
}

#[test_traced]
fn declined_build_is_retried_without_another_work_update() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let application = MockApplication::builder().decline(1).build();
        let log = application.log();
        let node = NodeBuilder::new(62, Role::Validator(Participant::new(0)), "primary")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let header = expect_within(
            &context,
            Duration::from_millis(500),
            next_block(&node, &mut data_rx),
            "declined application build was not retried after the production interval",
        )
        .await;
        assert_eq!(
            header.body_digest(),
            MockApplication::block_digest(Context::from(&header), b"mock payload 1")
        );
        // The producer may already have requested its next pipelined block, so compare the
        // counts: exactly one request, the first, went unbuilt.
        let log = log.lock();
        assert!(log.built >= 1);
        assert_eq!(
            log.proposed,
            log.built + 1,
            "exactly one request is declined"
        );
    });
}

#[test_traced]
fn checkpoints_interleave_with_pipelined_barriers() {
    // Barriers pipeline behind staged application, so a checkpoint must never observe a batch
    // the machine emitted but the journal has not appended. A one-event interval forces a
    // checkpoint attempt at every acknowledgement, exactly where that window would open.
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        // Every acknowledged event is due for a checkpoint.
        let mut node = NodeBuilder::new(53, Role::Validator(Participant::new(0)), "primary")
            .limits(|limits| limits.voter.checkpoint_interval = NZU64!(1))
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        // Two blocks exhaust the solo producer's pipeline depth; every event in between forces
        // a checkpoint attempt against the live barrier pipeline.
        for _ in 0..2 {
            next_block(&node, &mut data_rx).await;
        }
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() >= 2);
    });
}

#[test_traced]
fn checkpoint_roll_and_prune_keep_control_live() {
    const SEED: u64 = 89;
    const CHECKPOINT_INTERVAL: u64 = 32;

    DeterministicRunner::timed(Duration::from_secs(20)).start(|context| async move {
        let application = MockApplication::new();
        let application_log = application.log();
        let gates = TestGates::default();
        let mut roll = gates.arm_next_roll();
        let mut before_prune = gates.arm_next_before_prune();
        let mut after_prune = gates.arm_next_after_prune();
        let limits = VoterLimits {
            checkpoint_interval: NZU64!(CHECKPOINT_INTERVAL),
            ..voter_limits()
        };
        let mut node = NodeBuilder::new(
            SEED,
            Role::Validator(Participant::new(0)),
            "checkpoint_fence",
        )
        .attachments(Attachments {
            application,
            hooks: TestHooks::default().with_gates(gates.clone()),
            ..Attachments::default()
        })
        .limits(move |actor_limits| actor_limits.voter = limits)
        .start(&context)
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        // Certify every produced block through the real peer/ingress path. Each certificate
        // reopens the bounded producer window, so authority-producing work remains continuously
        // available until the checkpoint fence deliberately pauses its admission.
        let feeder_committee = Committee::<MinPk>::builder(SEED, 6).build();
        let feeder_me = node.me.clone();
        let feeder = context
            .child("checkpoint_feeder")
            .spawn(move |_| async move {
                while let Ok((_, bytes)) = data_rx.recv().await {
                    let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                        bytes,
                        &EnvelopeConfig {
                            max_frame_bytes: usize::MAX,
                            epoch: feeder_committee.config.epoch(),
                            payload: feeder_committee.codec(),
                        },
                    )
                    .expect("node emits canonical data envelopes");
                    let DataMessage::Block(block) = envelope.into_payload() else {
                        continue;
                    };
                    let header = block.header().clone();
                    let certificate = da_certificate(&feeder_committee, &header);
                    data_tx.send(
                        Recipients::One(feeder_me.clone()),
                        Envelope::new(
                            feeder_committee.config.epoch(),
                            DataMessage::<MinPk, Sha256Digest>::DaCertificate(certificate),
                        )
                        .encode(),
                        false,
                    );
                }
            });

        select! {
            () = roll.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("continuous authority load starved the journal roll");
            },
        }
        assert!(
            application_log.lock().built >= 3,
            "the checkpoint must follow sustained certificate-driven production"
        );
        let roll_appends = gates.appends().len();
        expect_within(
            &context,
            Duration::from_secs(1),
            node.inspect(),
            "journal rolling blocked read-only inspection",
        )
        .await;
        assert_eq!(
            gates.appends().len(),
            roll_appends,
            "post-cut authority waits for the journal roll"
        );
        roll.release();

        select! {
            () = before_prune.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("continuous authority load starved checkpoint pruning");
            },
        }
        let prune_appends = gates.appends().len();
        context.sleep(Duration::from_secs(1)).await;
        assert_eq!(
            gates.appends().len(),
            prune_appends,
            "a stalled prune reopened post-cut journal growth"
        );
        expect_within(
            &context,
            Duration::from_secs(1),
            node.inspect(),
            "the prune fence blocked read-only inspection",
        )
        .await;
        let checkpoint_partition = partitions(&format!("node_{SEED}")).checkpoints;
        assert!(
            !context
                .scan(&checkpoint_partition)
                .await
                .unwrap()
                .is_empty(),
            "pruning must follow a durable checkpoint"
        );
        before_prune.release();

        select! {
            () = after_prune.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("the admitted prune did not complete");
            },
        }
        let journal_partition = partitions(&format!("node_{SEED}")).journal;
        let sections = context
            .scan(&journal_partition)
            .await
            .expect("journal partition remains readable");
        assert!(
            sections
                .iter()
                .all(|name| name.as_slice() != 0u64.to_be_bytes()),
            "pruning retained the checkpoint-covered journal section"
        );
        after_prune.release();

        feeder.abort();
        let _ = feeder.await;
    });
}

#[test_traced]
fn fresh_validator_builds_signs_and_publishes_a_block() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = NodeBuilder::new(41, Role::Validator(Participant::new(0)), "primary")
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let header = next_block(&node, &mut data_rx).await;
        assert_eq!(header.chain().get(), 0);
        assert!(
            [b"mock payload 1".as_slice(), b"mock payload 2".as_slice()]
                .into_iter()
                .map(|payload| MockApplication::block_digest(Context::from(&header), payload))
                .any(|commitment| commitment == header.body_digest())
        );

        // The producer keeps building while its certificate window remains open.
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() >= 1);

        let metrics = context.encode();
        assert!(
            !metrics.contains("primary_voter_view_advances_total"),
            "current_view is the single source of leader-view progress: {metrics}"
        );
        for metric in ["transmissions_total", "transmitted_bytes_total"] {
            assert!(
                metrics.lines().any(|line| {
                    line.contains(metric)
                        && line.contains("plane=\"Data\"")
                        && !line.ends_with(" 0")
                }),
                "published data traffic was not counted in {metric}: {metrics}"
            );
        }
        for name in [
            "primary_voter_current_view",
            "primary_voter_proposal_anchor_view",
            "primary_voter_produced_blocks",
            "primary_voter_producer_pipeline_blocked",
            "primary_voter_invalid_blocks",
            "primary_voter_unavailable_validations",
            "primary_voter_validation_latency",
            "primary_voter_build_active",
            "primary_voter_custody_active",
            "primary_voter_build_latency",
            "primary_voter_vqc_latency",
            "primary_voter_lqc_latency",
            "primary_voter_chains_finalized{chain=\"0\"}",
            "primary_voter_chain_certified_floor",
            "primary_voter_chain_da_voted_floor",
            "primary_voter_chain_known_floor",
            "primary_voter_lagging_chains",
        ] {
            assert!(metrics.contains(name), "missing metric {name}: {metrics}");
        }
        // Per-chain series scale with the validator count, so only finality stays per chain.
        for name in [
            "primary_voter_chains_known",
            "primary_voter_chains_certified",
            "primary_voter_chains_da_voted",
        ] {
            assert!(
                !metrics.contains(name),
                "unexpected metric {name}: {metrics}"
            );
        }
    });
}

#[test_traced]
fn local_custody_failure_stops_the_voter() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        for (seed, result, instance) in [
            (141, Some(false), "custody_false"),
            (142, None, "custody_dropped"),
        ] {
            let mut node = NodeBuilder::new(seed, Role::Validator(Participant::new(0)), instance)
                .attachments(Attachments {
                    application: MockApplication::builder().verify_result(result).build(),
                    ..Attachments::default()
                })
                .start(&context)
                .await;
            let voter = node.tasks.remove(1);
            select! {
                _ = voter => {},
                () = context.sleep(Duration::from_secs(1)) => {
                    panic!("voter continued after local custody result {result:?}");
                },
            }
        }
    });
}

#[test_collect_traces]
fn delayed_custody_failure_is_recorded_once_on_its_original_root(traces: TraceStorage) {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::builder()
            .verify_result(Some(false))
            .build();
        let mut custody = application.gate_verification();
        application.permit_builds(1);
        let mut node = NodeBuilder::new(76, Role::Validator(Participant::new(0)), "fatal_root")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        custody.wait_started().await;
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
        custody.release();
        node.tasks
            .remove(1)
            .await
            .expect("voter stops after failure");
        let errors = traces.get_by_level(Level::ERROR);
        assert_eq!(errors.len(), 1, "exactly one terminal error: {errors:?}");
        let error = &errors[0];
        assert_eq!(error.metadata.content, "voter failed");
        assert_eq!(error.spans.len(), 1, "error is directly on its root");
        assert_eq!(error.spans[0].content, "multimmit.voter.round");
        error.spans[0].expect_field_exact("view", "1").unwrap();
    });
}

/// One signed publication must not reach the wire before the barrier sync covering it.
#[test_traced]
fn publication_waits_for_the_covering_barrier_sync() {
    const STORAGE_DELAY: Duration = Duration::from_millis(250);

    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::new();
        let mut build = application.gate_build();
        application.permit_builds(1);
        let gates = TestGates::default();
        let node = NodeBuilder::new(
            81,
            Role::Validator(Participant::new(0)),
            "publication_barrier",
        )
        .attachments(Attachments {
            application,
            hooks: TestHooks::default().with_gates(gates.clone()),
            ..Attachments::default()
        })
        .start(&context)
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        build.wait_started().await;

        // Hold the authorization append after it reaches the journal. Private signing can finish
        // while the owner is suspended, but the owner cannot consume the signed completion yet.
        let mut authorization_append = gates.arm_after_append();
        build.release();
        authorization_append.wait_entered().await;

        // Catch the signed completion after it appends, then arm the one sync that covers both the
        // non-exposing authorization and the ready signature.
        let mut signature_append = gates.arm_after_append();
        authorization_append.release();
        signature_append.wait_entered().await;
        let mut publication_sync = gates.arm_next_start_sync();
        signature_append.release();
        publication_sync.wait_entered().await;

        // One sync is necessary and sufficient for this causally ready authorization/signature
        // wave. Nothing may reach the wire while it is held, however long it takes.
        select! {
            result = data_rx.recv() => {
                panic!("a signed publication escaped the covering barrier sync: {result:?}");
            },
            () = context.sleep(STORAGE_DELAY) => {},
        }

        publication_sync.release();
        expect_within(
            &context,
            Duration::from_secs(1),
            next_block(&node, &mut data_rx),
            "the durable signed wave never reached the wire",
        )
        .await
    });
}

#[test_traced]
fn verified_block_signing_reaches_wire_without_application_correlation() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let application = MockApplication::new();
        let mut verification = application.gate_verification();
        application.pause_building();
        let node = NodeBuilder::new(82, Role::Validator(Participant::new(0)), "verify_timing")
            .attachments(Attachments {
                application,
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;
        let commitment = Sha256::hash(&[b"timed remote payload"]);
        let block = node.committee.signed_block(ChainId::new(1), commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block)).encode(),
            false,
        );
        verification.wait_started().await;
        verification.release();

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = expect_before(
                &context,
                deadline,
                peer_data_rx.recv(),
                "DA vote was not published",
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
    });
}
