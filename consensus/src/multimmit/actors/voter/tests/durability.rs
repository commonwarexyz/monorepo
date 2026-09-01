//! Journal stall and durability-cut exposure tests.

use super::harness::{
    Attachments, DurableLedger, ExposureLedger, Node, NodeBuilder, slot_publications, voter_limits,
    wait_for_live_publication, wait_for_slot_block,
};
use crate::{
    multimmit::{
        actors::voter::{
            VoterLimits,
            actor::{TestDurableAttempt, TestHooks},
            persistence::TestGates,
        },
        config::Role,
        machine::{
            Cursor, DurableEffect, EffectId, Generation, MAX_STAGED_BARRIERS, Publication,
            SendRequest, SignRequest, testing::EffectExt,
        },
        mocks::{Committee, MockApplication},
        storage::partitions,
        testing::expect_within,
        types::{Artifact, ChainId, Context, SignedTransactionBlock, ViewMessage},
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope},
    },
    types::{Attributable as _, Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as P2pReceiver, Recipients, Sender as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Storage as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    telemetry::metrics::metric_sum,
};
use commonware_utils::NZU64;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
#[derive(Copy, Clone)]
enum JournalStall {
    Append,
    StartSync,
}

async fn assert_journal_stall_does_not_block_voter(
    context: &DeterministicContext,
    seed: u64,
    instance: &'static str,
    stall: JournalStall,
) {
    let application = MockApplication::default();
    application.pause_building();
    let gates = TestGates::default();
    let mut node = NodeBuilder::new(seed, Role::Validator(Participant::new(0)), instance)
        .attachments(Attachments {
            application,
            hooks: TestHooks::default().with_gates(gates.clone()),
            ..Attachments::default()
        })
        .start(context)
        .await;
    let mut gate = match stall {
        JournalStall::Append => gates.arm_next_append(),
        JournalStall::StartSync => gates.arm_next_start_sync(),
    };
    let (mut data_tx, _) = node.peer(1, 0).await;
    let (mut consensus_tx, _) = node.peer(2, 1).await;

    let remote = node.committee.signed_block(
        ChainId::new(1),
        Sha256::hash(&[b"journal stall remote payload"]),
    );
    data_tx.send(
        Recipients::One(node.me.clone()),
        node.envelope(DataMessage::Block(remote)).encode(),
        false,
    );
    select! {
        () = gate.wait_entered() => {},
        () = context.sleep(Duration::from_secs(1)) => {
            panic!("voter did not reach the armed journal storage call");
        },
    }

    let baseline = expect_within(
        context,
        Duration::from_millis(100),
        node.inspect(),
        "pending journal storage blocked voter control",
    )
    .await
    .waiting_artifacts();
    let leader = node.committee.leader_block(View::new(1));
    let vote = node.committee.vote(Participant::new(2), &leader);
    consensus_tx.send(
        Recipients::One(node.me.clone()),
        node.envelope(ConsensusMessage::Vote(vote)).encode(),
        true,
    );

    let peer_deadline = context.current() + Duration::from_secs(1);
    loop {
        let inspection = expect_within(
            context,
            Duration::from_millis(100),
            node.inspect(),
            "pending journal storage blocked voter control",
        )
        .await;
        if inspection.waiting_artifacts() > baseline {
            break;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(peer_deadline) => {
                panic!("pending journal storage blocked peer verification or machine service");
            },
        }
    }

    let metric = format!("{instance}_voter_view_timeouts_total 1");
    let timer_deadline = context.current() + Duration::from_secs(1);
    loop {
        let metrics = context.encode();
        if metrics.lines().any(|line| line == metric) {
            break;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(timer_deadline) => {
                panic!("pending journal storage blocked the view timer: {metrics}");
            },
        }
    }
    expect_within(
        context,
        Duration::from_millis(100),
        node.inspect(),
        "voter control stopped after servicing the timer",
    )
    .await;

    gate.release();
}

#[test_traced]
fn pending_journal_append_does_not_starve_voter_progress() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        assert_journal_stall_does_not_block_voter(
            &context,
            77,
            "append_stall",
            JournalStall::Append,
        )
        .await;
    });
}

#[test_traced]
fn pending_journal_start_sync_does_not_starve_voter_progress() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        assert_journal_stall_does_not_block_voter(
            &context,
            78,
            "start_sync_stall",
            JournalStall::StartSync,
        )
        .await;
    });
}

#[test_traced]
fn stalled_journal_sync_bounds_staged_persistence() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let gates = TestGates::default();
        let mut node = NodeBuilder::new(79, Role::Observer, "staged_bound")
            .attachments(Attachments {
                hooks: TestHooks::default().with_gates(gates.clone()),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let mut sync = gates.arm_next_start_sync();
        let (mut certificates_tx, _) = node.peer(2, 2).await;
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::Lqc(node.committee.lqc(View::new(1)))).encode(),
            true,
        );


        let metric = "staged_bound_voter_staged_batches";
        let ceiling = MAX_STAGED_BARRIERS as f64;
        let mut parent = node.committee.vqc(View::new(1));
        let mut ceiling_view = None;
        let mut last_submitted_view = 0;
        for view in 2..=128 {
            let block = node.committee.leader_block_with_parent(View::new(view), &parent);
            let votes = (0..node.committee.codec().view_quorum())
                .map(|signer| node.committee.vote(Participant::from_usize(signer), &block))
                .collect::<Vec<_>>();
            let messages = votes
                .iter()
                .cloned()
                .map(ViewMessage::Vote)
                .collect::<Vec<_>>();
            let lqc = node
                .committee
                .verifier
                .assemble_lqc::<Sha256, _>(block.block().clone(), &votes, &Sequential)
                .expect("quorum of chained votes aggregates");
            parent = node
                .committee
                .verifier
                .assemble_vqc::<Sha256, _>(block.block().clone(), &messages, &Sequential)
                .expect("quorum of chained view messages aggregates");
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::Lqc(lqc)).encode(),
                true,
            );

            if let Some(first_fenced_view) = ceiling_view {
                last_submitted_view = view;
                context.sleep(Duration::from_millis(1)).await;
                let encoded = context.encode();
                assert_eq!(metric_sum(&encoded, metric, &[]), ceiling, "{encoded}");
                if view == first_fenced_view + 2 {
                    break;
                }
                continue;
            }

            let deadline = context.current() + Duration::from_secs(1);
            loop {
                let encoded = context.encode();
                if metric_sum(&encoded, metric, &[]) == ceiling {
                    ceiling_view = Some(view);
                    last_submitted_view = view;
                    break;
                }
                if metric_sum(&encoded, "staged_bound_voter_current_view", &[]) > view as f64 {
                    break;
                }
                select! {
                    () = context.sleep(Duration::from_millis(1)) => {},
                    () = context.sleep_until(deadline) => {
                        let inspection = node.inspect().await;
                        panic!("chained L-QC did not advance view {view}: {inspection:?}");
                    },
                }
            }
        }

        select! {
            () = sync.wait_entered() => {},
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("voter did not reach the armed journal sync");
            },
        }

        let ceiling_view = ceiling_view.expect("staged persistence reached its ceiling");
        assert_eq!(last_submitted_view, ceiling_view + 2);
        let encoded = context.encode();
        assert_eq!(metric_sum(&encoded, metric, &[]), ceiling, "{encoded}");
        let fenced_view = metric_sum(&encoded, "staged_bound_voter_current_view", &[]);

        context.sleep(Duration::from_secs(2)).await;
        let encoded = context.encode();
        assert_eq!(metric_sum(&encoded, metric, &[]), ceiling, "{encoded}");
        assert_eq!(
            metric_sum(&encoded, "staged_bound_voter_current_view", &[]),
            fenced_view,
            "{encoded}"
        );
        expect_within(
            &context,
            Duration::from_millis(100),
            node.inspect(),
            "the persistence fence blocked voter control",
        )
        .await;

        sync.release();
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let encoded = context.encode();
            if metric_sum(&encoded, metric, &[]) == 0.0
                && metric_sum(&encoded, "staged_bound_voter_current_view", &[]) > fenced_view
            {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("persistence did not fully drain and resume after sync completed: {encoded}");
                },
            }
        }
    });
}

#[test_traced]
fn quiet_voter_syncs_its_buffered_journal_prefix_on_demand() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let mut node = NodeBuilder::new(80, Role::Observer, "quiet_prefix")
            .start(&context)
            .await;
        let (mut certificates_tx, _) = node.peer(2, 2).await;
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::Lqc(node.committee.lqc(View::new(1))))
                .encode(),
            true,
        );

        // An observer signs nothing, so entering the next view stages only reconstructible
        // records, and no later input demands their durability.
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let inspection = node.inspect().await;
            if inspection.view() > View::new(1) {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("the L-QC did not advance the view: {inspection:?}");
                },
            }
        }
        context.sleep(Duration::from_secs(5)).await;
        let inspection = node.inspect().await;
        assert!(inspection.persistence_pending(), "{inspection:?}");

        // Repeated requests collapse into one demand for the whole buffered prefix.
        let start_syncs = "quiet_prefix_voter_driver_journal_start_syncs_total";
        let baseline = metric_sum(&context.encode(), start_syncs, &[]);
        for _ in 0..8 {
            node.flusher.flush().unwrap();
        }
        let deadline = context.current() + Duration::from_millis(100);
        loop {
            let inspection = node.inspect().await;
            if !inspection.persistence_pending() {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("the flush left the journal prefix unsynced: {inspection:?}");
                },
            }
        }
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            metric_sum(&context.encode(), start_syncs, &[]),
            baseline + 1.0
        );
    });
}

#[derive(Clone, Copy, Debug)]
enum DurabilityCut {
    BeforeAppend,
    AppendBeforeSync,
    SyncBeforeAck,
    BeforeCheckpoint,
    CheckpointBeforePrune,
    AfterSuccessfulPrune,
}

impl DurabilityCut {
    const fn checkpointing(self) -> bool {
        matches!(
            self,
            Self::BeforeCheckpoint | Self::CheckpointBeforePrune | Self::AfterSuccessfulPrune
        )
    }

    const fn durable_subject(self) -> bool {
        matches!(
            self,
            Self::SyncBeforeAck
                | Self::BeforeCheckpoint
                | Self::CheckpointBeforePrune
                | Self::AfterSuccessfulPrune
        )
    }
}

#[derive(Clone)]
struct DurableScenario {
    publication: EffectId,
    generation: u64,
    block: SignedTransactionBlock<MinPk, Sha256Digest>,
    before_publication: DurableLedger,
}

async fn collect_data_exposure(
    context: &DeterministicContext,
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
    exposure: &mut ExposureLedger,
    duration: Duration,
) {
    let deadline = context.current() + duration;
    loop {
        select! {
            result = receiver.recv() => {
                let (_, bytes) = result.expect("network stays up");
                let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical envelope");
                exposure.record(node, envelope.into_payload());
            },
            () = context.sleep_until(deadline) => return,
        }
    }
}

fn exact_block_publication(
    id: EffectId,
    generation: u64,
    block: SignedTransactionBlock<MinPk, Sha256Digest>,
) -> DurableLedger {
    BTreeMap::from([(
        id,
        vec![TestDurableAttempt {
            generation: Generation::new(generation),
            effect: DurableEffect::broadcast(Arc::new(Artifact::TransactionBlock(block))),
        }],
    )])
}

fn exact_durable_ledger(
    committee: &Committee<MinPk>,
    block: &SignedTransactionBlock<MinPk, Sha256Digest>,
    generation: u64,
) -> DurableLedger {
    let attempt = |effect| {
        vec![TestDurableAttempt {
            generation: Generation::new(generation),
            effect,
        }]
    };
    let block = Arc::new(block.clone());
    let vote = committee.da_vote(Participant::new(0), block.header().clone());
    BTreeMap::from([
        (
            EffectId::from_cursor(Cursor::new(2)),
            attempt(DurableEffect::sign(SignRequest::TransactionBlock(
                block.header().clone(),
            ))),
        ),
        (
            EffectId::from_cursor(Cursor::new(3)),
            attempt(DurableEffect::broadcast(Arc::new(
                Artifact::TransactionBlock(block.as_ref().clone()),
            ))),
        ),
        (
            EffectId::from_cursor(Cursor::new(4)),
            attempt(DurableEffect::sign(SignRequest::DaVote(block))),
        ),
        (
            EffectId::from_cursor(Cursor::new(5)),
            attempt(DurableEffect::Publish(Publication::Send(Arc::from([
                SendRequest::new(Participant::new(0), Arc::new(Artifact::DaVote(vote))),
            ])))),
        ),
    ])
}

fn exact_private_ledger(
    committee: &Committee<MinPk>,
    block: &SignedTransactionBlock<MinPk, Sha256Digest>,
    generation: u64,
) -> DurableLedger {
    exact_durable_ledger(committee, block, generation)
        .into_iter()
        .filter(|(_, attempts)| {
            attempts
                .iter()
                .all(|attempt| attempt.effect.publication().is_none())
        })
        .collect()
}

fn calibrate_durable_scenario(seed: u64) -> DurableScenario {
    let role = Role::Validator(Participant::new(0));
    let application = MockApplication::new();
    application.pause_building();
    let gates = TestGates::default();
    let hooks = TestHooks::default();
    let committee = Committee::<MinPk>::builder(seed, 6).build();
    let context =
        Context::from(&committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"context"])));
    let expected_block = committee.signed_block(
        ChainId::new(0),
        MockApplication::block_digest(context, b"mock payload 1"),
    );
    let generation = 1;
    let publication = EffectId::from_cursor(Cursor::new(3));
    let expected_ledger = exact_durable_ledger(&committee, &expected_block, generation);
    let before_publication = exact_private_ledger(&committee, &expected_block, generation);
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    runner.start(move |context| async move {
        let node = NodeBuilder::new(seed, role, "durability_node")
            .attachments(Attachments {
                application: application.clone(),
                hooks: hooks.clone().with_gates(gates.clone()),
                ..Attachments::default()
            })
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        application.permit_builds(1);
        let mut exposure = ExposureLedger::default();
        let block = wait_for_slot_block(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            expected_block.header().chain(),
            expected_block.header().height(),
            expected_block.signer(),
        )
        .await;
        assert_eq!(block, expected_block);
        wait_for_live_publication(&context, &hooks, |effect| {
            matches!(effect.send_one(), Some(request)
                if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                    if vote.header() == block.header()))
        })
        .await;

        let ledger = hooks.durable_effects();
        assert_eq!(ledger, expected_ledger, "the fixture ledger changed");
        DurableScenario {
            publication,
            generation,
            block,
            before_publication,
        }
    })
}

fn exercise_durability_cut(cut: DurabilityCut, scenario: DurableScenario, seed: u64) {
    let role = Role::Validator(Participant::new(0));
    let application = MockApplication::new();
    application.pause_building();
    let recovered_application = application.clone();
    let first_gates = TestGates::default();
    let first_hooks = TestHooks::default();
    let expected = scenario.block.clone();
    let first_expected = expected.clone();
    let first_scenario = scenario.clone();
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    let (mut exposure, checkpoint) = runner.start_and_recover(move |context| async move {
        let limits = VoterLimits {
            checkpoint_interval: if cut.checkpointing() {
                NZU64!(1)
            } else {
                voter_limits().checkpoint_interval
            },
            ..voter_limits()
        };
        let node = NodeBuilder::new(seed, role, "durability_node")
            .attachments(Attachments {
                application: application.clone(),
                hooks: first_hooks.clone().with_gates(first_gates.clone()),
                ..Attachments::default()
            })
            .production_resolver()
            .limits(move |actor_limits| actor_limits.voter = limits)
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let mut exposure = ExposureLedger::default();

        let mut gate = if cut.checkpointing() {
            application.permit_builds(1);
            let block = wait_for_slot_block(
                &context,
                &node,
                &mut data_rx,
                &mut exposure,
                first_expected.header().chain(),
                first_expected.header().height(),
                first_expected.signer(),
            )
            .await;
            assert_eq!(
                block, first_expected,
                "checkpoint setup changed the durable subject"
            );
            assert_eq!(
                slot_publications(
                    &first_hooks.durable_effects(),
                    first_expected.header().chain(),
                    first_expected.header().height(),
                ),
                exact_block_publication(
                    first_scenario.publication,
                    first_scenario.generation,
                    first_expected.clone(),
                )
            );
            match cut {
                DurabilityCut::BeforeCheckpoint => first_gates.arm_next_roll(),
                DurabilityCut::CheckpointBeforePrune => first_gates.arm_next_before_prune(),
                DurabilityCut::AfterSuccessfulPrune => first_gates.arm_next_after_prune(),
                _ => unreachable!("checkpoint cuts were filtered"),
            }
        } else {
            let gate = match cut {
                DurabilityCut::BeforeAppend => first_gates.arm_append_covering(
                    Generation::new(first_scenario.generation),
                    Cursor::new(first_scenario.publication.get()),
                ),
                DurabilityCut::AppendBeforeSync => first_gates.arm_start_sync_covering(
                    Generation::new(first_scenario.generation),
                    Cursor::new(first_scenario.publication.get()),
                ),
                DurabilityCut::SyncBeforeAck => first_gates.arm_after_sync_covering(
                    Generation::new(first_scenario.generation),
                    Cursor::new(first_scenario.publication.get()),
                ),
                _ => unreachable!("journal cuts were filtered"),
            };
            application.permit_builds(1);
            gate
        };
        select! {
            () = gate.wait_entered() => {},
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("{cut:?} did not reach its exact storage coordinate");
            },
        }

        collect_data_exposure(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            Duration::from_millis(50),
        )
        .await;
        if !cut.checkpointing() {
            assert!(
                exposure
                    .block(
                        first_expected.header().chain(),
                        first_expected.header().height(),
                        first_expected.signer(),
                    )
                    .is_none(),
                "{cut:?} exposed a signed block before its barrier acknowledgement"
            );
            assert_eq!(
                first_hooks.durable_effects(),
                first_scenario.before_publication,
                "{cut:?} executed a durable effect outside the calibrated pre-release map"
            );
            assert!(
                slot_publications(
                    &first_hooks.durable_effects(),
                    first_expected.header().chain(),
                    first_expected.header().height(),
                )
                .is_empty(),
                "{cut:?} executed its publication before acknowledgement"
            );
        }
        node.crash(&context).await;
        drop(gate);
        exposure
    });

    recovered_application.permit_builds(1);
    let recovered_hooks = TestHooks::default();
    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let node = NodeBuilder::new(seed, role, "durability_node")
            .attachments(Attachments {
                application: recovered_application,
                hooks: recovered_hooks.clone(),
                ..Attachments::default()
            })
            .production_resolver()
            .start(&context)
            .await;
        if matches!(cut, DurabilityCut::CheckpointBeforePrune) {
            let partition = partitions(&format!("node_{seed}")).journal;
            let sections = context
                .scan(&partition)
                .await
                .expect("recovered journal partition remains readable");
            assert!(
                sections
                    .iter()
                    .all(|name| name.as_slice() != 0u64.to_be_bytes()),
                "startup did not complete checkpoint-covered pruning"
            );
        }
        let (_, mut data_rx) = node.peer(1, 0).await;
        let block = wait_for_slot_block(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            expected.header().chain(),
            expected.header().height(),
            expected.signer(),
        )
        .await;
        collect_data_exposure(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            Duration::from_millis(50),
        )
        .await;

        let alternate = node.committee.signed_block(
            ChainId::new(0),
            MockApplication::block_digest(Context::from(expected.header()), b"mock payload 2"),
        );
        if cut.durable_subject() {
            assert_eq!(
                block, expected,
                "{cut:?} forgot its durable signing subject"
            );
        } else {
            assert!(
                block == expected || block == alternate,
                "{cut:?} exposed a block outside the two independently constructed subjects"
            );
        }
        assert_eq!(
            exposure
                .blocks
                .iter()
                .filter(|((chain, height, signer), _)| {
                    *chain == expected.header().chain()
                        && *height == expected.header().height()
                        && *signer == expected.signer()
                })
                .count(),
            1,
            "{cut:?} exposed more than one artifact for the signing slot"
        );

        let publications = slot_publications(
            &recovered_hooks.durable_effects(),
            block.header().chain(),
            block.header().height(),
        );
        if cut.durable_subject() {
            assert_eq!(
                publications,
                exact_block_publication(scenario.publication, scenario.generation + 1, expected,),
                "{cut:?} did not reissue the exact durable obligation"
            );
        } else {
            let publication_entries = publications.iter().collect::<Vec<_>>();
            let [(id, attempts)] = publication_entries.as_slice() else {
                panic!(
                    "{cut:?} did not issue exactly one recovered slot obligation: {publications:?}"
                );
            };
            assert_eq!(attempts.len(), 1);
            assert_eq!(
                attempts[0].generation,
                Generation::new(scenario.generation + 1)
            );
            assert_eq!(
                attempts[0].effect,
                DurableEffect::broadcast(Arc::new(Artifact::TransactionBlock(block)))
            );
            assert!(id.get() >= scenario.publication.get());
        }
    });
}

#[test_traced]
fn durability_cut_matrix_reissues_and_retires_exact_obligations() {
    let seed = 80;
    let scenario = calibrate_durable_scenario(seed);
    for cut in [
        DurabilityCut::BeforeAppend,
        DurabilityCut::AppendBeforeSync,
        DurabilityCut::SyncBeforeAck,
        DurabilityCut::BeforeCheckpoint,
        DurabilityCut::CheckpointBeforePrune,
        DurabilityCut::AfterSuccessfulPrune,
    ] {
        exercise_durability_cut(cut, scenario.clone(), seed);
    }
}
