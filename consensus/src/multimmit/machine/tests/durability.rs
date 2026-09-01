//! Barrier acknowledgement, exposure floor, replay, and restore tests.

use super::fixtures::{
    Harness, TEST_RESOURCES, TestMachine, active_driver, active_machine, attestation, digest,
    durable_effect, durable_job, leader, leader_artifact, lqc, no_vote, nullify, observe,
    proposal_request, proposal_request_with_parent, queued_effect_id, sign_job, snapshot_reason,
    start_profile, symbolic_da_certificate, symbolic_nullification, transition_reason,
    unacknowledged_proposal, view_one_vqc, view_vote, vqc,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::{LeaderSchedule, Profile, ResourceLimits, Role},
        machine::{
            ProposalParent,
            capability::{Capability, CryptoJob, TimerCommand},
            durability::{
                BarrierAck, BatchId, Change, ChangeKind, Cursor, Discharge, DischargeKind,
                DomainEvent, DurableEffect, DurableJob, DurableState, EffectCompletion, EffectId,
                OutboxEntry, PersistDirective, ProposalPublication, Publication, SendRequest,
                SignEffect, SignRequest, Snapshot, SnapshotReason, TransitionReason,
            },
            input::{Input, StepError, StepStatus},
            job::{Generation, Issued},
            reducer::{DeferredRelease, machine::Machine},
            scheduler::CORE_BUDGET,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, MachineExt as _,
                PersistSink, Until, fixtures::DischargeFamily,
            },
            view::ViewTimer,
        },
        types::{
            Artifact, BlockRef, ChainId, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, ViewMessage, ViewProof,
        },
    },
    types::{Height, Participant, Round, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::{collections::HashSet, sync::Arc};

#[test]
fn publication_signature_references_cover_every_shape() {
    let machine = Machine::new(Harness::validator(0).participants(6).profile());
    let view = View::new(1);
    let own: Arc<Artifact<MinPk, Digest>> = Arc::new(Artifact::NoVote(no_vote(&machine, view, 0)));
    let foreign: Arc<Artifact<MinPk, Digest>> =
        Arc::new(Artifact::NoVote(no_vote(&machine, view, 1)));
    let aggregate: Arc<Artifact<MinPk, Digest>> = Arc::new(Artifact::Nullification(
        symbolic_nullification(&machine, view, 7),
    ));
    let publications = |artifact: Arc<Artifact<MinPk, Digest>>| {
        [
            ("Broadcast", Publication::broadcast(Arc::clone(&artifact))),
            (
                "Broadcast of two",
                Publication::Broadcast(Arc::from([Arc::clone(&foreign), Arc::clone(&artifact)])),
            ),
            (
                "Send",
                Publication::Send(Arc::from([SendRequest::new(
                    Participant::new(5),
                    Arc::clone(&artifact),
                )])),
            ),
            (
                "Send of two",
                Publication::Send(Arc::from([
                    SendRequest::new(Participant::new(5), Arc::clone(&foreign)),
                    SendRequest::new(Participant::new(5), Arc::clone(&artifact)),
                ])),
            ),
        ]
    };

    for (shape, publication) in publications(Arc::clone(&own)) {
        assert!(
            publication.references_own_signature(Some(Participant::new(0))),
            "{shape} must recognize an own signature"
        );
        assert!(
            !publication.references_own_signature(None),
            "{shape} must not attribute an individual signature to an observer"
        );
    }
    for (shape, publication) in publications(Arc::clone(&foreign)) {
        assert!(
            !publication.references_own_signature(Some(Participant::new(0))),
            "{shape} must reject a foreign signature"
        );
        assert!(
            !publication.references_own_signature(None),
            "{shape} must not attribute a foreign signature to an observer"
        );
    }
    for (shape, publication) in publications(Arc::clone(&aggregate)) {
        assert!(
            publication.references_own_signature(Some(Participant::new(0))),
            "{shape} must conservatively recognize an aggregate"
        );
        assert!(
            publication.references_own_signature(None),
            "{shape} must conservatively recognize an aggregate for an observer"
        );
    }

    let proposal = Publication::Propose(ProposalPublication::new(
        Arc::new(SignedLeaderBlock::new(leader(&machine, 1), attestation(1))),
        ProposalParent::Genesis,
        false,
    ));
    assert!(proposal.references_own_signature(Some(Participant::new(0))));
    assert!(proposal.references_own_signature(None));
}

#[test]
fn durable_custody_and_references_share_one_retained_set() {
    let machine = Machine::new(Harness::validator(0).participants(6).profile());
    let epoch = machine.profile().protocol().epoch();
    let parent = view_one_vqc(&machine);
    let block = SignedLeaderBlock::new(leader(&machine, 2), attestation(0));
    let proposal = Publication::Propose(ProposalPublication::new(
        Arc::new(block.clone()),
        ProposalParent::Exact(Arc::new(parent.clone())),
        true,
    ));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        epoch,
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"awaiting vote"),
    )
    .unwrap();
    let voted = SignedTransactionBlock::new(header, attestation(1));
    let exit = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        3,
    )));

    let discharges = machine.discharges(&proposal).unwrap();
    let mut state = machine.durable.state;
    state.outbox.insert(
        EffectId::from_cursor(Cursor::new(1)),
        OutboxEntry::new(proposal.clone(), discharges),
    );
    state.signing_reservations.insert(
        EffectId::from_cursor(Cursor::new(2)),
        SignEffect::one(SignRequest::DaVote(Arc::new(voted.clone()))),
    );
    state
        .forwarded_nullifications
        .insert(View::new(1), Arc::clone(&exit));
    state.exits.insert(View::new(1), Arc::clone(&exit));

    // A proposal carries its block and parent.
    let leader_block = Artifact::LeaderBlock(block);
    let parent_vqc = Artifact::Vqc(parent.clone());
    let mut carried = Vec::new();
    proposal.visit_retained(|retained| carried.push(retained.to_artifact()));
    assert_eq!(carried.len(), 2);
    assert_eq!(carried[0].as_ref(), &leader_block);
    assert_eq!(carried[1].as_ref(), &parent_vqc);

    // Custody holds every retained artifact, so the resolver serves the proposal parent.
    let custody = Snapshot::new(epoch, Role::Validator(Participant::new(0)), state.clone())
        .retained_artifacts()
        .collect::<Vec<_>>();
    let transaction_block = Artifact::TransactionBlock(voted);
    for expected in [
        &leader_block,
        &parent_vqc,
        &transaction_block,
        exit.as_ref(),
    ] {
        assert!(custody.iter().any(|artifact| artifact.as_ref() == expected));
    }
    assert!(state.resolver_proofs().iter().any(|proof| matches!(
        proof,
        ViewProof::Vqc(proof) if proof.as_ref() == &parent
    )));

    // References count the same set, less exits and blocks awaiting a vote.
    let references = state.artifact_references::<Sha256>();
    assert_eq!(references.get(&leader_block.id::<Sha256>()), Some(&1));
    assert_eq!(references.get(&parent_vqc.id::<Sha256>()), Some(&1));
    assert_eq!(references.get(&exit.id::<Sha256>()), Some(&1));
    assert!(!references.contains_key(&transaction_block.id::<Sha256>()));
}

#[test]
fn batched_barriers_preserve_the_durable_event_sequence() {
    // Budget size decides how many staged facts share one barrier, and must never change the
    // durable event sequence itself: a batch is a framing choice, not a semantic one.
    let drain = |budget: usize| {
        let role = Role::Validator(Participant::new(0));
        let mut machine = active_machine(role);
        let epoch = machine.profile().protocol().epoch();

        // Three parked signing completions are the batchable class.
        let mut signings = Vec::new();
        let mut artifacts = Vec::new();
        for view in 10..13 {
            let view = View::new(view);
            let reserved = machine
                .reserve_test_effect(DurableEffect::sign(SignRequest::Nullify {
                    round: Round::new(epoch, view),
                }))
                .unwrap();
            // The signing request carries no signature out, so it releases at staging.
            signings.push(sign_job(&reserved));
            machine.persist(&reserved.persist_job(), Until::Step);
            artifacts.push(Artifact::Nullify(nullify(&machine, view, 0)));
        }
        for (signing, artifact) in signings.iter().zip(&artifacts) {
            machine
                .step(Input::EffectCompleted(EffectCompletion::signed(
                    signing.issued(),
                    vec![Arc::new(artifact.clone())],
                )))
                .unwrap();
        }

        let budget = NonZeroUsize::new(budget).unwrap();
        let mut events = Vec::new();
        let mut barriers = 0usize;
        for _ in 0..256 {
            let result = machine.poll(budget).unwrap();
            let work_remaining = machine.work_remaining();
            let mut staged = None;
            for effect in result.into_capabilities() {
                if let Capability::Journal(PersistDirective { job, .. }) = effect {
                    barriers += 1;
                    events.extend(job.events().iter().cloned());
                    staged = Some(job);
                }
            }
            if let Some(job) = staged {
                machine.persist(&job, Until::Step);
            } else if !work_remaining {
                break;
            }
        }
        (events, barriers, machine.inspect())
    };

    let (serial_events, serial_barriers, serial_state) = drain(1);
    let (batched_events, batched_barriers, batched_state) = drain(16);
    assert_eq!(serial_events, batched_events);
    assert_eq!(serial_state, batched_state);
    assert!(
        batched_barriers < serial_barriers,
        "a larger budget must coalesce barriers: {batched_barriers} vs {serial_barriers}"
    );
}

#[test]
fn durable_broadcast_replays_with_stable_id() {
    let mut machine = active_machine(Role::Observer);
    let artifact = Artifact::NoVote(no_vote(&machine, View::new(1), 0));
    let before = machine.live_snapshot_for_test();
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(artifact.clone())))
        .unwrap();
    let job = reserved.persist_job();

    assert_eq!(reserved.status(), &StepStatus::Accepted);
    assert!(before.outbox().is_empty());

    let id = match job.events()[0].change() {
        Change::OutboxQueued { id, .. } => *id,
        _ => panic!("expected queued outbox event"),
    };
    // Staging is application: the entry exists before its barrier acknowledges, and replaying
    // the same event over the pre-stage snapshot must rebuild it identically.
    assert_eq!(
        machine
            .live_snapshot_for_test()
            .outbox()
            .get(&id)
            .map(OutboxEntry::publication),
        Some(&Publication::broadcast(Arc::new(artifact.clone())))
    );
    let mut restored =
        Machine::<Sha256, MinPk>::restore(Harness::observer().profile(), before).unwrap();
    for event in job.events() {
        restored.replay(event.clone()).unwrap();
    }
    assert!(!restored.inspect().is_live());
    assert_eq!(
        restored.live_snapshot_for_test(),
        machine.live_snapshot_for_test()
    );

    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    // The view timer arms with the staged generation advance; the recovered outbox re-releases
    // at that barrier's acknowledgement.
    assert!(
        recovery.has(|effect| matches!(effect, Capability::Timer(TimerCommand::View(_)))),
        "recovery must arm the view timer at staging"
    );
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let broadcast = recovered
        .find(|capability| match capability {
            Capability::Released(job) => Some(job),
            _ => None,
        })
        .expect("recovery must reissue the durable outbox");
    let Some(actual) = broadcast.request().broadcast_one() else {
        panic!("recovery must reissue the durable outbox");
    };
    assert_eq!(broadcast.issued().id(), id);
    assert_eq!(actual.as_ref(), &artifact);

    let completion = restored
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            Issued::new(id, broadcast.issued().generation()),
        )))
        .unwrap();
    assert!(matches!(completion.status(), StepStatus::Accepted));
    assert!(restored.live_snapshot_for_test().outbox().contains_key(&id));
    assert!(completion.capabilities().is_empty());

    let mut restarted = Machine::<Sha256, MinPk>::restore(
        Harness::observer().profile(),
        restored.live_snapshot_for_test(),
    )
    .unwrap();
    let recovery = restarted.step(Input::RecoveryComplete).unwrap();
    let recovered = restarted.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(recovered.has(
        |effect| matches!(durable_job(effect), Some(job) if job.issued().id() == id
                && job.request().broadcast_one().is_some())
    ));
}

#[test]
fn checkpoint_cut_matches_the_acknowledged_cursor() {
    let mut machine = active_machine(Role::Observer);
    let artifact = Arc::new(Artifact::NoVote(no_vote(&machine, View::new(1), 0)));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(artifact))
        .unwrap();

    assert!(machine.checkpoint_cut().is_none());

    let job = reserved.persist_job();
    machine.persist(&job, Until::CursorAdvance);
    assert_eq!(
        machine.checkpoint_cut().unwrap().cursor(),
        job.last_cursor()
    );
}

#[test]
fn replayed_durable_prefix_advances_the_acknowledged_cursor() {
    let profile = Harness::observer().profile();
    let mut source = active_machine(Role::Observer);
    let before = source.live_snapshot_for_test();
    let artifact = Arc::new(Artifact::NoVote(no_vote(&source, View::new(1), 0)));
    let reserved = source
        .reserve_test_effect(DurableEffect::broadcast(artifact))
        .unwrap();
    let job = reserved.persist_job();

    let mut replayed = Machine::<Sha256, MinPk>::restore(profile, before).unwrap();
    for event in job.events() {
        replayed.replay(event.clone()).unwrap();
    }
    assert_eq!(replayed.pipeline.acked, replayed.durable.state.cursor);
}

#[test]
fn restore_rejects_mismatched_publication_obligation_rows() {
    let profile = Harness::observer().profile();
    let mut machine = active_machine(Role::Observer);
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"obligation payload"),
    )
    .unwrap();
    let block = Arc::new(Artifact::TransactionBlock(SignedTransactionBlock::new(
        header,
        attestation(0),
    )));
    let queued = machine
        .reserve_test_effect(DurableEffect::broadcast(block))
        .unwrap();
    let effect = queued_effect_id(&queued);
    machine.persist(&queued.persist_job(), Until::CursorAdvance);

    let canonical = machine.live_snapshot_for_test();
    let publication = canonical.outbox()[&effect].publication().clone();
    let with_discharge =
        |until| OutboxEntry::new(publication.clone(), vec![Discharge::new(0, until)]);
    let mut wrong_family =
        Machine::<Sha256, MinPk>::restore(profile.clone(), canonical.clone()).unwrap();
    wrong_family.durable.state.outbox.insert(
        effect,
        with_discharge(DischargeKind::ExitReplacedAfter { view: View::new(1) }),
    );
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            wrong_family.live_snapshot_for_test()
        )),
        SnapshotReason::Obligation
    );

    let mut wrong_object = Machine::<Sha256, MinPk>::restore(profile.clone(), canonical).unwrap();
    wrong_object.durable.state.outbox.insert(
        effect,
        with_discharge(DischargeKind::BlockCertifiedAtLeast {
            chain: ChainId::new(1),
            height: Height::new(2),
        }),
    );
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile,
            wrong_object.live_snapshot_for_test()
        )),
        SnapshotReason::Obligation
    );
}

#[test]
fn publication_discharge_table_enforces_exact_boundaries() {
    let mut machine = active_machine(Role::Observer);
    let chain = ChainId::new(0);
    let height = Height::new(5);
    let block = EffectId::from_cursor(Cursor::new(10));
    let vote = EffectId::from_cursor(Cursor::new(11));
    let certificate = EffectId::from_cursor(Cursor::new(12));
    let exit = EffectId::from_cursor(Cursor::new(13));
    let own_message = EffectId::from_cursor(Cursor::new(14));
    // The discharge table reads only the discharges, so every entry shares one publication.
    let publication = Publication::broadcast(Arc::new(Artifact::Nullification(
        symbolic_nullification(&machine, View::new(8), 0),
    )));
    let discharges = [
        (
            block,
            DischargeKind::BlockCertifiedAtLeast { chain, height },
        ),
        (vote, DischargeKind::VoteCertifiedAtLeast { chain, height }),
        (
            certificate,
            DischargeKind::CertificateSupersededAbove { chain, height },
        ),
        (
            exit,
            DischargeKind::ExitReplacedAfter { view: View::new(8) },
        ),
        (
            own_message,
            DischargeKind::ViewRetired { view: View::new(8) },
        ),
    ];
    assert_eq!(
        discharges
            .iter()
            .map(|(_, until)| DischargeFamily::of(until))
            .collect::<Vec<_>>(),
        DischargeFamily::ALL,
        "the table covers every discharge family once"
    );
    for (id, until) in discharges {
        machine.durable.state.outbox.insert(
            id,
            OutboxEntry::new(publication.clone(), vec![Discharge::new(0, until)]),
        );
    }

    assert!(
        machine
            .obligations_retired_by_da(chain, Height::new(4))
            .is_empty()
    );
    assert_eq!(
        machine.obligations_retired_by_da(chain, height),
        vec![block, vote]
    );
    assert_eq!(
        machine.obligations_retired_by_da(chain, Height::new(6)),
        vec![block, vote, certificate]
    );
    assert!(machine.obligations_retired_by_exit(View::new(8)).is_empty());
    assert_eq!(
        machine.obligations_retired_by_exit(View::new(9)),
        vec![exit]
    );
    assert!(
        machine
            .obligations_retired_by_floor(View::new(8))
            .is_empty()
    );
    assert_eq!(
        machine.obligations_retired_by_floor(View::new(9)),
        vec![own_message]
    );
}

#[test]
fn replayable_publication_is_exposed_before_its_obligation_barrier() {
    let mut machine = active_machine(Role::Observer);
    let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        1,
    )));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::clone(&artifact)))
        .unwrap();

    assert!(reserved.has(|effect| {
        matches!(durable_effect(effect).and_then(EffectExt::broadcast_one), Some(actual)
            if actual == &artifact)
    }));
    assert!(reserved.has(Capability::is_journal));
}

#[test]
fn barrier_acknowledgements_are_exact_and_ordered() {
    let pending = |view| {
        let mut machine = active_machine(Role::Observer);
        let reserved = machine
            .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
                &machine, view,
            ))))
            .unwrap();
        let barrier = reserved.persist_job();
        (machine, barrier)
    };

    let (mut machine, barrier) = pending(2);
    let stale = machine
        .step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            Generation::new(
                barrier
                    .generation()
                    .get()
                    .checked_sub(1)
                    .expect("the active generation must have a predecessor"),
            ),
            barrier.last_cursor(),
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().is_empty());

    for case in 0..5 {
        let (mut machine, barrier) = pending(2);
        let acknowledgement = match case {
            0 => BarrierAck::new(
                barrier.id(),
                Generation::new(barrier.generation().get() + 1),
                barrier.last_cursor(),
            ),
            1 => BarrierAck::new(
                BatchId::new(barrier.id().get() + 1),
                barrier.generation(),
                barrier.last_cursor(),
            ),
            2 => BarrierAck::new(
                BatchId::new(barrier.id().get() + 2),
                barrier.generation(),
                barrier.last_cursor(),
            ),
            3 => BarrierAck::new(barrier.id(), barrier.generation(), barrier.previous()),
            4 => BarrierAck::new(
                barrier.id(),
                barrier.generation(),
                barrier
                    .last_cursor()
                    .next()
                    .expect("the test barrier cursor must have a successor"),
            ),
            _ => unreachable!(),
        };
        assert!(
            matches!(
                machine.step(Input::Persisted(acknowledgement)),
                Err(StepError::CompletionMismatch)
            ),
            "impossible acknowledgement case {case} must be fatal"
        );
    }

    let (mut machine, first) = pending(2);
    let first_ack = first.ack();
    let applied = machine.step(Input::Persisted(first_ack)).unwrap();
    assert_eq!(applied.status(), &StepStatus::Accepted);

    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let second = reserved.persist_job();
    let duplicate = machine.step(Input::Persisted(first_ack)).unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    let second_ack = second.ack();
    let applied = machine.step(Input::Persisted(second_ack)).unwrap();
    assert_eq!(applied.status(), &StepStatus::Accepted);
    assert!(matches!(
        machine.step(Input::Persisted(first_ack)),
        Err(StepError::CompletionMismatch)
    ));

    let (mut machine, first) = pending(2);
    let _ = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let queued = machine
        .pipeline
        .staged
        .back()
        .expect("the later barrier remains queued")
        .job
        .clone();
    assert_ne!(queued.id(), first.id());
    assert!(!machine.pipeline.staged.back().unwrap().emitted);
    assert!(matches!(
        machine.step(Input::Persisted(queued.ack())),
        Err(StepError::CompletionMismatch)
    ));
}

#[test]
fn signature_publication_waits_for_its_exact_barrier_acknowledgement() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = sign_job(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            )))],
        )))
        .unwrap();
    let staged = machine.settle(completed, Until::CursorAdvance);
    let barrier = staged.persist_job();
    assert!(staged.capabilities().iter().all(|effect| {
        !durable_effect(effect)
            .and_then(EffectExt::proposal)
            .is_some()
    }));

    assert!(matches!(
        machine.step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            Generation::new(barrier.generation().get() + 1),
            barrier.last_cursor(),
        ))),
        Err(StepError::CompletionMismatch)
    ));

    assert!(matches!(
        machine.step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            barrier.generation(),
            Cursor::zero(),
        ))),
        Err(StepError::CompletionMismatch)
    ));

    let released = machine.persist(&barrier, Until::Step);
    assert!(matches!(released.status(), StepStatus::Accepted));
    assert!(matches!(
        released.capabilities(),
        [Capability::Released(publication)]
            if publication.request().proposal().is_some()
    ));
}

#[test]
fn aggregate_publication_defers_to_the_signature_exposure_floor() {
    // An aggregate certificate may embed one of our shares, so its publication must wait
    // until every fresh local signature staged before it is durable. With such a signature
    // pending, the aggregate defers; the signature's acknowledgement releases both.
    let (mut machine, completed) = unacknowledged_proposal();
    let signature_barrier = completed.persist_job();

    // The signature is staged but not yet acknowledged: an aggregate queued now is unsafe to
    // release, even though nothing in it is individually ours.
    let aggregate = Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 7));
    let deferred = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(aggregate.clone())))
        .unwrap();
    assert!(
        !deferred.has(|effect| durable_effect(effect)
            .and_then(EffectExt::broadcast_one)
            .is_some()),
        "an aggregate queued behind an unacknowledged signature must defer"
    );

    // Acknowledging the signature floor releases both its publication and replayable work below
    // that floor. The aggregate's own metadata may remain in the append-behind-sync tail.
    let released = machine.persist(&signature_barrier, Until::CursorAdvance);
    assert!(
        released.has(|effect| durable_effect(effect)
            .and_then(EffectExt::proposal)
            .is_some()),
        "the durable signature must release its own publication"
    );
    assert!(released.has(|effect| {
        matches!(durable_effect(effect).and_then(EffectExt::broadcast_one), Some(artifact)
            if artifact.as_ref() == &aggregate)
    }));
}

#[test]
fn resolver_retention_defers_to_the_signature_exposure_floor() {
    let (mut machine, completed) = unacknowledged_proposal();
    let signature_barrier = completed.persist_job();
    let proposed = leader(&machine, 3);
    let votes = (0..machine.profile().codec().participants() as u32)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let proof = Arc::new(Artifact::Lqc(lqc(&machine, proposed, &votes)));
    let observed = observe(&mut machine, proof.as_ref().clone());
    let completed = machine.verify(&observed, true, Until::CursorAdvance);
    let completed = machine.settle(completed, Until::CursorAdvance);
    assert!(
        !completed.has(|capability| {
            matches!(capability, Capability::Retain(artifact)
            if artifact == &proof)
        }),
        "resolver retention must not expose an unacknowledged own share"
    );
    assert!(
        machine
            .pipeline
            .deferred_releases
            .iter()
            .any(|(floor, release)| {
                *floor == signature_barrier.last_cursor()
                    && matches!(release, DeferredRelease::Retain(artifact) if artifact == &proof)
            })
    );
    let released = machine.persist(&signature_barrier, Until::Step);
    assert!(
        released.has(|capability| {
            matches!(capability, Capability::Retain(artifact)
            if artifact == &proof)
        }),
        "the exact signature floor releases custody before the proof metadata is synced"
    );
}

#[test]
fn generation_ack_preserves_resolver_exposure_floors() {
    let mut machine = Machine::new(Harness::observer().participants(6).profile());
    let started = machine.step(Input::Start).unwrap();
    let barrier = started.persist_job();
    let ready = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        7,
    )));
    let later = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(2),
        8,
    )));
    machine.pipeline.deferred_releases.push_back((
        barrier.last_cursor(),
        DeferredRelease::Retain(ready.clone()),
    ));
    let later_floor = barrier.last_cursor().next().unwrap();
    machine
        .pipeline
        .deferred_releases
        .push_back((later_floor, DeferredRelease::Retain(later.clone())));
    let acknowledged = machine.persist(&barrier, Until::Step);
    let retained = acknowledged
        .capabilities()
        .iter()
        .filter_map(|capability| match capability {
            Capability::Retain(artifact) => Some(artifact),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(retained, vec![&ready]);
    assert!(
        matches!(machine.pipeline.deferred_releases.front(), Some((floor, DeferredRelease::Retain(artifact)))
        if *floor == later_floor && artifact == &later)
    );
}

#[test]
fn deferred_view_certificate_scan_survives_current_view_drives() {
    // The current view's certificate drive and the drive for another ready view share one scan
    // slot. Once a single pass over a ready view's messages costs more than one core budget, a
    // current-view drive that discarded the other view's partial scan would leave the machine
    // reporting progress on every poll without ever assembling that certificate. The committee
    // is sized so one pass exceeds the budget on its own.
    const PARTICIPANTS: usize = 111;
    const MAX_POLLS: usize = 64;
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(1_024).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(3).unwrap(),
        2,
        NonZeroUsize::new(512).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(PARTICIPANTS)
        .resources(resources)
        .profile();
    let quorum = profile.codec().view_quorum();
    assert!(
        quorum * 3 > CORE_BUDGET as usize,
        "one certificate scan must exceed one core budget"
    );
    let (mut machine, _) = start_profile(profile);
    assert_eq!(machine.view(), View::new(1));

    // The machine holds view 1 while a view quorum votes in view 2.
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::Step);
    for signer in 0..quorum {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer as u32));
        let vote = observe(&mut machine, vote);
        machine.verify(&vote, true, Until::Step);
    }

    // Machine-owned work must assemble the ready view's V-QC within a bounded number of polls.
    let mut aggregate = None;
    let mut polls = 0;
    while aggregate.is_none() && polls < MAX_POLLS {
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        polls += 1;
        let work_remaining = machine.work_remaining();
        let (effects, _) = result.into_parts();
        aggregate = effects.into_iter().find_map(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job),
            _ => None,
        });
        if aggregate.is_none() && !work_remaining {
            break;
        }
    }
    let aggregate = aggregate
        .unwrap_or_else(|| panic!("no V-QC assembly for the ready view after {polls} polls"));
    assert_eq!(aggregate.leader().view(), View::new(2));
    assert_eq!(aggregate.messages().len(), quorum);
}

#[test]
fn observer_cannot_reserve_signing() {
    let mut machine = active_machine(Role::Observer);
    let leader = leader(&machine, 1);
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(leader),
        ))),
        Err(StepError::UnauthorizedEffect)
    ));
}

#[test]
fn replay_rejects_forwarding_an_artifact_that_is_not_an_exit_certificate() {
    let machine = Machine::<Sha256, MinPk>::new(Harness::observer().profile());
    let snapshot = machine.live_snapshot_for_test();
    let mut restored = Machine::restore(Harness::observer().profile(), snapshot).unwrap();
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        cursor,
        Change::ArtifactForwarded {
            publication: EffectId::from_cursor(cursor),
            retired_publications: Vec::new(),
            artifact: Arc::new(leader_artifact(&restored, 1)),
        },
    );

    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::ArtifactKind
    );
    assert_eq!(restored.inspect().cursor(), Cursor::zero());
}

#[test]
fn replay_rejects_unauthorized_local_da_certificates() {
    for role in [Role::Observer, Role::Validator(Participant::new(0))] {
        let profile = Harness::builder(role).participants(6).profile();
        let machine = Machine::<Sha256, MinPk>::new(profile.clone());
        let mut restored =
            Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
        let epoch = restored.profile().protocol().epoch();
        let genesis = restored.profile().protocol().genesis().tips()[1];
        let header = TransactionBlockHeader::new(
            epoch,
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            digest(b"unauthorized local certificate"),
        )
        .unwrap();
        let cursor = Cursor::zero().next().unwrap();
        let event = DomainEvent::new(
            epoch,
            cursor,
            Change::DaCertificateAdvanced {
                publication: Some(EffectId::from_cursor(cursor)),
                retired_publications: Vec::new(),
                artifact: Arc::new(Artifact::DaCertificate(symbolic_da_certificate(header, 0))),
            },
        );

        assert_eq!(
            transition_reason(restored.replay(event)),
            TransitionReason::Unauthorized
        );
        assert_eq!(restored.inspect().cursor(), Cursor::zero());
    }
}

#[test]
fn replay_rejects_a_certificate_for_a_chain_outside_the_epoch() {
    let profile = Harness::observer().profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let epoch = restored.profile().protocol().epoch();
    let chains = restored.profile().codec().chains();
    let header = TransactionBlockHeader::new(
        epoch,
        ChainId::new(u32::try_from(chains).unwrap()),
        Height::new(1),
        digest(b"missing chain parent"),
        digest(b"missing chain block"),
    )
    .unwrap();
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        epoch,
        cursor,
        Change::DaCertificateAdvanced {
            publication: None,
            retired_publications: Vec::new(),
            artifact: Arc::new(Artifact::DaCertificate(symbolic_da_certificate(header, 0))),
        },
    );

    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::ChainState
    );
}

#[test]
fn snapshot_bounds_every_reserved_da_vote_by_its_safety_height() {
    let role = Role::Validator(Participant::new(0));
    let profile = Harness::builder(role).participants(6).profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let epoch = machine.profile().protocol().epoch();
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        epoch,
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"first voted block"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        epoch,
        genesis.chain(),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"second voted block"),
    )
    .unwrap();
    let run = SignEffect::new(Arc::from([
        SignRequest::DaVote(Arc::new(SignedTransactionBlock::new(first, attestation(1)))),
        SignRequest::DaVote(Arc::new(SignedTransactionBlock::new(
            second,
            attestation(1),
        ))),
    ]));
    let snapshot = |safety| {
        let mut state = machine.durable.state.clone();
        state.cursor = state.cursor.next().unwrap();
        state
            .signing_reservations
            .insert(EffectId::from_cursor(state.cursor), run.clone());
        state.da_safety_heights[genesis.chain().index()] = Height::new(safety);
        Snapshot::new(epoch, role, state)
    };

    // The later vote in the run is above the chain's durable safety height.
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            snapshot(1)
        )),
        SnapshotReason::Effect
    );
    Machine::<Sha256, MinPk>::restore(profile, snapshot(2)).unwrap();
}

#[test]
fn observer_replay_rejects_queued_signing_authority() {
    let machine = Machine::<Sha256, MinPk>::new(Harness::observer().profile());
    let snapshot = machine.live_snapshot_for_test();
    let mut restored = Machine::restore(Harness::observer().profile(), snapshot).unwrap();
    let proposed = leader(&restored, 1);
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        cursor,
        Change::OutboxQueued {
            id: EffectId::from_cursor(cursor),
            effect: Box::new(DurableEffect::sign(SignRequest::LeaderBlock(
                proposal_request(proposed),
            ))),
        },
    );

    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::Unauthorized
    );
    assert_eq!(restored.inspect().cursor(), Cursor::zero());
    assert!(restored.inspect().outbox().is_empty());
}

#[test]
fn replay_requires_view_advance_proof_to_be_retained_and_forwarded() {
    let profile = Harness::observer().participants(6).profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let proof =
        Artifact::Nullification(symbolic_nullification(&restored, View::new(1), 0)).id::<Sha256>();
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        cursor,
        Change::ViewAdvanced {
            proof,
            floor: View::zero(),
            retired_publications: Vec::new(),
        },
    );

    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::Exit
    );
    assert_eq!(restored.inspect().view(), View::new(1));
}

/// Replay rejects an L-QC finality floor until a V-QC of its view was forwarded. Any same-view
/// V-QC discharges that duty, and the floor's derived V-QC becomes the proposal anchor.
#[test]
fn replay_requires_the_views_first_vqc_forwarding_before_a_current_lqc_floor() {
    let profile = Harness::observer().participants(6).profile();
    let machine = Machine::new(profile.clone());
    let proposed = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed, &votes);
    let proof = Arc::new(Artifact::Lqc(certificate.clone()));
    let first = Cursor::zero().next().unwrap();
    let floor = DomainEvent::new(
        machine.profile().protocol().epoch(),
        first,
        Change::FinalityFloorAdvanced {
            proof: Arc::clone(&proof),
            retired_signing: Vec::new(),
            retired_publications: Vec::new(),
        },
    );
    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();

    assert_eq!(
        transition_reason(restored.replay(floor)),
        TransitionReason::FinalityFloor
    );

    let derived = Arc::new(Artifact::Vqc(
        certificate.derive_vqc(machine.profile().codec()).unwrap(),
    ));
    let anchor_id = derived.id::<Sha256>();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first),
                retired_publications: Vec::new(),
                artifact: Arc::clone(&derived),
            },
        ))
        .unwrap();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first.next().unwrap(),
            Change::FinalityFloorAdvanced {
                proof: Arc::clone(&proof),
                retired_signing: Vec::new(),
                retired_publications: Vec::new(),
            },
        ))
        .unwrap();

    assert!(matches!(
        restored.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate
    ));

    // The forwarding duty is one V-QC per view, not one copy of every same-view transcript. A
    // different V-QC may therefore satisfy that duty, while the L-QC's derived V-QC becomes
    // the proposal anchor and must accompany any proposal that selects it.
    let alternate_votes = [0, 1, 2, 3, 5]
        .into_iter()
        .map(|signer| ViewMessage::Vote(view_vote(&machine, certificate.leader(), signer)))
        .collect::<Vec<_>>();
    let alternate = Arc::new(Artifact::Vqc(vqc(
        &machine,
        certificate.leader().clone(),
        &alternate_votes,
    )));
    let alternate_id = alternate.id::<Sha256>();
    assert_ne!(alternate_id, anchor_id);

    let mut restored = Machine::<Sha256, MinPk>::restore(
        machine.profile().clone(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first),
                retired_publications: Vec::new(),
                artifact: Arc::clone(&alternate),
            },
        ))
        .unwrap();
    assert_eq!(
        restored
            .durable
            .state
            .forwarded_vqcs
            .get(&certificate.view())
            .map(|artifact| artifact.id::<Sha256>()),
        Some(alternate_id),
    );
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first.next().unwrap(),
            Change::FinalityFloorAdvanced {
                proof,
                retired_signing: Vec::new(),
                retired_publications: Vec::new(),
            },
        ))
        .unwrap();
    assert_eq!(
        restored
            .durable
            .state
            .proposal_anchor
            .as_ref()
            .map(|artifact| artifact.id::<Sha256>()),
        Some(anchor_id),
    );
    Machine::<Sha256, MinPk>::restore(machine.profile().clone(), restored.live_snapshot_for_test())
        .unwrap();
}

#[test]
fn proposal_may_repeat_its_exact_parent_after_forwarding() {
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
    let profile = Harness::builder(Role::Validator(signer))
        .participants(6)
        .profile();
    let machine = Machine::new(profile.clone());
    let parent = view_one_vqc(&machine);
    let request = proposal_request_with_parent(&machine, View::new(2), parent.clone());
    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();

    let forwarding_cursor = Cursor::zero().next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            forwarding_cursor,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(forwarding_cursor),
                retired_publications: Vec::new(),
                artifact: Arc::new(Artifact::Vqc(parent)),
            },
        ))
        .unwrap();

    let proposal_cursor = forwarding_cursor.next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            proposal_cursor,
            Change::OutboxQueued {
                id: EffectId::from_cursor(proposal_cursor),
                effect: Box::new(DurableEffect::sign(SignRequest::LeaderBlock(request))),
            },
        ))
        .unwrap();
}

#[test]
fn proposal_parent_forwarding_provenance_survives_retirement() {
    for forwarded_exact_parent in [true, false] {
        let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
        let profile = Harness::builder(Role::Validator(signer))
            .participants(6)
            .profile();
        let machine = Machine::new(profile.clone());
        let proposed = leader(&machine, 1);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let certificate = lqc(&machine, proposed.clone(), &votes);
        let parent = certificate.derive_vqc(machine.profile().codec()).unwrap();
        let forwarded = if forwarded_exact_parent {
            parent.clone()
        } else {
            let messages = [0, 1, 2, 3, 5]
                .into_iter()
                .map(|signer| ViewMessage::Vote(view_vote(&machine, &proposed, signer)))
                .collect::<Vec<_>>();
            let alternate = vqc(&machine, proposed, &messages);
            assert_ne!(alternate.id::<Sha256>(), parent.id::<Sha256>());
            alternate
        };
        let mut restored =
            Machine::<Sha256, MinPk>::restore(profile.clone(), machine.live_snapshot_for_test())
                .unwrap();

        let forwarding_cursor = Cursor::zero().next().unwrap();
        restored
            .replay(DomainEvent::new(
                profile.protocol().epoch(),
                forwarding_cursor,
                Change::ArtifactForwarded {
                    publication: EffectId::from_cursor(forwarding_cursor),
                    retired_publications: Vec::new(),
                    artifact: Arc::new(Artifact::Vqc(forwarded)),
                },
            ))
            .unwrap();
        let floor_cursor = forwarding_cursor.next().unwrap();
        restored
            .replay(DomainEvent::new(
                profile.protocol().epoch(),
                floor_cursor,
                Change::FinalityFloorAdvanced {
                    proof: Arc::new(Artifact::Lqc(certificate)),
                    retired_signing: Vec::new(),
                    retired_publications: Vec::new(),
                },
            ))
            .unwrap();
        assert!(restored.durable.state.forwarded_vqcs.is_empty());
        let snapshot = restored.live_snapshot_for_test();
        let request = restored
            .views
            .drive_regular_sign_request::<Sha256>(&profile, View::new(2), &restored.chain, 16)
            .unwrap()
            .output
            .unwrap();
        let SignRequest::LeaderBlock(proposal) = &request else {
            panic!("the view-two leader must propose");
        };
        assert_eq!(proposal.parent().exact().map(Arc::as_ref), Some(&parent));
        assert_eq!(proposal.attach_parent(), !forwarded_exact_parent);
        let artifact = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposal.block().clone(),
            attestation(signer.get()),
        )));

        // A snapshot retains the proof, but retired forwarding provenance is volatile.
        let mut recovered = Machine::<Sha256, MinPk>::restore(profile.clone(), snapshot).unwrap();
        recovered.step(Input::RecoveryComplete).unwrap();
        let recovered_request = recovered
            .views
            .drive_regular_sign_request::<Sha256>(&profile, View::new(2), &recovered.chain, 16)
            .unwrap()
            .output
            .unwrap();
        let SignRequest::LeaderBlock(proposal) = recovered_request else {
            panic!("the recovered leader must propose");
        };
        assert_eq!(proposal.parent().exact().map(Arc::as_ref), Some(&parent));
        assert!(proposal.attach_parent());

        let proposal_cursor = floor_cursor.next().unwrap();
        restored
            .replay(DomainEvent::new(
                profile.protocol().epoch(),
                proposal_cursor,
                Change::OutboxQueued {
                    id: EffectId::from_cursor(proposal_cursor),
                    effect: Box::new(DurableEffect::sign(request)),
                },
            ))
            .unwrap();
        Machine::<Sha256, MinPk>::restore(profile.clone(), restored.live_snapshot_for_test())
            .unwrap();
        let signed_cursor = proposal_cursor.next().unwrap();
        let publication = EffectId::from_cursor(signed_cursor);
        restored
            .replay(DomainEvent::new(
                profile.protocol().epoch(),
                signed_cursor,
                Change::SignedArtifacts {
                    sign: EffectId::from_cursor(proposal_cursor),
                    publication,
                    artifacts: Arc::from([Arc::clone(&artifact)]),
                },
            ))
            .unwrap();
        let parent_id = Artifact::Vqc(parent).id::<Sha256>();
        assert_eq!(
            restored.durable.effect_ids[&publication],
            vec![artifact.id::<Sha256>(), parent_id]
        );
        assert!(restored.durable.state.local.contains_key(&parent_id));
        let recovered =
            Machine::<Sha256, MinPk>::restore(profile, restored.live_snapshot_for_test()).unwrap();
        assert_eq!(recovered.durable.effect_ids, restored.durable.effect_ids);
        assert_eq!(
            recovered.durable.artifact_references,
            restored.durable.artifact_references
        );
    }
}

#[test]
fn replay_bounds_forwarded_certificate_outbox_growth() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(9))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(1));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let first = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(1),
        0,
    )));
    let second = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(2),
        0,
    )));
    let first_cursor = Cursor::zero().next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            first_cursor,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first_cursor),
                retired_publications: Vec::new(),
                artifact: first,
            },
        ))
        .unwrap();
    let second_cursor = first_cursor.next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        second_cursor,
        Change::ArtifactForwarded {
            publication: EffectId::from_cursor(second_cursor),
            retired_publications: Vec::new(),
            artifact: second,
        },
    );
    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::OutboxFull
    );
    assert_eq!(restored.inspect().cursor(), first_cursor);
    assert_eq!(restored.inspect().outbox().len(), 1);
}

#[test]
fn replay_accepts_reordered_future_exit_forwarding() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(9))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(16));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let mut cursor = Cursor::zero();

    // Future certificates can finish verification before the current view. Every publication
    // remains within the global outbox, artifact, and forwarding-history bounds.
    for view in [3, 2, 1] {
        cursor = cursor.next().unwrap();
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored,
            View::new(view),
            0,
        )));
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                cursor,
                Change::ArtifactForwarded {
                    publication: EffectId::from_cursor(cursor),
                    retired_publications: Vec::new(),
                    artifact,
                },
            ))
            .unwrap();
    }

    assert_eq!(restored.inspect().outbox().len(), 3);
}

#[test]
fn successor_forwarding_reuses_retired_artifact_capacity() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(9))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(16));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile.clone());

    let first = symbolic_nullification(&machine, View::new(1), 0);
    let first = observe(&mut machine, Artifact::Nullification(first));
    let forwarding = machine.verify(&first, true, Until::CursorAdvance);
    machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));

    let previous_vqc = Arc::new(Artifact::Vqc(view_one_vqc(&machine)));
    let previous_vqc = machine
        .reserve_test_effect(DurableEffect::broadcast(previous_vqc))
        .unwrap();
    machine.persist(&previous_vqc.persist_job(), Until::CursorAdvance);

    // Fill the durable artifact budget. Advancing through view 2 retires the two exit
    // publications above, so forwarding its certificate must reuse their capacity atomically.
    for view in 10..16 {
        let filler = Arc::new(leader_artifact(&machine, view));
        let reserved = machine
            .reserve_test_effect(DurableEffect::broadcast(filler))
            .unwrap();
        machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    }
    let proof_filler = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(20),
        2,
    )));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(proof_filler))
        .unwrap();
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.durable.artifact_references.len(), 9);
    assert_eq!(machine.durable.state.outbox.len(), 9);

    let successor = symbolic_nullification(&machine, View::new(2), 1);
    let successor = observe(&mut machine, Artifact::Nullification(successor));
    let acknowledged = machine.live_snapshot_for_test();
    let forwarded = machine.verify(&successor, true, Until::CursorAdvance);
    let forwarding = forwarded.persist_job();
    // The exit derives beside the forwarding it reads, so one range retires the two exit
    // publications above, admits the successor's certificate, and retires what the new view
    // floor releases.
    assert_eq!(
        forwarding
            .events()
            .iter()
            .map(|event| event.change().kind())
            .collect::<Vec<_>>(),
        [ChangeKind::ArtifactForwarded, ChangeKind::ViewAdvanced]
    );
    assert_eq!(machine.store.artifacts.len(), 1);
    assert!(machine.durable.state.nullification_forwarded(View::new(2)));
    assert_eq!(machine.durable.state.outbox.len(), 8);
    assert_eq!(machine.durable.artifact_references.len(), 8);

    let mut restored = Machine::<Sha256, MinPk>::restore(profile.clone(), acknowledged).unwrap();
    for event in forwarding.events().iter().cloned() {
        restored.replay(event).unwrap();
    }
    assert!(restored.durable.state.nullification_forwarded(View::new(2)));
    assert_eq!(restored.durable.state.outbox.len(), 8);
    assert_eq!(restored.durable.artifact_references.len(), 8);
    Machine::<Sha256, MinPk>::restore(profile, restored.live_snapshot_for_test()).unwrap();
}

#[test]
fn replay_bounds_locally_created_view_certificates() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(9))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(16));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let mut cursor = Cursor::zero();
    for view in 1..=9 {
        cursor = cursor.next().unwrap();
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored,
            View::new(view),
            0,
        )));
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                cursor,
                Change::ViewCertificateCreated { artifact },
            ))
            .unwrap();
    }
    let rejected_cursor = cursor.next().unwrap();
    let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(10),
        0,
    )));
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        rejected_cursor,
        Change::ViewCertificateCreated { artifact },
    );
    assert_eq!(
        transition_reason(restored.replay(event)),
        TransitionReason::ArtifactCapacity
    );
    assert_eq!(restored.inspect().cursor(), cursor);
    assert_eq!(restored.live_snapshot_for_test().local_artifacts().len(), 9);
}

#[test]
fn checkpoint_cut_retained_artifacts_list_each_holder_and_dedupe_by_id() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let view = View::new(2);
    let nullification: Arc<Artifact<MinPk, Digest>> = Arc::new(Artifact::Nullification(
        symbolic_nullification(&machine, view, 0),
    ));
    // The same certificate is both forwarded and the view's exit proof, held by separate
    // allocations as it is after a snapshot decode.
    machine
        .durable
        .state
        .forwarded_nullifications
        .insert(view, Arc::clone(&nullification));
    machine
        .durable
        .state
        .exits
        .insert(view, Arc::new(nullification.as_ref().clone()));

    let id = nullification.id::<Sha256>();
    let cut = machine
        .checkpoint_cut()
        .expect("a fresh machine is quiescent");
    // Each holder reports its certificate; recovery verifies the certificate once by keeping the
    // first artifact per identifier.
    let held = cut
        .retained_artifacts()
        .filter(|artifact| artifact.id::<Sha256>() == id)
        .count();
    assert_eq!(held, 2);
    let mut ids = HashSet::new();
    let distinct = cut
        .retained_artifacts()
        .filter(|artifact| ids.insert(artifact.id::<Sha256>()))
        .filter(|artifact| artifact.id::<Sha256>() == id)
        .count();
    assert_eq!(distinct, 1);
}

#[test]
fn replay_and_restore_count_signing_reservations_with_retained_artifacts() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(9))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(9));
    let profile = Harness::validator(0)
        .participants(6)
        .resources(limits)
        .profile();
    let machine = Machine::<Sha256, MinPk>::new(profile.clone());
    let mut restored = Machine::restore(profile.clone(), machine.live_snapshot_for_test()).unwrap();
    let mut forwarded_cursor = Cursor::zero();
    for view in 2..=9 {
        forwarded_cursor = forwarded_cursor.next().unwrap();
        let view = View::new(view);
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored, view, 0,
        )));
        let retired = restored.obligations_retired_by_exit(view);
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                forwarded_cursor,
                Change::ArtifactForwarded {
                    publication: EffectId::from_cursor(forwarded_cursor),
                    retired_publications: retired,
                    artifact,
                },
            ))
            .unwrap();
    }

    let round = Round::new(restored.profile().protocol().epoch(), View::new(1));
    let requests = Arc::from([
        SignRequest::NoVote { round },
        SignRequest::Nullify { round },
    ]);
    let sign_cursor = forwarded_cursor.next().unwrap();
    let sign = DomainEvent::new(
        restored.profile().protocol().epoch(),
        sign_cursor,
        Change::OutboxQueued {
            id: EffectId::from_cursor(sign_cursor),
            effect: Box::new(DurableEffect::Sign(SignEffect::new(Arc::clone(&requests)))),
        },
    );
    assert_eq!(
        transition_reason(restored.replay(sign)),
        TransitionReason::ArtifactCapacity
    );

    let mut applied = restored.durable.state.clone();
    applied.cursor = sign_cursor;
    applied.signing_reservations.insert(
        EffectId::from_cursor(sign_cursor),
        SignEffect::new(requests),
    );
    let snapshot = Snapshot::new(
        machine.profile().protocol().epoch(),
        Role::Validator(Participant::new(0)),
        applied,
    );
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(profile, snapshot)),
        SnapshotReason::Bounds
    );
}

#[test]
fn replay_rejects_a_vote_after_a_local_nullify() {
    let signer = Participant::new(1);
    let role = Role::Validator(signer);
    let profile = Harness::builder(role).participants(6).profile();
    let machine = Machine::new(profile.clone());
    let epoch = machine.profile().protocol().epoch();
    let view = View::new(1);
    let vote = view_vote(&machine, &leader(&machine, view.get()), signer.get());
    let vote_request = SignRequest::Vote(vote.body().clone());
    let nullify_request = SignRequest::Nullify {
        round: Round::new(epoch, view),
    };

    let queued = |cursor: Cursor, request: &SignRequest<MinPk, Digest>| {
        DomainEvent::new(
            epoch,
            cursor,
            Change::OutboxQueued {
                id: EffectId::from_cursor(cursor),
                effect: Box::new(DurableEffect::sign(request.clone())),
            },
        )
    };
    let first = Cursor::zero().next().unwrap();
    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile.clone(), machine.live_snapshot_for_test())
            .unwrap();
    restored.replay(queued(first, &vote_request)).unwrap();
    restored
        .replay(queued(first.next().unwrap(), &nullify_request))
        .unwrap();

    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile.clone(), machine.live_snapshot_for_test())
            .unwrap();
    restored.replay(queued(first, &nullify_request)).unwrap();
    assert_eq!(
        transition_reason(restored.replay(queued(first.next().unwrap(), &vote_request))),
        TransitionReason::ViewState
    );

    let snapshot = |reserved: &[&SignRequest<MinPk, Digest>], local: &[Artifact<MinPk, Digest>]| {
        let mut applied = machine.durable.state.clone();
        for request in reserved {
            applied.cursor = applied.cursor.next().unwrap();
            applied.signing_reservations.insert(
                EffectId::from_cursor(applied.cursor),
                SignEffect::one((*request).clone()),
            );
        }
        for artifact in local {
            applied
                .local
                .insert(artifact.id::<Sha256>(), Arc::new(artifact.clone()));
        }
        Snapshot::new(epoch, role, applied)
    };
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            snapshot(&[&nullify_request, &vote_request], &[])
        )),
        SnapshotReason::View
    );

    // Every durable form of vote-then-nullify restores, whatever map order observes it in.
    let local_vote = Artifact::Vote(vote);
    let local_nullify = Artifact::Nullify(nullify(&machine, view, signer.get()));
    Machine::<Sha256, MinPk>::restore(
        profile.clone(),
        snapshot(&[&vote_request, &nullify_request], &[]),
    )
    .unwrap();
    Machine::<Sha256, MinPk>::restore(
        profile.clone(),
        snapshot(&[&nullify_request], core::slice::from_ref(&local_vote)),
    )
    .unwrap();
    Machine::<Sha256, MinPk>::restore(
        profile.clone(),
        snapshot(&[&vote_request], core::slice::from_ref(&local_nullify)),
    )
    .unwrap();
    Machine::<Sha256, MinPk>::restore(
        profile.clone(),
        snapshot(&[], &[local_vote.clone(), local_nullify.clone()]),
    )
    .unwrap();

    // Exits apply after every choice, so an exited view still restores its vote and nullify.
    let mut exited = snapshot(&[], &[local_vote, local_nullify]).into_state();
    let exit = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        view,
        view.get(),
    )));
    exited
        .forwarded_nullifications
        .insert(view, Arc::clone(&exit));
    exited.exits.insert(view, exit);
    exited.view = view.next();
    Machine::<Sha256, MinPk>::restore(profile, Snapshot::new(epoch, role, exited)).unwrap();
}

#[test]
fn recovered_timeout_publication_requires_the_exact_artifact_pair() {
    let profile = Harness::validator(0).participants(6).profile();
    let machine = Machine::new(profile.clone());
    let view = View::new(1);
    let novote = Arc::new(Artifact::NoVote(no_vote(&machine, view, 0)));
    let other_novote = Arc::new(Artifact::NoVote(no_vote(&machine, view, 1)));
    let nullify = Arc::new(Artifact::Nullify(nullify(&machine, view, 0)));
    let mut unrelated = [Arc::clone(&novote), other_novote];
    unrelated.sort_unstable_by_key(|artifact| artifact.id::<Sha256>());
    let malformed = [
        Arc::from([Arc::clone(&novote), Arc::clone(&novote)]),
        Arc::from([Arc::clone(&nullify), Arc::clone(&nullify)]),
        Arc::from([Arc::clone(&nullify), Arc::clone(&novote)]),
        Arc::from(unrelated),
    ];

    for artifacts in malformed {
        let mut applied = machine.durable.state.clone();
        let cursor = Cursor::zero().next().unwrap();
        applied.cursor = cursor;
        applied.outbox.insert(
            EffectId::from_cursor(cursor),
            OutboxEntry::new(
                Publication::Broadcast(artifacts),
                vec![Discharge::new(0, DischargeKind::ViewRetired { view })],
            ),
        );
        let snapshot = Snapshot::new(
            machine.profile().protocol().epoch(),
            Role::Validator(Participant::new(0)),
            applied,
        );
        assert_eq!(
            snapshot_reason(Machine::<Sha256, MinPk>::restore(profile.clone(), snapshot)),
            SnapshotReason::Effect
        );
    }
}

/// Returns an observer profile and a machine built from it.
fn observer_fixture() -> (Profile<Digest>, TestMachine) {
    let profile = Harness::observer().participants(6).profile();
    (profile.clone(), Machine::new(profile))
}

/// Restores `state` as an observer snapshot and returns the snapshot check it fails.
fn observer_restore_reason(
    profile: Profile<Digest>,
    state: DurableState<MinPk, Digest>,
) -> SnapshotReason {
    let snapshot = Snapshot::new(profile.protocol().epoch(), Role::Observer, state);
    snapshot_reason(Machine::<Sha256, MinPk>::restore(profile, snapshot))
}

#[test]
fn snapshot_rejects_local_artifacts_the_role_cannot_construct() {
    let (profile, machine) = observer_fixture();
    let vote = Artifact::Vote(view_vote(&machine, &leader(&machine, 1), 0));
    let mut state = machine.durable.state;
    state.local.insert(vote.id::<Sha256>(), Arc::new(vote));
    assert_eq!(
        observer_restore_reason(profile, state),
        SnapshotReason::LocalArtifact
    );
}

#[test]
fn snapshot_rejects_certified_tips_without_their_certificate() {
    let (profile, machine) = observer_fixture();
    let mut state = machine.durable.state;
    state.certified_tips[1] = BlockRef::new(ChainId::new(1), Height::new(1), digest(b"tip"));
    state.da_safety_heights[1] = Height::new(1);
    assert_eq!(
        observer_restore_reason(profile, state),
        SnapshotReason::CertifiedTip
    );
}

#[test]
fn snapshot_rejects_publications_without_discharges() {
    let (profile, machine) = observer_fixture();
    let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        0,
    )));
    let mut state = machine.durable.state;
    state.cursor = state.cursor.next().unwrap();
    state.outbox.insert(
        EffectId::from_cursor(state.cursor),
        OutboxEntry::new(Publication::broadcast(proof), Vec::new()),
    );
    assert_eq!(
        observer_restore_reason(profile, state),
        SnapshotReason::Obligation
    );
}

#[test]
fn snapshot_rejects_misfiled_forwarded_certificates() {
    let (profile, machine) = observer_fixture();
    let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        0,
    )));
    let mut state = machine.durable.state;
    state.forwarded_vqcs.insert(View::new(1), proof);
    assert_eq!(
        observer_restore_reason(profile, state),
        SnapshotReason::Forwarded
    );
}

#[test]
fn snapshot_rejects_a_proposal_anchor_that_is_not_a_vqc() {
    let (profile, machine) = observer_fixture();
    let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        0,
    )));
    let mut state = machine.durable.state;
    state.proposal_anchor = Some(proof);
    assert_eq!(
        observer_restore_reason(profile, state),
        SnapshotReason::ProposalAnchor
    );
}

#[test]
fn snapshot_written_under_a_larger_retention_restores_and_compacts_on_exit() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let machine = Machine::new(profile.clone());
    let mut state = machine.durable.state.clone();
    state.view = View::new(5);
    state.retired_view = View::new(1);
    state.proposal_nullified_through = View::new(4);
    for view in (2..5).map(View::new) {
        let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
            &machine, view, 0,
        )));
        state
            .forwarded_nullifications
            .insert(view, Arc::clone(&proof));
        state.exits.insert(view, proof);
    }

    // At view 5 a retention of 2 retires through view 2, one view above the snapshot's floor: the
    // node that wrote it retained more views. The snapshot restores as written.
    assert_eq!(profile.retention_floor(View::new(5)), View::new(2));
    let snapshot = Snapshot::new(machine.profile().protocol().epoch(), Role::Observer, state);
    let mut restored = Machine::restore(profile, snapshot).unwrap();
    assert_eq!(restored.retired_view(), View::new(1));
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);

    // The next exit compacts through the floor of the view it enters.
    let exit = Artifact::Nullification(symbolic_nullification(&restored, View::new(5), 5));
    let verification = observe(&mut restored, exit);
    let admitted = restored.verify(&verification, true, Until::CursorAdvance);
    restored.drain_persisting(admitted);
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.retired_view(), View::new(3));
    assert_eq!(
        restored
            .durable
            .state
            .exits
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [View::new(4), View::new(5)]
    );
    assert!(
        restored
            .durable
            .state
            .forwarded_nullifications
            .keys()
            .all(|view| *view > View::new(3))
    );
}

/// Drives `capabilities` until the machine quiesces, acknowledging every persistence barrier in
/// emission order and appending its events to `journal`. Returns every other capability.
fn drive_journaled(
    machine: &mut TestMachine,
    capabilities: Vec<Capability<MinPk, Digest>>,
    journal: &mut Vec<DomainEvent<MinPk, Digest>>,
) -> Vec<Capability<MinPk, Digest>> {
    let mut sink = PersistSink::default();
    let emitted = machine.drain(&mut sink, capabilities, Until::Step);
    journal.extend(sink.events);
    emitted
}

/// Returns the timer `effects` armed for `view`.
fn view_timer(effects: &[Capability<MinPk, Digest>], view: View) -> ViewTimer {
    effects
        .iter()
        .rev()
        .find_map(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) if timer.round().view() == view => {
                Some(*timer)
            }
            _ => None,
        })
        .expect("every entered view arms its timer")
}

/// Returns the timeout signing choice `effects` released for `view`, if any.
fn timeout_job(
    effects: &[Capability<MinPk, Digest>],
    view: View,
) -> Option<DurableJob<MinPk, Digest>> {
    effects.iter().find_map(|effect| {
        durable_job(effect)
            .filter(|job| {
                matches!(
                    job.request().sign_many(),
                    Some([SignRequest::NoVote { round }, SignRequest::Nullify { .. }])
                        if round.view() == view
                )
            })
            .cloned()
    })
}

/// Completes the timeout signing choice `job` for `view` with `signer`'s no-vote and nullify.
fn sign_timeout(
    machine: &mut TestMachine,
    job: &DurableJob<MinPk, Digest>,
    view: View,
    signer: u32,
    journal: &mut Vec<DomainEvent<MinPk, Digest>>,
) -> Vec<Capability<MinPk, Digest>> {
    let artifacts = vec![
        Arc::new(Artifact::NoVote(no_vote(machine, view, signer))),
        Arc::new(Artifact::Nullify(nullify(machine, view, signer))),
    ];
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            job.issued(),
            artifacts,
        )))
        .unwrap();
    drive_journaled(machine, signed.into_capabilities(), journal)
}

/// Exits `view` through a peer nullification.
fn exit_view(
    machine: &mut TestMachine,
    view: View,
    journal: &mut Vec<DomainEvent<MinPk, Digest>>,
) -> Vec<Capability<MinPk, Digest>> {
    let nullification = symbolic_nullification(machine, view, 0);
    let verification = observe(machine, Artifact::Nullification(nullification));
    let verified = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = drive_journaled(machine, verified.into_capabilities(), journal);
    assert_eq!(machine.inspect().view(), View::new(view.get() + 1));
    effects
}

/// Returns the own-message discharges the durable outbox holds.
fn own_message_discharges(machine: &TestMachine) -> usize {
    machine
        .durable
        .state
        .outbox
        .values()
        .flat_map(OutboxEntry::discharges)
        .filter(|discharge| matches!(discharge.until(), DischargeKind::ViewRetired { .. }))
        .count()
}

#[test]
fn validator_journal_written_under_a_larger_retention_replays_after_lowering_it() {
    let signer = 1;
    let role = Role::Validator(Participant::new(signer));
    let written = Harness::builder(role)
        .participants(6)
        .retention(ViewDelta::new(4))
        .profile();
    let lowered = Harness::builder(role)
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let mut machine = Machine::new(written);
    let mut journal = Vec::new();
    let start = machine.step(Input::Start).unwrap();
    let mut effects = drive_journaled(&mut machine, start.into_capabilities(), &mut journal);
    let mut checkpoint = None;
    let mut timeouts = Vec::new();
    for view in (1..=8).map(View::new) {
        // Time the view out and leave its signing choice outstanding, except in view 3, whose
        // timeout pair is signed and published before the view exits. Its publication stays
        // outstanding across the tail's exits into views 7 and 8, between the two floors.
        let fired = machine
            .step(Input::TimerFired(view_timer(&effects, view)))
            .unwrap();
        effects = drive_journaled(&mut machine, fired.into_capabilities(), &mut journal);
        if let Some(job) = timeout_job(&effects, view) {
            if view == View::new(3) {
                effects.extend(sign_timeout(&mut machine, &job, view, signer, &mut journal));
            }
            timeouts.push((view, job));
        }
        effects.extend(exit_view(&mut machine, view, &mut journal));
        if view == View::new(2) {
            let cut = machine
                .checkpoint_cut()
                .expect("the drained machine is quiescent");
            checkpoint = Some((cut, journal.len()));
        }
        if view == View::new(6) {
            assert!(own_message_discharges(&machine) > 0);
        }
    }

    // Under a retention of 4 the exit into view 9 retired through view 4, so view 5's timeout
    // choice is still reserved; a retention of 2 would already have retired it.
    assert_eq!(machine.retired_view(), View::new(4));
    assert_eq!(lowered.retention_floor(View::new(9)), View::new(6));
    let (_, job) = timeouts
        .iter()
        .find(|(view, _)| *view == View::new(5))
        .expect("view 5 reserved its timeout choice");
    let job = job.clone();
    sign_timeout(&mut machine, &job, View::new(5), signer, &mut journal);
    let (cut, checkpointed) = checkpoint.expect("the checkpoint was cut at view 3");
    let tail = &journal[checkpointed..];
    assert!(
        tail.iter()
            .any(|event| event.change().kind() == ChangeKind::ViewAdvanced)
    );
    assert!(matches!(
        tail.last().map(|event| event.change().kind()),
        Some(ChangeKind::SignedArtifacts)
    ));

    // Restored under the lowered retention, replay applies each journaled floor.
    let mut restored = Machine::restore(lowered.clone(), cut).unwrap();
    for event in tail {
        restored.replay(event.clone()).unwrap();
    }
    assert_eq!(restored.retired_view(), View::new(4));
    assert_eq!(restored.inspect().view(), View::new(9));
    assert_eq!(
        restored.live_snapshot_for_test(),
        machine.live_snapshot_for_test()
    );

    // The first exit staged after restore compacts to the lowered retention.
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let mut ignored = Vec::new();
    drive_journaled(&mut restored, recovery.into_capabilities(), &mut ignored);
    let nullification = symbolic_nullification(&restored, View::new(9), 0);
    let verification = observe(&mut restored, Artifact::Nullification(nullification));
    let verified = restored.verify(&verification, true, Until::CursorAdvance);
    drive_journaled(&mut restored, verified.into_capabilities(), &mut ignored);
    assert_eq!(restored.inspect().view(), View::new(10));
    assert_eq!(
        restored.retired_view(),
        lowered.retention_floor(View::new(10))
    );
}

#[test]
fn validator_publishing_every_timeout_restores_under_a_smaller_retention() {
    let signer = 1;
    let role = Role::Validator(Participant::new(signer));
    let written = Harness::builder(role)
        .participants(6)
        .retention(ViewDelta::new(8))
        .profile();
    let lowered = Harness::builder(role)
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let mut machine = Machine::new(written);
    let mut journal = Vec::new();
    let start = machine.step(Input::Start).unwrap();
    let mut effects = drive_journaled(&mut machine, start.into_capabilities(), &mut journal);
    let mut checkpoint = None;
    for view in (1..=12).map(View::new) {
        // Time the view out, then sign and publish its timeout pair before it exits.
        let fired = machine
            .step(Input::TimerFired(view_timer(&effects, view)))
            .unwrap();
        effects = drive_journaled(&mut machine, fired.into_capabilities(), &mut journal);
        let job = timeout_job(&effects, view).expect("a timed out view reserves its timeout pair");
        effects.extend(sign_timeout(&mut machine, &job, view, signer, &mut journal));
        effects.extend(exit_view(&mut machine, view, &mut journal));
        if view == View::new(1) {
            let cut = machine
                .checkpoint_cut()
                .expect("the drained machine is quiescent");
            checkpoint = Some((cut, journal.len()));
        }
    }

    // A retention of 8 keeps more own messages outstanding than a retention of 2 would hold.
    assert_eq!(machine.retired_view(), View::new(4));
    let lowered_steady_state = Machine::<Sha256, MinPk>::new(lowered.clone())
        .obligation_family_bounds()
        .own_messages;
    assert!(own_message_discharges(&machine) > lowered_steady_state);

    // Restored under the lowered retention, replay installs every journaled publication.
    let (cut, checkpointed) = checkpoint.expect("the checkpoint was cut at view 2");
    let mut restored = Machine::restore(lowered.clone(), cut).unwrap();
    for event in &journal[checkpointed..] {
        restored.replay(event.clone()).unwrap();
    }
    assert_eq!(
        restored.live_snapshot_for_test(),
        machine.live_snapshot_for_test()
    );

    // The first publication staged after restore installs next to the writer's whole window.
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let mut live = Vec::new();
    let effects = drive_journaled(&mut restored, recovery.into_capabilities(), &mut live);
    let view = View::new(13);
    let fired = restored
        .step(Input::TimerFired(view_timer(&effects, view)))
        .unwrap();
    let effects = drive_journaled(&mut restored, fired.into_capabilities(), &mut live);
    let job = timeout_job(&effects, view).expect("a timed out view reserves its timeout pair");
    let outstanding = own_message_discharges(&restored);
    sign_timeout(&mut restored, &job, view, signer, &mut live);
    assert!(own_message_discharges(&restored) > outstanding);
    assert!(
        live.iter()
            .any(|event| event.change().kind() == ChangeKind::SignedArtifacts)
    );

    // The next exit compacts the window to the lowered retention.
    exit_view(&mut restored, view, &mut live);
    assert_eq!(
        restored.retired_view(),
        lowered.retention_floor(View::new(14))
    );
    assert!(own_message_discharges(&restored) <= lowered_steady_state);
}

#[test]
fn replay_bounds_a_view_advance_floor_between_the_retired_and_exited_views() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(1))
        .profile();
    let mut machine = Machine::new(profile.clone());
    let base = machine.live_snapshot_for_test();
    let mut journal = Vec::new();
    let start = machine.step(Input::Start).unwrap();
    drive_journaled(&mut machine, start.into_capabilities(), &mut journal);
    for view in (1..=3).map(View::new) {
        let nullification = symbolic_nullification(&machine, view, 0);
        let verification = observe(&mut machine, Artifact::Nullification(nullification));
        let verified = machine.verify(&verification, true, Until::CursorAdvance);
        drive_journaled(&mut machine, verified.into_capabilities(), &mut journal);
    }
    let position = journal
        .iter()
        .rposition(|event| event.change().kind() == ChangeKind::ViewAdvanced)
        .expect("the exit is journaled");
    let Change::ViewAdvanced {
        proof,
        floor: staged,
        retired_publications,
    } = journal[position].change().clone()
    else {
        unreachable!("the selected event advances the view")
    };
    assert_eq!(staged, View::new(2));

    // Exiting view 3 with view 1 retired may retire through views 1 or 2, but never below the
    // retired view nor the exited or entered view.
    for (floor, accepted) in [
        (View::new(0), false),
        (View::new(1), true),
        (View::new(2), true),
        (View::new(3), false),
        (View::new(4), false),
    ] {
        let mut restored =
            Machine::<Sha256, MinPk>::restore(profile.clone(), base.clone()).unwrap();
        for event in &journal[..position] {
            restored.replay(event.clone()).unwrap();
        }
        assert_eq!(restored.retired_view(), View::new(1));
        let event = DomainEvent::new(
            journal[position].epoch(),
            journal[position].cursor(),
            Change::ViewAdvanced {
                proof,
                floor,
                retired_publications: retired_publications.clone(),
            },
        );
        let replayed = restored.replay(event);
        if accepted {
            replayed.unwrap();
            assert_eq!(restored.retired_view(), floor);
        } else {
            assert_eq!(transition_reason(replayed), TransitionReason::Retirement);
        }
    }
}

#[test]
fn snapshot_requires_contiguous_completed_view_exits() {
    let profile = Harness::observer().participants(6).profile();
    let machine = Machine::new(profile.clone());
    let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        0,
    )));
    let mut valid = machine.durable.state.clone();
    valid.view = View::new(2);
    valid
        .forwarded_nullifications
        .insert(View::new(1), Arc::clone(&proof));
    valid.exits.insert(View::new(1), proof);
    let snapshot =
        |state| Snapshot::new(machine.profile().protocol().epoch(), Role::Observer, state);
    Machine::<Sha256, MinPk>::restore(profile.clone(), snapshot(valid.clone())).unwrap();

    let mut zero = valid.clone();
    zero.view = View::zero();
    zero.exits.clear();
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            snapshot(zero)
        )),
        SnapshotReason::Exits
    );

    let mut missing = valid.clone();
    missing.view = View::new(3);
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            snapshot(missing)
        )),
        SnapshotReason::Exits
    );

    let mut sparse = valid.clone();
    sparse.exits.clear();
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            profile.clone(),
            snapshot(sparse)
        )),
        SnapshotReason::Exits
    );

    let future_proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(2),
        0,
    )));
    valid
        .forwarded_nullifications
        .insert(View::new(2), Arc::clone(&future_proof));
    valid.exits.insert(View::new(2), future_proof);
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(profile, snapshot(valid))),
        SnapshotReason::View
    );
}

#[test]
fn mismatched_effect_completion_preserves_outbox() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    // Signing carries no signature out, so the request releases alongside its barrier.
    let [Capability::Released(sign), Capability::Journal(_)] = reserved.capabilities() else {
        panic!("a staged signing choice must release its request");
    };
    assert!(sign.request().sign_one().is_some());
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    let wrong = leader(&machine, 3);

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                wrong,
                attestation(0),
            )))]
        ))),
        Err(StepError::EffectMismatch)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.issued().id()]);
    assert!(machine.inspect().pending_barrier().is_none());
    assert!(machine.inspect().ready_artifacts().is_empty());

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(1),
            )))]
        ))),
        Err(StepError::EffectMismatch)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.issued().id()]);
    assert!(machine.inspect().ready_artifacts().is_empty());
}

#[test]
fn publication_attempt_ignores_an_unrelated_barrier() {
    let mut machine = active_machine(Role::Observer);
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
            &machine, 1,
        ))))
        .unwrap();
    let broadcast = reserved
        .find(|effect| match effect {
            Capability::Released(job) if job.request().broadcast_one().is_some() => {
                Some(job.clone())
            }
            _ => None,
        })
        .unwrap();
    let published = machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    assert!(published.capabilities().iter().all(|effect| {
        !durable_effect(effect)
            .and_then(EffectExt::broadcast_one)
            .is_some()
    }));
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            broadcast.issued(),
        )))
        .unwrap();
    assert!(delivered.capabilities().is_empty());

    machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
            &machine, 2,
        ))))
        .unwrap();
    let stale = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            broadcast.issued(),
        )))
        .unwrap();
    assert!(matches!(stale.status(), StepStatus::Accepted));
    assert!(stale.capabilities().is_empty());
}

#[test]
fn signed_completion_survives_crash_before_barrier_acknowledgement() {
    let mut runner = active_driver(Role::Validator(Participant::new(0)));
    let baseline = runner.inspect().outbox()[0];
    let proposed = leader(runner.machine(), 2);
    let reserved = runner
        .reserve(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    // The signing request releases at staging; the signed block's publication is what waits
    // for durability below.
    let sign = reserved
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_one().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("a staged signing request must be released");
    let signed = runner.persist(&reserved.persist_job(), Until::Step);
    assert!(
        !signed.has(|effect| durable_effect(effect)
            .and_then(EffectExt::sign_one)
            .is_some()),
        "the acknowledgement must not release the signing request a second time"
    );
    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let artifact_id = artifact.id::<Sha256>();
    let completed = runner
        .submit(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    let completed = runner.settle(completed, Until::Persist);
    let job = completed.persist_job();
    let broadcast_id = match job.events()[0].change() {
        Change::SignedArtifacts {
            sign: completed_sign,
            publication,
            artifacts,
        } => {
            assert_eq!(*completed_sign, sign.issued().id());
            assert!(matches!(artifacts.as_ref(), [recorded] if recorded.as_ref() == &artifact));
            *publication
        }
        _ => panic!("signed completion must be one atomic durable transition"),
    };
    runner.append(&job).unwrap();

    let recovery = runner.crash_and_restore().unwrap();
    assert_eq!(runner.inspect().ready_artifacts(), &[artifact_id]);
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    assert!(
        recovery.has(|effect| matches!(effect, Capability::Timer(TimerCommand::View(_)))),
        "recovery must arm the view timer at staging"
    );
    let recovered = runner.persist(&recovery.persist_job(), Until::Step);
    let [Capability::Released(sign), Capability::Released(broadcast)] = recovered.capabilities()
    else {
        panic!("recovery must reissue the completed signed artifact");
    };
    assert!(sign.request().sign_one().is_some());
    let Some(publication) = broadcast.request().proposal() else {
        panic!("recovery must reissue the completed signed artifact");
    };
    assert_eq!(broadcast.issued().id(), broadcast_id);
    let Artifact::LeaderBlock(expected) = &artifact else {
        unreachable!();
    };
    assert_eq!(publication.block().as_ref(), expected);
    assert!(matches!(publication.parent(), ProposalParent::Genesis));

    let delivered = runner
        .submit(Input::EffectCompleted(EffectCompletion::delivered(
            broadcast.issued(),
        )))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    assert_eq!(runner.inspect().local_artifacts(), 1);

    let recovery = runner.crash_and_restore().unwrap();
    assert_eq!(runner.inspect().ready_artifacts(), &[artifact_id]);
    assert_eq!(runner.inspect().local_artifacts(), 1);
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    runner.persist(&recovery.persist_job(), Until::Step);
}

#[test]
fn oversized_signing_completion_never_reaches_the_journal() {
    let limits = TEST_RESOURCES.with_max_artifact_bytes(NZUsize!(1));
    let profile = Harness::validator(0).resources(limits).profile();
    let mut machine = Machine::new(profile);
    let start = machine.step(Input::Start).unwrap();
    let started = machine.persist(&start.persist_job(), Until::CursorAdvance);
    // The producer's signing choice stages behind the generation barrier and its request
    // releases at staging.
    assert!(matches!(
        started.capabilities(),
        [Capability::Released(job), Capability::Journal(_)]
            if job.request().sign_one().is_some()
    ));
    machine.persist(&started.persist_job(), Until::CursorAdvance);
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let [Capability::Released(sign), Capability::Journal(_)] = reserved.capabilities() else {
        panic!("a staged signing choice must release its request");
    };
    assert!(sign.request().sign_one().is_some());
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            )))]
        ))),
        Err(StepError::LocalArtifactTooLarge)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.issued().id()]);
    assert!(machine.inspect().pending_barrier().is_none());
    assert_eq!(machine.inspect().local_artifacts(), 0);
    assert!(machine.inspect().ready_artifacts().is_empty());
}
