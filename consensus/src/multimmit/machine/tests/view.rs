//! View timeout, nullification, V-QC aggregation, exit, and retention tests.

use super::fixtures::{
    Harness, TEST_RESOURCES, active_driver, attestation, digest, drive_to_exit,
    drive_unanimous_votes, durable_effect, durable_job, genesis_tip_history, leader,
    leader_artifact, lqc, no_vote, nullify, observe, produce_own_header,
    proposal_request_with_parent, record_view_fact, release_after_enqueue, sign_job, sign_request,
    snapshot_reason, start_profile, symbolic_da_certificate, symbolic_nullification, view_one_vqc,
    view_vote, vqc, vqc_completion,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::{LeaderSchedule, Role},
        machine::{
            capability::{Capability, CryptoJob, ResolverCommand, TimerCommand},
            durability::{
                Change, ChangeKind, DischargeKind, DurableEffect, EffectCompletion,
                PersistDirective, Publication, SignRequest, Snapshot, SnapshotCodecConfig,
                SnapshotReason,
            },
            input::{CryptoCompletion, Input, ObservationStatus, Step, StepError, StepStatus},
            job::Generation,
            reducer::machine::Machine,
            resolution::ResolutionCompletion,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, MachineExt as _,
                StepExt as _, SymbolicPersistence, Until, VerifyJobExt as _, cohort,
            },
            verification::{Observation, Verdict, VerificationCompletion, VerifyJob},
            view::{NullificationRecoveryCompletion, VqcAggregateCompletion},
        },
        types::{
            Anchor, Artifact, CertificateId, ChainProposal, DigestedLeader, Extension, FinalityId,
            LeaderBlock, Position, SignedLeaderBlock, ViewMessage, ViewProof, Vote, VoteBody,
        },
    },
    types::{Attributable, Participant, Round, View, ViewDelta},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn full_publication_outbox_does_not_block_view_certificate_assembly() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(1));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let filler = Arc::new(leader_artifact(&machine, 10));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(filler))
        .unwrap();
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.live_snapshot_for_test().outbox().len(), 1);

    let proposed = leader(&machine, 1);
    let proposal = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(0),
    )));
    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        proposal.as_ref().clone(),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, artifact) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), artifact);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = machine.settle(driven, Until::CursorAdvance);
    assert!(driven.has(Capability::is_aggregate_vqc));
    assert_eq!(machine.live_snapshot_for_test().outbox().len(), 1);
}

#[test]
fn locally_assembled_vqc_forwards_and_exits_in_one_work_quantum() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    assert_eq!(machine.view(), View::new(1));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);

    let vqc_job = |effect: &Capability<MinPk, Digest>| match effect {
        Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
        _ => None,
    };
    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        aggregate = aggregate.or_else(|| step.find(vqc_job));
        let effects = machine.drain_persisting(step);
        aggregate = aggregate.or_else(|| effects.iter().find_map(vqc_job));
    }
    let aggregate = aggregate.expect("a view quorum assembles the current view's V-QC");
    assert_eq!(aggregate.leader().view(), View::new(1));

    let messages = aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, aggregate.leader().clone(), &messages);
    let staged = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    assert_eq!(staged.status(), &StepStatus::Accepted);

    // The forwarding fact the exit reads applies as soon as it is staged, so the view drive
    // does not requeue between them and one persistence range carries both events.
    let drive = drive_to_exit(&mut machine, staged, View::new(1));
    assert_eq!(machine.view(), View::new(2));
    assert_eq!(drive.quanta, 3);
    assert_eq!(drive.barriers, 0);
    assert_eq!(
        drive.exit,
        [ChangeKind::ArtifactForwarded, ChangeKind::ViewAdvanced]
    );
}

#[test]
fn stale_vqc_completion_releases_the_pending_view() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 2);
    let view = View::new(2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);
    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        if signer == 4 {
            let effects = machine.drain_persisting(step);
            aggregate = effects.find(|effect| match effect {
                Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
                _ => None,
            });
        }
    }
    let aggregate = aggregate.expect("the n-f message must schedule V-QC assembly");
    assert!(machine.views.certificate_pending(view));

    // A generation advance strands the dispatched assembly. Consuming its completion must
    // clear the pending marker and re-ready the view from its retained messages.
    let messages = aggregate.messages().collect::<Vec<_>>();
    let assembled = vqc(&machine, aggregate.leader().clone(), &messages);
    let profile = machine.profile().clone();
    let completion = vqc_completion(&aggregate, assembled, profile.codec());
    let released = machine
        .views
        .prepare_vqc(
            &completion,
            Generation::new(aggregate.issued().generation().get() + 1),
        )
        .unwrap();
    assert!(released.is_none());
    assert!(!machine.views.certificate_pending(view));
    assert!(machine.views.certificate_ready(view));
}

#[test]
fn stale_nullification_completion_releases_the_pending_view() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let view = View::new(1);
    let shares = [2, 0, 1]
        .into_iter()
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(shares)).unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("nullify shares must be verified");
    };
    let verified = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    let recovery = verified
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the nullification quorum must schedule recovery");
    assert_eq!(machine.views.certificate_reservations(), 1);
    assert!(machine.views.certificate_pending(view));

    // A generation advance strands the dispatched recovery. Consuming its completion must
    // clear the pending marker and re-ready the view from its retained shares.
    let completion = NullificationRecoveryCompletion::new(
        recovery.issued(),
        symbolic_nullification(&machine, view, 0),
    );
    let released = machine
        .views
        .prepare_nullification(
            &completion,
            Generation::new(recovery.issued().generation().get() + 1),
        )
        .unwrap();
    assert!(released.is_none());
    assert_eq!(machine.views.certificate_reservations(), 0);
    assert!(!machine.views.certificate_pending(view));
    assert!(machine.views.certificate_ready(view));
}

#[test]
fn timeout_atomically_authorizes_novote_and_nullify() {
    let (mut machine, started) = Harness::validator(0).participants(6).start();
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    assert!(
        elapsed
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
        "a normal view timer must not enter the recovery network path"
    );
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    let queued = elapsed.persist_job();
    assert!(matches!(
        queued.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_many(), Some(requests)
                if matches!(requests,
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]))
    ));

    // Signing carries no signature out, so the batch releases with the step that stages the
    // atomic choice.
    let batch = elapsed
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_many().is_some() => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    machine.persist(&queued, Until::CursorAdvance);
    let view = View::new(1);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            batch.issued(),
            vec![
                Arc::new(Artifact::NoVote(no_vote(&machine, view, 0))),
                Arc::new(Artifact::Nullify(nullify(&machine, view, 0))),
            ],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    // Staging records both artifacts atomically; only their broadcast waits for durability.
    assert_eq!(machine.live_snapshot_for_test().local_artifacts().len(), 2);
    assert!(completed.capabilities().iter().all(|effect| {
        !durable_effect(effect)
            .and_then(EffectExt::broadcast_many)
            .is_some()
    }));
    let published = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.live_snapshot_for_test().local_artifacts().len(), 2);
    assert!(published.has(|capability| matches!(
        capability,
        Capability::Released(job)
            if job.request().broadcast_many().is_some()
    )));
}

#[test]
fn post_vote_nullification_counts_existential_non_support() {
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let proposed = leader(&machine, 1);
    let signer = machine.profile().protocol().leader(View::new(1));
    let proposal = Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(signer.get()),
    ));
    let verified = observe(&mut machine, proposal);
    let selected = machine.verify(&verified, true, Until::CursorAdvance);
    // The signing request releases with the step that stages the vote choice.
    let sign = sign_job(&selected);
    machine.persist(&selected.persist_job(), Until::CursorAdvance);
    let vote = view_vote(&machine, &proposed, 0);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::Vote(vote))],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    machine.persist(&completed.persist_job(), Until::CursorAdvance);

    let evidence = (1..=3)
        .map(|signer| Artifact::NoVote(no_vote(&machine, View::new(1), signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(evidence)).unwrap();
    let [Capability::Verify(job)] = observed.capabilities() else {
        panic!("non-support evidence must be verified together");
    };
    let nullify = machine.step(Input::Verified(job.all_valid())).unwrap();
    let nullify = machine.settle(nullify, Until::CursorAdvance);
    assert!(matches!(
        nullify.persist_job().events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::Nullify { .. }))
    ));
}

#[test]
fn nullification_recovery_uses_the_canonical_subset_and_exits() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let view = View::new(1);
    let shares = [2, 0, 1]
        .into_iter()
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(shares)).unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("nullify shares must be verified");
    };
    let verified = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    let recovery = verified
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        recovery
            .shares()
            .iter()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..3).map(Participant::new).collect::<Vec<_>>()
    );
    let certificate = symbolic_nullification(&machine, view, 0);
    let proof = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), certificate),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    // The recovered nullification is an independently verifiable aggregate with no local
    // signature pending behind it, so its broadcast releases with the forwarding staging
    // instead of waiting for that barrier's acknowledgement.
    assert!(
        release_after_enqueue(&retained)
            .iter()
            .any(|job| job.request().broadcast_one().is_some()),
        "the forwarding staging must release the recovered certificate"
    );
    // The exit derives in the drive that stages the forwarding it reads, so one barrier
    // carries the forwarded certificate and the transition it proves.
    let exit = retained.persist_job();
    assert!(matches!(
        exit.events()[1].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    let published = machine.persist(&exit, Until::CursorAdvance);
    assert!(
        published.capabilities().iter().all(|effect| {
            !durable_effect(effect)
                .and_then(EffectExt::broadcast_one)
                .is_some()
        }),
        "persistence must not release the staged broadcast a second time"
    );
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn vqc_aggregation_retains_exact_messages_and_exits_observer() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let proposed = leader(&machine, 1);
    let proposal_signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(1));
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(proposal_signer.get()),
        )),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let artifacts = messages
        .iter()
        .cloned()
        .map(|message| match message {
            ViewMessage::Vote(vote) => Artifact::Vote(vote),
            ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
        })
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("view messages must be verified");
    };
    let verified = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    let aggregate = verified
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let messages = aggregate.messages().collect::<Vec<_>>();
    assert_eq!(
        messages
            .iter()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
    let certificate = vqc(&machine, proposed, &messages);
    let proof = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            vqc_completion(&aggregate, certificate, machine.profile().codec()),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    // The exit derives in the drive that stages the forwarding it reads, so one barrier
    // carries the forwarded certificate and the transition it proves.
    let exit = retained.persist_job();
    assert!(matches!(
        exit.events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(_))
    ));
    assert!(matches!(
        exit.events()[1].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    machine.persist(&exit, Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn prepared_vqc_completion_requires_the_issuing_job() {
    let (mut first, _) = Harness::observer().participants(6).start();
    let (mut second, _) = Harness::observer().participants(6).start();
    let proposed = leader(&first, 1);
    let (first_job, _) = drive_unanimous_votes(&mut first, &proposed);
    let (second_job, _) = drive_unanimous_votes(&mut second, &proposed);
    assert_eq!(first_job.issued().id(), second_job.issued().id());
    assert_eq!(
        first_job.issued().generation(),
        second_job.issued().generation()
    );
    let messages = first_job.messages().collect::<Vec<_>>();
    assert_eq!(messages, second_job.messages().collect::<Vec<_>>());
    let certificate = vqc(&first, proposed, &messages);
    let codec = first.profile().codec();
    let foreign =
        VqcAggregateCompletion::prepare::<Sha256>(&second_job, certificate.clone(), codec).unwrap();
    let submitted = first
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(foreign))))
        .unwrap();
    assert_eq!(submitted.status(), &StepStatus::Accepted);
    assert!(matches!(
        first.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));
    assert!(first.views.certificate_pending(View::new(1)));

    let id = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let own = VqcAggregateCompletion::prepare::<Sha256>(&first_job, certificate, codec).unwrap();
    let submitted = first
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(own))))
        .unwrap();
    let completed = first.settle(submitted, Until::CursorAdvance);
    first.persist(&completed.persist_job(), Until::CursorAdvance);
    assert!(first.durable.state.local.contains_key(&id));
}

#[test]
fn local_vqc_emits_quorum_then_grows_to_the_full_sticky_transcript() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(
                LeaderSchedule::round_robin(6)
                    .unwrap()
                    .leader(View::new(1))
                    .get(),
            ),
        )),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let observed = machine
        .step(cohort::<Sha256, _>(
            messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("view messages must be verified together");
    };
    let verified = machine.verify(verification, true, Until::CursorAdvance);
    let first = verified
        .find(|capability| match capability {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the first quorum must aggregate promptly");
    let first_messages = first.messages().collect::<Vec<_>>();
    assert_eq!(first_messages.len(), 5);
    let mut barriers = verified;
    while let Some(job) = barriers.find(|capability| match capability {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        barriers = machine.persist(&job, Until::CursorAdvance);
    }

    let full_certificate = vqc(&machine, proposed.clone(), &messages);
    assert!(
        VqcAggregateCompletion::prepare::<Sha256>(
            &first,
            full_certificate.clone(),
            machine.profile().codec(),
        )
        .is_err()
    );
    let first_certificate = vqc(&machine, proposed, &first_messages);
    let first_id = Artifact::Vqc(first_certificate.clone()).id::<Sha256>();
    let full_id = Artifact::Vqc(full_certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &first,
                first_certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let effects = machine.drain_persisting(completed);
    let improved = effects
        .find(|capability| match capability {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the materialized quorum must schedule its strict extension");
    assert_ne!(improved.issued().id(), first.issued().id());
    assert_eq!(improved.messages().count(), 6);
    assert_eq!(machine.views.retained_vqc_transcripts(), 1);

    let improved = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &improved,
                full_certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let improved = machine.settle(improved, Until::CursorAdvance);
    machine.drain_persisting(improved);
    assert!(machine.durable.state.local.contains_key(&full_id));
    assert_eq!(machine.views.retained_vqc_transcripts(), 1);
    assert_eq!(
        machine
            .durable
            .state
            .forwarded_vqcs
            .get(&View::new(1))
            .map(|artifact| artifact.id::<Sha256>()),
        Some(first_id),
        "an improved same-view V-QC is attached to a later proposal, not forwarded twice",
    );
}

#[test]
fn invalid_earlier_message_unblocks_sticky_vqc_choice() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);

    let earlier_artifact = Artifact::NoVote(no_vote(&machine, View::new(1), 0));
    let earlier = observe(&mut machine, earlier_artifact);
    let later = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::Vote(view_vote(&machine, &proposed, 0)),
            Artifact::Vote(view_vote(&machine, &proposed, 1)),
            Artifact::Vote(view_vote(&machine, &proposed, 2)),
            Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
            Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
        ]))
        .unwrap();
    let [Capability::Verify(later)] = later.capabilities() else {
        panic!("later messages must be verified together");
    };
    let completed_later = machine.step(Input::Verified(later.all_valid())).unwrap();
    let completed_later = machine.settle(completed_later, Until::CursorAdvance);
    assert!(!completed_later.has(Capability::is_aggregate_vqc));

    let rejected_earlier = machine
        .step(Input::Verified(VerificationCompletion::new(
            earlier.issued(),
            vec![Verdict::new(earlier.items()[0].ticket(), false)],
        )))
        .unwrap();
    let rejected_earlier = machine.settle(rejected_earlier, Until::CursorAdvance);
    assert!(rejected_earlier.has(Capability::is_aggregate_vqc));
}

#[test]
fn proposal_anchor_does_not_retire_the_certificate_broadcast() {
    // A leader block anchoring a chain's newest DA certificate is not a substitute for the
    // certificate broadcast: peers never admit proposal anchors into their DA state, so
    // retiring the broadcast strands every peer that missed it. Their certified tips freeze,
    // the DA-vote window (height - certified <= pipeline depth) goes permanently false, and
    // the chain halts at exactly the pipeline limit.
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(4));
    let profile = Harness::validator(5)
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let header = produce_own_header(&mut machine);
    let certificate = symbolic_da_certificate(header.clone(), 0);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block: header.block_ref::<Sha256>(),
            certificate: certificate.clone(),
        }))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let broadcast = completed
        .find(|effect| match effect {
            Capability::Released(job) if job.request().broadcast_one().is_some() => {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the recovered certificate must broadcast");
    machine.persist(&completed.persist_job(), Until::CursorAdvance);

    // Observe the scheduled view-1 leader's block whose chain proposal anchors the
    // certificate exactly.
    let protocol = machine.profile().protocol().clone();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            let anchor = if tip.chain() == header.chain() {
                Anchor::Certificate(certificate.clone())
            } else {
                Anchor::Tip(*tip)
            };
            ChainProposal::new(
                tip.chain(),
                anchor,
                Vec::new(),
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let block = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let scheduled = protocol.leader(View::new(1));
    let artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(scheduled.get())));
    let job = observe(&mut machine, artifact);
    machine.verify(&job, true, Until::CursorAdvance);

    // Fold the publication supersession sweep to a fixed point.
    for _ in 0..8 {
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = machine.work_remaining();
        let (effects, _) = result.into_parts();
        if effects.is_empty() && !work_remaining {
            break;
        }
    }

    assert!(
        machine
            .durable
            .state
            .outbox
            .contains_key(&broadcast.issued().id()),
        "a chain's newest certificate broadcast must outlive proposals anchoring it"
    );
}

#[test]
fn vote_quorum_assembles_a_vqc_despite_a_matching_proposal_parent() {
    // A V-QC retained only as a proposal parent cannot be forwarded, and view exit requires a
    // durably forwarded exit certificate. Holding a matching parent must therefore never
    // suppress local assembly: without it the node has no exit certificate to forward and the
    // view freezes while the process stays responsive.
    let profile = Harness::validator(5).participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    machine
        .views
        .observe_sign_request(&SignRequest::NoVote { round })
        .unwrap();

    let proposed = leader(&machine, 1);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Arc::new(Artifact::Vqc(vqc(&machine, proposed.clone(), &messages)));
    machine.views.retain_vqc_parent::<Sha256>(&parent).unwrap();

    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(
                LeaderSchedule::round_robin(6)
                    .unwrap()
                    .leader(View::new(1))
                    .get(),
            ),
        )),
    );
    let facts = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, artifact) in facts.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), artifact);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = machine.settle(driven, Until::CursorAdvance);
    assert!(
        driven.has(Capability::is_aggregate_vqc),
        "a vote quorum must assemble a forwardable V-QC even when a matching parent is retained"
    );
}

#[test]
fn late_past_nullification_is_recovered_and_forwarded() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 1);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let forwarding = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));

    let shares = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(shares)] = shares.capabilities() else {
        panic!("past-view nullify shares must be verified together");
    };
    let verified = machine.step(Input::Verified(shares.all_valid())).unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    let recovery = verified
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a late past-view quorum must still be recovered");
    let certificate = symbolic_nullification(&machine, View::new(1), 0);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), certificate),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    assert!(matches!(
        retained.persist_job().events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                if certificate.round().view() == View::new(1))
    ));
}

#[test]
fn late_leader_cannot_preempt_an_earlier_nullification() {
    for leader_first in [false, true] {
        let (mut machine, _) = Harness::observer().participants(6).start();
        let proposed = leader(&machine, 1);
        let messages = machine
            .step(cohort::<Sha256, _>(vec![
                Artifact::Vote(view_vote(&machine, &proposed, 0)),
                Artifact::Vote(view_vote(&machine, &proposed, 1)),
                Artifact::Vote(view_vote(&machine, &proposed, 2)),
                Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
                Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
            ]))
            .unwrap();
        let [Capability::Verify(messages)] = messages.capabilities() else {
            panic!("view messages must be verified together");
        };
        let messages = messages.clone();
        machine.verify(&messages, true, Until::CursorAdvance);

        let nullifies = machine
            .step(cohort::<Sha256, _>(
                (0..3)
                    .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                    .collect(),
            ))
            .unwrap();
        let [Capability::Verify(nullifies)] = nullifies.capabilities() else {
            panic!("nullify shares must be verified together");
        };
        let nullifies = nullifies.clone();

        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(
                    LeaderSchedule::round_robin(6)
                        .unwrap()
                        .leader(View::new(1))
                        .get(),
                ),
            )),
        );

        let complete = |job: &VerifyJob<MinPk, Digest>| Input::Verified(job.all_valid());
        let (first, second) = if leader_first {
            (&proposal, &nullifies)
        } else {
            (&nullifies, &proposal)
        };
        let first_complete = machine.step(complete(first)).unwrap();
        let first_complete = machine.settle(first_complete, Until::CursorAdvance);
        let second_complete = machine.step(complete(second)).unwrap();
        let second_complete = machine.settle(second_complete, Until::CursorAdvance);
        let constructions = first_complete
            .capabilities()
            .iter()
            .chain(second_complete.capabilities())
            .filter_map(|effect| match effect {
                Capability::Crypto(CryptoJob::RecoverNullification(_)) => Some("nullification"),
                Capability::Crypto(CryptoJob::AggregateVqc(_)) => Some("V-QC"),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(constructions, ["nullification"]);
    }
}

#[test]
fn invalid_target_vote_does_not_poison_vqc_aggregation() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    record_view_fact(
        &mut machine,
        Observation::new(1, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );

    let protocol = machine.profile().protocol();
    let chains = protocol.codec_config().chains();
    let invalid = VoteBody::new(
        proposed.round(),
        proposed.digest::<Sha256>(),
        vec![Position::new(1); chains],
        (0..chains)
            .map(|_| Extension::new(Vec::new(), 1).unwrap())
            .collect(),
        protocol.codec_config(),
    )
    .unwrap();
    assert!(!invalid.valid_for(DigestedLeader::new::<Sha256>(&proposed)));
    let messages = [
        Artifact::Vote(Vote::new(invalid, attestation(0))),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(2, index as u32), message);
    }

    let incomplete = machine.step(Input::ProducerWake).unwrap();
    let incomplete = machine.settle(incomplete, Until::CursorAdvance);
    assert!(
        incomplete
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Crypto(CryptoJob::AggregateVqc(_))))
    );

    let later = Artifact::Vote(view_vote(&machine, &proposed, 3));
    record_view_fact(&mut machine, Observation::new(3, 0), later);
    let completed = machine.step(Input::ProducerWake).unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let aggregate = completed
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job),
            _ => None,
        })
        .expect("later valid support must complete the V-QC");
    assert!(aggregate.messages().all(|message| {
        !matches!(message, ViewMessage::Vote(vote) if vote.signer() == Participant::new(0))
    }));
}

#[test]
fn current_vqc_preempts_noncurrent_nullification_recovery() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(1));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(2), signer));
        record_view_fact(&mut machine, Observation::new(1, signer), share);
    }
    let proposed = leader(&machine, 1);
    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), message);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = machine.settle(driven, Until::CursorAdvance);
    assert!(driven.has(Capability::is_aggregate_vqc));
    assert!(!driven.has(|effect| matches!(
        effect,
        Capability::Crypto(CryptoJob::RecoverNullification(_))
    )));
}

#[test]
fn current_nullification_preempts_noncurrent_vqc_aggregation() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(1));
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    record_view_fact(
        &mut machine,
        Observation::new(1, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(2), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(2), 4)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(2, index as u32), message);
    }
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(1), signer));
        record_view_fact(&mut machine, Observation::new(3, signer), share);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = machine.settle(driven, Until::CursorAdvance);
    assert!(driven.has(|effect| matches!(
        effect,
        Capability::Crypto(CryptoJob::RecoverNullification(_))
    )));
    assert!(!driven.has(Capability::is_aggregate_vqc));
}

#[test]
fn last_voter_signature_still_publishes_its_vote() {
    // The pool holds quorum-minus-one peer votes, so the machine's own signed vote completes
    // the view certificate the instant it lands. The vote publication must still release to
    // the transport: peers holding sub-quorum pools depend on this exact vote (or on the
    // certificate forward), and eliding it silences the committee's last voters.
    let probe = Harness::observer().participants(6).profile();
    let leader_participant = probe.protocol().leader(View::new(1));
    let voter = Participant::new((leader_participant.get() + 1) % 6);
    let (mut machine, _) = Harness::builder(Role::Validator(voter))
        .participants(6)
        .start();

    let proposed = leader(&machine, 1);
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(leader_participant.get()),
        )),
    );
    let published = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&published.persist_job(), Until::CursorAdvance);

    // Quorum is five: four peer votes held, own vote pending.
    let peers = (0..6u32)
        .filter(|signer| *signer != voter.get())
        .take(4)
        .collect::<Vec<_>>();
    for signer in peers {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let verification = observe(&mut machine, artifact);
        machine.verify(&verification, true, Until::CursorAdvance);
    }
    assert_eq!(machine.inspect().view(), View::new(1));

    // The own signature lands and instantly completes the pool.
    let own = view_vote(&machine, &proposed, voter.get());
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::Vote(own.body().clone())))
        .unwrap();
    let sign = sign_job(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::Vote(own))],
        )))
        .unwrap();
    let mut step = machine.settle(signed, Until::CursorAdvance);

    // Drive persistence; the vote's broadcast publication must release before retirement.
    let mut vote_published = false;
    for _ in 0..64 {
        vote_published |= step.has(|effect| {
            matches!(
                effect,
                Capability::Released(job)
                    if matches!(job.request().broadcast_one(), Some(artifact)
                        if matches!(artifact.as_ref(), Artifact::Vote(vote)
                            if vote.signer() == voter))
            )
        });
        if vote_published {
            break;
        }
        if step.has(Capability::is_journal) {
            let job = step.persist_job();
            step = machine.persist(&job, Until::CursorAdvance);
            continue;
        }
        let before = machine.inspect().view();
        step = machine.settle(
            Step::for_tests(step.status().clone(), Vec::new(), Vec::new()),
            Until::CursorAdvance,
        );
        if machine.inspect().view() == before
            && step.capabilities().is_empty()
            && machine.inspect().view() >= View::new(2)
        {
            break;
        }
    }
    assert!(
        vote_published,
        "the last voter's vote publication was elided (view now {:?})",
        machine.inspect().view()
    );
}

#[test]
fn wire_vqc_advances_a_voted_view_without_local_quorum() {
    // The global n=10 freeze: a validator votes in the view, holds a sub-quorum message pool
    // (peers' votes lost in flight), and then receives the view's V-QC assembled elsewhere.
    // The certificate is the exit proof; the view must advance without a rescue vote.
    let probe = Harness::observer().participants(6).profile();
    let leader_participant = probe.protocol().leader(View::new(1));
    let voter = Participant::new((leader_participant.get() + 1) % 6);
    let (mut machine, _) = Harness::builder(Role::Validator(voter))
        .participants(6)
        .start();

    // Admit the view-1 proposal; the machine stages its own direct vote.
    let proposed = leader(&machine, 1);
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(leader_participant.get()),
        )),
    );
    let published = machine.verify(&verification, true, Until::CursorAdvance);
    let vote = published.persist_job();
    assert!(matches!(
        vote.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(request))
                if request.leader() == proposed.digest::<Sha256>())
    ));
    // Persisting the queued vote commits the machine's durable vote choice for the view.
    machine.persist(&vote, Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(1));

    // A sub-quorum of peer votes arrives: four held messages against a quorum of five.
    let mut peers = (0..6u32).filter(|signer| *signer != voter.get());
    let heard = [
        peers.next().unwrap(),
        peers.next().unwrap(),
        peers.next().unwrap(),
    ];
    let missing = peers.collect::<Vec<_>>();
    for signer in heard {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let verification = observe(&mut machine, artifact);
        machine.verify(&verification, true, Until::CursorAdvance);
    }
    assert_eq!(machine.inspect().view(), View::new(1));

    // The view's V-QC arrives fully assembled from the wire. Its tally includes the local
    // node's own vote: the assembler heard this node even though this node heard too few
    // peers to assemble locally.
    let messages = [voter.get(), heard[0], heard[1], heard[2], missing[0]]
        .iter()
        .map(|signer| ViewMessage::Vote(view_vote(&machine, &proposed, *signer)))
        .collect::<Vec<_>>();
    let certificate = vqc(&machine, proposed, &messages);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let mut step = machine.verify(&verification, true, Until::CursorAdvance);

    // Drive persistence until the machine exits the view on the certificate.
    for _ in 0..64 {
        if machine.inspect().view() == View::new(2) {
            return;
        }
        let job = step.has(Capability::is_journal).then(|| step.persist_job());
        step = match job {
            Some(job) => machine.persist(&job, Until::CursorAdvance),
            None => machine.settle(
                Step::for_tests(step.status().clone(), Vec::new(), Vec::new()),
                Until::CursorAdvance,
            ),
        };
    }
    panic!(
        "the wire V-QC never exited the voted view: view {:?}",
        machine.inspect().view()
    );
}

#[test]
fn inbound_vqc_requires_rescue_vote_before_view_advance() {
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let certificate = vqc(&machine, proposed.clone(), &messages);
    let proof = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let forwarding = machine.verify(&verification, true, Until::CursorAdvance);
    let staged = forwarding.persist_job();
    // Forwarding and the rescue choice derive in one drive, so one range carries both.
    assert!(matches!(
        staged.events()[0].change(),
        Change::ArtifactForwarded { .. }
    ));
    assert!(matches!(
        staged.events()[1].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(request))
                if request.leader() == proposed.digest::<Sha256>())
    ));
    assert_eq!(staged.events().len(), 2);
    // The exit is staged only behind the rescue vote, so the view is still 1 while that range
    // is the only staged work.
    assert_eq!(machine.inspect().view(), View::new(1));
    // The signing request released with the step that staged the rescue choice.
    let sign = sign_job(&forwarding);
    let released = machine.persist(&staged, Until::CursorAdvance);
    let advance = released.persist_job();
    assert!(matches!(
        advance.events()[0].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    machine.persist(&advance, Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::Vote(view_vote(&machine, &proposed, 0)))],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    machine.persist(&completed.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn timeout_signing_batch_survives_recovery_intact() {
    let profile = Harness::validator(0).participants(6).profile();
    let expected_delay = profile.tuning().view_timeout;
    let (mut machine, started) = start_profile(profile.clone());
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    machine.persist(&elapsed.persist_job(), Until::CursorAdvance);

    let snapshot = machine.live_snapshot_for_test();
    let mut restored = Machine::<Sha256, MinPk>::restore(profile, snapshot).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    assert!(recovery.has(
        |effect| matches!(effect, Capability::Timer(TimerCommand::View(timer)) if timer.delay() == expected_delay)
    ));
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(recovered.has(|effect| {
        matches!(
            durable_effect(effect).and_then(EffectExt::sign_many),
            Some(requests)
                if matches!(requests,
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));
}

#[test]
fn restore_derives_the_timeout_choice_from_durable_state() {
    let profile = Harness::validator(0).participants(6).profile();
    let (mut machine, started) = start_profile(profile.clone());
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    machine.persist(&elapsed.persist_job(), Until::CursorAdvance);

    let snapshot = machine.live_snapshot_for_test();
    let reserved = snapshot
        .signing_reservations()
        .keys()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(reserved.len(), 1);
    let config = SnapshotCodecConfig::from_profile(&profile);
    let decoded = Snapshot::<MinPk, Digest>::decode_cfg(snapshot.encode(), &config).unwrap();
    assert_eq!(decoded, snapshot);

    // The snapshot carries no view projection: restore derives the timeout choice from the
    // durable reservation and reissues exactly that reservation.
    let mut restored = Machine::<Sha256, MinPk>::restore(profile, decoded).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let reissued = recovered
        .capabilities()
        .iter()
        .filter_map(durable_job)
        .filter(|job| job.request().sign_many().is_some())
        .map(|job| job.issued().id())
        .collect::<Vec<_>>();
    assert_eq!(reissued, reserved);
}

#[test]
fn timeout_choice_recovers_at_each_durable_crash_prefix() {
    let profile = Harness::validator(0).participants(6).profile();
    let (mut machine, started) = start_profile(profile.clone());
    let before = machine.live_snapshot_for_test();
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    let timeout = elapsed.persist_job();

    let mut without_timeout =
        Machine::<Sha256, MinPk>::restore(profile.clone(), before.clone()).unwrap();
    let recovery = without_timeout.step(Input::RecoveryComplete).unwrap();
    let recovered = without_timeout.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(recovered.capabilities().iter().all(|effect| {
        !matches!(
            durable_effect(effect).and_then(EffectExt::sign_many),
            Some(requests)
                if matches!(requests,
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));

    let mut with_timeout = Machine::<Sha256, MinPk>::restore(profile, before).unwrap();
    for event in timeout.events() {
        with_timeout.replay(event.clone()).unwrap();
    }
    let recovery = with_timeout.step(Input::RecoveryComplete).unwrap();
    let recovered = with_timeout.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(recovered.has(|effect| {
        matches!(
            durable_effect(effect).and_then(EffectExt::sign_many),
            Some(requests)
                if matches!(requests,
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));
}

#[test]
fn pending_proposal_parent_survives_recovery() {
    let role = Role::Validator(LeaderSchedule::round_robin(6).unwrap().leader(View::new(2)));
    let profile = Harness::builder(role).participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());

    let nullification = symbolic_nullification(&machine, View::new(1), 0);
    let nullification = observe(&mut machine, Artifact::Nullification(nullification));
    let forwarding = machine
        .step(Input::Verified(nullification.all_valid()))
        .unwrap();
    // Stage the forwarding barrier before the parent certificate completes.
    let forwarding = machine.settle(forwarding, Until::CursorAdvance);

    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = vqc(&machine, proposed, &messages);
    let parent_id = Artifact::Vqc(parent.clone()).id::<Sha256>();
    let parent_verification = observe(&mut machine, Artifact::Vqc(parent.clone()));
    let proposal = machine.verify(&parent_verification, true, Until::CursorAdvance);

    let entered = machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));
    // Acknowledge the proposal barrier without letting the scheduler stage anything on top of
    // it, so the crash snapshot holds the reserved proposal and nothing later.
    machine.persist(&entered.persist_job(), Until::Step);
    let crashed = machine.live_snapshot_for_test();
    // The signing request released with the step that staged the proposal choice. The exit
    // derives beside the forwarding it reads, so that step is the parent's completion.
    let sign = sign_job(&proposal);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the view-two leader must reserve a proposal");
    };
    assert_eq!(request.parent().exact().map(Arc::as_ref), Some(&parent));
    assert!(request.attach_parent());
    assert!(!machine.durable.state.vqc_forwarded(View::new(1)));

    let mut restored = Machine::<Sha256, MinPk>::restore(profile, crashed).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let mut recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let recovered_sign = sign_job(&recovered);
    assert_eq!(recovered_sign.issued().id(), sign.issued().id());
    assert!(restored.inspect().ready_artifacts().contains(&parent_id));

    while let Some(job) = recovered.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        recovered = restored.persist(&job, Until::CursorAdvance);
    }
    let SignRequest::LeaderBlock(request) = sign_request(&recovered_sign) else {
        unreachable!("the recovered request was checked above");
    };
    assert!(request.attach_parent());
    restored
        .step(Input::EffectCompleted(EffectCompletion::signed(
            recovered_sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                request.block().clone(),
                attestation(
                    LeaderSchedule::round_robin(6)
                        .unwrap()
                        .leader(View::new(2))
                        .get(),
                ),
            )))],
        )))
        .unwrap();
    assert_eq!(restored.inspect().waiting_artifacts(), 0);
}

#[test]
fn outstanding_proposal_parent_survives_recovery() {
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
    let role = Role::Validator(signer);
    let profile = Harness::builder(role).participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let request = proposal_request_with_parent(&machine, View::new(2), view_one_vqc(&machine));
    let parent_id = Artifact::Vqc(
        request
            .parent()
            .exact()
            .expect("the view-two proposal must carry its exact V-QC")
            .as_ref()
            .clone(),
    )
    .id::<Sha256>();

    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            request.clone(),
        )))
        .unwrap();
    // The signing request releases with the step that stages the choice.
    let sign = sign_job(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                request.block().clone(),
                attestation(signer.get()),
            )))],
        )))
        .unwrap();
    let signed = machine.settle(signed, Until::CursorAdvance);
    let published = machine.persist(&signed.persist_job(), Until::CursorAdvance);
    let publication = published
        .find(|effect| match effect {
            Capability::Released(job) if job.request().proposal().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("the signed leader block must be published");
    let Some(proposal) = publication.request().proposal() else {
        unreachable!("the publication was selected as a proposal");
    };
    assert!(proposal.attach_parent());
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            publication.issued(),
        )))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert!(machine.durable.state.vqc_forwarded(View::new(1)));

    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(restored.inspect().ready_artifacts().contains(&parent_id));
}

#[test]
fn pending_proposal_parent_counts_against_recovery_capacity() {
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
    let role = Role::Validator(signer);
    let profile = Harness::builder(role)
        .participants(6)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(11))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(16)),
        )
        .profile();
    let (mut machine, _) = start_profile(profile);
    let request = proposal_request_with_parent(&machine, View::new(2), view_one_vqc(&machine));
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(request)))
        .unwrap();
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    for view in 3..=10 {
        let artifact = Arc::new(leader_artifact(&machine, view));
        let reserved = machine
            .reserve_test_effect(DurableEffect::broadcast(artifact))
            .unwrap();
        machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    }

    let constrained = Harness::builder(role)
        .participants(6)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(9))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(16)),
        )
        .profile();
    assert_eq!(
        snapshot_reason(Machine::<Sha256, MinPk>::restore(
            constrained,
            machine.live_snapshot_for_test()
        )),
        SnapshotReason::Bounds
    );
}

#[test]
fn timeout_cutoff_respects_verified_proposal_order() {
    for proposal_first in [false, true] {
        let profile = Harness::validator(5).participants(6).profile();
        let (mut machine, started) = start_profile(profile);
        let timer = started
            .find(|effect| match effect {
                Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
                _ => None,
            })
            .unwrap();
        let filler = Arc::new(leader_artifact(&machine, 2));
        let pending = machine
            .reserve_test_effect(DurableEffect::broadcast(filler))
            .unwrap();
        if !proposal_first {
            let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
            assert!(elapsed.capabilities().is_empty());
        }
        let proposed = leader(&machine, 1);
        let signer = machine.profile().protocol().leader(View::new(1));
        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(signer.get()))),
        );
        machine.verify(&proposal, true, Until::Step);
        if proposal_first {
            let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
            assert!(elapsed.capabilities().is_empty());
        }
        assert_eq!(machine.progress().timeout_cutoff_vote, proposal_first);
        assert_eq!(machine.progress().timeout_cutoff_timeout, !proposal_first);
        let released = machine.persist(&pending.persist_job(), Until::CursorAdvance);
        let choice = released.persist_job();
        let Change::OutboxQueued { effect, .. } = choice.events()[0].change() else {
            panic!("timeout choice must queue signing");
        };
        match effect.sign_requests() {
            Some([SignRequest::Vote(_)]) => assert!(proposal_first),
            Some([SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]) => {
                assert!(!proposal_first);
            }
            other => panic!("unexpected timeout choice: {other:?}"),
        }
        assert!(choice.events().iter().all(|event| {
            !matches!(event.change(), Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::LeaderBlock(_))))
        }));
    }
}

#[test]
fn observer_timeout_with_a_valid_proposal_never_requests_a_signature() {
    let (mut machine, started) = Harness::observer().participants(6).start();
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let proposal = leader_artifact(&machine, 1);
    let proposal = observe(&mut machine, proposal);
    machine.verify(&proposal, true, Until::CursorAdvance);

    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    assert_eq!(elapsed.status(), &StepStatus::Accepted);
    assert!(elapsed.capabilities().iter().all(|effect| {
        !matches!(effect, Capability::Journal(_))
            && !matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))
    }));
}

#[test]
fn outstanding_future_exit_certificate_survives_recovery() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let future = Artifact::Nullification(symbolic_nullification(&machine, View::new(2), 0));
    let verification = observe(&mut machine, future);
    let forwarding = machine.verify(&verification, true, Until::CursorAdvance);
    // The independently verifiable certificate releases with the forwarding staging; only a
    // locally signed subject would wait for the barrier acknowledgement.
    let broadcast = release_after_enqueue(&forwarding)
        .into_iter()
        .find(|job| job.request().broadcast_one().is_some())
        .unwrap();
    machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            broadcast.issued(),
        )))
        .unwrap();
    assert!(delivered.capabilities().is_empty());

    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);

    let current = Artifact::Nullification(symbolic_nullification(&restored, View::new(1), 0));
    let verification = observe(&mut restored, current);
    let mut step = restored.verify(&verification, true, Until::CursorAdvance);
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = restored.persist(&job, Until::CursorAdvance);
    }
    assert_eq!(restored.inspect().view(), View::new(3));
}

#[test]
fn consecutive_exit_certificates_advance_exactly_one_view_at_a_time() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let artifacts = vec![
        Artifact::Nullification(symbolic_nullification(&machine, View::new(2), 0)),
        Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 0)),
    ];
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("exit certificates must be verified together");
    };
    let step = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    let mut step = machine.settle(step, Until::CursorAdvance);
    let mut advanced = Vec::new();
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        // Staging applies the transition, so the staged view is already the new one: two
        // separate barriers stepping to view 2 then view 3 is exactly one exit per proof.
        let advances = job
            .events()
            .iter()
            .filter(|event| matches!(event.change(), Change::ViewAdvanced { .. }))
            .count();
        assert!(advances <= 1, "one barrier carries at most one exit");
        if advances == 1 {
            advanced.push(machine.inspect().view());
        }
        step = machine.persist(&job, Until::CursorAdvance);
    }
    assert_eq!(advanced, [View::new(2), View::new(3)]);
    assert_eq!(machine.inspect().view(), View::new(3));
}

#[test]
fn retained_view_history_keeps_one_typed_exit_obligation() {
    let role = Role::Observer;
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(64))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(8))
        .with_max_forwarded_certificates(NonZeroUsize::new(64).unwrap());
    let profile = Harness::builder(role)
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile.clone());

    for view in 1..=16 {
        let artifact =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, artifact);
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);

        for _ in 0..8 {
            if let Some(job) = step.find(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                _ => None,
            }) {
                step = machine.persist(&job, Until::CursorAdvance);
                continue;
            }
            break;
        }

        assert_eq!(machine.inspect().view(), View::new(view + 1));
        assert!(machine.inspect().cached_artifacts() < 64);
        assert!(!machine.durable.state.vqc_forwarded(View::new(view)));
        assert!(
            machine
                .durable
                .state
                .nullification_forwarded(View::new(view))
        );

        if view % 4 == 0 {
            let mut restored =
                Machine::restore(profile.clone(), machine.live_snapshot_for_test()).unwrap();
            let recovery = restored.step(Input::RecoveryComplete).unwrap();
            restored.persist(&recovery.persist_job(), Until::CursorAdvance);
            machine = restored;
        }
    }

    let exits = machine
        .durable
        .state
        .outbox
        .values()
        .filter_map(|entry| match (entry.publication(), entry.discharges()) {
            (Publication::Broadcast(artifacts), [discharge])
                if matches!(discharge.until(), DischargeKind::ExitReplacedAfter { .. }) =>
            {
                artifacts.first()
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].view(), Some(View::new(16)));
}

#[test]
fn forwarding_history_remains_certificate_class_specific() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let old = symbolic_nullification(&machine, View::new(1), 1);

    for view in 1..=2 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);

        loop {
            if let Some(job) = step.find(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                _ => None,
            }) {
                step = machine.persist(&job, Until::CursorAdvance);
                continue;
            }
            break;
        }
    }

    assert_eq!(machine.inspect().view(), View::new(3));
    assert!(machine.durable.state.nullification_forwarded(View::new(1)));

    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let duplicate = restored
        .step(cohort::<Sha256, _>(vec![Artifact::Nullification(old)]))
        .unwrap();
    assert!(matches!(
        duplicate.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Duplicate
    ));
    assert!(duplicate.capabilities().is_empty());

    let late_vqc = Artifact::Vqc(view_one_vqc(&restored));
    let verification = observe(&mut restored, late_vqc);
    let completed = restored.verify(&verification, true, Until::CursorAdvance);
    assert!(
        completed.has(|effect| {
            matches!(effect, Capability::Journal(PersistDirective { job, .. })
                if matches!(job.events()[0].change(), Change::ArtifactForwarded {
                    artifact,
                    ..
                } if matches!(artifact.as_ref(), Artifact::Vqc(_))))
        }),
        "late V-QC status/effects: {:?} {:?}",
        completed.status(),
        completed.capabilities(),
    );
}

#[test]
fn memory_plateaus_while_finality_stalls() {
    // Perpetual operation. A node whose finality never advances still has to bound its memory, so
    // drive far more views than the retention window and require the tracked state to stop
    // growing rather than to grow slowly.
    let retention = ViewDelta::new(4);
    let profile = Harness::observer()
        .participants(6)
        .retention(retention)
        .profile();
    let (mut machine, _) = start_profile(profile);

    let mut samples = Vec::new();
    for view in 1..=200u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        while let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) {
            step = machine.persist(&job, Until::CursorAdvance);
        }
        if view % 20 == 0 {
            samples.push(machine.inspect().cached_artifacts());
        }
    }

    let settled = samples[1];
    assert!(
        samples[1..].iter().all(|cached| *cached == settled),
        "tracked artifacts did not plateau across 200 views: {samples:?}"
    );
}

#[test]
fn authenticated_finality_is_bounded_by_the_retained_view_window() {
    let retention = ViewDelta::new(2);
    let profile = Harness::observer()
        .participants(6)
        .retention(retention)
        .profile();
    let (mut machine, _) = start_profile(profile);

    // Advance beyond the retained diagnostic window without producing finality.
    for view in 1..=8u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        while let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) {
            step = machine.persist(&job, Until::CursorAdvance);
        }
        assert_eq!(machine.inspect().view(), View::new(view + 1));
    }

    assert_eq!(machine.inspect().view(), View::new(9));
    assert_eq!(machine.inspect().finality_floor(), View::zero());

    // Old L-QCs remain valid certificates, but diagnostics retain only the configured view window.
    let certificates = (1..=8u64)
        .map(|view| {
            let proposed = leader(&machine, view);
            let votes = (0..5)
                .map(|signer| view_vote(&machine, &proposed, signer))
                .collect::<Vec<_>>();
            Artifact::Lqc(lqc(&machine, proposed, &votes))
        })
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(certificates)).unwrap();
    let [Capability::Verify(job)] = observed.capabilities() else {
        panic!("the certificate cohort must emit one verification job");
    };
    machine.verify(job, true, Until::Step);

    assert_eq!(machine.inspect().pools().len(), 2);
    assert_eq!(
        machine
            .inspect()
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .count(),
        2
    );
}

#[test]
fn omitted_parent_proposal_does_not_block_view_advance_and_retires() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(1))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 1);
    let orphan = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"omitted proposal parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let orphan = Artifact::LeaderBlock(SignedLeaderBlock::new(orphan, attestation(0)));
    let orphan_id = orphan.id::<Sha256>();
    let verification = observe(&mut machine, orphan);
    let waiting = machine.verify(&verification, true, Until::CursorAdvance);
    assert!(
        waiting
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_))))
    );
    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert_eq!(machine.dependencies.slots, 1);
    assert!(machine.store.artifacts.contains_key(&orphan_id));

    for view in 1..=2 {
        let exit = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(exit));
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        while let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) {
            step = machine.persist(&job, Until::CursorAdvance);
        }
        assert_eq!(
            machine.inspect().view(),
            View::new(view + 1),
            "the nullification for view {view} was not applied"
        );
    }

    assert_eq!(machine.inspect().view(), View::new(3));
    assert_eq!(machine.retired_view(), View::new(1));
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.dependencies.slots, 0);
    assert!(!machine.store.artifacts.contains_key(&orphan_id));
}

#[test]
fn view_retention_retires_history_while_finality_stalls() {
    // Nullified views never advance the finality floor. Retirement is keyed off the current view
    // instead, which is what keeps a node that cannot finalize bounded.
    let retention = ViewDelta::new(2);
    let profile = Harness::observer()
        .participants(6)
        .retention(retention)
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let mut resolver_prunes = Vec::new();

    for view in 1..=5u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        loop {
            resolver_prunes.extend(
                step.capabilities()
                    .iter()
                    .filter_map(|effect| match effect {
                        Capability::Resolver(ResolverCommand::Prune(through)) => Some(*through),
                        _ => None,
                    }),
            );
            let Some(job) = step.find(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                _ => None,
            }) else {
                break;
            };
            step = machine.persist(&job, Until::CursorAdvance);
        }
    }

    assert_eq!(machine.inspect().view(), View::new(6));
    assert_eq!(machine.retired_view(), View::new(3));
    assert_eq!(
        resolver_prunes,
        vec![View::new(1), View::new(2), View::new(3)]
    );
    assert_eq!(
        machine
            .durable
            .state
            .forwarded_nullifications
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![View::new(4), View::new(5)]
    );
    assert_eq!(
        machine
            .durable
            .state
            .exits
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![View::new(4), View::new(5)]
    );
    assert!(
        machine
            .durable
            .state
            .local
            .values()
            .all(|artifact| artifact.view().is_none_or(|view| view > View::new(3)))
    );

    let expected_exits = machine.views.retained_exit_proofs();

    // The retired suffix is exactly what the snapshot carries, and it restores unchanged.
    let restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    assert_eq!(restored.durable.state, machine.durable.state);
    assert_eq!(restored.views.retained_exit_proofs(), expected_exits);
}

#[test]
fn recovery_requests_first_missing_exit_after_retained_prefix() {
    let mut runner = active_driver(Role::Observer);
    for view in [1, 2, 4] {
        let proof = symbolic_nullification(runner.machine(), View::new(view), view);
        let reserved = runner
            .reserve(DurableEffect::broadcast(Arc::new(Artifact::Nullification(
                proof,
            ))))
            .unwrap();
        runner.persist(&reserved.persist_job(), Until::Step);
    }
    // Publication custody is durable before the scheduled view transitions run.
    assert_eq!(runner.inspect().view(), View::new(1));
    let recovery = runner.crash_and_restore().unwrap();
    let requests = recovery
        .capabilities()
        .iter()
        .filter_map(|capability| match capability {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        requests.iter().map(|job| job.view()).collect::<Vec<_>>(),
        vec![View::new(3)],
        "recovery must request the first hole beyond its retained exit prefix"
    );
    let request = requests[0];
    let mut persistence = SymbolicPersistence;
    let drained = runner.drain(&mut persistence, recovery.into_capabilities(), Until::Step);
    assert_eq!(runner.inspect().view(), View::new(3));
    assert!(drained.iter().all(|capability| !matches!(
        capability,
        Capability::Resolver(ResolverCommand::Cancel(job)) if *job == request
    )));

    let finalized = leader(runner.machine(), 5);
    let votes = vec![view_vote(runner.machine(), &finalized, 0)];
    let certificate = lqc(runner.machine(), finalized, &votes);
    let resolved = runner
        .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
            request.issued(),
            request.view(),
            ViewProof::Lqc(Box::new(certificate)),
        )))
        .unwrap();
    let [Capability::Verify(job)] = resolved.capabilities() else {
        panic!("the covering L-QC must be authenticated before admission");
    };
    let admitted = runner.submit(Input::Verified(job.all_valid())).unwrap();
    runner.drain(&mut persistence, admitted.into_capabilities(), Until::Step);
    assert_eq!(runner.inspect().view(), View::new(6));
    assert_eq!(runner.inspect().finality_floor(), View::new(5));
    assert_eq!(runner.inspect().resolution_jobs(), 0);
}

#[test]
fn invalid_resolved_exit_rearms_exact_want_and_accepts_retry() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let exit = recovery
        .find(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job))
                if job.view() == restored.inspect().view() =>
            {
                Some(*job)
            }
            _ => None,
        })
        .expect("recovery requests one exact exit proof");
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);

    let forged = symbolic_nullification(&restored, restored.inspect().view(), 41);
    let verifying = restored
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            exit.issued(),
            exit.view(),
            ViewProof::Nullification(Box::new(forged)),
        )))
        .unwrap();
    let verification = verifying.verify_job();
    let rejected = restored.verify(&verification, false, Until::CursorAdvance);
    assert!(
        rejected
            .has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Reject(job)) if *job == exit))
    );
    let retry = rejected
        .find(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job)) if job.view() == exit.view() => {
                Some(*job)
            }
            _ => None,
        })
        .expect("the still-needed exit want must be re-armed immediately");
    assert_ne!(retry.issued().id(), exit.issued().id());

    let authentic = symbolic_nullification(&restored, restored.inspect().view(), 42);
    let verifying = restored
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            retry.issued(),
            retry.view(),
            ViewProof::Nullification(Box::new(authentic)),
        )))
        .unwrap();
    let verification = verifying.verify_job();
    let admitted = restored.verify(&verification, true, Until::CursorAdvance);
    restored.drain_persisting(admitted);

    assert_eq!(restored.inspect().view(), View::new(2));
    assert_eq!(
        restored.inspect().resolution_jobs(),
        0,
        "the exact exit is complete and a floor within the horizon opens no probe"
    );
}

#[test]
fn vqc_forwarding_waits_for_the_earliest_observation_cohort() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let early_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let later_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let early = vqc(&machine, proposed.clone(), &early_messages);
    let later = vqc(&machine, proposed, &later_messages);
    let early_job = observe(&mut machine, Artifact::Vqc(early.clone()));
    let later_job = observe(&mut machine, Artifact::Vqc(later));

    let later_first = machine
        .step(Input::Verified(later_job.all_valid()))
        .unwrap();
    let later_first = machine.settle(later_first, Until::CursorAdvance);
    assert!(!later_first.has(Capability::is_journal));

    let selected = machine
        .step(Input::Verified(early_job.all_valid()))
        .unwrap();
    let selected = machine.settle(selected, Until::CursorAdvance);
    let forwarding = selected.persist_job();
    let Change::ArtifactForwarded { artifact, .. } = forwarding.events()[0].change() else {
        panic!("the earliest observation cohort must determine forwarding");
    };
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(certificate) if certificate == &early));

    // Forwarding remains one structurally fenced persistence command even though the exit it
    // proves is staged into the same range.
    let directive = selected.persist_directive();
    assert_eq!(directive.job.id(), forwarding.id());
    let [released] = directive.release_after_enqueue.as_slice() else {
        panic!("the persistence command must carry its one post-enqueue publication");
    };
    assert!(matches!(
        released.request().broadcast_one(),
        Some(forwarded) if forwarded == artifact
    ));
}

#[test]
fn cross_class_exit_selection_is_completion_order_independent() {
    for nullification_first in [false, true] {
        let profile = Harness::validator(0).participants(6).profile();
        let (mut machine, _) = start_profile(profile.clone());
        let proposed = leader(&machine, 1);
        let messages = vec![
            ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
            ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
            ViewMessage::Vote(view_vote(&machine, &proposed, 3)),
            ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
            ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
        ];
        let vqc = vqc(&machine, proposed.clone(), &messages);
        let vqc_job = observe(&mut machine, Artifact::Vqc(vqc));
        let certificate = symbolic_nullification(&machine, View::new(1), 0);
        let nullification_job = observe(&mut machine, Artifact::Nullification(certificate));
        let complete = |job: &VerifyJob<MinPk, Digest>| Input::Verified(job.all_valid());

        let selected = if nullification_first {
            let later = machine.step(complete(&nullification_job)).unwrap();
            let later = machine.settle(later, Until::CursorAdvance);
            assert!(
                later
                    .capabilities()
                    .iter()
                    .all(|effect| !matches!(effect, Capability::Journal(_)))
            );
            machine.step(complete(&vqc_job)).unwrap()
        } else {
            machine.step(complete(&vqc_job)).unwrap()
        };
        let selected = machine.settle(selected, Until::CursorAdvance);
        let forwarding = selected.persist_job();
        assert!(matches!(
            forwarding.events()[0].change(),
            Change::ArtifactForwarded { artifact, .. }
                if matches!(artifact.as_ref(), Artifact::Vqc(_))
        ));
        // The exit derivation reads the forwarding fact staged beside it, so one barrier
        // carries the forwarded certificate and the vote it rescues.
        assert!(matches!(
            forwarding.events()[1].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(request))
                    if request.leader() == proposed.digest::<Sha256>())
        ));
        // Snapshot the instant that barrier lands so recovery has to reissue the rescued vote
        // from its recovered reservation.
        machine.persist(&forwarding, Until::Step);
        let crashed = machine.live_snapshot_for_test();

        let mut restored = Machine::<Sha256, MinPk>::restore(profile, crashed).unwrap();
        let recovery = restored.step(Input::RecoveryComplete).unwrap();
        let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
        assert!(recovered.has(|effect| matches!(
            durable_effect(effect).and_then(EffectExt::sign_one),
            Some(SignRequest::Vote(request))
                if request.leader() == proposed.digest::<Sha256>()
        )));
    }
}

#[test]
fn earlier_unverified_vqc_claim_blocks_later_local_nullification() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let _pending_vqc = observe(&mut machine, Artifact::Vqc(certificate));

    let shares = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(shares)] = shares.capabilities() else {
        panic!("nullify shares must be verified together");
    };
    let completed = machine.step(Input::Verified(shares.all_valid())).unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    assert!(completed.capabilities().iter().all(|effect| {
        !matches!(
            effect,
            Capability::Crypto(CryptoJob::RecoverNullification(_)) | Capability::Journal(_)
        )
    }));
}
