//! L-QC floor and floor-pull tests.

use super::fixtures::{
    Harness, TestMachine, assert_lqc_floors_restore, attestation, digest, drive_unanimous_votes,
    durable_effect, leader, leader_extending_view_one_vqc, lqc, no_vote, observe, queued_effect_id,
    self_certifying_view_proofs, start_profile, symbolic_nullification, view_one_vqc, view_vote,
    vqc, vqc_completion,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::LeaderSchedule,
        machine::{
            capability::{Capability, CryptoJob, ResolverCommand, TimerCommand},
            durability::{Change, DurableEffect, SignEffect, SignRequest},
            finality::LqcAggregateCompletion,
            input::{CryptoCompletion, Input},
            reducer::machine::Machine,
            resolution::ResolutionCompletion,
            testing::{CapabilitiesExt as _, Drive as _, EffectExt, MachineExt as _, Until},
            verification::Observation,
            view::VqcAggregateCompletion,
        },
        types::{
            Activity, Artifact, ChainId, LeaderBlock, SignedLeaderBlock, TransactionBlockHeader,
            ViewMessage, ViewProof,
        },
    },
    types::{Height, Round, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn future_lqc_durably_advances_consensus_floors() {
    let profile = Harness::validator(3).participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let before = machine.live_snapshot_for_test();

    let genesis = machine.profile().protocol().genesis().tips()[3];
    let transaction = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(3),
        Height::new(1),
        genesis.digest(),
        digest(b"pending transaction"),
    )
    .unwrap();
    let transaction = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::TransactionBlock(
            transaction,
        )))
        .unwrap();
    let transaction_id = queued_effect_id(&transaction);
    machine.persist(&transaction.persist_job(), Until::CursorAdvance);

    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    let pending = machine
        .reserve_test_effect(DurableEffect::Sign(SignEffect::new(
            vec![
                SignRequest::NoVote { round },
                SignRequest::Nullify { round },
            ]
            .into(),
        )))
        .unwrap();
    let pending_id = queued_effect_id(&pending);
    machine.persist(&pending.persist_job(), Until::CursorAdvance);

    let finalized = leader(&machine, 5);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(advanced);

    assert_eq!(machine.inspect().view(), View::new(6));
    assert!(
        !machine
            .live_snapshot_for_test()
            .signing_reservations()
            .contains_key(&pending_id)
    );
    assert!(
        machine
            .live_snapshot_for_test()
            .signing_reservations()
            .contains_key(&transaction_id)
    );
    assert_eq!(
        machine.live_snapshot_for_test().certified_tips(),
        before.certified_tips()
    );
    assert_eq!(
        machine.live_snapshot_for_test().da_safety_heights(),
        before.da_safety_heights()
    );
    assert!(effects.iter().any(|effect| {
        matches!(effect, Capability::Timer(TimerCommand::View(timer)) if timer.round().view() == View::new(6))
    }));
    assert!(
        effects.iter().any(|effect| {
            matches!(
                durable_effect(effect).and_then(EffectExt::broadcast_one),
                Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::Vqc(derived)
                        if certificate.equivalent_vqc(derived))
            )
        }),
        "an inbound L-QC must forward its derivable V-QC before leaving the view"
    );

    assert!(matches!(machine.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(anchor))
            if anchor.leader() == certificate.leader()
                && anchor.tally() == certificate.tally()
                && anchor.novoters().count() == 0
                && anchor.conflicting_votes().is_empty()));
    assert_eq!(machine.inspect().finality_floor(), certificate.view());

    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.inspect().finality_floor(), certificate.view());
    assert!(matches!(restored.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(restored.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
    assert_eq!(
        restored.live_snapshot_for_test().certified_tips(),
        before.certified_tips()
    );
    assert_eq!(
        restored.live_snapshot_for_test().da_safety_heights(),
        before.da_safety_heights()
    );
}

#[test]
fn future_lqc_advances_signing_and_proposal_floors_without_resolution_and_restores() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    assert_lqc_floors_restore(&mut machine);
}

#[test]
fn late_lqc_advances_signing_and_proposal_floors_without_resolution_and_restores() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    for view in 1..=5 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);
    }

    assert_lqc_floors_restore(&mut machine);
}

#[test]
fn verified_lqc_beyond_diagnostic_retention_advances_consensus_floors() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    for view in 1..=8 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);
    }
    assert_eq!(machine.inspect().view(), View::new(9));
    assert!(machine.retention_floor() > View::new(3));

    let finalized = leader(&machine, 3);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);

    assert_eq!(machine.inspect().view(), View::new(9));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_))))
    );
    assert_eq!(machine.inspect().finality_floor(), certificate.view());
    assert!(matches!(machine.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
}

#[test]
fn late_finality_admissions_retain_only_the_highest_proof_without_parents() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    for view in 1..=8 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);
    }
    let retained_parents = machine.views.retained_parents();

    for view in [3, 4, 5, 5, 4] {
        let finalized = leader(&machine, view);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &finalized, signer))
            .collect::<Vec<_>>();
        let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));
        machine
            .apply_finality(Observation::new(view, 0), proof, None)
            .unwrap();
    }

    assert_eq!(machine.finality.retained_finality_proofs(), 1);
    assert_eq!(machine.views.retained_parents(), retained_parents);
    assert!(matches!(
        machine.next_finality_floor_change(),
        Some(Change::FinalityFloorAdvanced { proof, .. })
            if proof.view() == Some(View::new(5))
    ));
}

#[test]
fn lqc_released_by_retirement_keeps_its_leader_parent() {
    // Retention two retires every view at or below `view - 3`.
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let owner = machine.profile().protocol().leader(View::new(2));
    assert_eq!(machine.profile().protocol().leader(View::new(8)), owner);
    let admit = |machine: &mut TestMachine, artifact| {
        let verification = observe(machine, artifact);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted)
    };

    // The view-one V-QC is a proposal parent kept alive only by the view-two leader extending
    // it, and the view-three V-QC raises the anchor above it.
    let parent = view_one_vqc(&machine);
    let (extending, _) = leader_extending_view_one_vqc(&machine, 2, &parent);
    let extending =
        Artifact::LeaderBlock(SignedLeaderBlock::new(extending, attestation(owner.get())));
    let nullification = Artifact::Nullification(symbolic_nullification(&machine, View::new(2), 2));
    let [_, anchor, _] = self_certifying_view_proofs(&machine, View::new(3));
    for artifact in [
        Artifact::Vqc(parent.clone()),
        extending,
        nullification,
        anchor,
    ] {
        admit(&mut machine, artifact);
    }
    assert_eq!(machine.inspect().view(), View::new(4));

    // An unverified view-two equivocation holds the owner's finality queue, so a view-eight
    // L-QC for a leader extending the same parent waits behind it.
    let equivocation = Artifact::LeaderBlock(SignedLeaderBlock::new(
        leader(&machine, 2),
        attestation(owner.get()),
    ));
    let _pending = observe(&mut machine, equivocation);
    let (finalized, history) = leader_extending_view_one_vqc(&machine, 8, &parent);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, finalized.clone(), &votes));
    admit(&mut machine, certificate);
    assert!(machine.views.leader_history::<Sha256>(&finalized).is_ok());

    // Leaving view four retires view two, which drops the only live leader extending the parent
    // and releases the queued L-QC in the same pass. The released leader must keep the parent,
    // since its history acceptance and proposal validation read it, until the finality floor
    // the L-QC raises retires both.
    let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(4), 4));
    let verification = observe(&mut machine, exit);
    machine.verify(&verification, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(5));
    assert_eq!(machine.inspect().finality_floor(), View::zero());
    assert_eq!(
        machine
            .views
            .leader_history::<Sha256>(&finalized)
            .unwrap()
            .commitment::<Sha256>(),
        history
    );
}

#[test]
fn parent_retirement_preserves_history_for_a_retained_leader() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let parent = view_one_vqc(&machine);
    let verification = observe(&mut machine, Artifact::Vqc(parent.clone()));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);

    let (leader, history) = leader_extending_view_one_vqc(&machine, 2, &parent);
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            leader.clone(),
            attestation(signer.get()),
        )),
    );
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);

    machine.views.retire_parents_through(View::new(2), None);
    assert_eq!(
        machine
            .views
            .leader_history::<Sha256>(&leader)
            .unwrap()
            .commitment::<Sha256>(),
        history
    );

    let parent_id = parent.id::<Sha256>();
    machine.views.retire_transitions_through(View::new(2));
    assert!(
        machine
            .views
            .retire_parents_through(View::new(1), None)
            .is_empty()
    );
    assert!(
        machine
            .views
            .retire_parents_through(View::new(2), Some(parent_id))
            .is_empty()
    );
    assert_eq!(
        machine.views.retire_parents_through(View::new(2), None),
        [parent_id]
    );
    assert!(machine.views.leader_history::<Sha256>(&leader).is_err());
    assert_eq!(machine.views.retained_parents(), 1);
    assert!(
        machine
            .views
            .retire_parents_through(View::zero(), None)
            .is_empty()
    );
}

#[test]
fn successive_lqc_floors_retain_only_the_latest_proposal_parent() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    for view in [5, 10, 15] {
        let finalized = leader(&machine, view);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &finalized, signer))
            .collect::<Vec<_>>();
        let certificate = lqc(&machine, finalized, &votes);
        let verification = observe(&mut machine, Artifact::Lqc(certificate));
        let advanced = machine.verify(&verification, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(advanced);
        assert!(
            effects
                .iter()
                .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_))))
        );
        assert_eq!(machine.finality.retained_finality_proofs(), 0);
        assert_eq!(machine.views.retained_forwarded_vqcs(), 1);
    }

    assert_eq!(machine.inspect().view(), View::new(16));
    assert_eq!(machine.inspect().finality_floor(), View::new(15));
    assert_eq!(machine.views.retained_parents(), 2);
}

#[test]
fn ordinary_view_progress_does_not_arm_recovery_pulls() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let first = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &first, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, first, &votes);
    let derived = certificate.derive_vqc(machine.profile().codec()).unwrap();
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let mut effects = machine.drain_persisting(admitted);

    let template = leader(&machine, 2);
    let second = LeaderBlock::new(
        template.round(),
        derived.id::<Sha256>(),
        derived.leader().history(),
        template.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &second, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, second, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    effects.extend(machine.drain_persisting(admitted));

    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
        "ordinary view progress must not enter the recovery network path"
    );
}

#[test]
fn floor_pull_retries_once_per_view_until_lqc_advances_the_floor() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    let first = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &first, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, first, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);
    assert_eq!(machine.inspect().view(), View::new(2));
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));

    // Finality trails the view by a few views in healthy operation, so the pull waits until the
    // floor lags by more than the future-view horizon.
    let horizon = machine.profile.resources().max_future_view_distance();
    let exit = symbolic_nullification(&machine, View::new(2), 2);
    let mut last_view = 2;
    for view in 2..=horizon {
        let nullification = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(nullification));
        let advanced = machine.verify(&verification, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(advanced);
        last_view = view + 1;
        assert_eq!(machine.inspect().view(), View::new(last_view));
        assert!(
            effects
                .iter()
                .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
            "a floor within the horizon does not pull"
        );
    }
    let nullification = symbolic_nullification(&machine, View::new(last_view), last_view);
    let verification = observe(&mut machine, Artifact::Nullification(nullification));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(advanced);
    last_view += 1;
    assert_eq!(machine.inspect().view(), View::new(last_view));
    let pulls = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(pulls.len(), 1);
    let floor_pull = pulls[0];
    assert_eq!(floor_pull.view(), View::new(2));
    assert_eq!(machine.inspect().resolution_jobs(), 1);

    let completed = machine
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            floor_pull.issued(),
            floor_pull.view(),
            ViewProof::Nullification(Box::new(exit)),
        )))
        .unwrap();
    let effects = machine.drain_persisting(completed);
    assert!(
        effects.has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Cancel(job)) if *job == floor_pull))
    );
    assert!(
        effects.iter().all(
            |effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(job)) if job.view() == floor_pull.view())
        )
    );
    assert_eq!(machine.inspect().resolution_jobs(), 0);

    let next_exit = symbolic_nullification(&machine, View::new(last_view), last_view);
    let verification = observe(&mut machine, Artifact::Nullification(next_exit));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(advanced);
    assert_eq!(machine.inspect().view(), View::new(last_view + 1));
    let rearmed = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job))
                if job.view() == floor_pull.view() =>
            {
                Some(*job)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rearmed.len(), 1);
    assert_ne!(rearmed[0].issued().id(), floor_pull.issued().id());
    assert_eq!(machine.inspect().resolution_jobs(), 1);

    let second = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &second, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, second, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);
    assert!(
        effects.has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Cancel(job)) if *job == rearmed[0]))
    );
    assert!(
        effects.iter().all(
            |effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(job)) if job.view() == floor_pull.view())
        )
    );
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(2)
    ));
    assert_eq!(machine.inspect().resolution_jobs(), 0);
}

#[test]
fn idle_vqc_progress_does_not_wait_for_persistence() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let (aggregate, _) = drive_unanimous_votes(&mut machine, &proposed);
    assert!(!machine.scheduler.has_work());
    assert!(machine.pipeline.staged.is_empty());
    let acknowledged = machine.pipeline.acked;

    let messages = aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, aggregate.leader().clone(), &messages);
    let certificate_id = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            vqc_completion(&aggregate, certificate, machine.profile().codec()),
        ))))
        .unwrap();
    assert!(completed.capabilities().is_empty());

    // An observer has no fresh signatures to force a sync. Polling supplies neither journal
    // acknowledgements nor external inputs that could wake otherwise stranded view work.
    let mut directives = Vec::new();
    for _ in 0..64 {
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = machine.work_remaining();
        for capability in result.into_capabilities() {
            if let Capability::Journal(directive) = capability {
                directives.push(directive);
            }
        }
        if !work_remaining {
            break;
        }
    }
    assert!(!machine.scheduler.has_work());
    assert_eq!(machine.pipeline.acked, acknowledged);
    assert_eq!(
        machine.inspect().view(),
        View::new(2),
        "an admitted V-QC must wake the view without a durability acknowledgement"
    );
    assert!(directives.iter().all(|directive| !directive.job.urgent()));
    assert!(
        directives.into_iter().any(|directive| {
            directive.release_after_enqueue.iter().any(|job| {
                matches!(job.request().broadcast_one(), Some(artifact)
                if artifact.id::<Sha256>() == certificate_id)
            })
        }),
        "forwarding must reach journal enqueue without acknowledging the certificate record"
    );
}

#[test]
fn aggregated_lqc_is_retained_without_a_publication() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 1);
    let (_, aggregate) = drive_unanimous_votes(&mut machine, &proposed);

    let votes = aggregate.votes().cloned().collect::<Vec<_>>();
    let certificate = lqc(&machine, aggregate.leader().clone(), &votes);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                certificate.clone(),
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let job = completed.persist_job();
    assert!(
        job.events().iter().any(|event| matches!(
            event.change(),
            Change::ViewCertificateCreated { artifact }
                if artifact.as_ref() == &Artifact::Lqc(certificate.clone())
        )),
        "the aggregate is journaled as a retained certificate"
    );
    assert!(
        job.events()
            .iter()
            .all(|event| event.change().queued_effect().is_none()),
        "retaining an aggregate must not queue a publication"
    );

    assert!(
        completed.has(|capability| {
            matches!(capability, Capability::Retain(artifact)
            if artifact.as_ref() == &Artifact::Lqc(certificate.clone()))
        }),
        "a locally assembled proof is servable before its reconstructible metadata is synced"
    );
    let persisted = machine.persist(&job, Until::CursorAdvance);
    for step in [&completed, &persisted] {
        assert!(
            step.capabilities().iter().all(|effect| !matches!(
                durable_effect(effect).and_then(EffectExt::broadcast_one),
                Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::Lqc(_))
            )),
            "no aggregate leaves the process as a publication"
        );
    }
    assert!(
        machine
            .durable
            .state
            .outbox
            .values()
            .all(|effect| !matches!(
                effect.broadcast_one(),
                Some(artifact) if matches!(artifact.as_ref(), Artifact::Lqc(_))
            )),
        "no aggregate occupies a publication slot"
    );
    assert!(
        machine.durable.state.local.values().any(
            |artifact| matches!(artifact.as_ref(), Artifact::Lqc(held) if held == &certificate)
        ),
        "the aggregate stays durable so local finality and peer requests both read it"
    );
}

#[test]
fn local_finality_suppresses_the_floor_pull() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 1);
    let (view_aggregate, aggregate) = drive_unanimous_votes(&mut machine, &proposed);

    // Leave view 1 on its own view certificate while the finality aggregate is still assembling.
    let messages = view_aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, view_aggregate.leader().clone(), &messages);
    let exited = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &view_aggregate,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let effects = machine.drain_persisting(exited);
    assert_eq!(machine.inspect().view(), View::new(2));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
        "a pool that already reached finality settles the view without a peer request"
    );
    assert_eq!(machine.inspect().resolution_jobs(), 0);

    let votes = aggregate.votes().cloned().collect::<Vec<_>>();
    let finality = lqc(&machine, aggregate.leader().clone(), &votes);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                finality,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let effects = machine.drain_persisting(completed);
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
        "the local aggregate raises the floor without a peer request"
    );
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));
    assert_eq!(machine.inspect().resolution_jobs(), 0);
}

#[test]
fn an_exit_above_the_current_view_pulls_a_covering_lqc() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    // The committee left views whose exit proofs peers have already retired, so nothing this
    // node can receive advances it one view at a time.
    let ahead = symbolic_nullification(&machine, View::new(5), 5);
    let verification = observe(&mut machine, Artifact::Nullification(ahead));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);
    assert_eq!(machine.inspect().view(), View::new(1));
    assert!(machine.durable.state.nullification_forwarded(View::new(5)));
    let pulls = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(pulls.len(), 1, "a stranded view asks for a covering L-QC");
    assert_eq!(pulls[0].view(), View::new(1));

    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let resolved = machine
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            pulls[0].issued(),
            pulls[0].view(),
            ViewProof::Lqc(Box::new(certificate.clone())),
        )))
        .unwrap();
    let [Capability::Verify(job)] = resolved.capabilities() else {
        panic!("a resolved certificate is authenticated before admission");
    };
    let job = job.clone();
    let admitted = machine.verify(&job, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(floor)) if floor == &certificate
    ));
    assert_eq!(machine.inspect().view(), View::new(2));
    assert!(
        effects.has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Cancel(job)) if *job == pulls[0])
        ),
        "the covering certificate retires the request it answered"
    );

    // Still short of the exit it holds, so the walk continues at the next gap rather than
    // opening a second request for the view it just settled.
    let rearmed = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rearmed.len(), 1);
    assert_eq!(rearmed[0].view(), View::new(2));
    assert_eq!(machine.inspect().resolution_jobs(), 1);
}

#[test]
fn floor_pull_accepts_a_resolved_lqc() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    // Leaving views on nullifications settles no leader, so the floor stays at zero; once the
    // view is more than the future-view horizon past it, the machine asks for the L-QC.
    let horizon = machine.profile.resources().max_future_view_distance();
    for view in 1..horizon {
        let exit = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(exit));
        let advanced = machine.verify(&verification, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(advanced);
        assert!(
            effects
                .iter()
                .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_)))),
            "a floor within the horizon does not pull"
        );
    }
    let exit = symbolic_nullification(&machine, View::new(horizon), horizon);
    let verification = observe(&mut machine, Artifact::Nullification(exit));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(advanced);
    assert_eq!(machine.inspect().view(), View::new(horizon + 1));
    let pulls = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(pulls.len(), 1, "entering a later view asks for the L-QC");
    let pull = pulls[0];
    assert_eq!(pull.view(), View::new(1));
    assert_eq!(machine.inspect().resolution_jobs(), 1);

    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let resolved = machine
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            pull.issued(),
            pull.view(),
            ViewProof::Lqc(Box::new(certificate.clone())),
        )))
        .unwrap();
    let [Capability::Verify(job)] = resolved.capabilities() else {
        panic!("a resolved certificate is authenticated before admission");
    };
    let job = job.clone();
    let admitted = machine.verify(&job, true, Until::CursorAdvance);
    let accepted = admitted.activities().iter().any(|activity| {
        matches!(activity, Activity::ProtocolAccepted { artifact, .. }
            if artifact.as_ref() == &Artifact::Lqc(certificate.clone()))
    });
    let effects = machine.drain_persisting(admitted);
    assert!(
        accepted,
        "a resolved certificate reaches the marshal like a received one"
    );
    assert!(
        effects.has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Cancel(job)) if *job == pull)
        ),
        "the resolved certificate retires its own request"
    );
    assert_eq!(machine.inspect().resolution_jobs(), 0);
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(floor)) if floor == &certificate
    ));
}

#[test]
fn late_lqc_advances_the_signing_floor_after_the_view_exits() {
    let (mut machine, _) = Harness::observer().participants(6).start();
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
    let mut vqc_job = None;
    let mut lqc_job = None;
    for signer in 0..5 {
        let vote = view_vote(&machine, &proposed, signer);
        let observed = observe(&mut machine, Artifact::Vote(vote));
        let step = machine.verify(&observed, true, Until::CursorAdvance);
        if signer == 4 {
            let effects = machine.drain_persisting(step);
            for effect in effects.iter() {
                match effect {
                    Capability::Crypto(CryptoJob::AggregateVqc(job)) => vqc_job = Some(job.clone()),
                    Capability::Crypto(CryptoJob::AggregateLqc(job)) => lqc_job = Some(job.clone()),
                    _ => {}
                }
            }
        }
    }
    let vqc_job = vqc_job.expect("the full quorum must schedule V-QC assembly");
    let lqc_job = lqc_job.expect("the full quorum must schedule L-QC assembly");

    // The view exits through the assembled V-QC before the L-QC aggregation completes, which
    // is the ordinary order outside inline-crypto tests: the same quorum that finalizes the
    // leader also exits the view, and the finality aggregation finishes strictly later.
    let messages = vqc_job.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, vqc_job.leader().clone(), &messages);
    let exited = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &vqc_job,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    machine.drain_persisting(exited);
    assert_eq!(machine.inspect().view(), View::new(2));

    // The late L-QC must still advance the signing floor; the view and its timer stay where
    // the ordinary exit put them.
    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let step = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &lqc_job,
                assembled,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    machine.drain_persisting(step);
    assert!(
        matches!(
            machine.signing_floor(),
            Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
        ),
        "the late L-QC must set the signing floor"
    );
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn late_old_view_vote_assembles_lqc_after_view_advance() {
    let (mut machine, _) = Harness::observer().participants(6).start();
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

    let mut messages = (0..4)
        .map(|signer| ViewMessage::Vote(view_vote(&machine, &proposed, signer)))
        .collect::<Vec<_>>();
    messages.push(ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)));
    let mut effects = None;
    for (index, message) in messages.iter().enumerate() {
        let artifact = match message {
            ViewMessage::Vote(vote) => Artifact::Vote(vote.clone()),
            ViewMessage::NoVote(no_vote) => Artifact::NoVote(no_vote.clone()),
        };
        let verification = observe(&mut machine, artifact);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        if index + 1 == messages.len() {
            effects = Some(machine.drain_persisting(admitted));
        }
    }

    let effects = effects.expect("the last view message must drive certificate assembly");
    let vqc_job = effects
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("four votes and one novote must assemble a V-QC");
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Crypto(CryptoJob::AggregateLqc(_)))),
        "four votes must remain below the L-QC threshold"
    );

    let certificate = vqc(&machine, proposed.clone(), &messages);
    let advanced = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &vqc_job,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    machine.drain_persisting(advanced);
    assert_eq!(machine.inspect().view(), View::new(2));

    let late_vote = Artifact::Vote(view_vote(&machine, &proposed, 4));
    let late = observe(&mut machine, late_vote);
    let admitted = machine.verify(&late, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);
    let lqc_job = effects
        .aggregate_lqc()
        .expect("the late fifth vote must complete the retained finality pool");

    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &lqc_job,
                assembled,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    machine.drain_persisting(completed);

    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));
    assert_eq!(machine.inspect().view(), View::new(2));
}
