//! Local certificate origin and forwarding tests.

use super::fixtures::{
    Harness, attestation, leader, no_vote, nullify, observe, sign_job, sign_request, start_profile,
    symbolic_nullification, view_vote, vqc, vqc_completion,
};
use crate::{
    multimmit::{
        config::{LeaderSchedule, Role},
        machine::{
            capability::{Capability, CryptoJob},
            durability::{Change, DischargeKind, EffectCompletion, PersistDirective, SignRequest},
            input::{CryptoCompletion, Input, StepError, StepStatus},
            reducer::machine::Machine,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, Until, VerifyJobExt as _,
                cohort,
            },
            verification::{Verdict, VerificationCompletion},
            view::{NullificationRecoveryCompletion, VqcAggregateCompletion},
        },
        types::{Artifact, SignedLeaderBlock, ViewMessage},
    },
    types::View,
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn local_vqc_survives_a_crash_before_forwarding() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
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

    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let observed_messages = machine
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
    let [Capability::Verify(observed_messages)] = observed_messages.capabilities() else {
        panic!("view messages must be verified together");
    };
    let observed_nullifies = machine
        .step(cohort::<Sha256, _>(
            (1..4)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(observed_nullifies)] = observed_nullifies.capabilities() else {
        panic!("nullify shares must be verified together");
    };

    let later_completed = machine
        .step(Input::Verified(observed_nullifies.all_valid()))
        .unwrap();
    let later_completed = machine.settle(later_completed, Until::CursorAdvance);
    assert!(
        later_completed
            .capabilities()
            .iter()
            .all(|effect| !matches!(
                effect,
                Capability::Crypto(CryptoJob::RecoverNullification(_))
            ))
    );

    let earlier_completed = machine
        .step(Input::Verified(observed_messages.all_valid()))
        .unwrap();
    let earlier_completed = machine.settle(earlier_completed, Until::CursorAdvance);
    let aggregate = earlier_completed
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the earlier V-QC quorum must win the exit frontier");
    let selected = aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, proposed, &selected);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            vqc_completion(&aggregate, certificate, machine.profile().codec()),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let acknowledged = machine.persist(&completed.persist_job(), Until::Step);
    // Crash between the retention barrier and the forwarding the scheduler is about to stage.
    let crashed = machine.live_snapshot_for_test();
    let retained = machine.settle(acknowledged, Until::CursorAdvance);
    assert!(matches!(
        retained.persist_job().events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(_))
    ));

    let mut restored = Machine::<Sha256, MinPk>::restore(profile, crashed).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let forwarding = recovered.persist_job();
    assert!(matches!(
        forwarding.events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(_))
    ));
}

#[test]
fn forwarding_one_certificate_class_does_not_suppress_the_other() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let view = View::new(2);
    let certificate = symbolic_nullification(&machine, view, 0);
    let nullification_job = observe(&mut machine, Artifact::Nullification(certificate));
    let nullification_ready = machine.verify(&nullification_job, true, Until::CursorAdvance);
    let nullification_forwarding = nullification_ready.persist_job();
    let Change::ArtifactForwarded {
        publication: nullification_publication,
        retired_publications: retired,
        artifact,
    } = nullification_forwarding.events()[0].change()
    else {
        panic!("the nullification must be forwarded");
    };
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::Nullification(_)));
    machine.persist(&nullification_forwarding, Until::CursorAdvance);

    let proposed = leader(&machine, 2);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, view, 3)),
        ViewMessage::NoVote(no_vote(&machine, view, 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let vqc_job = observe(&mut machine, Artifact::Vqc(certificate));
    let vqc_ready = machine.verify(&vqc_job, true, Until::CursorAdvance);
    let forwarding = vqc_ready.persist_job();
    let Change::ArtifactForwarded {
        publication: vqc_publication,
        retired_publications: retired,
        artifact,
    } = forwarding.events()[0].change()
    else {
        panic!("the V-QC must be forwarded");
    };
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(_)));
    machine.persist(&forwarding, Until::CursorAdvance);

    let snapshot = machine.live_snapshot_for_test();
    assert!(snapshot.outbox().contains_key(nullification_publication));
    assert!(snapshot.outbox().contains_key(vqc_publication));
    let exits = snapshot
        .outbox()
        .iter()
        .filter(|(_, entry)| {
            entry
                .discharges()
                .iter()
                .any(|discharge| discharge.until() == DischargeKind::ExitReplacedAfter { view })
        })
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    assert_eq!(exits, vec![nullification_publication, vqc_publication]);

    let restored = Machine::<Sha256, MinPk>::restore(profile, snapshot).unwrap();
    assert!(
        restored
            .live_snapshot_for_test()
            .outbox()
            .contains_key(nullification_publication)
    );
    assert!(
        restored
            .live_snapshot_for_test()
            .outbox()
            .contains_key(vqc_publication)
    );

    let successor = Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(view.get() + 1),
        1,
    ));
    let successor = observe(&mut machine, successor);
    let successor = machine.verify(&successor, true, Until::CursorAdvance);
    let successor = successor.persist_job();
    let Change::ArtifactForwarded {
        publication: successor_publication,
        retired_publications: retired,
        ..
    } = successor.events()[0].change()
    else {
        panic!("the next-view exit must be forwarded");
    };
    assert_eq!(
        retired.as_slice(),
        [*nullification_publication, *vqc_publication]
    );
    machine.persist(&successor, Until::CursorAdvance);

    let snapshot = machine.live_snapshot_for_test();
    assert!(!snapshot.outbox().contains_key(nullification_publication));
    assert!(!snapshot.outbox().contains_key(vqc_publication));
    assert!(snapshot.outbox().contains_key(successor_publication));
}

#[test]
fn local_nullification_promotes_an_identical_pending_artifact() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let view = View::new(1);
    let observed = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(shares)] = observed.capabilities() else {
        panic!("nullify shares must be verified together");
    };
    let verified = machine.step(Input::Verified(shares.all_valid())).unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    let recovery = verified
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a threshold quorum must request nullification recovery");

    let certificate = symbolic_nullification(&machine, view, 0);
    let certificate_id = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let inbound = observe(&mut machine, Artifact::Nullification(certificate.clone()));
    let local = machine
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), certificate),
        )))
        .unwrap();
    let local = machine.settle(local, Until::CursorAdvance);
    let retained = machine.persist(&local.persist_job(), Until::CursorAdvance);
    assert!(
        machine
            .inspect()
            .ready_artifacts()
            .contains(&certificate_id)
    );

    let stale_worker = machine
        .step(Input::Verified(VerificationCompletion::new(
            inbound.issued(),
            vec![Verdict::new(inbound.items()[0].ticket(), false)],
        )))
        .unwrap();
    assert!(matches!(
        stale_worker.status(),
        StepStatus::Verified {
            valid: 0,
            invalid: 0
        }
    ));
    assert!(matches!(
        retained.persist_job().events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if artifact.id::<Sha256>() == certificate_id
    ));
}

#[test]
fn local_vqc_origin_reconciles_identical_pending_later_ingress() {
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

    let local_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let messages = machine
        .step(cohort::<Sha256, _>(
            local_messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(messages)] = messages.capabilities() else {
        panic!("view messages must be verified together");
    };

    let local = vqc(&machine, proposed, &local_messages);
    let inbound = observe(&mut machine, Artifact::Vqc(local.clone()));

    let ready = machine.step(Input::Verified(messages.all_valid())).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let aggregate = ready
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the local quorum must issue V-QC aggregation");

    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            vqc_completion(&aggregate, local.clone(), machine.profile().codec()),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let forwarding = retained.persist_job();
    assert!(matches!(
        forwarding.events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(actual) if actual == &local)
    ));

    let stale = machine.step(Input::Verified(inbound.all_valid())).unwrap();
    assert_eq!(
        stale.status(),
        &StepStatus::Verified {
            valid: 0,
            invalid: 0,
        }
    );
}

#[test]
fn local_vqc_origin_precedes_identical_later_ingress() {
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
    let local_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let messages = machine
        .step(cohort::<Sha256, _>(
            local_messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(messages)] = messages.capabilities() else {
        panic!("view messages must be verified together");
    };
    let competing_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let local = vqc(&machine, proposed.clone(), &local_messages);
    let competing = vqc(&machine, proposed, &competing_messages);
    let certificates = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::Vqc(competing),
            Artifact::Vqc(local.clone()),
        ]))
        .unwrap();
    let [Capability::Verify(certificates)] = certificates.capabilities() else {
        panic!("V-QCs must be verified together");
    };
    machine.verify(certificates, true, Until::CursorAdvance);

    let ready = machine.step(Input::Verified(messages.all_valid())).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let aggregate = ready
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                local.clone(),
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let forwarding = retained.persist_job();
    let Change::ArtifactForwarded { artifact, .. } = forwarding.events()[0].change() else {
        panic!("the local origin must re-enter representative selection");
    };
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(actual) if actual == &local));
}

#[test]
fn proposal_parent_suppresses_identical_local_assembly() {
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(View::new(2));
    let profile = Harness::builder(Role::Validator(signer))
        .participants(6)
        .profile();
    let (mut machine, _) = start_profile(profile);

    // View one nullifies before its view messages arrive.
    let exit = symbolic_nullification(&machine, View::new(1), 0);
    let nullification = observe(&mut machine, Artifact::Nullification(exit));

    // The view-one messages arrive late and sit in verification.
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let pending = machine
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
    let [Capability::Verify(pending)] = pending.capabilities() else {
        panic!("view messages must be verified together");
    };
    let pending = pending.clone();

    // The nullification verifies and becomes the exit proof for view one. Settling stages its
    // forwarding barrier before the peer's certificate finishes verification.
    let forwarding = machine
        .step(Input::Verified(nullification.all_valid()))
        .unwrap();
    let forwarding = machine.settle(forwarding, Until::CursorAdvance);

    // A peer assembled the same V-QC from the same messages and it verifies first.
    let parent = vqc(&machine, proposed, &messages);
    let certificate = observe(&mut machine, Artifact::Vqc(parent.clone()));
    // The exit derives beside the forwarding it reads, so view two is already current here and
    // the proposal choice stages with the parent's completion.
    let proposal = machine.verify(&certificate, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().view(), View::new(2));
    // The signing request releases with the step that stages the proposal choice.
    let sign = sign_job(&proposal);

    let entered = machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    machine.persist(&entered.persist_job(), Until::CursorAdvance);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the view-two leader must reserve a proposal");
    };
    assert_eq!(request.parent().exact().map(Arc::as_ref), Some(&parent));
    assert!(request.attach_parent());
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

    // The view messages finish verification with the publication barrier still in flight. The
    // proposal already disseminates their V-QC, so the machine must not assemble and broadcast it
    // again.
    let ready = machine.step(Input::Verified(pending.all_valid())).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    assert!(!ready.has(Capability::is_aggregate_vqc));
    machine.persist(&published.persist_job(), Until::CursorAdvance);
    let assembled = Artifact::Vqc(parent);
    assert!(
        machine
            .durable
            .state
            .local
            .contains_key(&assembled.id::<Sha256>())
    );
    assert!(machine.inspect().pending_barrier().is_none());
    let cursor = machine.inspect().cursor();
    let drained = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(drained.capabilities().is_empty());
    assert_eq!(machine.inspect().cursor(), cursor);
    assert!(machine.inspect().is_live());
}

#[test]
fn forwarded_vqc_does_not_suppress_different_local_assembly() {
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

    let first_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let first = vqc(&machine, proposed.clone(), &first_messages);
    let first = Arc::new(Artifact::Vqc(first));
    machine.views.retain_vqc_parent::<Sha256>(&first).unwrap();
    machine.views.observe_forwarded::<Sha256>(&first);

    let second_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let second = vqc(&machine, proposed, &second_messages);
    let messages = machine
        .step(cohort::<Sha256, _>(
            second_messages
                .into_iter()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(messages)] = messages.capabilities() else {
        panic!("the different V-QC transcript must be verified together");
    };
    let ready = machine.verify(messages, true, Until::CursorAdvance);
    let aggregate = ready
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a different transcript must still be aggregated locally");
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                second,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let retained = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    assert!(!retained.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if matches!(
            job.events()[0].change(),
            Change::ArtifactForwarded { artifact, .. } if matches!(artifact.as_ref(), Artifact::Vqc(_))
        ))
    }));
    assert_eq!(machine.views.retained_parents(), 3);
}

#[test]
fn mismatched_nullification_recovery_preserves_the_job() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let view = View::new(1);
    let shares = (0..3)
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
    let mismatch = symbolic_nullification(&machine, View::new(view.get() + 1), 0);
    let parked = machine
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), mismatch),
        )))
        .unwrap();
    assert_eq!(parked.status(), &StepStatus::Accepted);
    // The mismatch surfaces exactly once when the parked completion drains; the recovery job
    // survives for the corrected certificate.
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    let certificate = symbolic_nullification(&machine, view, 0);
    let certificate_id = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let matched = machine
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), certificate),
        )))
        .unwrap();
    assert_eq!(matched.status(), &StepStatus::Accepted);
    let matched = machine.settle(matched, Until::CursorAdvance);
    assert!(machine.store.artifacts.contains_key(&certificate_id));
    assert!(
        matched.has(Capability::is_journal),
        "the corrected recovery must stage its durable transition"
    );
}
