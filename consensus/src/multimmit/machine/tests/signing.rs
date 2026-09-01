//! Signing reservation and signed-completion ordering tests.

use super::fixtures::{
    TEST_RESOURCES, TestConfig, active_machine, attestation, durable_effect, leader,
    leader_artifact, proposal_request, retention_for, sign_job, start_profile,
};
use crate::{
    multimmit::{
        config::{Profile, Role, Tuning},
        machine::{
            ProposalParent,
            capability::Capability,
            durability::{Change, DurableEffect, EffectCompletion, SignRequest},
            input::{Input, ObservationStatus, StepStatus},
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, MachineExt as _,
                Until, cohort,
            },
        },
        types::{Activity, Artifact, SignedLeaderBlock},
    },
    types::{Participant, View},
};
use commonware_cryptography::Sha256;
use commonware_utils::NZUsize;
use core::{num::NonZeroUsize, time::Duration};
use std::sync::Arc;

#[test]
fn sign_self_admits_before_publication_attempt() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = reserved
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_one().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("private signing must start before its reservation is acknowledged");
    let signing_barrier = reserved.persist_job();

    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let Artifact::LeaderBlock(expected) = &artifact else {
        unreachable!("the test constructs a leader artifact")
    };
    let id = artifact.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    assert!(matches!(completed.status(), StepStatus::Accepted));
    // The parked completion self-admits when the scheduler stages it, before any barrier
    // acknowledgement and before any publication attempt. Its signed transition reaches the
    // journal immediately so it can join the sync pipeline behind the signing authorization.
    let completed = machine.settle(completed, Until::CursorAdvance);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);
    assert!(completed.activities().iter().any(|activity| matches!(
        activity,
        Activity::ProtocolAccepted {
            artifact_id,
            artifact: accepted,
        } if *artifact_id == id && accepted.as_ref() == &artifact
    )));
    let signed_barrier = completed.persist_job();
    let inspection = machine.inspect();
    let outbox = inspection.outbox();
    assert_eq!(outbox.len(), 2);
    assert_eq!(outbox[0], baseline);
    let publication = outbox[1];
    assert!(!completed.has(Capability::is_verify));
    assert!(!completed.has(
        |effect| matches!(effect, Capability::Released(job) if job.issued().id() == publication)
    ));
    assert!(matches!(
        machine.durable.state.local.get(&id),
        Some(recorded) if recorded.as_ref() == &artifact
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, publication]);

    let duplicate = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    let echo = machine
        .step(cohort::<Sha256, _>(vec![artifact.clone()]))
        .unwrap();
    assert!(matches!(
        echo.status(),
        StepStatus::Observed(results) if results[0].status() == ObservationStatus::Duplicate
    ));

    let acknowledged = machine.persist(&signing_barrier, Until::Step);
    assert!(!acknowledged.has(|effect| {
        durable_effect(effect)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));
    assert!(!acknowledged.has(
        |effect| matches!(effect, Capability::Released(job) if job.issued().id() == publication)
    ));
    assert!(
        acknowledged
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Journal(_)))
    );
    let [event] = signed_barrier.events() else {
        panic!("the signed artifact must be recorded atomically");
    };
    let Change::SignedArtifacts {
        sign: completed_sign,
        publication: recorded_publication,
        artifacts: recorded,
    } = event.change()
    else {
        panic!("the signing completion must record its exact artifact");
    };
    assert_eq!(*completed_sign, sign.issued().id());
    assert_eq!(*recorded_publication, publication);
    assert!(matches!(recorded.as_ref(), [recorded] if recorded.as_ref() == &artifact));

    let published = machine.persist(&signed_barrier, Until::CursorAdvance);
    let mut publications = published
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Released(job) if job.issued().id() == publication => Some(job),
            _ => None,
        });
    let broadcast = publications
        .next()
        .expect("signed proposal must publish after its barrier is acknowledged");
    assert!(publications.next().is_none());
    let Some(proposal) = broadcast.request().proposal() else {
        panic!("signed proposal must become a durable proposal publication");
    };
    assert_eq!(proposal.block().as_ref(), expected);
    assert!(matches!(proposal.parent(), ProposalParent::Genesis));
    assert_eq!(
        machine.inspect().outbox(),
        &[baseline, broadcast.issued().id()]
    );

    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(
            broadcast.issued(),
        )))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert_eq!(
        machine.inspect().outbox(),
        &[baseline, broadcast.issued().id()]
    );
}

#[test]
fn signed_completion_reaches_the_journal_behind_an_inflight_barrier() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
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

    let unrelated = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let artifact_id = artifact.id::<Sha256>();
    let buffered = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    assert!(matches!(buffered.status(), StepStatus::Accepted));
    assert!(buffered.capabilities().is_empty());
    assert!(machine.inspect().ready_artifacts().is_empty());

    let duplicate = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    // The poll admits the artifact and hands its signed transition to the journal immediately.
    // The active sync cannot cover the later append, but the journal can append behind it and
    // include every urgent tail event in exactly one successor sync.
    let staged = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(staged.activities().iter().any(|activity| matches!(
        activity,
        Activity::ProtocolAccepted {
            artifact_id: accepted,
            artifact: reported,
        } if *accepted == artifact_id && reported.as_ref() == &artifact
    )));
    assert_eq!(machine.inspect().ready_artifacts(), &[artifact_id]);
    assert!(
        !staged.has(|effect| matches!(effect, Capability::Verify(_))
            || durable_effect(effect)
                .and_then(EffectExt::proposal)
                .is_some()),
        "self-admission must not loop back and the publication must wait for durability"
    );
    let mut jobs = staged
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Journal(job) => Some(job),
            _ => None,
        });
    let signed = jobs
        .next()
        .expect("the signed transition must reach the journal immediately")
        .clone();
    assert!(jobs.next().is_none());
    let [event] = signed.job.events() else {
        panic!("the signed-artifact transition must be atomic");
    };
    let Change::SignedArtifacts {
        sign: completed_sign,
        artifacts: recorded,
        ..
    } = event.change()
    else {
        panic!("the buffered completion must stage a signed artifact");
    };
    assert_eq!(*completed_sign, sign.issued().id());
    assert!(matches!(recorded.as_ref(), [recorded] if recorded.as_ref() == &artifact));

    // Acknowledging the older barrier neither emits the already handed-off transition again nor
    // releases its publication before the successor sync is durable.
    let resumed = machine.persist(&unrelated.persist_job(), Until::Step);
    assert!(resumed.capabilities().iter().all(|effect| {
        !durable_effect(effect)
            .and_then(EffectExt::proposal)
            .is_some()
    }));
    assert!(
        resumed
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Journal(_))),
        "the signed transition was already handed to the journal"
    );

    let published = machine.persist(&signed.job, Until::CursorAdvance);
    let publication = published
        .find(|capability| match capability {
            Capability::Released(job) => Some(job),
            _ => None,
        })
        .expect("the self-admitted artifact must publish without a network loopback");
    assert!(publication.request().proposal().is_some());
}

#[test]
fn one_poll_emits_at_most_one_persistence_range() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(128))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(128));
    let profile = Profile::with_limits(
        TestConfig::new(2)
            .producers(vec![Participant::new(0)])
            .depth(2)
            .build(),
        Role::Validator(Participant::new(1)),
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(resources, 2),
            ..Tuning::default()
        },
        resources,
    )
    .unwrap();
    let (mut machine, _) = start_profile(profile);

    let signer = Participant::new(1);
    let mut view = 2;
    for _ in 0..3 {
        while machine
            .profile()
            .protocol()
            .leaders()
            .leader(View::new(view))
            != signer
        {
            view += 1;
        }
        let proposed = leader(&machine, view);
        let reserved = machine
            .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
                proposal_request(proposed.clone()),
            )))
            .unwrap();
        let sign = sign_job(&reserved);
        let buffered = machine
            .step(Input::EffectCompleted(EffectCompletion::signed(
                sign.issued(),
                vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                    proposed,
                    attestation(signer.get()),
                )))],
            )))
            .unwrap();
        assert!(buffered.capabilities().is_empty());
        let emitted = machine.settle(buffered, Until::CursorAdvance);
        assert_eq!(
            emitted
                .capabilities()
                .iter()
                .filter(|effect| matches!(effect, Capability::Journal(_)))
                .count(),
            1,
        );
        view += 1;
    }

    for filler in 10..42 {
        let step = machine
            .reserve_test_effect(DurableEffect::broadcast(Arc::new(leader_artifact(
                &machine,
                1_000 + filler,
            ))))
            .unwrap();
        assert!(
            step.capabilities()
                .iter()
                .all(|effect| !matches!(effect, Capability::Journal(_)))
        );
    }

    while machine
        .profile()
        .protocol()
        .leaders()
        .leader(View::new(view))
        != signer
    {
        view += 1;
    }
    let proposed = leader(&machine, view);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    assert!(
        reserved
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Journal(_)))
    );
    let sign = sign_job(&reserved);
    let artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(signer.get())));
    let buffered = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact)],
        )))
        .unwrap();
    assert!(buffered.capabilities().is_empty());

    let first = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(machine.work_remaining());
    assert_eq!(
        first
            .capabilities()
            .iter()
            .filter(|effect| matches!(effect, Capability::Journal(_)))
            .count(),
        1,
    );
    let second = machine.poll(NonZeroUsize::MIN).unwrap();
    assert_eq!(
        second
            .capabilities()
            .iter()
            .filter(|effect| matches!(effect, Capability::Journal(_)))
            .count(),
        1,
    );
}
