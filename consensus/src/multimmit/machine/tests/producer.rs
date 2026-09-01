//! Producer build, custody, recovery, and capacity tests.

use super::fixtures::{
    Harness, TEST_RESOURCES, active_machine, attestation, complete_custody, digest, durable_effect,
    leader_artifact, mismatched_resolution_proof, observe, prepare_block, start_profile,
    symbolic_da_certificate, threshold_share, validate_block,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::{AppJob, Capability, ObservedBlock, TimerCommand, ValidatorCommand},
            durability::{Change, DurableEffect, EffectCompletion, SignRequest},
            input::{Input, StepError, StepStatus},
            job::{Generation, Issued},
            producer::{BuildCompletion, CustodyCompletion},
            reducer::machine::Machine,
            resolution::ResolutionCompletion,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, MachineExt as _,
                Until,
            },
        },
        types::{
            Artifact, ChainId, Context, DaVote, SignedTransactionBlock, TransactionBlockHeader,
        },
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
use commonware_utils::NZUsize;
use std::sync::Arc;

#[test]
fn declined_build_retries_only_after_post_decline_delay() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let started = machine.step(Input::ProducerWake).unwrap();
    let started = machine.settle(started, Until::CursorAdvance);
    let [Capability::Application(AppJob::Build(build))] = started.capabilities() else {
        panic!("producer wake must issue one build without arming a production timer");
    };
    let build = build.clone();

    let coalesced = machine.step(Input::ProducerWake).unwrap();
    let coalesced = machine.settle(coalesced, Until::CursorAdvance);
    assert_eq!(coalesced.status(), &StepStatus::Accepted);
    assert!(coalesced.capabilities().is_empty());

    let declined = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            None,
        )))
        .unwrap();
    let declined = machine.settle(declined, Until::CursorAdvance);
    let [Capability::Timer(TimerCommand::Production(timer))] = declined.capabilities() else {
        panic!("declined build must arm one retry timer without rebuilding");
    };
    assert_eq!(timer.parent(), build.parent());
    assert_eq!(timer.generation(), build.issued().generation());

    let elapsed = machine.step(Input::ProductionTimerFired(*timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    let [Capability::Application(AppJob::Build(retry))] = elapsed.capabilities() else {
        panic!("post-decline timer must issue exactly one retry");
    };
    assert_ne!(retry.issued().id(), build.issued().id());
    assert_eq!(retry.parent(), build.parent());
}

#[test]
fn prepared_builds_pipeline_and_authorize_only_the_custodied_prefix() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let first = machine.step(Input::ProducerWake).unwrap();
    let first = machine.settle(first, Until::CursorAdvance);
    let first_build = first.build_job();
    let first_prepared = prepare_block(&mut machine, &first_build, digest(b"block one"));
    assert!(first_prepared.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));
    let first_custody = first_prepared.custody_job();
    let second_build = first_prepared.build_job();
    assert_eq!(
        second_build.parent(),
        first_custody.header().block_ref::<Sha256>()
    );

    let second_prepared = prepare_block(&mut machine, &second_build, digest(b"block two"));
    let second_custody = second_prepared.custody_job();
    assert!(second_prepared.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));
    assert!(
        machine
            .inspect()
            .producer()
            .expect("the validator owns a producer chain")
            .pipeline_blocked()
    );

    let out_of_order = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            second_custody.issued(),
            second_custody.header().clone(),
        )))
        .unwrap();
    let out_of_order = machine.settle(out_of_order, Until::CursorAdvance);
    assert!(out_of_order.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));

    let contiguous = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            first_custody.issued(),
            first_custody.header().clone(),
        )))
        .unwrap();
    let contiguous = machine.settle(contiguous, Until::CursorAdvance);
    let following = machine.persist(&contiguous.persist_job(), Until::CursorAdvance);
    let signed_heights = contiguous
        .capabilities()
        .iter()
        .chain(following.capabilities())
        .filter_map(
            |capability| match durable_effect(capability).and_then(EffectExt::sign_one) {
                Some(SignRequest::TransactionBlock(header)) => Some(header.height()),
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(signed_heights, [Height::new(1), Height::new(2)]);
}

#[test]
fn matching_certificate_preserves_a_custodied_prepared_descendant() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let first_build = (machine.settle(ready, Until::CursorAdvance)).build_job();
    let first = prepare_block(&mut machine, &first_build, digest(b"prepared first"));
    let first_custody = first.custody_job();
    let second_build = first.build_job();
    let second = prepare_block(&mut machine, &second_build, digest(b"prepared second"));
    let second_custody = second.custody_job();
    let out_of_order = complete_custody(&mut machine, &second_custody);
    assert!(out_of_order.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));

    let certificate =
        Artifact::DaCertificate(symbolic_da_certificate(first_custody.header().clone(), 1));
    let verification = observe(&mut machine, certificate);
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let late = complete_custody(&mut machine, &first_custody);
    assert_eq!(late.status(), &StepStatus::StaleCompletion);

    let persisted = machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let signing = persisted.persist_job();
    let Change::OutboxQueued { effect, .. } = signing.events()[0].change() else {
        panic!("the retained descendant must reserve its signing subject");
    };
    assert!(matches!(
        effect.as_ref().sign_one(),
        Some(SignRequest::TransactionBlock(header))
            if header == second_custody.header()
    ));
}

#[test]
fn divergent_certificate_discards_the_prepared_suffix() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let first_build = (machine.settle(ready, Until::CursorAdvance)).build_job();
    let first = prepare_block(&mut machine, &first_build, digest(b"orphaned first"));
    let first_custody = first.custody_job();
    let second_build = first.build_job();
    let second = prepare_block(&mut machine, &second_build, digest(b"orphaned second"));
    let second_custody = second.custody_job();
    complete_custody(&mut machine, &second_custody);

    let sibling = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        first_build.parent().chain(),
        Height::new(first_build.parent().height().get() + 1),
        first_build.parent().digest(),
        digest(b"certified sibling"),
    )
    .unwrap();
    let verification = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(sibling.clone(), 2)),
    );
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let persisted = machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let cancellation = persisted
        .find(|capability| match capability {
            Capability::Application(AppJob::CancelCustody(cancellation)) => Some(*cancellation),
            _ => None,
        })
        .expect("the divergent certificate must cancel orphaned custody");
    let cancelled = machine.step(Input::CustodyCancelled(cancellation)).unwrap();
    let cancelled = machine.settle(cancelled, Until::CursorAdvance);
    let first_late = complete_custody(&mut machine, &first_custody);
    let second_late = complete_custody(&mut machine, &second_custody);
    assert_eq!(first_late.status(), &StepStatus::StaleCompletion);
    assert_eq!(second_late.status(), &StepStatus::StaleCompletion);

    let steps = [&advanced, &cancelled, &first_late, &second_late, &persisted];
    assert!(
        steps
            .iter()
            .flat_map(|step| step.capabilities())
            .all(|capability| {
                !matches!(
                    durable_effect(capability).and_then(EffectExt::sign_one),
                    Some(SignRequest::TransactionBlock(header))
                        if header == first_custody.header() || header == second_custody.header()
                )
            })
    );
    let replacement = steps
        .iter()
        .flat_map(|step| step.capabilities())
        .find_map(|capability| match capability {
            Capability::Application(AppJob::Build(job)) => Some(job),
            _ => None,
        })
        .expect("the divergent certificate must wake production on its own tip");
    assert_eq!(replacement.parent(), sibling.block_ref::<Sha256>());
}

#[test]
fn prepared_suffix_is_discarded_across_restart_without_authority() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = active_machine(role);
    let snapshot = machine.live_snapshot_for_test();
    let ready = machine.step(Input::ProducerWake).unwrap();
    let build = (machine.settle(ready, Until::CursorAdvance)).build_job();
    let prepared = prepare_block(&mut machine, &build, digest(b"volatile prepared block"));
    let custody = prepared.custody_job();
    assert!(prepared.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));

    let mut restored =
        Machine::<Sha256, MinPk>::restore(Harness::builder(role).profile(), snapshot).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let stale = restored
        .step(Input::BlockCustodied(CustodyCompletion::new(
            custody.issued(),
            custody.header().clone(),
        )))
        .unwrap();
    let stale = restored.settle(stale, Until::CursorAdvance);
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().iter().all(|capability| {
        !durable_effect(capability)
            .and_then(EffectExt::sign_one)
            .is_some()
    }));
}

#[test]
fn producer_builds_after_an_external_own_chain_certificate() {
    let role = Role::Validator(Participant::new(0));
    let profile = Harness::builder(role).profile();
    let mut machine = active_machine(role);
    let before_certificate = machine.live_snapshot_for_test();
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"sibling producer block"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(first.clone(), 1);

    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let advanced_job = advanced.persist_job();
    let Change::DaCertificateAdvanced {
        publication,
        retired_publications: retired,
        artifact,
    } = advanced_job.events()[0].change()
    else {
        panic!("the external certificate must advance the own-chain tip");
    };
    assert!(publication.is_none());
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
        if actual == &certificate));

    let mut replayed = Machine::<Sha256, MinPk>::restore(profile, before_certificate).unwrap();
    for event in advanced_job.events() {
        replayed.replay(event.clone()).unwrap();
    }
    assert_eq!(
        replayed.durable.state.certified_tips[0].height(),
        Height::new(1)
    );
    assert_eq!(replayed.durable.state.produced_height, Height::zero());

    let outbox_before = machine.live_snapshot_for_test().outbox().clone();
    let advanced = machine.persist(&advanced_job, Until::CursorAdvance);
    let build = advanced.build_job();
    assert_eq!(build.parent(), first.block_ref::<Sha256>());

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"local successor")),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(&mut machine, &completed.custody_job());
    let completed_job = completed.persist_job();
    let Change::OutboxQueued { id, effect } = completed_job.events()[0].change() else {
        panic!("the local successor must reserve its exact signing subject");
    };
    let Some(SignRequest::TransactionBlock(successor)) = effect.as_ref().sign_one() else {
        panic!("the reserved subject must be the local transaction block");
    };
    assert_eq!(successor.height(), Height::new(2));
    assert_eq!(successor.parent(), first.block_ref::<Sha256>().digest());
    assert_eq!(machine.durable.state.produced_blocks, 1);
    assert_eq!(machine.durable.state.produced_height, Height::new(2));

    let snapshot = machine.live_snapshot_for_test();
    assert_eq!(snapshot.outbox(), &outbox_before);
    assert_eq!(
        snapshot
            .signing_reservations()
            .get(id)
            .cloned()
            .map(DurableEffect::Sign),
        Some(effect.as_ref().clone())
    );

    for event in completed_job.events() {
        replayed.replay(event.clone()).unwrap();
    }
    assert_eq!(replayed.durable.state.produced_blocks, 1);
    assert_eq!(replayed.durable.state.produced_height, Height::new(2));
    let replayed = replayed.live_snapshot_for_test();
    assert_eq!(replayed.outbox(), &outbox_before);
    assert_eq!(
        replayed
            .signing_reservations()
            .get(id)
            .cloned()
            .map(DurableEffect::Sign),
        Some(effect.as_ref().clone())
    );
}

#[test]
fn superseded_build_waits_for_completion_before_building_on_new_parent() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let first = machine.step(Input::ProducerWake).unwrap();
    let first = machine.settle(first, Until::CursorAdvance);
    let old_build = first.build_job();
    let new_parent_header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        old_build.parent().chain(),
        Height::new(old_build.parent().height().get() + 1),
        old_build.parent().digest(),
        digest(b"twin commitment"),
    )
    .unwrap();
    let new_parent = new_parent_header.block_ref::<Sha256>();

    machine
        .chain
        .observe_producer_choice::<Sha256>(&new_parent_header)
        .unwrap();
    let advanced = machine.step(Input::ProducerWake).unwrap();
    let advanced = machine.settle(advanced, Until::CursorAdvance);
    assert!(
        advanced
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Application(AppJob::Build(_))))
    );

    let mismatched = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            Issued::new(
                old_build.issued().id(),
                Generation::new(old_build.issued().generation().get() + 1),
            ),
            old_build.parent(),
            Some(digest(b"mismatched commitment")),
        )))
        .unwrap();
    assert_eq!(mismatched.status(), &StepStatus::StaleCompletion);
    assert!(mismatched.capabilities().iter().all(|effect| {
        !matches!(effect, Capability::Application(AppJob::Build(_)))
            && !durable_effect(effect)
                .and_then(EffectExt::sign_one)
                .is_some()
    }));

    let old_commitment = digest(b"old commitment");
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            old_build.issued(),
            old_build.parent(),
            Some(old_commitment),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::StaleCompletion);
    let completed = machine.settle(completed, Until::CursorAdvance);
    let builds = completed
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Application(AppJob::Build(job)) => Some(job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].parent(), new_parent);
    assert!(!completed.has(|effect| {
        matches!(
            durable_effect(effect).and_then(EffectExt::sign_one),
            Some(SignRequest::TransactionBlock(header))
                if header.body_digest() == old_commitment
        )
    }));
}

#[test]
fn empty_build_waits_for_its_exact_parent_timer() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let [Capability::Application(AppJob::Build(build))] = ready.capabilities() else {
        panic!("producer wake must issue one build without arming a production timer");
    };
    let build = build.clone();

    let stale = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            Issued::new(
                build.issued().id(),
                Generation::new(build.issued().generation().get() + 1),
            ),
            build.parent(),
            Some(digest(b"stale")),
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().is_empty());

    let empty = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            None,
        )))
        .unwrap();
    assert_eq!(empty.status(), &StepStatus::Accepted);
    let empty = machine.settle(empty, Until::CursorAdvance);
    let [Capability::Timer(TimerCommand::Production(timer))] = empty.capabilities() else {
        panic!("empty build must arm one production timer");
    };
    let timer = *timer;
    assert_eq!(timer.generation(), build.issued().generation());
    assert_eq!(timer.parent(), build.parent());

    let late = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"late")),
        )))
        .unwrap();
    assert_eq!(late.status(), &StepStatus::StaleCompletion);
    assert!(late.capabilities().is_empty());

    let elapsed = machine.step(Input::ProductionTimerFired(timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::CursorAdvance);
    let retry = elapsed.build_job();
    assert_ne!(retry.issued().id(), build.issued().id());
    assert_eq!(retry.parent(), build.parent());
}

#[test]
fn crash_recovery_rejects_mismatched_old_resolution_completions_as_stale() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let keys = [View::new(2), View::new(3), View::new(4)];
    let old = keys.map(|key| {
        machine
            .resolution
            .request(
                machine.durable.state.generation,
                key,
                machine.profile().resources().max_dependency_waiters(),
            )
            .unwrap()
            .unwrap()
    });

    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let current = keys.map(|key| {
        restored
            .resolution
            .request(
                restored.durable.state.generation,
                key,
                restored.profile().resources().max_dependency_waiters(),
            )
            .unwrap()
            .unwrap()
    });

    for (old, current) in old.into_iter().zip(current) {
        assert_ne!(old.issued().id(), current.issued().id());
        assert_ne!(old.issued().generation(), current.issued().generation());
        let completed = restored
            .step(Input::ResolutionCompleted(ResolutionCompletion::new(
                old.issued(),
                old.view(),
                mismatched_resolution_proof(&restored),
            )))
            .unwrap();
        assert_eq!(completed.status(), &StepStatus::StaleCompletion);
        assert!(completed.capabilities().is_empty());
    }
    assert_eq!(restored.inspect().resolution_jobs(), keys.len() + 1);
}

#[test]
fn producer_window_stops_before_the_third_uncertified_block() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));

    // Preparation pipelines while custody and signing complete for earlier blocks.
    let wake = machine.step(Input::ProducerWake).unwrap();
    let mut build = (machine.settle(wake, Until::CursorAdvance)).build_job();
    for height in 1..=2u64 {
        let completed = machine
            .step(Input::BlockBuilt(BuildCompletion::new(
                build.issued(),
                build.parent(),
                Some(digest(format!("block {height}").as_bytes())),
            )))
            .unwrap();
        let completed = machine.settle(completed, Until::CursorAdvance);
        let next = (height < 2).then(|| completed.build_job());
        let completed = complete_custody(&mut machine, &completed.custody_job());
        // The signing request releases with the step that stages the producer choice.
        assert!(completed.has(|effect| {
            matches!(
                durable_effect(effect).and_then(EffectExt::sign_one),
                Some(SignRequest::TransactionBlock(_))
            )
        }));
        machine.persist(&completed.persist_job(), Until::CursorAdvance);
        if let Some(next) = next {
            build = next;
        }
    }

    // The third block would exceed the certificate window, so no further build is issued even
    // while work remains pending.
    let blocked = machine.step(Input::ProducerWake).unwrap();
    let blocked = machine.settle(blocked, Until::CursorAdvance);
    assert_eq!(blocked.status(), &StepStatus::Accepted);
    assert!(!blocked.has(Capability::is_build));

    let second = machine
        .live_snapshot_for_test()
        .signing_reservations()
        .values()
        .filter_map(|effect| match effect.requests() {
            [SignRequest::TransactionBlock(header)] if header.height() == Height::new(2) => {
                Some(header.clone())
            }
            _ => None,
        })
        .next()
        .unwrap();
    let certificate = symbolic_da_certificate(second, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    let admitted = machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    assert_eq!(admitted.build_job().parent().height(), Height::new(2));
}

#[test]
fn certified_chain_state_plateaus_without_ordering() {
    // Chain dissemination is independent of total ordering. Once a higher DA certificate is
    // accepted, the machine needs only that certified frontier and the bounded uncertified suffix;
    // older blocks and certificates remain retrievable from storage. Keeping them in live state
    // until ordering would let one continuously certified chain exhaust every validator.
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(512))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(512));
    let profile = Harness::observer()
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let mut parent = machine.profile().protocol().genesis().tips()[0];

    for height in 1..=100u64 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            parent.chain(),
            Height::new(height),
            parent.digest(),
            digest(format!("certified body {height}").as_bytes()),
        )
        .unwrap();
        let block = header.block_ref::<Sha256>();
        let validated = validate_block(&mut machine, header.clone(), parent.chain().get());
        assert!(validated.capabilities().is_empty());

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height)),
        );
        let certified = machine.verify(&certificate, true, Until::CursorAdvance);
        let advanced = machine.persist(&certified.persist_job(), Until::CursorAdvance);
        machine.drain_persisting(advanced);
        parent = block;
    }

    assert_eq!(machine.chain.tip_heights()[0].certified, Height::new(100));
    assert!(machine.chain.da.retained_ancestry() <= 1);
    assert!(
        machine.inspect().cached_artifacts() <= 4,
        "certified chain history remained live: {} artifacts",
        machine.inspect().cached_artifacts()
    );

    let profile = machine.profile().clone();
    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert_eq!(restored.chain.tip_heights()[0].certified, Height::new(100));
    assert!(restored.chain.da.retained_ancestry() <= 1);
    assert!(restored.inspect().cached_artifacts() <= 4);
}

#[test]
fn validator_da_safety_state_plateaus_across_restarts() {
    let role = Role::Validator(Participant::new(0));
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(64))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(32));
    let profile = Harness::builder(role)
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let mut parent = machine.profile().protocol().genesis().tips()[1];

    for height in 1..=40u64 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            parent.chain(),
            Height::new(height),
            parent.digest(),
            digest(format!("validator body {height}").as_bytes()),
        )
        .unwrap();
        let block = header.block_ref::<Sha256>();

        let vote_reserved = validate_block(&mut machine, header.clone(), parent.chain().get());
        // The signing request releases with the step that stages the DA choice.
        let sign = vote_reserved
            .find(|effect| match effect {
                Capability::Released(job)
                    if matches!(job.request().sign_one(), Some(SignRequest::DaVote(actual))
                        if actual.header() == &header) =>
                {
                    Some(job.clone())
                }
                _ => None,
            })
            .expect("the staged DA choice must be signed");
        machine.persist(&vote_reserved.persist_job(), Until::CursorAdvance);
        let signed = machine
            .step(Input::EffectCompleted(EffectCompletion::signed(
                sign.issued(),
                vec![Arc::new(Artifact::DaVote(DaVote::new(
                    header.clone(),
                    threshold_share(0),
                )))],
            )))
            .unwrap();
        let signed = machine.settle(signed, Until::CursorAdvance);
        machine.persist(&signed.persist_job(), Until::CursorAdvance);

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height)),
        );
        let certified = machine.verify(&certificate, true, Until::CursorAdvance);
        let advanced = machine.persist(&certified.persist_job(), Until::CursorAdvance);
        machine.drain_persisting(advanced);
        parent = block;

        assert_eq!(
            machine.live_snapshot_for_test().da_safety_heights()[1],
            Height::new(height)
        );
        assert!(machine.inspect().cached_artifacts() <= 4);
        assert!(machine.live_snapshot_for_test().local_artifacts().len() <= 1);
        assert!(machine.live_snapshot_for_test().outbox().len() <= 1);

        if height % 10 == 0 {
            let mut restored =
                Machine::restore(profile.clone(), machine.live_snapshot_for_test()).unwrap();
            let recovery = restored.step(Input::RecoveryComplete).unwrap();
            restored.persist(&recovery.persist_job(), Until::CursorAdvance);
            machine = restored;
        }
    }

    assert_eq!(machine.chain.tip_heights()[1].certified, Height::new(40));
}

#[test]
fn recovery_reissues_the_exact_durable_producer_choice() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let build = ready.build_job();
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"durable block")),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(&mut machine, &completed.custody_job());
    machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let expected = machine
        .live_snapshot_for_test()
        .signing_reservations()
        .values()
        .find_map(|effect| match effect.requests() {
            [SignRequest::TransactionBlock(header)] => Some(header.clone()),
            _ => None,
        })
        .expect("producer choice must be durable");

    let mut restored = Machine::<Sha256, MinPk>::restore(
        Harness::validator(0).profile(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let actual = recovered
        .find(|effect| match effect {
            Capability::Released(job) => match job.request().sign_one() {
                Some(SignRequest::TransactionBlock(header)) => Some(header),
                _ => None,
            },
            _ => None,
        })
        .expect("recovery must reissue producer signing");
    assert_eq!(actual, &expected);
    let next_build = recovered.build_job();
    assert_eq!(next_build.parent(), expected.block_ref::<Sha256>());
    assert!(
        recovered
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Timer(TimerCommand::Production(_))))
    );

    let declined = restored
        .step(Input::BlockBuilt(BuildCompletion::new(
            next_build.issued(),
            next_build.parent(),
            None,
        )))
        .unwrap();
    let declined = restored.settle(declined, Until::CursorAdvance);
    let [Capability::Timer(TimerCommand::Production(timer))] = declined.capabilities() else {
        panic!("declined recovered build must arm one production timer");
    };
    assert_eq!(timer.generation(), next_build.issued().generation());
    assert_eq!(timer.parent(), next_build.parent());
}

#[test]
fn recovered_payloads_are_the_exact_local_producer_and_da_union() {
    let role = Role::Validator(Participant::new(0));
    let recovery_profile = Harness::builder(role).participants(6).profile();
    let (mut machine, _) = start_profile(recovery_profile.clone());
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let build = ready.build_job();
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"local recovery payload")),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(&mut machine, &completed.custody_job());
    let local = completed
        .find(|effect| match effect {
            Capability::Released(job) => match job.request().sign_one() {
                Some(SignRequest::TransactionBlock(header)) => Some(header.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("the producer choice carries its complete recovery context");
    machine.persist(&completed.persist_job(), Until::CursorAdvance);

    let local_observation = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(local.clone(), attestation(0))),
    );
    let local_da = machine.verify(&local_observation, true, Until::CursorAdvance);
    assert!(
        local_da.has(|capability| matches!(
            capability,
            Capability::Validator(
                _,
                ValidatorCommand::Observe(ObservedBlock {
                    custodied: true,
                    ..
                })
            )
        )),
        "the local producer's own block routes to its chain plane as custodied and is valid \
         without an application re-validation"
    );
    // The local producer's own DA root was already recorded durably through its custody choice
    // above; the re-observation only confirms it routes as custodied and needs no vote from the machine.

    let remote_parent = machine.profile().protocol().genesis().tips()[1];
    let remote = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        remote_parent.chain(),
        Height::new(1),
        remote_parent.digest(),
        digest(b"remote recovery payload"),
    )
    .unwrap();
    let remote_da = validate_block(&mut machine, remote.clone(), 1);
    machine.persist(&remote_da.persist_job(), Until::CursorAdvance);

    let certified_parent = machine.profile().protocol().genesis().tips()[2];
    let certified = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        certified_parent.chain(),
        Height::new(1),
        certified_parent.digest(),
        digest(b"certificate-only payload"),
    )
    .unwrap();
    let observed = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(certified, 2)),
    );
    let verified = machine.verify(&observed, true, Until::CursorAdvance);
    machine.persist(&verified.persist_job(), Until::CursorAdvance);

    let restored = Machine::<Sha256, MinPk>::restore(
        recovery_profile.clone(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    assert_eq!(
        restored.recovered_payloads(),
        vec![
            (Context::from(&local), local.body_digest()),
            (Context::from(&remote), remote.body_digest()),
        ],
        "the duplicate local producer/DA root is verified once and certificate-only roots are excluded"
    );

    let observed = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(remote, 3)),
    );
    let verified = machine.verify(&observed, true, Until::CursorAdvance);
    machine.persist(&verified.persist_job(), Until::CursorAdvance);
    let restored =
        Machine::<Sha256, MinPk>::restore(recovery_profile, machine.live_snapshot_for_test())
            .unwrap();
    assert_eq!(
        restored.recovered_payloads(),
        vec![(Context::from(&local), local.body_digest())],
        "a durable certificate retires the covered DA custody root"
    );

    let observer_profile = Harness::observer().participants(6).profile();
    let observer = Machine::<Sha256, MinPk>::restore(
        observer_profile.clone(),
        Machine::<Sha256, MinPk>::new(observer_profile).live_snapshot_for_test(),
    )
    .unwrap();
    assert!(observer.recovered_payloads().is_empty());
}

#[test]
fn validator_cannot_authorize_another_producer_chain() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        digest(b"other parent"),
        digest(b"other body"),
    )
    .unwrap();
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::sign(SignRequest::TransactionBlock(header))),
        Err(StepError::UnauthorizedEffect)
    ));
}

#[test]
fn an_issued_build_reserves_its_durable_completion_capacity() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(16));
    let profile = Harness::validator(0)
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let build = ready.build_job();
    let limit = machine.profile().resources().max_outbox_effects();
    let mut filler_view = 10;
    loop {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        match machine.reserve_test_effect(DurableEffect::broadcast(filler)) {
            Ok(reserved) => {
                machine.persist(&reserved.persist_job(), Until::CursorAdvance);
            }
            Err(StepError::OutboxFull) => break,
            Err(error) => panic!("unexpected filler rejection: {error:?}"),
        }
    }
    assert_eq!(machine.inspect().outbox().len(), limit - 1);

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"reserved completion")),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::Accepted);
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(&mut machine, &completed.custody_job());
    machine.persist(&completed.persist_job(), Until::CursorAdvance);
    assert_eq!(
        machine.inspect().outbox().len() + machine.chain.build_reservations(),
        limit
    );
}

#[test]
fn an_issued_build_reserves_its_durable_artifact_capacity() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(16))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(64));
    let profile = Harness::validator(0)
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile);

    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let build = ready.build_job();
    let mut filler_view = 10;
    loop {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        match machine.reserve_test_effect(DurableEffect::broadcast(filler)) {
            Ok(reserved) => {
                machine.persist(&reserved.persist_job(), Until::CursorAdvance);
            }
            Err(StepError::LocalArtifactReservation) => break,
            Err(error) => panic!("unexpected filler rejection: {error:?}"),
        }
    }

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"artifact-reserved completion")),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::Accepted);
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(&mut machine, &completed.custody_job());
    machine.persist(&completed.persist_job(), Until::CursorAdvance);
}

#[test]
fn recovered_chain_signing_reservations_use_global_capacity() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(64))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(64));
    let profile = Harness::validator(0)
        .participants(2)
        .depth(1)
        .resources(resources)
        .profile();
    let chain_capacity = profile.codec().chains() * (profile.codec().pipeline_depth() + 1);
    let (mut machine, _) = start_profile(profile.clone());
    let chain = ChainId::new(1);
    let mut parent = machine.profile().protocol().genesis().tips()[chain.get() as usize];

    for height in 1..=chain_capacity {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            chain,
            Height::new(height as u64),
            parent.digest(),
            digest(format!("pending block {height}").as_bytes()),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>();
        let reserved = validate_block(&mut machine, header.clone(), 1);
        machine.persist(&reserved.persist_job(), Until::CursorAdvance);

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height as u64)),
        );
        let certified = machine.verify(&certificate, true, Until::CursorAdvance);
        let advanced = machine.persist(&certified.persist_job(), Until::CursorAdvance);
        machine.drain_persisting(advanced);
    }

    let mut recovered = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = recovered.step(Input::RecoveryComplete).unwrap();
    recovered.persist(&recovery.persist_job(), Until::CursorAdvance);

    let global_effects =
        recovered.durable.state.signing_reservations.len() + recovered.durable.state.outbox.len();
    assert_eq!(global_effects, chain_capacity);
    assert!(global_effects < recovered.profile().resources().max_outbox_effects());
    let global_artifacts = recovered.durable.state.artifact_occupancy::<Sha256>();
    assert!(global_artifacts < recovered.profile().resources().max_cached_artifacts());

    let header = TransactionBlockHeader::new(
        recovered.profile().protocol().epoch(),
        chain,
        Height::new(chain_capacity as u64 + 1),
        parent.digest(),
        digest(b"next pending block"),
    )
    .unwrap();
    let reserved = validate_block(&mut recovered, header, 1);
    recovered.persist(&reserved.persist_job(), Until::CursorAdvance);
    assert_eq!(
        recovered.durable.state.signing_reservations.len(),
        chain_capacity + 1
    );
}
