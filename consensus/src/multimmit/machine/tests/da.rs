//! Data-availability vote, certificate, and frontier tests.

use super::fixtures::{
    Harness, TEST_RESOURCES, TestConfig, TestMachine, active_machine, attestation,
    authenticate_block, complete_custody, da_run_headers, digest, drain_da_choices, durable_effect,
    durable_job, frontier_chain, genesis_tip_history, leader, lqc, observe, offer_eligible,
    plane_eligible_run, poll_seed, produce_own_header, queued_effect_id, reserved_da_runs,
    route_blocks, sign_job, sign_request, stage_eligible, start_profile, symbolic_da_certificate,
    symbolic_nullification, threshold_share, validate_block,
};
use crate::{
    Epochable,
    multimmit::{
        config::{HEIGHT_WINDOW_PIPELINES, LeaderSchedule, Profile, Role, Tuning},
        machine::{
            capability::{Capability, ChainCommand, ObservedBlock, ValidatorCommand},
            chain::ChainState,
            durability::{
                Change, DischargeKind, DomainEvent, DomainEventCodecConfig, DurableEffect,
                EffectCompletion, OutboxEntry, PersistDirective, Publication, SendRequest,
                SignEffect, SignRequest, Snapshot, SnapshotCodecConfig,
            },
            input::{
                CryptoCompletion, DaVotesOffer, Input, ObservationStatus, Rejection, StepError,
                StepStatus,
            },
            job::Generation,
            producer::BuildCompletion,
            reducer::machine::Machine,
            scheduler::DA_VOTE_RUN,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, MachineExt as _,
                Until, VerifyJobExt as _, cohort,
            },
            verification::{Verdict, VerificationCompletion},
        },
        types::{
            Activity, Anchor, Artifact, ChainId, ChainProposal, DaVote, DigestedLeader, Extension,
            LeaderBlock, Position, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, Vote, VoteBody,
        },
    },
    types::{Height, Participant, Round, View},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn da_choices_below_a_newer_certificate_still_endorse_proposed_positions() {
    // Pipelining depth 2: the retained window below the certified floor is two heights.
    let profile = Harness::validator(0).participants(6).profile();
    let mut chain = ChainState::<MinPk, Digest>::new(&profile);
    let protocol = profile.protocol();
    let genesis = protocol.genesis().tips()[0];
    let mut parent = genesis.digest();
    let mut headers = Vec::new();
    for height in 1..=3u64 {
        let header = TransactionBlockHeader::new(
            protocol.epoch(),
            ChainId::new(0),
            Height::new(height),
            parent,
            digest(format!("body {height}").as_bytes()),
        )
        .unwrap();
        parent = header.digest::<Sha256>();
        headers.push(header);
    }
    chain
        .da
        .reconcile_choices::<Sha256>(headers.clone())
        .unwrap();

    // A certificate for height 3 retires those heights as availability work. A leader that held
    // only the height-1 certificate when it proposed still names heights 2 and 3 as payloads,
    // and this voter DA-voted both, so its vote must endorse position 2.
    chain
        .compact_certified::<Sha256>(
            &symbolic_da_certificate(headers[2].clone(), 0),
            Height::new(3),
        )
        .unwrap();
    let depth = protocol.codec_config().pipeline_depth();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            if tip.chain() == ChainId::new(0) {
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Certificate(symbolic_da_certificate(headers[0].clone(), 1)),
                    vec![headers[1].body_digest(), headers[2].body_digest()],
                    depth,
                )
            } else {
                ChainProposal::new(tip.chain(), Anchor::Tip(*tip), Vec::new(), depth)
            }
            .unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(protocol),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let body = chain.vote_body::<Sha256>(&leader).unwrap();
    assert_eq!(body.positions()[0], Position::new(2));
}

#[test]
fn da_certificate_atomically_replaces_the_block_and_vote_publications() {
    let role = Role::Validator(Participant::new(0));
    let (mut machine, mut step) = Harness::builder(role).participants(6).start();
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = machine.persist(&job, Until::CursorAdvance);
    }
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(0),
        Height::new(1),
        genesis.digest(),
        digest(b"superseded block"),
    )
    .unwrap();
    let block = Arc::new(Artifact::TransactionBlock(SignedTransactionBlock::new(
        header.clone(),
        attestation(0),
    )));
    let vote = Arc::new(Artifact::DaVote(DaVote::new(
        header.clone(),
        threshold_share(0),
    )));
    let block_step = machine
        .reserve_test_effect(DurableEffect::broadcast(block))
        .unwrap();
    let block_id = queued_effect_id(&block_step);
    machine.persist(&block_step.persist_job(), Until::CursorAdvance);
    let vote_step = machine
        .reserve_test_effect(DurableEffect::Publish(Publication::Send(Arc::from([
            SendRequest::new(Participant::new(0), vote),
        ]))))
        .unwrap();
    let vote_id = queued_effect_id(&vote_step);
    machine.persist(&vote_step.persist_job(), Until::CursorAdvance);

    let certificate = Artifact::DaCertificate(symbolic_da_certificate(header, 0));
    let verification = observe(&mut machine, certificate.clone());
    let replacement = machine.verify(&verification, true, Until::CursorAdvance);
    let job = replacement.persist_job();
    let Change::DaCertificateAdvanced {
        publication,
        retired_publications: retired,
        artifact,
    } = job.events()[0].change()
    else {
        panic!("admitted DA certificate must replace its source publications");
    };
    assert_eq!(retired, &[block_id, vote_id]);
    assert!(publication.is_some());
    assert_eq!(artifact.as_ref(), &certificate);
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&block_id)
    );
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&vote_id)
    );
    let acknowledged = machine.persist(&job, Until::Step);
    let acknowledged = machine.settle(acknowledged, Until::CursorAdvance);
    assert!(
        acknowledged
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Journal(_)))
    );
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&block_id)
    );
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&vote_id)
    );
}

#[test]
fn remote_da_certificate_retires_vote_without_rebroadcast_and_replays() {
    let profile = Harness::validator(3)
        .participants(6)
        .producers(vec![Participant::new(1), Participant::new(4)])
        .profile();
    let (mut machine, mut step) = start_profile(profile.clone());
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = machine.persist(&job, Until::CursorAdvance);
    }

    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"remote certified block"),
    )
    .unwrap();
    let vote = Arc::new(Artifact::DaVote(DaVote::new(
        header.clone(),
        threshold_share(3),
    )));
    let vote_step = machine
        .reserve_test_effect(DurableEffect::Publish(Publication::Send(Arc::from([
            SendRequest::new(Participant::new(4), vote),
        ]))))
        .unwrap();
    let vote_id = queued_effect_id(&vote_step);
    machine.persist(&vote_step.persist_job(), Until::CursorAdvance);
    let checkpoint = machine.live_snapshot_for_test();

    let certificate = Arc::new(Artifact::DaCertificate(symbolic_da_certificate(header, 4)));
    let verification = observe(&mut machine, certificate.as_ref().clone());
    let replacement = machine.verify(&verification, true, Until::CursorAdvance);
    let replacement_job = replacement.persist_job();
    let Change::DaCertificateAdvanced {
        publication,
        retired_publications: retired,
        artifact,
    } = replacement_job.events()[0].change()
    else {
        panic!("the remote certificate must retire the directed DA vote");
    };
    assert_eq!(publication, &None);
    assert_eq!(retired, &[vote_id]);
    assert_eq!(artifact, &certificate);

    machine.persist(&replacement_job, Until::CursorAdvance);
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&vote_id)
    );
    assert!(
        machine
            .live_snapshot_for_test()
            .outbox()
            .values()
            .all(|effect| {
                !matches!(effect.broadcast_one(), Some(artifact) if artifact == &certificate)
            })
    );
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::broadcast(Arc::clone(&certificate))),
        Err(StepError::UnauthorizedEffect)
    ));

    let mut restored = Machine::<Sha256, MinPk>::restore(profile, checkpoint).unwrap();
    for event in replacement_job.events() {
        restored.replay(event.clone()).unwrap();
    }
    assert!(
        !restored
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&vote_id)
    );
    assert!(
        restored
            .live_snapshot_for_test()
            .outbox()
            .values()
            .all(|effect| {
                !matches!(effect.broadcast_one(), Some(artifact) if artifact == &certificate)
            })
    );
}

#[test]
fn full_outbox_exit_replacement_uses_the_retired_slot() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(16))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(1))
        .with_max_forwarded_certificates(NonZeroUsize::new(16).unwrap());
    let profile = Harness::observer()
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile);

    for view in 1..=2 {
        let artifact =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, artifact);
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        for _ in 0..8 {
            let Some(job) = step.find(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                _ => None,
            }) else {
                break;
            };
            step = machine.persist(&job, Until::CursorAdvance);
        }
    }

    let exits = machine
        .durable
        .state
        .outbox
        .values()
        .flat_map(OutboxEntry::discharges)
        .filter_map(|discharge| match discharge.until() {
            DischargeKind::ExitReplacedAfter { view } => Some(view),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exits, vec![View::new(2)]);
    assert_eq!(machine.live_snapshot_for_test().outbox().len(), 1);
}

#[test]
fn delayed_da_vote_signing_completion_retires_after_certification() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"certified before signing completion"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, header.clone(), genesis.chain().get());
    let sign = sign_job(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(header.clone(), 1)),
    );
    let certified = machine.verify(&certificate, true, Until::CursorAdvance);
    machine.persist(&certified.persist_job(), Until::CursorAdvance);
    assert_eq!(
        machine.live_snapshot_for_test().certified_tips()[genesis.chain().get() as usize].height(),
        Height::new(1)
    );

    let vote = Artifact::DaVote(DaVote::new(header, threshold_share(0)));
    let vote_id = vote.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(vote)],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completion_job = completed.persist_job();
    let [event] = completion_job.events() else {
        panic!("signed completion must remain one durable transition");
    };
    let Change::SignedArtifacts { publication, .. } = event.change() else {
        panic!("the delayed signing result must complete its reservation");
    };
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&sign.issued().id())
    );
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(publication)
    );
    assert!(
        machine
            .live_snapshot_for_test()
            .local_artifacts()
            .contains_key(&vote_id)
    );
}

/// Items a DA certificate already covers do not count against the live DA obligation bound, so
/// batches held open by one uncertified item stay recoverable.
#[test]
fn certified_items_in_mixed_da_batches_do_not_exhaust_live_obligations() {
    let profile = Harness::validator(0)
        .participants(6)
        .depth(4)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(512))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(128)),
        )
        .profile();
    let (mut machine, mut started) = start_profile(profile.clone());
    while let Some(job) = started.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        started = machine.persist(&job, Until::CursorAdvance);
    }
    let headers = (0..6)
        .map(|chain| da_run_headers(&machine, chain, 16, "mixed certification"))
        .collect::<Vec<_>>();

    for round in 0..4 {
        // Chain zero leaves one vote outstanding per batch, within its pipeline. Every other
        // chain certifies its entire four-block run before the next batch is reserved.
        let batch = (0..6)
            .flat_map(|chain| {
                let range = if chain == 0 {
                    round..round + 1
                } else {
                    round * 4..(round + 1) * 4
                };
                headers[chain][range].iter().cloned()
            })
            .collect::<Vec<_>>();
        let requests = batch
            .iter()
            .map(|header| {
                SignRequest::DaVote(Arc::new(SignedTransactionBlock::new(
                    header.clone(),
                    attestation(header.chain().get()),
                )))
            })
            .collect::<Vec<_>>();
        let reserved = machine
            .reserve_test_effect(DurableEffect::Sign(SignEffect::new(requests.into())))
            .unwrap();
        let signing = reserved
            .find(|effect| match effect {
                Capability::Released(job) if job.request().sign_many().is_some() => {
                    Some(job.clone())
                }
                _ => None,
            })
            .expect("the batch signing reservation is issued");
        machine.persist(&reserved.persist_job(), Until::CursorAdvance);
        let completed = machine
            .step(Input::EffectCompleted(EffectCompletion::signed(
                signing.issued(),
                batch
                    .into_iter()
                    .map(|header| {
                        Arc::new(Artifact::DaVote(DaVote::new(header, threshold_share(0))))
                    })
                    .collect(),
            )))
            .unwrap();
        let completed = machine.settle(completed, Until::CursorAdvance);
        machine.persist(&completed.persist_job(), Until::CursorAdvance);

        for (chain, headers) in headers.iter().enumerate().skip(1) {
            let certificate = Artifact::DaCertificate(symbolic_da_certificate(
                headers[(round + 1) * 4 - 1].clone(),
                (round * 6 + chain) as u64,
            ));
            let verification = observe(&mut machine, certificate);
            let certified = machine.verify(&verification, true, Until::CursorAdvance);
            machine.persist(&certified.persist_job(), Until::CursorAdvance);
        }
        Machine::<Sha256, MinPk>::restore(profile.clone(), machine.live_snapshot_for_test())
            .expect("partially certified batches remain recoverable");
    }

    let snapshot = machine.live_snapshot_for_test();
    assert_eq!(snapshot.outbox().len(), 4);
    assert!(
        snapshot
            .outbox()
            .values()
            .flat_map(OutboxEntry::discharges)
            .count()
            > machine.obligation_family_bounds().da
    );
    assert_eq!(snapshot.certified_tips()[0].height(), Height::zero());
    assert!(
        snapshot.certified_tips()[1..]
            .iter()
            .all(|tip| tip.height() == Height::new(16))
    );
}

#[test]
fn typed_obligation_family_bounds_match_their_retained_state() {
    let machine = active_machine(Role::Observer);
    let bounds = machine.obligation_family_bounds();
    let participants = machine.profile().codec().participants();
    let depth = machine.profile().codec().pipeline_depth();
    let retained_views = usize::try_from(machine.profile().view_retention().get() + 1).unwrap();

    assert_eq!(bounds.own_messages, retained_views * 4);
    assert_eq!(bounds.da, participants * depth * 3);
}

#[test]
fn da_frontier_cannot_monopolize_durable_progress() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let genesis = machine.profile().protocol().genesis().tips();
    let certificates = [0, 1].map(|chain| {
        let tip = genesis[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            tip.chain(),
            Height::new(1),
            tip.digest(),
            digest(format!("certified chain {chain}").as_bytes()),
        )
        .unwrap();
        Artifact::DaCertificate(symbolic_da_certificate(header, chain as u64))
    });
    let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 2));

    let observed = machine
        .step(cohort::<Sha256, _>(
            certificates.into_iter().chain([exit]).collect(),
        ))
        .unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("the artifact batch must be verified together");
    };
    let first = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    let first = machine.settle(first, Until::CursorAdvance);
    let first_job = first.persist_job();
    let next = machine.persist(&first_job, Until::CursorAdvance);
    let next_job = next.persist_job();
    let mut changes = first_job
        .events()
        .iter()
        .chain(next_job.events())
        .map(|event| event.change());
    assert!(
        changes
            .clone()
            .any(|change| matches!(change, Change::DaCertificateAdvanced { .. }))
    );
    assert!(changes.any(|change| matches!(change, Change::ArtifactForwarded { .. })));
}

#[test]
fn higher_da_certificate_replacement_replays_atomically() {
    let profile = Harness::validator(0).participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"first certified block"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        first.epoch(),
        first.chain(),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"retained intermediate block"),
    )
    .unwrap();
    let third = TransactionBlockHeader::new(
        second.epoch(),
        second.chain(),
        Height::new(3),
        second.block_ref::<Sha256>().digest(),
        digest(b"higher certified block"),
    )
    .unwrap();

    let first_certificate = symbolic_da_certificate(first, 1);
    let first_verification = observe(
        &mut machine,
        Artifact::DaCertificate(first_certificate.clone()),
    );
    let advanced = machine.verify(&first_verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let first_publication = machine
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(Artifact::DaCertificate(
            first_certificate,
        ))))
        .unwrap();
    let first_publication_id = queued_effect_id(&first_publication);
    machine.persist(&first_publication.persist_job(), Until::CursorAdvance);

    let da_choice = validate_block(&mut machine, second, 0);
    let da_choice_job = da_choice.persist_job();
    machine.persist(&da_choice_job, Until::CursorAdvance);
    let checkpoint = machine.live_snapshot_for_test();

    let third_certificate = symbolic_da_certificate(third, 3);
    let third_verification = observe(
        &mut machine,
        Artifact::DaCertificate(third_certificate.clone()),
    );
    let replacement = machine.verify(&third_verification, true, Until::CursorAdvance);
    let replacement_job = replacement.persist_job();
    let Change::DaCertificateAdvanced {
        publication,
        retired_publications: retired,
        artifact,
    } = replacement_job.events()[0].change()
    else {
        panic!("the higher certificate must replace its certified ancestor");
    };
    assert_eq!(retired, &[first_publication_id]);
    let publication = publication.expect("the replacement needs one active retry");
    assert!(matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
        if actual == &third_certificate));

    let mut restored = Machine::<Sha256, MinPk>::restore(profile, checkpoint).unwrap();
    for event in replacement_job.events() {
        restored.replay(event.clone()).unwrap();
    }
    let snapshot = restored.live_snapshot_for_test();
    assert!(!snapshot.outbox().contains_key(&first_publication_id));
    assert!(
        matches!(snapshot.outbox().get(&publication).and_then(EffectExt::broadcast_one),
        Some(artifact)
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
                if actual == &third_certificate))
    );
    let recovered = restored.step(Input::RecoveryComplete).unwrap();
    let released = restored.persist(&recovered.persist_job(), Until::CursorAdvance);
    assert!(
        !restored
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&first_publication_id)
    );
    assert!(released.has(|effect| {
        matches!(durable_job(effect), Some(job)
        if job.issued().id() == publication
            && matches!(job.request().broadcast_one(), Some(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
                if actual == &third_certificate))
            )
    }));
}

#[test]
fn da_vote_choice_is_durable_and_sent_only_to_the_producer() {
    let mut machine = Machine::new(
        Harness::validator(3)
            .participants(6)
            .producers(vec![Participant::new(1), Participant::new(4)])
            .profile(),
    );
    assert_eq!(
        machine
            .profile()
            .protocol()
            .producer_chain(Participant::new(3)),
        None
    );
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"remote body"),
    )
    .unwrap();

    let reserved = validate_block(&mut machine, header.clone(), 4);
    let choice = reserved.persist_job();
    assert!(matches!(
        choice.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::DaVote(actual)) if actual.header() == &header)
    ));
    // Signing carries no signature out of the process, so the request releases at staging;
    // only the signed vote's publication waits for its record's durability.
    let sign = reserved
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_one().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("the staged DA choice must release signing immediately");
    assert!(matches!(sign_request(&sign), SignRequest::DaVote(actual)
        if actual.header() == &header));
    let released = machine.persist(&choice, Until::CursorAdvance);
    assert!(
        !released.has(|effect| durable_effect(effect)
            .and_then(EffectExt::sign_one)
            .is_some()),
        "the acknowledgement must not release the signing request a second time"
    );

    let vote = Artifact::DaVote(DaVote::new(header.clone(), threshold_share(3)));
    let vote_id = vote.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(vote)],
        )))
        .unwrap();
    // The completion parks; settling drains it into its staging barrier, and the self-admission
    // shows up in the artifact cache.
    assert!(matches!(completed.status(), StepStatus::Accepted));
    let completed = machine.settle(completed, Until::CursorAdvance);
    assert!(machine.store.artifacts.contains_key(&vote_id));
    let published = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let send = published
        .find(|capability| match capability {
            Capability::Released(job) => Some(job),
            _ => None,
        })
        .expect("a DA vote must use directed publication");
    let Some(request) = send.request().send_one() else {
        panic!("a DA vote must use directed publication");
    };
    assert_eq!(request.recipient(), Participant::new(4));
    assert!(matches!(
        request.artifact().as_ref(),
        Artifact::DaVote(vote) if vote.header() == &header
    ));
    assert_eq!(machine.inspect().local_artifacts(), 1);
}

#[test]
fn producer_subset_snapshots_restore_for_every_validator_role() {
    let producers = vec![Participant::new(4), Participant::new(1)];
    for participant in [Participant::new(3), Participant::new(4)] {
        let profile = Harness::builder(Role::Validator(participant))
            .participants(6)
            .producers(producers.clone())
            .profile();
        let machine = Machine::<Sha256, MinPk>::new(profile.clone());
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test())
            .expect("K<n snapshot restores");
    }
}

#[test]
fn durable_da_vote_enables_the_next_height_in_the_same_drain() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"second"),
    )
    .unwrap();

    let routed = route_blocks(&mut machine, 1, &[first.clone(), second.clone()]);
    // The validated parent and child form one contiguous eligible run: the machine reserves both
    // heights in one drain, the first's in-batch vote counting as sent for the second's eligibility.
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, vec![first, second]);
}

#[test]
fn da_vote_offer_from_another_generation_is_stale() {
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let headers = da_run_headers(&machine, 1, 1, "stale offer");
    let routed = route_blocks(&mut machine, 1, &headers);
    let (candidates, ready_through) = plane_eligible_run(&machine, 1, &routed);

    let stale = machine.offer_da_votes(DaVotesOffer {
        generation: Generation::new(machine.generation().get() + 1),
        chain: ChainId::new(1),
        candidates,
        ready_through,
    });
    assert_eq!(stale, StepStatus::StaleCompletion);
    machine.settle(poll_seed(), Until::CursorAdvance);
    assert!(
        machine
            .live_snapshot_for_test()
            .signing_reservations()
            .is_empty(),
        "a stale offer must not reserve a DA vote"
    );

    // The same run offered under the current generation reserves.
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, headers);
}

#[test]
fn da_votes_eligible_behind_one_barrier_reserve_as_one_batch() {
    // Four producer chains of two heights each. The first chain's first height reserves alone and
    // leaves its barrier in flight; every block that becomes eligible behind it must arrive as one
    // signing action carrying one consecutive run per chain, not one action per eligible block.
    let profile = Harness::validator(0)
        .participants(6)
        .depth(4)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(64))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(64)),
        )
        .profile();
    let (mut machine, _) = start_profile(profile);
    let runs = (1..=4)
        .map(|chain| da_run_headers(&machine, chain, 2, "coalesced"))
        .collect::<Vec<_>>();

    // Route every chain's run so the machine records ancestry; the planes then offer the eligible runs.
    let routed = (1..=4u32)
        .map(|chain| route_blocks(&mut machine, chain, &runs[(chain - 1) as usize]))
        .collect::<Vec<_>>();

    // The first chain offers only its first height, which reserves alone and leaves its barrier in
    // flight.
    let opened = offer_eligible(&mut machine, 1, &routed[0][..1]);
    let barrier = opened.persist_job();
    assert_eq!(reserved_da_runs(&barrier), vec![vec![runs[0][0].clone()]]);

    // Everything else becomes eligible while that barrier is unacknowledged: the first chain's held
    // child and every other chain's full run.
    for chain in 1..=4u32 {
        stage_eligible(&mut machine, chain, &routed[(chain - 1) as usize]);
    }
    machine.settle(poll_seed(), Until::CursorAdvance);
    assert_eq!(
        machine
            .live_snapshot_for_test()
            .signing_reservations()
            .len(),
        1,
        "an unacknowledged reservation must absorb later eligible blocks"
    );

    // The acknowledgement releases them all as one batch, in round-robin chain order starting
    // after the chain the previous reservation served.
    let acknowledged = machine.persist(&barrier, Until::CursorAdvance);
    let coalesced = reserved_da_runs(&acknowledged.persist_job());
    let expected = runs[1..]
        .iter()
        .flatten()
        .chain(core::iter::once(&runs[0][1]))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(coalesced, vec![expected]);
}

#[test]
fn da_vote_batch_stops_at_the_per_chain_run_limit() {
    // One chain far enough ahead of its certified floor to offer more consecutive heights than a
    // single batch may carry. The run limit caps the batch; the remainder follows the next barrier.
    let profile = Harness::validator(0)
        .participants(6)
        .depth(64)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(128))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(128)),
        )
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let headers = da_run_headers(&machine, 1, DA_VOTE_RUN as u64 + 4, "run limit");

    let routed = route_blocks(&mut machine, 1, &headers);
    // The first height is eligible first and reserves alone as the barrier.
    let opened = offer_eligible(&mut machine, 1, &routed[..1]);
    let barrier = opened.persist_job();
    assert_eq!(reserved_da_runs(&barrier), vec![vec![headers[0].clone()]]);
    // The remaining heights become eligible while that barrier is unacknowledged.
    stage_eligible(&mut machine, 1, &routed);
    machine.settle(poll_seed(), Until::CursorAdvance);

    let acknowledged = machine.persist(&barrier, Until::CursorAdvance);
    let capped = acknowledged.persist_job();
    let runs = reserved_da_runs(&capped);
    assert_eq!(runs, vec![headers[1..=DA_VOTE_RUN].to_vec()]);
    // The batch is one action whose event stays inside the journal's decoding bounds.
    let config = DomainEventCodecConfig::from_profile(&profile);
    for event in capped.events() {
        let encoded = event.encode();
        assert!(encoded.len() <= config.max_encoded_size());
        assert_eq!(
            &DomainEvent::<MinPk, Digest>::decode_cfg(encoded, &config).unwrap(),
            event
        );
    }

    let remainder = machine.persist(&capped, Until::CursorAdvance);
    assert_eq!(
        reserved_da_runs(&remainder.persist_job()),
        vec![headers[DA_VOTE_RUN + 1..].to_vec()]
    );
}

#[test]
fn wide_da_vote_publication_survives_the_snapshot_codec() {
    // A signed run publishes as one directed batch that carries more votes than there are chains,
    // so the recovery codecs must admit the run length the signing batch was allowed to reserve.
    let profile = Harness::validator(0)
        .participants(6)
        .depth(64)
        .resources(
            TEST_RESOURCES
                .with_max_cached_artifacts(NZUsize!(128))
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_outbox_effects(NZUsize!(128)),
        )
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let headers = da_run_headers(&machine, 1, DA_VOTE_RUN as u64, "wide publication");
    assert!(DA_VOTE_RUN > profile.codec().chains());

    let routed = route_blocks(&mut machine, 1, &headers);
    let opened = offer_eligible(&mut machine, 1, &routed[..1]);
    let barrier = opened.persist_job();
    stage_eligible(&mut machine, 1, &routed);
    machine.settle(poll_seed(), Until::CursorAdvance);
    let acknowledged = machine.persist(&barrier, Until::CursorAdvance);
    let staged = acknowledged.persist_job();
    assert_eq!(reserved_da_runs(&staged), vec![headers[1..].to_vec()]);

    let batch = acknowledged
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_many().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("a coalesced run releases one batch signing job");
    machine.persist(&staged, Until::CursorAdvance);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            batch.issued(),
            headers[1..]
                .iter()
                .map(|header| {
                    Arc::new(Artifact::DaVote(DaVote::new(
                        header.clone(),
                        threshold_share(0),
                    )))
                })
                .collect(),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let published = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let send = published
        .find(|effect| durable_effect(effect).and_then(EffectExt::send_many))
        .expect("a signed run publishes as one directed batch");
    assert_eq!(send.len(), DA_VOTE_RUN - 1);

    let snapshot = machine.live_snapshot_for_test();
    let config = SnapshotCodecConfig::from_profile(&profile);
    let decoded = Snapshot::<MinPk, Digest>::decode_cfg(snapshot.encode(), &config)
        .expect("a wide directed publication stays decodable");
    Machine::<Sha256, MinPk>::restore(profile, decoded)
        .expect("recovery restores the wide publication");
}

#[test]
fn durable_da_certificate_precedes_child_vote_reservation() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips();
    let competing_genesis = genesis[0];
    let parent_genesis = genesis[1];
    let parent = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        parent_genesis.digest(),
        digest(b"certified parent"),
    )
    .unwrap();
    let child = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        parent.block_ref::<Sha256>().digest(),
        digest(b"validated child"),
    )
    .unwrap();

    // The child is votable only once a durable DA path to its parent exists. Here that path is a
    // certificate, not a DA vote: the parent is certified below and is never itself DA-voted. The
    // child is routed only after the certificate advances the anchor to the parent, since a routed
    // block on a chain defers that chain's certificate advance.
    let competing = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(0),
        Height::new(1),
        competing_genesis.digest(),
        digest(b"competing certificate"),
    )
    .unwrap();
    // Advance both certificates durably. The parent's certificate is the one that lifts the child's
    // DA safety floor; a competing certificate on the local chain does not stand in for it.
    let competing_cert = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(competing, 0)),
    );
    let competing_advanced = machine.verify(&competing_cert, true, Until::CursorAdvance);
    machine.persist(&competing_advanced.persist_job(), Until::CursorAdvance);
    let parent_cert = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(parent.clone(), 1)),
    );
    let parent_advanced = machine.verify(&parent_cert, true, Until::CursorAdvance);
    let advanced_job = parent_advanced.persist_job();
    assert!(
        advanced_job.events().iter().any(|event| {
            matches!(event.change(),
                Change::DaCertificateAdvanced { artifact, .. }
                    if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                        if certificate.header() == &parent))
        }),
        "the DA owner must durably advance the parent certificate before the child votes"
    );
    machine.persist(&advanced_job, Until::CursorAdvance);

    // Only now, with the child's durable DA safety floor lifted by the certificate, can the child,
    // offered by its chain plane once the anchor advanced, reserve its vote.
    let routed = route_blocks(&mut machine, 1, std::slice::from_ref(&child));
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, vec![child]);
}

#[test]
fn certification_lag_does_not_silence_later_da_votes() {
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let epoch = machine.profile().protocol().epoch();
    let first = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"lagged floor first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"lagged floor second"),
    )
    .unwrap();
    let third = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(3),
        second.block_ref::<Sha256>().digest(),
        digest(b"lagged floor third"),
    )
    .unwrap();

    // Every block finishes validation while the local certified floor still sits at genesis, so
    // the third block completes beyond the pipeline window and no vote can exist for it yet.
    let routed = route_blocks(
        &mut machine,
        1,
        &[first.clone(), second.clone(), third.clone()],
    );
    // Every block validates while the certified floor still sits at genesis, so the third completes
    // beyond the pipeline window and no vote can exist for it yet: only the first two are eligible.
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, vec![first.clone(), second]);

    // The cluster certifies the first height, moving the pipeline window over the third block.
    // The vote must resume even though the block was validated before the floor advanced.
    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(first, 1)),
    );
    let certified = machine.verify(&certificate, true, Until::CursorAdvance);
    // Persist the certificate so the anchor advances the pipeline window over the third block.
    machine.drain_persisting(certified);
    let resumed_step = offer_eligible(&mut machine, 1, &routed);
    let mut resumed = Vec::new();
    drain_da_choices(&mut machine, resumed_step, &mut resumed);
    assert_eq!(resumed, vec![third]);
}

#[test]
fn finalized_parent_requires_a_real_da_path_before_voting_for_its_child() {
    let role = Role::Validator(Participant::new(0));
    let (mut machine, _) = Harness::builder(role).participants(6).start();
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"finalized unseen parent"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        first.epoch(),
        first.chain(),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"held finalized child"),
    )
    .unwrap();
    let base = leader(&machine, 5);
    let mut proposals = base.proposals().to_vec();
    proposals[1] = ChainProposal::new(
        genesis.chain(),
        Anchor::Tip(genesis),
        vec![first.body_digest()],
        machine.profile().codec().pipeline_depth(),
    )
    .unwrap();
    let finalized = LeaderBlock::new(
        base.round(),
        base.parent(),
        base.history(),
        proposals,
        machine.profile().codec(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| {
            let mut positions = vec![Position::new(0); 6];
            positions[1] = Position::new(1);
            let body = VoteBody::for_leader(
                DigestedLeader::new::<Sha256>(&finalized),
                positions,
                vec![Extension::empty(); 6],
                machine.profile().codec(),
            )
            .unwrap();
            Vote::new(body, attestation(signer))
        })
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);

    assert_eq!(
        machine.inspect().chain_progress()[1].finalized(),
        Height::new(1)
    );
    assert_eq!(
        machine.live_snapshot_for_test().certified_tips()[1],
        genesis
    );
    assert_eq!(
        machine.live_snapshot_for_test().da_safety_heights()[1],
        genesis.height()
    );

    // The chain's DA safety floor was not advanced by the leader block's finality, so the child is
    // votable only behind a real DA vote for its parent, never on the strength of finality alone
    // (the chain plane gates this; see its unit coverage). Once both validate, the
    // parent's choice releases the held child into the same reservation: consecutive DA votes batch
    // as one run, each counting as sent for the next one's eligibility.
    let routed = route_blocks(&mut machine, 1, &[first.clone(), second.clone()]);
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut queued = Vec::new();
    drain_da_choices(&mut machine, opened, &mut queued);
    assert_eq!(
        queued,
        vec![first, second],
        "the durable parent choice must release the held child in run order"
    );
}

#[test]
fn application_digest_collision_retains_distinct_header_ancestry() {
    let mut machine = Machine::new(Harness::observer().participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make_parent = |body| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            body,
        )
        .unwrap()
    };
    let first_parent = make_parent(digest(b"first application parent"));
    let second_parent = make_parent(digest(b"second application parent"));
    validate_block(&mut machine, first_parent.clone(), 1);
    validate_block(&mut machine, second_parent.clone(), 1);

    let commitment = digest(b"shared untrusted application digest");
    let make = |parent| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(2),
            parent,
            commitment,
        )
        .unwrap()
    };
    let first = make(first_parent.block_ref::<Sha256>().digest());
    let second = make(second_parent.block_ref::<Sha256>().digest());
    // The two children share an application digest but descend from distinct parents. The machine
    // records each header's producer ancestry independently as it routes them to their
    // chain plane, so a shared body digest never collapses their distinct lineages.
    route_blocks(&mut machine, 1, &[first, second]);
    assert_eq!(machine.chain.da.retained_ancestry(), 4);
}

#[test]
fn da_fork_selection_does_not_depend_on_verification_completion_order() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let earlier = make(digest(b"earlier unverified fork"));
    let later = make(digest(b"later verified fork"));
    let earlier_job = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(earlier, attestation(1))),
    );
    let later_job = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(later.clone(), attestation(1))),
    );

    // Verify the later fork and reject the earlier one. Only the verified fork reaches the chain's
    // chain plane, so the DA choice lands on it regardless of the order verifications complete.
    let verified_later = machine
        .step(Input::Verified(later_job.all_valid()))
        .unwrap();
    let verified_later = machine.settle(verified_later, Until::CursorAdvance);
    let routed = verified_later
        .find(|effect| match effect {
            Capability::Validator(
                _,
                ValidatorCommand::Observe(ObservedBlock {
                    id,
                    observation,
                    block,
                    custodied,
                }),
            ) => Some((*id, *observation, block.clone(), *custodied)),
            _ => None,
        })
        .expect("the verified fork routes to its chain plane");

    let rejected_earlier = machine
        .step(Input::Verified(VerificationCompletion::new(
            earlier_job.issued(),
            vec![Verdict::new(earlier_job.items()[0].ticket(), false)],
        )))
        .unwrap();
    machine.settle(rejected_earlier, Until::CursorAdvance);

    let opened = offer_eligible(&mut machine, 1, &[routed]);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, vec![later]);
}

#[test]
fn producer_recovers_the_canonical_da_quorum_and_retains_the_certificate() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let header = produce_own_header(&mut machine);
    let block = header.block_ref::<Sha256>();
    let certificate = symbolic_da_certificate(header, 0);
    let recovered = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block,
            certificate: certificate.clone(),
        }))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging barrier.
    assert_eq!(recovered.status(), &StepStatus::Accepted);
    let recovered = machine.settle(recovered, Until::CursorAdvance);
    assert!(matches!(
        recovered.persist_job().events()[0].change(),
        Change::DaCertificateAdvanced {
            publication: Some(_),
            artifact,
            ..
        }
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
    assert!(
        recovered.has(|effect| {
            matches!(durable_effect(effect).and_then(EffectExt::broadcast_one), Some(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate))
        }),
        "staging must release the recovered certificate"
    );
    let published = machine.persist(&recovered.persist_job(), Until::CursorAdvance);
    assert!(!matches!(
        published.capabilities().first().and_then(durable_effect).and_then(EffectExt::broadcast_one),
        Some(artifact)
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
    assert_eq!(machine.inspect().local_artifacts(), 1);
}

#[test]
fn local_da_certificate_promotes_an_identical_pending_artifact() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let header = produce_own_header(&mut machine);
    let block = header.block_ref::<Sha256>();
    let certificate = symbolic_da_certificate(header, 0);
    let certificate_id = Artifact::DaCertificate(certificate.clone()).id::<Sha256>();
    let inbound = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));

    let local = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block,
            certificate,
        }))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging barrier.
    assert_eq!(local.status(), &StepStatus::Accepted);
    let local = machine.settle(local, Until::CursorAdvance);
    machine.persist(&local.persist_job(), Until::CursorAdvance);
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
    assert!(
        machine
            .inspect()
            .ready_artifacts()
            .contains(&certificate_id)
    );
}

#[test]
fn recovery_reissues_the_exact_durable_da_vote() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = Machine::new(Harness::builder(role).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"recoverable DA vote"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, header.clone(), 1);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let mut restored = Machine::<Sha256, MinPk>::restore(
        Harness::builder(role).participants(6).profile(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let exact = recovered.has(|effect| {
        matches!(durable_effect(effect).and_then(EffectExt::sign_one), Some(
            SignRequest::DaVote(actual)
        ) if actual.header() == &header)
    });
    assert!(exact, "recovery must reissue the durable DA choice");
}

#[test]
fn invalid_da_certificate_does_not_block_the_valid_certificate() {
    let mut machine = Machine::new(Harness::observer().participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"retry certificate"),
    )
    .unwrap();
    let forged = symbolic_da_certificate(header.clone(), 0);
    let forged = observe(&mut machine, Artifact::DaCertificate(forged));
    let recovered = symbolic_da_certificate(header, 1);
    let recovered = observe(&mut machine, Artifact::DaCertificate(recovered));
    machine.verify(&recovered, true, Until::CursorAdvance);
    let waiting = machine.chain.propose_chain(genesis).unwrap();
    assert!(matches!(waiting.anchor(), Anchor::Tip(_)));

    let advanced = machine.verify(&forged, false, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let promoted = machine.chain.propose_chain(genesis).unwrap();
    assert!(matches!(promoted.anchor(), Anchor::Certificate(_)));
    assert_eq!(machine.inspect().ready_artifacts().len(), 1);
}

#[test]
fn certified_proposals_stop_at_the_held_certificate() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).depth(3).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let headers = frontier_chain(&machine, 2);

    let voted = validate_block(&mut machine, headers[0].clone(), 1);
    machine.persist(&voted.persist_job(), Until::CursorAdvance);
    let _ = authenticate_block(&mut machine, headers[1].clone(), 1);

    let uncertified = machine.chain.propose_chain(genesis).unwrap();
    assert!(
        matches!(uncertified.anchor(), Anchor::Tip(tip) if *tip == genesis),
        "a DA-voted block with no held certificate must not reach the proposal",
    );
    assert!(uncertified.payloads().is_empty());

    let certificate = symbolic_da_certificate(headers[0].clone(), 0);
    let observed = observe(&mut machine, Artifact::DaCertificate(certificate));
    let completed = machine.verify(&observed, true, Until::CursorAdvance);
    machine.persist(&completed.persist_job(), Until::CursorAdvance);

    let certified = machine.chain.propose_chain(genesis).unwrap();
    assert!(
        matches!(certified.anchor(), Anchor::Certificate(certificate)
            if certificate.block_ref::<Sha256>() == headers[0].block_ref::<Sha256>()),
        "the held certificate must anchor the proposal",
    );
    assert!(
        certified.payloads().is_empty(),
        "a certified proposal must add nothing above the certificate it holds",
    );
}

#[test]
fn position_finality_covers_proposed_blocks_without_local_bodies() {
    let profile = Harness::validator(0).participants(6).depth(3).profile();
    let (mut machine, _) = start_profile(profile);
    let headers = frontier_chain(&machine, 2);

    // A leader proposes chain 1 two blocks past its tip. This node never ingests either body,
    // yet position finality must still cover the blocks the committee endorses.
    let protocol = machine.profile().protocol().clone();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            let payloads = if tip.chain() == ChainId::new(1) {
                vec![headers[0].body_digest(), headers[1].body_digest()]
            } else {
                Vec::new()
            };
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                payloads,
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let block = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(2)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    assert_eq!(
        block.proposals()[1].payloads(),
        &[headers[0].body_digest(), headers[1].body_digest()],
    );
    let observed = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(block.clone(), attestation(0))),
    );
    machine.verify(&observed, true, Until::CursorAdvance);

    // Five full-position votes reach the n-f pool; rank 3f+1 = 4 finalizes both entries.
    let positions = block
        .proposals()
        .iter()
        .map(|proposal| Position::new(proposal.payloads().len() as u32))
        .collect::<Vec<_>>();
    let finalized = headers[1].block_ref::<Sha256>();
    for signer in 0..5u32 {
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&block),
            positions.clone(),
            vec![Extension::empty(); 6],
            machine.profile().codec(),
        )
        .unwrap();
        let vote = observe(
            &mut machine,
            Artifact::Vote(Vote::new(body, attestation(signer))),
        );
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        if signer < 4 {
            continue;
        }
        let fact = step
            .activities()
            .iter()
            .find_map(|activity| match activity {
                Activity::LeaderFinalized { fact } => Some(fact.clone()),
                _ => None,
            })
            .expect("the n-f vote finalizes the leader from the pool");
        assert!(
            fact.blocks().contains(&finalized),
            "position finality must cover the frontier block this node never ingested",
        );
    }
}

#[test]
fn attested_headers_restart_an_in_flight_proposal_pass() {
    let participants = 130;
    let view = View::new(1);
    let signer = LeaderSchedule::round_robin(participants)
        .unwrap()
        .leader(view);
    let profile: Profile<Digest> = Profile::new::<MinPk>(
        TestConfig::new(participants).depth(2).build(),
        Role::Validator(signer),
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024),
            ..Tuning::default()
        },
    )
    .unwrap();
    let drive_to_completion = |machine: &mut TestMachine, restart_range: Option<(usize, usize)>| {
        let mut entries = 0;
        let mut turns = 0;
        loop {
            let drive = machine
                .views
                .drive_regular_sign_request::<Sha256>(&profile, view, &machine.chain, 1)
                .unwrap();
            entries += drive.processed;
            turns += 1;
            assert!(turns < 1024, "proposal construction failed to resume");
            if restart_range.is_some_and(|(from, to)| (from..to).contains(&turns)) {
                machine.views.observe_attested_header(view);
            }
            if let Some(request) = drive.output {
                assert!(matches!(request, SignRequest::LeaderBlock(_)));
                return entries;
            }
        }
    };

    let mut control = Machine::new(profile.clone());
    control.step(Input::Start).unwrap();
    let full = drive_to_completion(&mut control, None);

    // A verified header admitted mid-walk discards the in-flight pass, so the next walk starts
    // over and processes the full entry count again instead of resuming where it left off.
    let mut restarted = Machine::new(profile.clone());
    restarted.step(Input::Start).unwrap();
    let replayed = drive_to_completion(&mut restarted, Some((10, 11)));
    assert_eq!(
        replayed,
        full + 10,
        "the pass must restart from scratch after a header admission",
    );
    assert_eq!(restarted.views.header_restarts(), 1);
    assert_eq!(
        restarted.views.headers_after_seal(),
        0,
        "a header admitted before the seal is a restart, never a miss",
    );

    // Restarts are bounded per view: a sustained header stream consumes the cap and the pass
    // then seals after bounded work. Restarts fire at turns 10..16, the cap admits four, and
    // each capped restart discards exactly one processed entry.
    let mut flooded = Machine::new(profile.clone());
    flooded.step(Input::Start).unwrap();
    let replayed = drive_to_completion(&mut flooded, Some((10, 16)));
    assert_eq!(
        replayed,
        full + 10 + 3,
        "restarts past the per-view cap must not discard the pass",
    );
    assert_eq!(flooded.views.header_restarts(), 4);
}

#[test]
fn headers_admitted_after_the_seal_are_counted() {
    let view = View::new(1);
    let leader = LeaderSchedule::round_robin(6).unwrap().leader(view);
    let mut machine = Machine::new(
        Harness::builder(Role::Validator(leader))
            .participants(6)
            .depth(3)
            .profile(),
    );
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);

    // Starting a six-chain leader seals its view-one proposal within the first cycles: the
    // machine refuses to begin another pass.
    let probe = machine
        .views
        .drive_regular_sign_request::<Sha256>(&machine.profile().clone(), view, &machine.chain, 16)
        .unwrap();
    assert_eq!(
        probe.processed, 0,
        "the local proposal must already be sealed"
    );
    assert_eq!(machine.views.headers_after_seal(), 0);

    let chain = ChainId::new(u32::from(leader.get() == 0));
    let genesis = machine.profile().protocol().genesis().tips()[chain.get() as usize];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        chain,
        Height::new(1),
        genesis.digest(),
        digest(b"post-seal header"),
    )
    .unwrap();
    let _ = authenticate_block(&mut machine, header, chain.get());
    assert_eq!(
        machine.views.headers_after_seal(),
        1,
        "a header admitted after the local seal must count as a quantization miss",
    );
}

#[test]
fn conflicting_da_certificates_are_rejected() {
    let mut machine = Machine::new(Harness::observer().participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let first = symbolic_da_certificate(make(digest(b"certified first")), 0);
    let second = symbolic_da_certificate(make(digest(b"certified second")), 0);
    let first = observe(&mut machine, Artifact::DaCertificate(first));
    machine.verify(&first, true, Until::CursorAdvance);

    let second = observe(&mut machine, Artifact::DaCertificate(second));
    assert!(matches!(
        machine.step(Input::Verified(second.all_valid())),
        Err(StepError::ChainInvariant)
    ));
}

#[test]
fn rejecting_one_equivocating_certificate_keeps_the_other_candidate() {
    let mut machine = Machine::new(Harness::observer().participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let rejected = symbolic_da_certificate(make(digest(b"rejected fork")), 0);
    let survivor = symbolic_da_certificate(make(digest(b"surviving fork")), 1);
    let rejected = observe(&mut machine, Artifact::DaCertificate(rejected));
    let survivor = observe(&mut machine, Artifact::DaCertificate(survivor));
    assert_eq!(machine.chain.da.candidate_blocks(), 2);

    // Both forks sit at one height, so rejecting one removes only its own block's candidates.
    machine.verify(&rejected, false, Until::CursorAdvance);
    assert_eq!(machine.chain.da.candidate_blocks(), 1);
    let waiting = machine.chain.propose_chain(genesis).unwrap();
    assert!(matches!(waiting.anchor(), Anchor::Tip(_)));

    machine.verify(&survivor, true, Until::CursorAdvance);
    assert_eq!(machine.chain.da.candidate_blocks(), 0);
    let certified = machine.chain.propose_chain(genesis).unwrap();
    assert!(matches!(certified.anchor(), Anchor::Certificate(_)));
}

#[test]
fn da_voting_stops_at_the_uncertified_pipeline_boundary() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);

    let mut parent = machine.profile().protocol().genesis().tips()[1];
    let mut headers = Vec::new();
    for height in 1..=3 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(height),
            parent.digest(),
            digest(format!("bounded body {height}").as_bytes()),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>();
        headers.push(header);
    }

    // The third block validates too, but the certified floor sits at genesis, so it completes
    // beyond the pipeline window and no vote can exist for it: only the first two are eligible.
    let routed = route_blocks(&mut machine, 1, &headers);
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, headers[..2]);
}

#[test]
fn a_future_certificate_retires_lower_da_work() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let lower = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"lower body"),
    )
    .unwrap();
    let future = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(3),
        digest(b"future parent"),
        digest(b"future body"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(future, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);

    let choice = validate_block(&mut machine, lower, 1);
    assert!(choice.capabilities().is_empty());
}

#[test]
fn a_certified_base_allows_voting_for_its_child_after_a_gap() {
    let role = Role::Validator(Participant::new(0));
    let profile = Harness::builder(role).participants(6).profile();
    let (mut machine, _) = start_profile(profile.clone());
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let certified = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(3),
        digest(b"unheld certified parent"),
        digest(b"certified body"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(certified.clone(), 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);

    let child = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(4),
        certified.block_ref::<Sha256>().digest(),
        digest(b"certified child body"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, child.clone(), 1);
    assert!(matches!(
        reserved.persist_job().events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::DaVote(actual)) if actual.header() == &child)
    ));
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert_eq!(
        restored.live_snapshot_for_test().da_safety_heights()[genesis.chain().get() as usize],
        child.height()
    );
}

#[test]
fn recovery_requires_the_held_path_before_extending_a_da_vote() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = Machine::new(Harness::builder(role).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"restored first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"restored second"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, first.clone(), 1);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let mut restored = Machine::restore(
        Harness::builder(role).participants(6).profile(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    // The recovered authority re-seeds its chain plane from the durable first choice, but the
    // child extends only once the held path to its parent is re-obtained from gossip (the plane
    // gates this; see its unit coverage). With both re-observed, the child's vote reserves.
    let routed = route_blocks(&mut restored, 1, &[first, second.clone()]);
    let restored_path = offer_eligible(&mut restored, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut restored, restored_path, &mut choices);
    assert_eq!(choices, vec![second]);
}

#[test]
fn a_lagging_node_votes_redelivered_blocks_once_it_catches_up() {
    // The producer of chain 1 certified through `certified` and publishes the next pipeline of
    // blocks. This node still sits at genesis on chain 1, so every one of them is beyond its
    // height window.
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let depth = machine.profile().codec().pipeline_depth() as u64;
    let certified = depth * HEIGHT_WINDOW_PIPELINES + 1;
    let headers = da_run_headers(&machine, 1, certified + depth, "lagging");
    let live = &headers[certified as usize..];
    for header in live {
        let block =
            Artifact::TransactionBlock(SignedTransactionBlock::new(header.clone(), attestation(1)));
        let step = machine.step(cohort::<Sha256, _>(vec![block])).unwrap();
        assert!(matches!(
            step.status(),
            StepStatus::Observed(results)
                if results[0].status() == ObservationStatus::Rejected(Rejection::FutureHeight)
        ));
        assert!(
            !step.has(|capability| capability.is_quarantine()),
            "a window rejection blames no one"
        );
    }

    // The producer republishes its newest certificate until a higher one supersedes it, so the
    // node catches up.
    let certificate = symbolic_da_certificate(headers[certified as usize - 1].clone(), 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);

    // The producer republishes each block until it is certified, so the next delivery lands in
    // the window and the node DA-votes the whole pipeline.
    let routed = route_blocks(&mut machine, 1, live);
    let opened = offer_eligible(&mut machine, 1, &routed);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, live);
}

#[test]
fn forged_fake_header_votes_cannot_squat_honest_da_votes() {
    // Validator 0 produces chain 0. It signs its block at height one, which self-admits the block
    // before its publication can leave.
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let ready = machine.step(Input::ProducerWake).unwrap();
    let build = machine.settle(ready, Until::CursorAdvance).build_job();
    let built = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"own block")),
        )))
        .unwrap();
    let built = machine.settle(built, Until::CursorAdvance);
    let chosen = complete_custody(&mut machine, &built.custody_job());
    let sign = sign_job(&chosen);
    let Some(SignRequest::TransactionBlock(header)) = sign.request().sign_one().cloned() else {
        panic!("the producer choice signs its block");
    };
    machine.persist(&chosen.persist_job(), Until::CursorAdvance);
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::TransactionBlock(
                SignedTransactionBlock::new(header.clone(), attestation(0)),
            ))],
        )))
        .unwrap();
    machine.drain_persisting(signed);
    let fake = TransactionBlockHeader::new(
        header.epoch(),
        header.chain(),
        header.height(),
        header.parent(),
        digest(b"fake body"),
    )
    .unwrap();

    // Before any real vote arrives, a forger attributes a vote for a header the producer never
    // signed to every other signer. None of them takes a signer's slot.
    for signer in 1..6 {
        let forged = Artifact::DaVote(DaVote::new(fake.clone(), threshold_share(signer)));
        let step = machine.step(cohort::<Sha256, _>(vec![forged])).unwrap();
        assert!(matches!(
            step.status(),
            StepStatus::Observed(results)
                if results[0].status() == ObservationStatus::Rejected(Rejection::Unsolicited)
        ));
    }

    // Every real vote still enters and reaches the DA recovery task.
    let quorum = machine.profile().codec().da_quorum() as u32;
    for signer in 1..=quorum {
        let vote = DaVote::new(header.clone(), threshold_share(signer));
        let verification = observe(&mut machine, Artifact::DaVote(vote.clone()));
        let verified = machine.verify(&verification, true, Until::CursorAdvance);
        assert!(
            verified.has(|capability| matches!(
                capability,
                Capability::OwnChainDa(ChainCommand::Observe(share)) if share.as_ref() == &vote
            )),
            "signer {signer}'s vote must reach recovery"
        );
    }

    // The certificate the task assembles from those shares certifies the block.
    let recovered = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block: header.block_ref::<Sha256>(),
            certificate: symbolic_da_certificate(header.clone(), 0),
        }))
        .unwrap();
    let recovered = machine.settle(recovered, Until::CursorAdvance);
    machine.persist(&recovered.persist_job(), Until::CursorAdvance);
    assert_eq!(
        machine.live_snapshot_for_test().certified_tips()[0].height(),
        header.height()
    );
}
