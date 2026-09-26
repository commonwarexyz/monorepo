//! Leader proposal selection, validation, and direct-vote tests.

use super::fixtures::{
    Harness, TestConfig, TestMachine, active_machine, attestation, digest, durable_effect,
    enqueue_due_batch_controls, genesis_tip_history, leader, leader_artifact, lqc, no_vote,
    observe, offer_eligible, proposal_request_with_parent, queued_effect_id,
    record_protocol_acceptances, route_blocks, sign_job, sign_request, start_profile,
    symbolic_da_certificate, symbolic_nullification, threshold_share, validate_block, view_one_vqc,
    view_vote, vqc,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::VqcExtraction,
        config::{LeaderSchedule, Profile, ResourceLimits, Role, Tuning},
        machine::{
            ProposalParent,
            artifact::Dependency,
            capability::{Capability, ResolverCommand},
            core_state::{CoreState, CoreTurn},
            durability::{
                Change, DurableEffect, EffectCompletion, PersistDirective, SignEffect, SignRequest,
            },
            input::Input,
            reducer::machine::Machine,
            scheduler,
            testing::{
                CapabilitiesExt as _, Drive as _, EffectExt, MachineExt as _, Until,
                VerifyJobExt as _, cohort,
            },
            view::ViewState,
            vote_body::{VoteBodyProgress, VoteBuild, VoteBuildStats, VoteBuilds},
        },
        types::{
            Activity, Anchor, Artifact, BlockRef, CertificateId, ChainId, ChainProposal,
            ConflictingVote, DaVote, DigestedLeader, Extension, LeaderBlock, Position,
            SignedLeaderBlock, SignedTransactionBlock, Tally, TipRecord, TransactionBlockHeader,
            ViewMessage, Vqc,
        },
    },
    types::{Attributable, Height, Participant, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::{ops::aggregate, variant::MinPk},
    certificate::Signers,
    sha256::Digest,
};
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn vqc_does_not_supersede_a_vote_needed_for_lqc() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 1);
    let vote = Arc::new(Artifact::Vote(view_vote(&machine, &proposed, 0)));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(vote))
        .unwrap();
    let vote_id = queued_effect_id(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let certificate = Artifact::Vqc(view_one_vqc(&machine));
    let verification = observe(&mut machine, certificate);
    let mut step = machine.verify(&verification, true, Until::CursorAdvance);
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = machine.persist(&job, Until::CursorAdvance);
    }
    assert!(
        machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&vote_id)
    );
}

#[test]
fn a_skipped_view_must_be_nullified_even_after_retirement() {
    // A proposal may only skip views that provably could not have finalized. Retiring a view drops
    // its live records, so the rule must still reject a gap over a view that exited with a V-QC.
    let profile = Harness::validator(3).participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut views = ViewState::<MinPk, Digest>::new::<Sha256>(&profile);

    // Adjacent views leave no gap.
    assert!(views.gap_is_nullified(View::new(1), View::new(2)));

    // View 1 is retired without ever being nullified: a view-3 proposal parented at view 1 skips
    // view 2, and a view-2 proposal parented at genesis skips view 1.
    views.retire_transitions_through(View::new(1));
    assert!(
        !views.gap_is_nullified(View::zero(), View::new(2)),
        "a retired view that was never nullified must not be skippable"
    );
    assert!(
        !views.gap_is_nullified(View::new(1), View::new(3)),
        "a live view that was never nullified must not be skippable"
    );

    // Once view 1's nullification is durably forwarded, skipping it is allowed even though the
    // view is retired and its live record is gone.
    views.observe_forwarded::<Sha256>(&Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        7,
    )));
    assert!(views.gap_is_nullified(View::zero(), View::new(2)));
    assert!(
        !views.gap_is_nullified(View::zero(), View::new(3)),
        "view 2 is still not nullified"
    );
}

#[test]
fn vqc_anchor_does_not_nullify_its_own_view() {
    let profile = Harness::validator(3).participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    let certificate = view_one_vqc(&machine);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let mut step = machine.verify(&verification, true, Until::CursorAdvance);
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = machine.persist(&job, Until::CursorAdvance);
    }
    assert_eq!(machine.inspect().view(), View::new(2));

    let stale = leader(&machine, 2);
    let signer = machine.profile().protocol().leader(View::new(2));
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(stale, attestation(signer.get()))),
    );
    let completed = machine.verify(&verification, true, Until::CursorAdvance);

    assert!(!completed.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if job.events().iter().any(|event| {
            matches!(event.change(), Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_))))
        }))
    }));
}

#[test]
fn proposal_anchor_prefers_more_accounted_messages() {
    let participants = 6;
    let role = Role::Validator(
        LeaderSchedule::round_robin(participants)
            .unwrap()
            .leader(View::new(2)),
    );
    let profile = Harness::builder(role).participants(participants).profile();
    let (mut machine, _) = start_profile(profile);
    let config = machine.profile().codec();
    let proposed = leader(&machine, 1);

    let votes = (0..4)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&proposed),
        votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        config,
    )
    .unwrap();
    let fuller = Vqc::new(
        proposed.clone(),
        tally,
        Signers::new(
            u32::try_from(config.participants()).unwrap(),
            [Participant::new(4), Participant::new(5)],
        )
        .unwrap(),
        Vec::new(),
        aggregate::Signature::<MinPk>::zero(),
        config,
    )
    .unwrap();

    let votes = (0..3)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&proposed),
        votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        config,
    )
    .unwrap();
    let conflicting_leader = LeaderBlock::new(
        proposed.round(),
        CertificateId::new(digest(b"anchor conflicting parent")),
        proposed.history(),
        proposed.proposals().to_vec(),
        config,
    )
    .unwrap();
    let conflicting = (3..5)
        .map(|signer| {
            let vote = view_vote(&machine, &conflicting_leader, signer);
            ConflictingVote::new(vote.signer(), vote.body().ballot().clone(), config).unwrap()
        })
        .collect();
    let smaller = Vqc::new(
        proposed,
        tally,
        Signers::new(u32::try_from(config.participants()).unwrap(), []).unwrap(),
        conflicting,
        aggregate::Signature::<MinPk>::zero(),
        config,
    )
    .unwrap();

    let fuller_certificate = fuller.clone();
    let fuller = Arc::new(Artifact::Vqc(fuller));
    let smaller = Arc::new(Artifact::Vqc(smaller));
    machine.views.retain_vqc_parent::<Sha256>(&fuller).unwrap();
    machine.views.retain_vqc_parent::<Sha256>(&smaller).unwrap();

    machine.views.observe_forwarded::<Sha256>(&smaller);
    machine.views.retire_forwarded_through(View::new(1));

    let nullification = symbolic_nullification(&machine, View::new(1), 0);
    let nullification = observe(&mut machine, Artifact::Nullification(nullification));
    let forwarding = machine
        .step(Input::Verified(nullification.all_valid()))
        .unwrap();
    let forwarding = machine.settle(forwarding, Until::CursorAdvance);
    let entered = machine.persist(&forwarding.persist_job(), Until::CursorAdvance);
    let sign = sign_job(&entered);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the view-two leader must reserve a proposal");
    };
    assert_eq!(
        request.parent().exact().map(Arc::as_ref),
        Some(&fuller_certificate)
    );
    assert!(request.attach_parent());
}

#[test]
fn proposal_frontier_survives_retention_and_restart() {
    let target = View::new(6);
    let signer = LeaderSchedule::round_robin(6).unwrap().leader(target);
    let profile = Harness::builder(Role::Validator(signer))
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let mut proposal_reserved = false;

    let anchor = Artifact::Vqc(view_one_vqc(&machine));
    let anchor_id = match &anchor {
        Artifact::Vqc(certificate) => certificate.id::<Sha256>(),
        _ => unreachable!(),
    };
    let verification = observe(&mut machine, anchor);
    let mut step = machine.verify(&verification, true, Until::CursorAdvance);
    while let Some(job) = step.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        step = machine.persist(&job, Until::CursorAdvance);
    }

    for view in 2..target.get() {
        let certificate =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, certificate);
        let mut step = machine.verify(&verification, true, Until::CursorAdvance);
        while let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) {
            proposal_reserved |= job.events().iter().any(|event| {
                matches!(event.change(), Change::OutboxQueued { effect, .. }
                    if matches!(effect.as_ref().sign_one(), Some(SignRequest::LeaderBlock(_))))
            });
            step = machine.persist(&job, Until::CursorAdvance);
        }
    }

    assert_eq!(machine.inspect().view(), target);
    assert_eq!(machine.retired_view(), View::new(3));
    assert_eq!(
        machine.durable.state.proposal_nullified_through,
        View::new(5)
    );
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(certificate)) if certificate.id::<Sha256>() == anchor_id));
    assert!(
        proposal_reserved,
        "the target leader never reserved its proposal"
    );

    let mut restored =
        Machine::<Sha256, MinPk>::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    assert!(recovered.has(|effect| {
        matches!(
            durable_effect(effect).and_then(EffectExt::sign_one),
            Some(SignRequest::LeaderBlock(_))
        )
    }));
}

#[test]
fn prepared_artifact_keys_match_content() {
    let machine = Machine::new(Harness::observer().participants(6).profile());
    let block = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &block, signer))
        .collect::<Vec<_>>();
    let artifacts = [
        Artifact::Vqc(view_one_vqc(&machine)),
        Artifact::Lqc(lqc(&machine, block.clone(), &votes)),
        Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(0))),
        Artifact::NoVote(no_vote(&machine, View::new(1), 0)),
    ];
    let mut scratch = vec![0xff; 8192];
    for artifact in artifacts {
        let id = artifact.id::<Sha256>();
        let provisions = artifact.provisions::<Sha256>();
        let prepared = artifact.clone().identify::<Sha256>(&mut scratch);
        assert_eq!(prepared.id, id);
        assert_eq!(prepared.artifact, artifact);
        assert_eq!(prepared.provisions.as_slice(), provisions);
        assert_eq!(
            prepared,
            artifact.identify_from_canonical_encoding::<Sha256>(&scratch)
        );
    }
}

#[test]
fn retired_vqc_provider_indexes_match_retained_artifacts() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let mut first = None;
    for view in 1..=16 {
        let block = leader(&machine, view);
        let messages = (0..5)
            .map(|signer| ViewMessage::Vote(view_vote(&machine, &block, signer)))
            .collect::<Vec<_>>();
        let certificate = vqc(&machine, block, &messages);
        let certificate_id = certificate.id::<Sha256>();
        let artifact = Artifact::Vqc(certificate);
        let id = artifact.id::<Sha256>();
        first.get_or_insert((id, certificate_id));
        let verification = observe(&mut machine, artifact);
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);
        for (certificate, id) in &machine.store.vqcs {
            assert!(
                machine.store.artifacts[id]
                    .provisions
                    .contains(&Dependency::Vqc(*certificate))
            );
        }
        for (dependency, providers) in &machine.dependencies.providers {
            for id in providers {
                assert!(machine.store.artifacts[id].provisions.contains(dependency));
            }
        }
    }
    let (id, certificate) = first.unwrap();
    assert!(!machine.store.artifacts.contains_key(&id));
    assert!(!machine.store.vqcs.contains_key(&certificate));
    assert!(
        !machine
            .dependencies
            .providers
            .contains_key(&Dependency::Vqc(certificate))
    );
}

#[test]
fn retired_leader_dependencies_plateau() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);

    for view in 1..=32 {
        let block = leader(&machine, view);
        let signer = machine.profile().protocol().leader(block.view());
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(signer.get()))),
        );
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);

        let view = View::new(view);
        let exit = symbolic_nullification(&machine, view, view.get());
        let verification = observe(&mut machine, Artifact::Nullification(exit));
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        machine.drain_persisting(admitted);
    }

    let retained = machine
        .dependencies
        .available
        .iter()
        .filter(|dependency| matches!(dependency, Dependency::Leader { .. }))
        .count();
    assert!(retained <= 4, "retained {retained} leader dependencies");
}

#[test]
fn proposal_is_the_highest_certificate_even_with_a_voted_suffix() {
    let mut machine = Machine::new(Harness::validator(0).participants(6).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"proposal first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"proposal second"),
    )
    .unwrap();

    let first_choice = validate_block(&mut machine, first.clone(), 1);
    machine.persist(&first_choice.persist_job(), Until::CursorAdvance);
    let certificate = symbolic_da_certificate(first, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let second_choice = validate_block(&mut machine, second, 1);
    machine.persist(&second_choice.persist_job(), Until::CursorAdvance);

    let proposal = machine.chain.propose_chain(genesis).unwrap();
    assert_eq!(proposal.anchor(), &Anchor::Certificate(certificate));
    assert!(
        proposal.payloads().is_empty(),
        "fresh blocks above the anchor travel as vote extensions, never as proposal payloads",
    );
}

#[test]
fn leader_proposal_choice_is_durable() {
    let mut machine = Machine::new(Harness::validator(0).profile());
    let start = machine.step(Input::Start).unwrap();
    let started = machine.persist(&start.persist_job(), Until::CursorAdvance);
    let proposal = started.persist_job();

    let Change::OutboxQueued { effect, .. } = proposal.events()[0].change() else {
        panic!("view entry must durably queue the proposal choice");
    };
    let Some(SignRequest::LeaderBlock(request)) = effect.as_ref().sign_one() else {
        panic!("view-one leader must choose one exact proposal");
    };
    let expected = leader(&machine, 1);
    assert_eq!(request.block(), &expected);
    assert!(matches!(request.parent(), ProposalParent::Genesis));

    // Signing carries no signature out, so the request releases in the step that staged the
    // choice; the acknowledgement must not repeat it.
    let sign = sign_job(&started);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the staged proposal must be signed verbatim");
    };
    assert_eq!(request.block(), &expected);
    assert!(matches!(request.parent(), ProposalParent::Genesis));

    let released = machine.persist(&proposal, Until::CursorAdvance);
    assert!(
        !released.has(|effect| durable_effect(effect)
            .and_then(EffectExt::sign_one)
            .is_some()),
        "the choice acknowledgement must not release signing a second time"
    );
}

#[test]
fn oversized_proposal_pass_resumes_at_item_boundaries() {
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
    let mut machine = Machine::<Sha256, MinPk>::new(profile.clone());
    machine.step(Input::Start).unwrap();

    let quantum = 16;
    let mut turns = 0;
    let request = loop {
        let drive = machine
            .views
            .drive_regular_sign_request::<Sha256>(&profile, view, &machine.chain, quantum)
            .unwrap();
        assert!(drive.processed <= quantum);
        turns += 1;
        if let Some(request) = drive.output {
            break request;
        }
        assert!(!drive.complete);
        assert!(turns < 64, "proposal construction failed to resume");
    };

    let SignRequest::LeaderBlock(request) = request else {
        panic!("the local leader must construct a proposal")
    };
    assert_eq!(request.block().proposals().len(), participants);
    assert!(turns > 1, "the oversized pass completed in one quantum");
}

#[test]
fn maximum_verified_batch_resumes_at_real_item_boundaries() {
    let batch_items = 128;
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        batch_items as u64,
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
    );
    let profile = Harness::observer()
        .depth(1)
        .resources(resources)
        .retention(ViewDelta::new(batch_items as u64))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let artifacts = (1..=batch_items)
        .map(|view| leader_artifact(&machine, view as u64))
        .collect::<Vec<_>>();
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verify(verification)] = observed.capabilities() else {
        panic!("the maximum cohort must produce one verification job");
    };
    assert_eq!(verification.items().len(), batch_items);
    let expected = verification
        .items()
        .iter()
        .map(|item| item.ticket().artifact())
        .collect::<Vec<_>>();
    let completion = verification.all_valid();
    let filler = Arc::new(leader_artifact(&machine, batch_items as u64 + 1));
    let reserved = machine
        .reserve_test_effect(DurableEffect::broadcast(filler))
        .unwrap();
    let persistence = reserved.persist_job();

    let mut composer = CoreState::new(machine).unwrap();
    let batch = composer.enqueue(Input::Verified(completion)).unwrap();
    let controls = enqueue_due_batch_controls(&mut composer, persistence.ack());
    let mut control_cycles = [None; 3];
    let mut cycle = 0_u64;
    let mut accepted = Vec::new();
    let mut resumed = false;
    let mut complete = false;

    for _ in 0..10_000 {
        match composer.next_action(|_| {}).unwrap() {
            CoreTurn::Input(serviced) => {
                record_protocol_acceptances(&mut accepted, serviced.transition.activities());
                if serviced.ticket == batch {
                    resumed |= !serviced.final_chunk;
                    complete |= serviced.final_chunk;
                }
                for (index, (ticket, _)) in controls.iter().enumerate() {
                    if serviced.ticket == *ticket {
                        control_cycles[index] = Some(cycle);
                    }
                }
            }
            CoreTurn::Work(result) => {
                record_protocol_acceptances(&mut accepted, result.activities());
            }
            CoreTurn::YieldRequired => {
                composer.resume_after_yield().unwrap();
                cycle += 1;
            }
            CoreTurn::Idle => break,
        }
        if complete && control_cycles.iter().all(Option::is_some) {
            break;
        }
    }

    assert!(
        resumed,
        "the reducer must run before the final charged prefix"
    );
    assert!(
        complete,
        "the exact verification suffix must resume to completion"
    );
    assert_eq!(accepted, expected, "resume must preserve observation order");
    for (cycle, (_, lane)) in control_cycles.into_iter().zip(controls) {
        let cycle = cycle.unwrap_or_else(|| panic!("{lane:?} was not serviced"));
        assert!(cycle <= 1, "{lane:?} exceeded its one-cycle service bound");
    }
}

#[test]
fn maximum_signed_batch_preempts_without_partial_exposure() {
    let batch_items = scheduler::CORE_BUDGET as usize;
    let profile: Profile<Digest> = Profile::new::<MinPk>(
        TestConfig::new(batch_items).depth(1).build(),
        Role::Validator(Participant::new(0)),
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024),
            ..Tuning::default()
        },
    )
    .unwrap();
    let (mut machine, mut started) = start_profile(profile);
    while let Some(job) = started.find(|effect| match effect {
        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
        _ => None,
    }) {
        started = machine.persist(&job, Until::CursorAdvance);
    }

    let mut requests = Vec::with_capacity(batch_items);
    let mut artifacts = Vec::with_capacity(batch_items);
    for chain in 0..batch_items {
        let genesis = machine.profile().protocol().genesis().tips()[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain as u32),
            Height::new(1),
            genesis.digest(),
            digest(format!("preempted signing batch {chain}").as_bytes()),
        )
        .unwrap();
        let block = Arc::new(SignedTransactionBlock::new(
            header.clone(),
            attestation(chain as u32),
        ));
        requests.push(SignRequest::DaVote(block));
        artifacts.push(Artifact::DaVote(DaVote::new(header, threshold_share(0))));
    }
    let expected = artifacts
        .iter()
        .map(Artifact::id::<Sha256>)
        .collect::<Vec<_>>();
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignEffect::new(requests.into())))
        .unwrap();
    let persistence = reserved.persist_job();
    let signing = reserved
        .find(|effect| match effect {
            Capability::Released(job)
                if matches!(job.request().sign_many(), Some(requests)
                    if requests.len() == batch_items) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the exact signing batch must be issued before acknowledgement");

    let mut composer = CoreState::new(machine).unwrap();
    let batch = composer
        .enqueue(Input::EffectCompleted(EffectCompletion::signed(
            signing.issued(),
            artifacts.iter().cloned().map(Arc::new).collect(),
        )))
        .unwrap();
    let controls = enqueue_due_batch_controls(&mut composer, persistence.ack());
    let mut control_cycles = [None; 3];
    let mut cycle = 0_u64;
    let mut accepted = Vec::new();
    let mut resumed = false;
    let mut complete = false;
    let mut persisted_batch = false;

    for _ in 0..10_000 {
        match composer.next_action(|_| {}).unwrap() {
            CoreTurn::Input(serviced) => {
                record_protocol_acceptances(&mut accepted, serviced.transition.activities());
                if serviced.ticket == batch {
                    resumed |= !serviced.final_chunk;
                    complete |= serviced.final_chunk;
                }
                for (index, (ticket, _)) in controls.iter().enumerate() {
                    if serviced.ticket == *ticket {
                        control_cycles[index] = Some(cycle);
                    }
                }
            }
            CoreTurn::Work(result) => {
                record_protocol_acceptances(&mut accepted, result.activities());
                persisted_batch |= result.has(|effect| {
                    let Capability::Journal(PersistDirective { job, .. }) = effect else {
                        return false;
                    };
                    job.events().iter().any(|event| {
                        matches!(event.change(), Change::SignedArtifacts { sign, artifacts, .. }
                            if *sign == signing.issued().id()
                                && artifacts.iter().map(|artifact| artifact.id::<Sha256>())
                                    .eq(expected.iter().copied()))
                    })
                });
            }
            CoreTurn::YieldRequired => {
                composer.resume_after_yield().unwrap();
                cycle += 1;
            }
            CoreTurn::Idle => break,
        }

        let snapshot = composer.machine().live_snapshot_for_test();
        let local = snapshot.local_artifacts();
        let admitted = expected.iter().filter(|id| local.contains_key(id)).count();
        assert!(
            admitted == 0 || admitted == expected.len(),
            "an atomic signing batch exposed a partial prefix"
        );
        if complete
            && persisted_batch
            && admitted == expected.len()
            && control_cycles.iter().all(Option::is_some)
        {
            break;
        }
    }

    assert!(resumed, "signing validation must stop at an item boundary");
    assert!(
        complete,
        "the exact signing suffix must resume to completion"
    );
    assert!(
        persisted_batch,
        "the exact id and ordered batch must be staged once"
    );
    assert_eq!(
        accepted, expected,
        "self-admission order changed across resume"
    );
    for (cycle, (_, lane)) in control_cycles.into_iter().zip(controls) {
        let cycle = cycle.unwrap_or_else(|| panic!("{lane:?} was not serviced"));
        assert!(cycle <= 1, "{lane:?} exceeded its one-cycle service bound");
    }
}

#[test]
fn signed_valid_proposal_durably_selects_direct_vote() {
    let mut machine = Machine::<Sha256, MinPk>::new(Harness::validator(0).profile());
    let start = machine.step(Input::Start).unwrap();
    let started = machine.persist(&start.persist_job(), Until::CursorAdvance);
    // The signing request releases with the step that stages the choice; its barrier still has
    // to acknowledge before the signed proposal may publish.
    let proposal_sign = sign_job(&started);
    machine.persist(&started.persist_job(), Until::CursorAdvance);
    let SignRequest::LeaderBlock(request) = sign_request(&proposal_sign) else {
        panic!("view-one leader must sign a proposal");
    };
    let proposed = request.block().clone();

    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            proposal_sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed.clone(),
                attestation(0),
            )))],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let published = machine.persist(&completed.persist_job(), Until::CursorAdvance);
    let publication = published.find(|effect| durable_effect(effect).and_then(EffectExt::proposal));
    let publication = publication.expect("signed proposal must carry its exact parent");
    assert_eq!(publication.block().block(), &proposed);
    assert!(matches!(publication.parent(), ProposalParent::Genesis));

    let vote = published.persist_job();
    let Change::OutboxQueued { effect, .. } = vote.events()[0].change() else {
        panic!("proposal admission must durably queue the direct vote");
    };
    let Some(SignRequest::Vote(body)) = effect.as_ref().sign_one() else {
        panic!("a unique valid proposal must produce a vote choice");
    };
    assert_eq!(body.leader(), proposed.digest::<Sha256>());
    assert_eq!(body.positions(), &[Position::new(0)]);
    assert!(body.extensions()[0].is_empty());
}

#[test]
fn vote_body_pass_ignores_later_da_choices() {
    let participants = 6;
    let (mut machine, _) = Harness::validator(1)
        .participants(participants)
        .depth(3)
        .start();
    let genesis = machine.profile().protocol().genesis().tips();
    let headers = [0, 1].map(|chain| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain),
            Height::new(1),
            genesis[chain as usize].digest(),
            digest(format!("vote pass frontier {chain}").as_bytes()),
        )
        .unwrap()
    });
    // The machine self-admits chain 0's DA choice, then begins the vote body pass. The block store and
    // validation live in the per-chain plane; this exercises the machine's own vote-body snapshot.
    machine
        .chain
        .observe_da_choice::<Sha256>(&headers[0])
        .unwrap();
    let mut pass = machine.chain.begin_vote_body_pass(leader(&machine, 1));

    // Chain 1's choice is self-admitted mid-pass; the frozen pass must ignore it.
    machine
        .chain
        .observe_da_choice::<Sha256>(&headers[1])
        .unwrap();

    let (body, stats) = loop {
        match machine
            .chain
            .resume_vote_body_pass::<Sha256>(&mut pass)
            .unwrap()
        {
            VoteBodyProgress::Pending => {}
            VoteBodyProgress::Complete { body, stats } => break (body, stats),
        }
    };
    assert_eq!(body.extensions()[0].payloads(), &[headers[0].body_digest()]);
    assert!(body.extensions()[1].is_empty());
    // The statistics count the choice the frozen pass ignored as a late DA chain.
    assert_eq!(
        stats,
        VoteBuildStats {
            eligible_extensions: 1,
            short_chains: 0,
            extension_cap_chains: 1,
            late_da_chains: 1,
        }
    );
}

#[test]
fn terminal_height_rescue_vote_matches_ordinary_vote() {
    let machine = active_machine(Role::Validator(Participant::new(0)));
    let profile = machine.profile().clone();
    let protocol = profile.protocol();
    let proposals = (0..protocol.codec_config().chains())
        .map(|index| {
            let chain = ChainId::new(index as u32);
            ChainProposal::new(
                chain,
                Anchor::Tip(BlockRef::new(
                    chain,
                    Height::new(u64::MAX),
                    digest(format!("terminal anchor {index}").as_bytes()),
                )),
                Vec::new(),
                protocol.codec_config().pipeline_depth(),
            )
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

    let mut pass = machine.chain.begin_vote_body_pass(leader.clone());
    let ordinary = loop {
        match machine
            .chain
            .resume_vote_body_pass::<Sha256>(&mut pass)
            .unwrap()
        {
            VoteBodyProgress::Pending => {}
            VoteBodyProgress::Complete { body, .. } => break body,
        }
    };
    let rescue = machine.chain.vote_body::<Sha256>(&leader).unwrap();

    assert_eq!(rescue, ordinary);
    assert!(
        ordinary
            .positions()
            .iter()
            .all(|position| *position == Position::new(0))
    );
    assert!(ordinary.extensions().iter().all(Extension::is_empty));
}

#[test]
fn completed_ordinary_vote_survives_da_observation_until_reserved() {
    let participants = 6;
    let probe = Harness::observer().participants(participants).profile();
    let leader_participant = probe.protocol().leader(View::new(1));
    let voter = Participant::new((leader_participant.get() + 1) % participants as u32);
    let (mut machine, _) = Harness::builder(Role::Validator(voter))
        .participants(participants)
        .start();
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed,
            attestation(leader_participant.get()),
        )),
    );
    machine.verify(&proposal, true, Until::Step);

    let profile = machine.profile().clone();
    let first = loop {
        let drive = machine
            .views
            .drive_regular_sign_request::<Sha256>(
                &profile,
                View::new(1),
                &machine.chain,
                scheduler::CORE_BUDGET as usize,
            )
            .unwrap();
        if let Some(request) = drive.output {
            break request;
        }
    };
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let block = Arc::new(SignedTransactionBlock::new(
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            genesis.chain(),
            Height::new(1),
            genesis.digest(),
            digest(b"later DA observation"),
        )
        .unwrap(),
        attestation(0),
    ));
    machine
        .views
        .observe_sign_request(&SignRequest::DaVote(block))
        .unwrap();
    let resumed = machine
        .views
        .drive_regular_sign_request::<Sha256>(
            &profile,
            View::new(1),
            &machine.chain,
            scheduler::CORE_BUDGET as usize,
        )
        .unwrap();

    assert_eq!(resumed.processed, 0);
    assert_eq!(resumed.output, Some(first));
}

/// Returns a started validator holding a valid proposal for view 1 that it does not lead.
fn voting_machine() -> TestMachine {
    let participants = 6;
    let probe = Harness::observer().participants(participants).profile();
    let leader_participant = probe.protocol().leader(View::new(1));
    let voter = Participant::new((leader_participant.get() + 1) % participants as u32);
    let (mut machine, _) = Harness::builder(Role::Validator(voter))
        .participants(participants)
        .start();
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed,
            attestation(leader_participant.get()),
        )),
    );
    machine.verify(&proposal, true, Until::Step);
    machine
}

fn drive_view_one_vote(
    machine: &mut TestMachine,
    budget: usize,
) -> Option<SignRequest<MinPk, Digest>> {
    let profile = machine.profile().clone();
    machine
        .views
        .drive_regular_sign_request::<Sha256>(&profile, View::new(1), &machine.chain, budget)
        .unwrap()
        .output
}

#[test]
fn vote_pass_reports_its_start_and_completion_once() {
    let mut machine = voting_machine();
    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    let extension_bound = machine.profile().codec().extension_bound();

    assert!(drive_view_one_vote(&mut machine, 1).is_none());
    assert_eq!(
        machine
            .views
            .drain_vote_builds()
            .into_iter()
            .collect::<Vec<_>>(),
        [VoteBuild::Started {
            round,
            extension_bound,
        }]
    );
    assert!(drive_view_one_vote(&mut machine, scheduler::CORE_BUDGET as usize).is_some());
    assert_eq!(
        machine
            .views
            .drain_vote_builds()
            .into_iter()
            .collect::<Vec<_>>(),
        [VoteBuild::Completed(VoteBuildStats::default())]
    );

    // The kept body is returned again without reporting another build.
    assert!(drive_view_one_vote(&mut machine, scheduler::CORE_BUDGET as usize).is_some());
    assert_eq!(machine.views.drain_vote_builds(), VoteBuilds::default());
}

#[test]
fn vote_build_due_holds_exactly_before_the_poll_that_begins_the_pass() {
    let mut machine = voting_machine();
    let mut begun = 0;
    for _ in 0..256 {
        let due = machine.vote_build_due();
        let polled = machine.poll(NonZeroUsize::MIN).unwrap();
        let begins = polled
            .vote_builds
            .into_iter()
            .any(|build| matches!(build, VoteBuild::Started { .. }));
        assert_eq!(due, begins);
        begun += usize::from(begins);
        if !machine.work_remaining() {
            break;
        }
    }
    assert_eq!(
        begun, 1,
        "the proposal's vote pass begins in exactly one poll"
    );
}

#[test]
fn discarded_vote_pass_reports_its_abandonment() {
    let mut machine = voting_machine();
    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    assert!(drive_view_one_vote(&mut machine, 1).is_none());
    assert!(matches!(
        machine
            .views
            .drain_vote_builds()
            .into_iter()
            .collect::<Vec<_>>()[..],
        [VoteBuild::Started { .. }]
    ));

    machine
        .views
        .observe_sign_request(&SignRequest::Nullify { round })
        .unwrap();
    assert!(drive_view_one_vote(&mut machine, scheduler::CORE_BUDGET as usize).is_none());
    assert_eq!(
        machine
            .views
            .drain_vote_builds()
            .into_iter()
            .collect::<Vec<_>>(),
        [VoteBuild::Abandoned]
    );
}

#[test]
fn proposal_accepts_exact_tip_history_and_rejects_an_incorrect_commitment() {
    for valid_history in [true, false] {
        let profile = Harness::validator(1).participants(6).profile();
        let (mut machine, _) = start_profile(profile);
        let base = leader(&machine, 1);
        let history = if valid_history {
            base.history()
        } else {
            digest(b"incorrect tip history")
        };
        let proposal = LeaderBlock::new(
            base.round(),
            base.parent(),
            history,
            base.proposals().to_vec(),
            machine.profile().codec(),
        )
        .unwrap();
        let signer = machine.profile().protocol().leader(proposal.view());
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposal.clone(),
                attestation(signer.get()),
            )),
        );
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        let histories = admitted
            .activities()
            .iter()
            .filter_map(|activity| match activity {
                Activity::HistoryAccepted {
                    commitment, record, ..
                } => Some((*commitment, record.commitment::<Sha256>())),
                Activity::CommitmentsAccepted { .. } | Activity::ProtocolAccepted { .. } => None,
                Activity::TransactionProposed { .. }
                | Activity::LeaderFinalized { .. }
                | Activity::LeaderFinalityUpdated { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            histories,
            valid_history
                .then_some((history, history))
                .into_iter()
                .collect::<Vec<_>>()
        );
        let effects = machine.drain_persisting(admitted);
        let voted = effects.iter().any(|effect| {
            matches!(
                durable_effect(effect).and_then(EffectExt::sign_one),
                Some(SignRequest::Vote(request))
                    if request.leader() == proposal.digest::<Sha256>()
            )
        });

        assert_eq!(voted, valid_history);
    }
}

#[test]
fn proposal_accepts_exact_lower_parent_with_complete_gap() {
    let profile = Harness::validator(0).participants(6).profile();
    let (mut machine, _) = start_profile(profile);

    let higher_leader = leader(&machine, 3);
    let higher_votes = (0..machine.profile().codec().view_quorum())
        .map(|signer| view_vote(&machine, &higher_leader, signer as u32))
        .collect::<Vec<_>>();
    let higher = lqc(&machine, higher_leader, &higher_votes);
    let verification = observe(&mut machine, Artifact::Lqc(higher));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if anchor.view() == View::new(3)));
    assert_eq!(machine.inspect().view(), View::new(4));

    let parent = view_one_vqc(&machine);
    let parent_id = parent.id::<Sha256>();
    let extraction =
        VqcExtraction::new::<Sha256, MinPk>(&parent, machine.profile().codec()).unwrap();
    let (tips, _) = extraction.into_parts();
    let history = TipRecord::new(
        parent.leader().history(),
        tips.blocks().to_vec(),
        parent.leader().proposed_heights(),
    )
    .unwrap()
    .commitment::<Sha256>();
    let base = leader(&machine, 4);
    let proposal = LeaderBlock::new(
        base.round(),
        parent_id,
        history,
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();

    let verification = observe(&mut machine, Artifact::Vqc(parent));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);

    let signer = machine.profile().protocol().leader(proposal.view());
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposal.clone(),
            attestation(signer.get()),
        )),
    );
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let blocked = machine.drain_persisting(admitted);
    assert!(
        blocked.has(|effect| matches!(effect, Capability::Resolver(ResolverCommand::Resolve(job)) if job.view() == View::new(2)))
    );
    assert!(blocked.iter().all(|effect| {
        !matches!(
            durable_effect(effect).and_then(EffectExt::sign_one),
            Some(SignRequest::Vote(_))
        )
    }));

    let mut effects = Vec::new();
    for view in [View::new(2), View::new(3)] {
        let nullification = symbolic_nullification(&machine, view, view.get());
        let verification = observe(&mut machine, Artifact::Nullification(nullification));
        let admitted = machine.verify(&verification, true, Until::CursorAdvance);
        effects.extend(machine.drain_persisting(admitted));
    }

    assert!(effects.iter().any(|effect| {
        matches!(
            durable_effect(effect).and_then(EffectExt::sign_one),
            Some(SignRequest::Vote(request))
                if request.leader() == proposal.digest::<Sha256>()
        )
    }));
}

#[test]
fn proposal_equivocation_suppresses_direct_vote() {
    let mut machine = Machine::new(Harness::validator(0).participants(2).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let first = leader(&machine, 1);
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let observed = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(1))),
            Artifact::LeaderBlock(SignedLeaderBlock::new(second, attestation(1))),
        ]))
        .unwrap();
    let [Capability::Verify(job)] = observed.capabilities() else {
        panic!("both equivocations must share one exact verification cohort");
    };
    let verified = machine.step(Input::Verified(job.all_valid())).unwrap();
    // Staging arrives from the scheduler, so settle before asserting no vote was queued.
    let verified = machine.settle(verified, Until::CursorAdvance);
    assert!(!verified.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn pending_proposal_equivocation_blocks_direct_vote() {
    let mut machine = Machine::new(Harness::validator(0).participants(2).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let first = leader(&machine, 1);
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"pending equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();

    let first_observed = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(first, attestation(1)),
        )]))
        .unwrap();
    let [Capability::Verify(first_job)] = first_observed.capabilities() else {
        panic!("the first proposal must start verification");
    };
    let second_observed = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(second, attestation(1)),
        )]))
        .unwrap();
    let second_job = second_observed.find(|effect| match effect {
        Capability::Verify(job) => Some(job.clone()),
        _ => None,
    });

    let first_verified = machine
        .step(Input::Verified(first_job.all_valid()))
        .unwrap();
    let first_verified = machine.settle(first_verified, Until::CursorAdvance);
    let second_job = second_job
        .or_else(|| {
            first_verified.find(|effect| match effect {
                Capability::Verify(job) => Some(job.clone()),
                _ => None,
            })
        })
        .expect("the equivocation must eventually start verification");
    assert!(!first_verified.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
        ))
    }));

    let second_verified = machine
        .step(Input::Verified(second_job.all_valid()))
        .unwrap();
    let second_verified = machine.settle(second_verified, Until::CursorAdvance);
    assert!(!second_verified.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn staggered_verified_proposal_equivocation_suppresses_direct_vote() {
    let mut machine = Machine::new(Harness::validator(0).participants(2).profile());
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);

    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 1)),
    ];
    let parent = vqc(&machine, parent_leader, &parent_messages);
    let first = proposal_request_with_parent(&machine, View::new(2), parent.clone())
        .block()
        .clone();
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"staggered verified equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();

    let first = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(1))),
    );
    machine.verify(&first, true, Until::CursorAdvance);
    let second = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(second, attestation(1))),
    );
    machine.verify(&second, true, Until::CursorAdvance);

    let parent = observe(&mut machine, Artifact::Vqc(parent));
    let ready = machine.verify(&parent, true, Until::CursorAdvance);
    assert!(!ready.has(|effect| {
        matches!(effect, Capability::Journal(PersistDirective { job, .. }) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn vote_projection_uses_voted_prefix_and_extension() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let protocol = machine.profile().protocol().clone();
    let genesis = protocol.genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(0),
        Height::new(1),
        genesis.digest(),
        digest(b"first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(0),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"second"),
    )
    .unwrap();
    // Both heights are one contiguous run on chain 0; route them together so the plane can vouch for
    // the parent's held path when the child becomes eligible, then offer each in turn.
    let routed = route_blocks(&mut machine, 0, &[first.clone(), second.clone()]);
    let first_valid = offer_eligible(&mut machine, 0, &routed[..1]);
    machine.persist(&first_valid.persist_job(), Until::CursorAdvance);
    let second_valid = offer_eligible(&mut machine, 0, &routed);
    machine.persist(&second_valid.persist_job(), Until::CursorAdvance);

    let proposal = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(genesis),
        vec![first.body_digest()],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        vec![proposal],
        protocol.codec_config(),
    )
    .unwrap();
    let body = machine.chain.vote_body::<Sha256>(&leader).unwrap();
    assert_eq!(body.positions(), &[Position::new(1)]);
    assert_eq!(body.extensions()[0].payloads(), &[second.body_digest()]);
}
