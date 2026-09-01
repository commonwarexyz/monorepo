//! Artifact verification, dependency, and ingress-bound tests.

use super::fixtures::{
    Harness, RecoveredVoteSigning, TEST_RESOURCES, TestConfig, TestMachine, active_machine,
    attestation, da_run_headers, digest, leader, leader_artifact, no_vote, observe,
    recover_vote_signing, retention_for, start_profile, symbolic_da_certificate, threshold_share,
    view_messages, view_vote, vote_artifact, vqc,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{
            Error as ConfigError, HEIGHT_WINDOW_PIPELINES, LeaderSchedule, Profile, ResourceLimits,
            Role, Tuning,
        },
        machine::{
            artifact::Dependency,
            capability::{Capability, CryptoJob},
            durability::{Change, EffectCompletion, SignRequest, Snapshot},
            input::{Input, ObservationStatus, Rejection, StepError, StepStatus},
            job::{Generation, Issued},
            reducer::machine::Machine,
            testing::{
                CapabilitiesExt as _, Drive as _, EffectExt, Until, VerifyJobExt as _, cohort,
            },
            verification::{Verdict, VerificationCompletion, VerificationTicket},
        },
        types::{
            Artifact, ArtifactId, CertificateId, ChainProposal, DaVote, Extension, LeaderBlock,
            Position, SignedLeaderBlock, SignedTransactionBlock, ThresholdShare,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody,
        },
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::{group::G2, variant::MinPk},
    sha256::Digest,
};
use commonware_math::algebra::CryptoGroup as _;
use commonware_utils::NZUsize;
use core::{num::NonZeroUsize, time::Duration};
use std::sync::Arc;

#[test]
fn profile_rejects_validator_outside_committee() {
    assert_eq!(
        Profile::new::<MinPk>(
            TestConfig::new(1).build(),
            Role::Validator(Participant::new(1)),
            Tuning {
                view_timeout: Duration::ZERO,
                production_interval: Duration::ZERO,
                view_retention: retention_for(TEST_RESOURCES, 1),
                ..Tuning::default()
            },
        )
        .unwrap_err(),
        ConfigError::ValidatorOutOfRange(Participant::new(1))
    );
}

#[test]
fn decoded_artifact_requires_matching_verification() {
    let mut machine = active_machine(Role::Observer);
    let artifact = leader_artifact(&machine, 1);
    let id = artifact.id::<Sha256>();
    let job = observe(&mut machine, artifact.clone());

    assert!(machine.inspect().ready_artifacts().is_empty());
    assert_eq!(machine.inspect().pending_artifacts(), 1);

    let duplicate = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    assert!(matches!(
        duplicate.status(),
        StepStatus::Observed(results) if results[0].status() == ObservationStatus::Duplicate
    ));
    assert!(duplicate.capabilities().is_empty());

    let stale = machine
        .step(Input::Verified(VerificationCompletion::new(
            Issued::new(
                job.issued().id(),
                Generation::new(job.issued().generation().get() + 1),
            ),
            vec![Verdict::new(job.items()[0].ticket(), true)],
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(machine.inspect().ready_artifacts().is_empty());

    machine.verify(&job, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);

    let repeated = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.issued(),
            vec![Verdict::new(job.items()[0].ticket(), false)],
        )))
        .unwrap();
    assert_eq!(repeated.status(), &StepStatus::StaleCompletion);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);
}

#[test]
fn invalid_artifacts_release_cache_capacity() {
    let limits = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(8))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(8));
    let profile = Harness::observer().resources(limits).profile();
    let (mut machine, _) = start_profile(profile);

    let first = leader(&machine, 1);
    let artifacts = [
        leader_artifact(&machine, 1),
        leader_artifact(&machine, 2),
        vote_artifact(&machine, &first),
        Artifact::NoVote(no_vote(&machine, View::new(1), 0)),
    ];
    for artifact in artifacts {
        let verification = observe(&mut machine, artifact);
        machine.verify(&verification, false, Until::CursorAdvance);
    }
    assert_eq!(machine.inspect().cached_artifacts(), 0);

    let accepted = machine
        .step(cohort::<Sha256, _>(vec![Artifact::NoVote(no_vote(
            &machine,
            View::new(2),
            0,
        ))]))
        .unwrap();
    assert!(matches!(
        accepted.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Scheduled
    ));
}

#[test]
fn mismatched_completion_does_not_consume_job() {
    let mut machine = active_machine(Role::Observer);
    let artifact = leader_artifact(&machine, 1);
    let job = observe(&mut machine, artifact);
    let wrong = VerificationTicket::new(
        job.issued().id(),
        ArtifactId::new(digest(b"substitute")),
        job.items()[0].ticket().observation(),
    );

    assert!(matches!(
        machine.step(Input::Verified(VerificationCompletion::new(
            job.issued(),
            vec![Verdict::new(wrong, true)],
        ))),
        Err(StepError::CompletionMismatch)
    ));
    assert_eq!(machine.inspect().verification_jobs(), &[job.issued().id()]);

    machine.verify(&job, true, Until::CursorAdvance);
    assert!(machine.inspect().verification_jobs().is_empty());
}

#[test]
fn authenticated_vote_waits_for_exact_leader() {
    let mut machine = active_machine(Role::Observer);
    let leader = leader(&machine, 1);
    let vote = vote_artifact(&machine, &leader);
    let vote_id = vote.id::<Sha256>();
    let vote_job = observe(&mut machine, vote);
    machine.verify(&vote_job, true, Until::CursorAdvance);

    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert!(machine.inspect().ready_artifacts().is_empty());

    let leader = Artifact::LeaderBlock(SignedLeaderBlock::new(leader, attestation(0)));
    let leader_id = leader.id::<Sha256>();
    let leader_job = observe(&mut machine, leader);
    machine.verify(&leader_job, true, Until::CursorAdvance);

    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.inspect().ready_artifacts(), &[vote_id, leader_id]);
}

#[test]
fn dependency_overflow_releases_the_dropped_proposal_claim() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::validator(5)
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);

    let with_parent = |machine: &TestMachine, view, label: &[u8]| {
        let base = leader(machine, view);
        LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(label)),
            base.history(),
            base.proposals().to_vec(),
            machine.profile().codec(),
        )
        .unwrap()
    };
    let filler_artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(
        with_parent(&machine, 2, b"filler parent"),
        attestation(0),
    ));
    let filler = observe(&mut machine, filler_artifact);
    machine.verify(&filler, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let dropped_artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(
        with_parent(&machine, 1, b"dropped parent"),
        attestation(0),
    ));
    let dropped = machine
        .step(cohort::<Sha256, _>(vec![dropped_artifact]))
        .unwrap();
    assert!(matches!(
        dropped.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(dropped.capabilities().is_empty());
    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert_eq!(machine.inspect().dropped_artifacts(), 0);

    let valid_artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(leader(&machine, 1), attestation(0)));
    let valid = observe(&mut machine, valid_artifact);
    let voted = machine.verify(&valid, true, Until::CursorAdvance);
    assert!(matches!(
        voted.persist_job().events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
    ));
}

#[test]
fn dependency_overflow_cannot_leave_a_vote_in_the_vqc_pool() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);

    let base = leader(&machine, 2);
    let filler = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"missing filler parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let filler = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(filler, attestation(0))),
    );
    machine.verify(&filler, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let proposed = leader(&machine, 1);
    let overflow = Artifact::Vote(view_vote(&machine, &proposed, 0));
    let overflow = machine.step(cohort::<Sha256, _>(vec![overflow])).unwrap();
    assert!(matches!(
        overflow.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(overflow.capabilities().is_empty());
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

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
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let observed = machine.step(cohort::<Sha256, _>(messages)).unwrap();
    let [Capability::Verify(job)] = observed.capabilities() else {
        panic!("view messages must be verified together");
    };
    let verified = machine.step(Input::Verified(job.all_valid())).unwrap();
    assert!(
        verified
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Crypto(CryptoJob::AggregateVqc(_))))
    );
}

#[test]
fn parent_rejection_precedes_child_authentication() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, parent_leader, &parent_messages));
    let dependency = parent
        .provisions::<Sha256>()
        .into_iter()
        .find_map(|dependency| match dependency {
            Dependency::Vqc(certificate) => Some(certificate),
            Dependency::Leader { .. } => None,
        })
        .unwrap();
    let base = leader(&machine, 2);
    let child = LeaderBlock::new(
        base.round(),
        dependency,
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let child = Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0)));

    let observed = machine
        .step(cohort::<Sha256, _>(vec![parent, child]))
        .unwrap();
    let [Capability::Verify(job)] = observed.capabilities() else {
        panic!("the parent and child must share one verification job");
    };
    let completed = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.issued(),
            vec![
                Verdict::new(job.items()[0].ticket(), false),
                Verdict::new(job.items()[1].ticket(), true),
            ],
        )))
        .unwrap();
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 1,
        }
    );
    assert_eq!(machine.inspect().cached_artifacts(), 0);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
}

#[test]
fn invalid_dependency_bound_is_completion_order_independent() {
    let run = |target: usize, completion_order: [usize; 3]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(4).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = Harness::observer()
            .participants(6)
            .resources(limits)
            .profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 1);
        let message_sets = [[3, 4], [3, 5]]
            .map(|nonvoters| view_messages(&machine, &proposed, &[0, 1, 2], &nonvoters));
        let mut parents = message_sets
            .into_iter()
            .map(|messages| {
                let artifact = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
                let dependency = artifact
                    .provisions::<Sha256>()
                    .into_iter()
                    .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
                    .unwrap();
                (dependency, artifact)
            })
            .collect::<Vec<_>>();
        parents.sort_unstable_by_key(|(dependency, _)| *dependency);
        let Dependency::Vqc(parent) = parents[target].0 else {
            unreachable!("V-QC artifacts provide V-QC dependencies");
        };
        let jobs = parents
            .into_iter()
            .map(|(_, artifact)| observe(&mut machine, artifact))
            .collect::<Vec<_>>();

        let base = leader(&machine, 2);
        let child = LeaderBlock::new(
            base.round(),
            parent,
            base.history(),
            base.proposals().to_vec(),
            machine.profile().codec(),
        )
        .unwrap();
        let child = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0))),
        );
        for index in completion_order {
            if index == 2 {
                machine.verify(&child, true, Until::CursorAdvance);
            } else {
                machine.verify(&jobs[index], false, Until::CursorAdvance);
            }
        }
        machine.inspect()
    };

    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for target in 0..2 {
        let expected = run(target, orders[0]);
        assert_eq!(expected.waiting_artifacts(), 0);
        assert_eq!(expected.cached_artifacts(), 0);
        for order in orders.iter().skip(1) {
            assert_eq!(run(target, *order), expected);
        }
    }
}

#[test]
fn dependency_rejection_saturation_preserves_observed_valid_parents() {
    let run = |completion_order: [usize; 4]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(5).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = Harness::observer()
            .participants(6)
            .resources(limits)
            .profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let message_sets = [[3, 4], [3, 5], [4, 5]]
            .map(|nonvoters| view_messages(&machine, &proposed, &[0, 1, 2], &nonvoters));
        let mut parents = message_sets
            .into_iter()
            .map(|messages| {
                let artifact = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
                let Dependency::Vqc(dependency) = artifact
                    .provisions::<Sha256>()
                    .into_iter()
                    .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
                    .unwrap()
                else {
                    unreachable!("V-QC artifacts provide V-QC dependencies");
                };
                (dependency, artifact)
            })
            .collect::<Vec<_>>();
        parents.sort_unstable_by_key(|(dependency, _)| *dependency);
        let (valid_parent, valid_artifact) = parents.pop().unwrap();
        let mut jobs = parents
            .into_iter()
            .map(|(_, artifact)| observe(&mut machine, artifact))
            .collect::<Vec<_>>();
        jobs.push(observe(&mut machine, valid_artifact));

        let base = leader(&machine, 3);
        let child = LeaderBlock::new(
            base.round(),
            valid_parent,
            base.history(),
            base.proposals().to_vec(),
            machine.profile().codec(),
        )
        .unwrap();
        jobs.push(observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0))),
        ));

        for index in completion_order {
            machine.verify(&jobs[index], index >= 2, Until::CursorAdvance);
        }
        machine.inspect()
    };

    let parent_first = run([2, 3, 0, 1]);
    let saturation_first = run([0, 1, 3, 2]);
    assert_eq!(saturation_first, parent_first);
    assert_eq!(parent_first.waiting_artifacts(), 0);
    assert_eq!(parent_first.ready_artifacts().len(), 2);
}

/// With one dependency waiter, rejecting every provider of a waiting artifact settles it the same
/// way whether it completes before or after those rejections, and nothing stays waiting or cached.
#[test]
fn dependency_rejection_saturation_rechecks_failed_providers() {
    let run = |completion_order: [usize; 4]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(5).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = Harness::observer()
            .participants(6)
            .resources(limits)
            .profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let message_sets = [[3, 4], [3, 5], [4, 5]]
            .map(|nonvoters| view_messages(&machine, &proposed, &[0, 1, 2], &nonvoters));
        let parents = message_sets
            .into_iter()
            .map(|messages| Artifact::Vqc(vqc(&machine, proposed.clone(), &messages)))
            .collect::<Vec<_>>();
        let jobs = parents
            .iter()
            .cloned()
            .map(|artifact| observe(&mut machine, artifact))
            .collect::<Vec<_>>();
        let child = Artifact::Vote(view_vote(&machine, &proposed, 5));
        let child = observe(&mut machine, child);
        let jobs = [&jobs[0], &jobs[1], &jobs[2], &child];

        for index in completion_order {
            machine.verify(jobs[index], index == 3, Until::CursorAdvance);
        }
        machine.inspect()
    };

    let child_before_provider_failure = run([0, 3, 1, 2]);
    let provider_failure_before_child = run([0, 1, 2, 3]);
    assert_eq!(child_before_provider_failure, provider_failure_before_child);
    assert_eq!(child_before_provider_failure.waiting_artifacts(), 0);
    assert_eq!(child_before_provider_failure.cached_artifacts(), 0);
}

#[test]
fn dependency_capacity_is_reserved_by_observation_order() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(4).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, proposed, &messages));
    let Dependency::Vqc(parent_id) = parent
        .provisions::<Sha256>()
        .into_iter()
        .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
        .unwrap()
    else {
        unreachable!("V-QC artifacts provide V-QC dependencies");
    };
    let parent = observe(&mut machine, parent);

    let first = leader(&machine, 3);
    let first_history = first.history();
    let first = LeaderBlock::new(
        first.round(),
        parent_id,
        first.history(),
        first.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let first = Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(0)));
    let first_id = first.id::<Sha256>();
    let first = observe(&mut machine, first);

    let mut proposals = leader(&machine, 3).proposals().to_vec();
    let proposal = &proposals[0];
    proposals[0] = ChainProposal::new(
        proposal.anchor().chain(),
        proposal.anchor().clone(),
        vec![digest(b"equivocal proposal")],
        machine.profile().codec().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        Round::new(machine.profile().protocol().epoch(), View::new(3)),
        parent_id,
        first_history,
        proposals,
        machine.profile().codec(),
    )
    .unwrap();
    let second = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(second, attestation(0)),
        )]))
        .unwrap();
    assert!(matches!(
        second.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(second.capabilities().is_empty());

    machine.verify(&first, true, Until::CursorAdvance);
    machine.verify(&parent, true, Until::CursorAdvance);
    assert!(machine.inspect().ready_artifacts().contains(&first_id));
}

#[test]
fn recovery_does_not_apply_the_remote_dependency_ceiling_to_local_votes() {
    let role = Role::Validator(Participant::new(0));
    let profile = Harness::builder(role)
        .participants(6)
        .resources(
            TEST_RESOURCES
                .with_max_inflight_verifications(NZUsize!(3))
                .with_max_dependency_waiters(NZUsize!(1)),
        )
        .profile();
    let machine = Machine::new(profile.clone());
    let votes = [leader(&machine, 1), leader(&machine, 2)]
        .map(|leader| Arc::new(Artifact::Vote(view_vote(&machine, &leader, 0))));
    let mut durable = machine.durable.state.clone();
    for vote in votes {
        durable.local.insert(vote.id::<Sha256>(), vote);
    }
    let snapshot = Snapshot::new(machine.profile().protocol().epoch(), role, durable);

    let mut restored = Machine::<Sha256, MinPk>::restore(profile, snapshot).unwrap();
    restored.step(Input::RecoveryComplete).unwrap();

    assert_eq!(restored.inspect().waiting_artifacts(), 2);
    assert_eq!(restored.dependencies.slots, 0);
}

#[test]
fn recovered_vote_completion_survives_remote_dependency_capacity() {
    let RecoveredVoteSigning {
        mut machine,
        sign,
        leader: proposed,
        signer,
    } = recover_vote_signing(
        TEST_RESOURCES
            .with_max_inflight_verifications(NZUsize!(3))
            .with_max_dependency_waiters(NZUsize!(1)),
    );
    let base = leader(&machine, 2);
    let waiting = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"unavailable remote parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let waiting = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(waiting, attestation(0))),
    );
    machine.verify(&waiting, true, Until::CursorAdvance);
    assert_eq!(machine.dependencies.slots, 1);

    let vote = Artifact::Vote(view_vote(&machine, &proposed, signer.get()));
    let vote_id = vote.id::<Sha256>();
    let parked = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(vote)],
        )))
        .unwrap();
    machine.settle(parked, Until::CursorAdvance);

    assert_eq!(machine.dependencies.slots, 1);
    assert_eq!(machine.inspect().waiting_artifacts(), 2);
    assert!(machine.store.artifacts.contains_key(&vote_id));
}

#[test]
fn recovered_vote_survives_remote_dependency_rejection_saturation() {
    let RecoveredVoteSigning {
        mut machine,
        sign,
        leader: proposed,
        signer,
    } = recover_vote_signing(
        TEST_RESOURCES
            .with_max_inflight_verifications(NZUsize!(3))
            .with_max_dependency_waiters(NZUsize!(1)),
    );
    let parent_leader = leader(&machine, 2);
    let message_sets = [[3, 4], [3, 5]]
        .map(|nonvoters| view_messages(&machine, &parent_leader, &[0, 1, 2], &nonvoters));
    for messages in message_sets {
        let parent = Artifact::Vqc(vqc(&machine, parent_leader.clone(), &messages));
        let verification = observe(&mut machine, parent);
        machine.verify(&verification, false, Until::CursorAdvance);
    }
    assert!(machine.dependencies.rejections_saturated);

    let vote = Artifact::Vote(view_vote(&machine, &proposed, signer.get()));
    let vote_id = vote.id::<Sha256>();
    let parked = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(vote)],
        )))
        .unwrap();
    machine.settle(parked, Until::CursorAdvance);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert!(machine.store.artifacts.contains_key(&vote_id));

    let leader = Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed,
        attestation(
            LeaderSchedule::round_robin(6)
                .unwrap()
                .leader(View::new(1))
                .get(),
        ),
    ));
    let verification = observe(&mut machine, leader);
    machine.verify(&verification, true, Until::CursorAdvance);
    assert!(machine.inspect().ready_artifacts().contains(&vote_id));
}

#[test]
fn invalid_parent_vqc_releases_waiting_proposal_claim() {
    let profile = Harness::validator(5).participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, parent_leader, &parent_messages));
    let dependency = parent
        .provisions::<Sha256>()
        .into_iter()
        .find_map(|dependency| match dependency {
            Dependency::Vqc(certificate) => Some(certificate),
            Dependency::Leader { .. } => None,
        })
        .unwrap();
    let base = leader(&machine, 1);
    let blocked = LeaderBlock::new(
        base.round(),
        dependency,
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let blocked = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(blocked, attestation(0))),
    );
    machine.verify(&blocked, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let invalid_parent = observe(&mut machine, parent);
    machine.verify(&invalid_parent, false, Until::CursorAdvance);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.inspect().dropped_artifacts(), 0);
    assert!(machine.inspect().pools().is_empty());

    let valid_artifact = leader_artifact(&machine, 1);
    let valid = observe(&mut machine, valid_artifact);
    let ready = machine.step(Input::Verified(valid.all_valid())).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    assert!(matches!(
        ready.persist_job().events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref().sign_one(), Some(SignRequest::Vote(_)))
    ));
}

#[test]
fn rejected_votes_release_their_finality_pools() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    for index in 0..64 {
        let body = VoteBody::new(
            Round::new(machine.profile().protocol().epoch(), View::new(1)),
            digest(format!("invalid leader {index}").as_bytes()),
            vec![Position::new(0); 6],
            vec![Extension::empty(); 6],
            machine.profile().codec(),
        )
        .unwrap();
        let verification = observe(
            &mut machine,
            Artifact::Vote(Vote::new(body, attestation(0))),
        );
        machine.verify(&verification, false, Until::CursorAdvance);
        assert_eq!(machine.finality.retained_pools(), 0);
    }

    let owner = machine.profile().protocol().leader(View::new(1));
    let proposal = Artifact::LeaderBlock(SignedLeaderBlock::new(
        leader(&machine, 1),
        attestation(owner.get()),
    ));
    let proposal = observe(&mut machine, proposal);
    machine.verify(&proposal, false, Until::CursorAdvance);
    assert_eq!(machine.finality.retained_pools(), 0);
}

#[test]
fn ingress_bounds_apply_before_verification() {
    let mut machine = active_machine(Role::Observer);
    let far = leader_artifact(&machine, 4);
    let wrong_epoch = {
        let other = Machine::new(
            Profile::new::<MinPk>(
                TestConfig::new(1).epoch(Epoch::new(8)).build(),
                Role::Observer,
                Tuning {
                    view_timeout: Duration::from_secs(1),
                    production_interval: Duration::from_millis(100),
                    view_retention: retention_for(TEST_RESOURCES, 1),
                    ..Tuning::default()
                },
            )
            .unwrap(),
        );
        leader_artifact(&other, 1)
    };

    let step = machine
        .step(cohort::<Sha256, _>(vec![far, wrong_epoch]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("observation input must be classified");
    };
    assert_eq!(
        results[0].status(),
        ObservationStatus::Rejected(Rejection::FutureView)
    );
    assert_eq!(
        results[1].status(),
        ObservationStatus::Rejected(Rejection::Context)
    );
    assert!(step.capabilities().is_empty());
    assert_eq!(machine.inspect().cached_artifacts(), 0);

    let artifacts = (0..=TEST_RESOURCES.max_verification_batch())
        .map(|_| leader_artifact(&machine, 1))
        .collect();
    let oversized = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    assert_eq!(
        oversized.status(),
        &StepStatus::CohortRejected {
            count: TEST_RESOURCES.max_verification_batch() + 1,
            rejection: Rejection::VerificationBatchTooLarge,
        }
    );
    assert!(oversized.capabilities().is_empty());

    let limits = TEST_RESOURCES.with_max_artifact_bytes(NZUsize!(1));
    let mut limited = Machine::new(Harness::observer().resources(limits).profile());
    let start = limited.step(Input::Start).unwrap();
    limited.persist(&start.persist_job(), Until::CursorAdvance);
    let artifact = leader_artifact(&limited, 1);
    let rejected = limited.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = rejected.status() else {
        panic!("individual oversized artifact must be classified");
    };
    assert_eq!(results[0].id(), None);
    assert_eq!(
        results[0].status(),
        ObservationStatus::Rejected(Rejection::ArtifactTooLarge)
    );
}

#[test]
fn inputs_are_lifecycle_gated() {
    let mut fresh = Machine::new(Harness::observer().profile());
    let artifact = leader_artifact(&fresh, 1);
    assert!(matches!(
        fresh.step(cohort::<Sha256, _>(vec![artifact])),
        Err(StepError::Lifecycle)
    ));
    assert!(matches!(
        fresh.step(Input::RecoveryComplete),
        Err(StepError::Lifecycle)
    ));

    let mut active = active_machine(Role::Observer);
    assert!(matches!(
        active.step(Input::Start),
        Err(StepError::Lifecycle)
    ));
    assert!(matches!(
        active.step(Input::RecoveryComplete),
        Err(StepError::Lifecycle)
    ));
}

/// Returns how the machine classifies `artifact` observed alone.
fn observation(machine: &mut TestMachine, artifact: Artifact<MinPk, Digest>) -> ObservationStatus {
    let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    results[0].status()
}

fn producer_block(header: &TransactionBlockHeader<Digest>) -> Artifact<MinPk, Digest> {
    Artifact::TransactionBlock(SignedTransactionBlock::new(
        header.clone(),
        attestation(header.chain().get()),
    ))
}

fn da_vote(header: &TransactionBlockHeader<Digest>, signer: u32) -> Artifact<MinPk, Digest> {
    Artifact::DaVote(DaVote::new(header.clone(), threshold_share(signer)))
}

#[test]
fn height_window_admits_its_edge_and_rejects_beyond_it() {
    // Validator 5 produces chain 5 and votes on chain 1.
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    let depth = machine.profile().codec().pipeline_depth() as u64;
    let window = depth * HEIGHT_WINDOW_PIPELINES;
    // Chain 1 is certified at genesis, so the window ends at height `window`.
    let headers = da_run_headers(&machine, 1, window + 2, "window");
    let at = |height: u64| &headers[height as usize - 1];

    assert_eq!(
        observation(&mut machine, producer_block(at(window + 1))),
        ObservationStatus::Rejected(Rejection::FutureHeight)
    );
    let edge = observe(&mut machine, producer_block(at(window)));
    machine.verify(&edge, true, Until::CursorAdvance);

    // A DA certificate raises the frontier, and the window with it.
    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(at(1).clone(), 0)),
    );
    machine.verify(&certificate, true, Until::CursorAdvance);
    observe(&mut machine, producer_block(at(window + 1)));
    assert_eq!(
        observation(&mut machine, producer_block(at(window + 2))),
        ObservationStatus::Rejected(Rejection::FutureHeight)
    );

    // Votes on the chain this node produces are bounded by the same window before their header
    // is checked.
    let own = da_run_headers(&machine, 5, window + 1, "own window");
    assert_eq!(
        observation(&mut machine, da_vote(&own[window as usize], 2)),
        ObservationStatus::Rejected(Rejection::FutureHeight)
    );
    assert_eq!(
        observation(&mut machine, da_vote(&own[window as usize - 1], 2)),
        ObservationStatus::Rejected(Rejection::Unsolicited)
    );
}

#[test]
fn a_position_holds_one_da_vote_per_signer_for_a_verified_header() {
    // Validator 1 produces chain 1.
    let (mut machine, _) = Harness::validator(1).participants(6).start();
    let header = da_run_headers(&machine, 1, 1, "slot").remove(0);

    // Only the chain's producer uses its DA votes.
    let (mut other, _) = Harness::validator(5).participants(6).start();
    assert_eq!(
        observation(&mut other, da_vote(&header, 2)),
        ObservationStatus::Rejected(Rejection::Unsolicited)
    );
    // The producer takes a vote only for a header a verified producer block vouches for.
    assert_eq!(
        observation(&mut machine, da_vote(&header, 2)),
        ObservationStatus::Rejected(Rejection::Unsolicited)
    );
    let block = observe(&mut machine, producer_block(&header));
    machine.verify(&block, true, Until::CursorAdvance);

    let first = observe(&mut machine, da_vote(&header, 2));
    machine.verify(&first, true, Until::CursorAdvance);
    assert_eq!(
        observation(&mut machine, da_vote(&header, 2)),
        ObservationStatus::Duplicate
    );
    // Another share from the same signer for the same header takes no second slot.
    let other_share = Artifact::DaVote(DaVote::new(
        header.clone(),
        ThresholdShare::new(Participant::new(2), Lazy::from(G2::generator())),
    ));
    assert_eq!(
        observation(&mut machine, other_share),
        ObservationStatus::Rejected(Rejection::PositionFull)
    );
    let second_signer = observe(&mut machine, da_vote(&header, 3));
    machine.verify(&second_signer, true, Until::CursorAdvance);
    let cached = machine.inspect().cached_artifacts();
    assert_eq!(cached, 3, "the block and one vote from each of two signers");

    // Once the height is certified the position no longer bounds votes: late ones retire as soon
    // as they are ready.
    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(header.clone(), 0)),
    );
    let advanced = machine.verify(&certificate, true, Until::CursorAdvance);
    machine.drain_persisting(advanced);
    assert_eq!(
        machine.live_snapshot_for_test().certified_tips()[1].height(),
        header.height()
    );
    let late = observe(&mut machine, da_vote(&header, 4));
    machine.verify(&late, true, Until::CursorAdvance);
    assert!(
        !machine
            .inspect()
            .ready_artifacts()
            .contains(&da_vote(&header, 4).id::<Sha256>())
    );
}
