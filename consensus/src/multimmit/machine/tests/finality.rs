//! Finality pool, L-QC assembly, and finality-owner tests.

use super::fixtures::{
    Harness, TEST_RESOURCES, TestMachine, attestation, digest, drive_unanimous_votes,
    durable_effect, genesis_tip_history, leader, leader_artifact, lqc, no_vote, observe,
    start_profile, symbolic_da_certificate, view_vote, vqc,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::ResourceLimits,
        machine::{
            capability::{Capability, CryptoJob, ResolverCommand},
            durability::{Change, DurableEffect, PersistDirective, SignRequest},
            finality::{FinalityError, FinalityOutput, FinalityState, LqcAggregateCompletion},
            input::{CryptoCompletion, Input, ObservationStatus, StepError, StepStatus},
            job::Generation,
            scheduler::WorkKey,
            testing::{
                CapabilitiesExt as _, Drive as _, EffectExt, MachineExt as _, Until, cohort,
            },
            verification::Observation,
            view::VqcAggregateCompletion,
        },
        types::{
            Activity, Anchor, Artifact, CertificateId, ChainProposal, ConflictingVote,
            DigestedLeader, Extension, FinalityId, LeaderBlock, Position, SignedLeaderBlock, Tally,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc,
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
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[test]
fn pool_finality_precedes_lqc_assembly_and_grows_monotonically() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);

    let vote = |machine: &TestMachine, signer: u32, supports_extension: bool| {
        let mut extensions = vec![Extension::empty(); 6];
        if supports_extension {
            extensions[0] = Extension::new(vec![digest(b"late final tip")], 1).unwrap();
        }
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(0); 6],
            extensions,
            machine.profile().codec(),
        )
        .unwrap();
        Vote::new(body, attestation(signer))
    };

    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(vote(&machine, signer, signer < 4));
        let vote = observe(&mut machine, artifact);
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        if signer < 4 {
            assert!(
                step.activities()
                    .iter()
                    .all(|activity| !matches!(activity, Activity::LeaderFinalized { .. }))
            );
            assert!(machine.inspect().finality().is_empty());
            assert!(
                step.capabilities().iter().all(|effect| !matches!(
                    effect,
                    Capability::Crypto(CryptoJob::AggregateLqc(_))
                ))
            );
            continue;
        }
        assert_eq!(
            step.activities()
                .iter()
                .filter(|activity| matches!(activity, Activity::LeaderFinalized { .. }))
                .count(),
            1
        );
        // Finalization stages ordering barriers before the drive derives aggregation, so the
        // releasing completion is folded through every barrier it stages.
        let effects = machine.drain_persisting(step);
        aggregate = effects.aggregate_lqc();
    }

    let aggregate = aggregate.expect("the n-f vote must schedule L-QC assembly");
    assert_eq!(
        aggregate
            .votes()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
    let inspection = machine.inspect();
    let [pool] = inspection.pools() else {
        panic!("one exact leader must have one direct pool");
    };
    assert_eq!(pool.votes(), 5);
    assert!(pool.finalized());
    assert!(pool.lqc_pending());
    let [fact] = inspection.finality() else {
        panic!("the direct pool must finalize before aggregation completes");
    };
    assert_eq!(fact.votes(), 5);
    let initial_blocks = fact.blocks().to_vec();

    let last = Artifact::Vote(vote(&machine, 5, true));
    let last = observe(&mut machine, last);
    let grown = machine.verify(&last, true, Until::CursorAdvance);
    let updated_blocks = grown
        .activities()
        .iter()
        .find_map(|activity| match activity {
            Activity::LeaderFinalityUpdated { fact } => Some(fact.blocks().to_vec()),
            _ => None,
        })
        .expect("advancing final tips must report the stronger finality fact");
    assert!(
        grown
            .activities()
            .iter()
            .all(|activity| !matches!(activity, Activity::LeaderFinalized { .. }))
    );
    assert_ne!(updated_blocks, initial_blocks);
    let commitments = grown
        .activities()
        .iter()
        .find_map(|activity| match activity {
            Activity::CommitmentsAccepted { commitments } => Some(commitments),
            _ => None,
        })
        .expect("the direct pool supplies selected producer commitments");
    assert_eq!(commitments.epoch(), proposed.round().epoch());
    assert_eq!(commitments.paths().len(), 1);
    assert_eq!(
        commitments.paths()[0].as_ref(),
        &[initial_blocks[0], updated_blocks[0]]
    );
    let effects = machine.drain_persisting(grown);
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Crypto(CryptoJob::AggregateLqc(_))))
    );
    assert_eq!(machine.inspect().pools()[0].votes(), 6);
    assert_eq!(machine.inspect().finality()[0].votes(), 6);
    assert_eq!(machine.inspect().finality()[0].blocks(), updated_blocks);
}

#[test]
fn direct_finality_id_commits_to_the_sticky_vote_evidence() {
    let finalize = |branch: &str| {
        let profile = Harness::observer().participants(6).profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        machine.verify(&proposal, true, Until::CursorAdvance);

        for signer in 0..5 {
            let extensions = (0..6)
                .map(|chain| {
                    let label = format!("{branch} {chain}");
                    Extension::new(vec![digest(label.as_bytes())], 1).unwrap()
                })
                .collect();
            let body = VoteBody::for_leader(
                DigestedLeader::new::<Sha256>(&proposed),
                vec![Position::new(0); 6],
                extensions,
                machine.profile().codec(),
            )
            .unwrap();
            let vote = observe(
                &mut machine,
                Artifact::Vote(Vote::new(body, attestation(signer))),
            );
            machine.verify(&vote, true, Until::CursorAdvance);
        }

        machine.inspect().finality()[0].clone()
    };

    let left = finalize("left");
    let right = finalize("right");
    assert_eq!(left.round(), right.round());
    assert_eq!(left.leader(), right.leader());
    assert_eq!(left.votes(), right.votes());
    assert_ne!(left.blocks(), right.blocks());
    assert_ne!(left.id(), right.id());
}

#[test]
fn pool_stickiness_follows_observation_not_verification_completion() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);

    let earlier = Artifact::Vote(view_vote(&machine, &proposed, 0));
    let earlier = observe(&mut machine, earlier);
    let mut extensions = vec![Extension::empty(); 6];
    extensions[0] = Extension::new(vec![digest(b"later extension")], 1).unwrap();
    let later_body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&proposed),
        vec![Position::new(0); 6],
        extensions,
        machine.profile().codec(),
    )
    .unwrap();
    let later = observe(
        &mut machine,
        Artifact::Vote(Vote::new(later_body, attestation(0))),
    );
    let others = (1..5)
        .map(|signer| {
            let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
            observe(&mut machine, artifact)
        })
        .collect::<Vec<_>>();

    machine.verify(&later, true, Until::CursorAdvance);
    for vote in &others {
        machine.verify(vote, true, Until::CursorAdvance);
    }
    assert_eq!(machine.inspect().pools()[0].votes(), 0);

    let completed = machine.verify(&earlier, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(completed);
    let aggregate = effects
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job),
            _ => None,
        })
        .expect("resolving the earliest observation must release the pool");
    let selected = aggregate
        .votes()
        .find(|vote| vote.signer() == Participant::new(0))
        .unwrap();
    assert!(selected.body().extensions()[0].is_empty());
}

#[test]
fn completion_permutations_preserve_sticky_selection() {
    let run = |completion_order: [usize; 2]| {
        let (mut machine, _) = Harness::observer().start();
        let protocol = machine.profile().protocol();
        let genesis = protocol.genesis().tips()[0];
        let first_commitment = digest(b"sticky first");
        let second_commitment = digest(b"sticky second");
        let first_block = TransactionBlockHeader::new(
            protocol.epoch(),
            genesis.chain(),
            Height::new(1),
            genesis.digest(),
            first_commitment,
        )
        .unwrap()
        .block_ref::<Sha256>();
        let second_block = TransactionBlockHeader::new(
            protocol.epoch(),
            genesis.chain(),
            Height::new(2),
            first_block.digest(),
            second_commitment,
        )
        .unwrap()
        .block_ref::<Sha256>();
        let proposal = ChainProposal::new(
            genesis.chain(),
            Anchor::Tip(genesis),
            vec![first_commitment, second_commitment],
            protocol.codec_config().pipeline_depth(),
        )
        .unwrap();
        let proposed = LeaderBlock::new(
            Round::new(protocol.epoch(), View::new(2)),
            protocol.genesis().vqc(),
            genesis_tip_history(protocol),
            vec![proposal],
            protocol.codec_config(),
        )
        .unwrap();
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        machine.verify(&verification, true, Until::CursorAdvance);

        let earlier_body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(1)],
            vec![Extension::empty()],
            machine.profile().codec(),
        )
        .unwrap();
        let later_body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(2)],
            vec![Extension::empty()],
            machine.profile().codec(),
        )
        .unwrap();
        let earlier = observe(
            &mut machine,
            Artifact::Vote(Vote::new(earlier_body.clone(), attestation(0))),
        );
        let later = observe(
            &mut machine,
            Artifact::Vote(Vote::new(later_body, attestation(0))),
        );

        let jobs = [earlier, later];
        let mut aggregate = None;
        for index in completion_order {
            let step = machine.verify(&jobs[index], true, Until::CursorAdvance);
            let effects = machine.drain_persisting(step);
            for effect in effects {
                if let Capability::Crypto(CryptoJob::AggregateLqc(job)) = effect {
                    assert!(
                        aggregate.replace(job).is_none(),
                        "one pool must release only one aggregation job"
                    );
                }
            }
        }

        let aggregate = aggregate.expect("settling the pool must release an aggregation job");
        let selected = aggregate.votes().collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].signer(), Participant::new(0));
        assert_eq!(selected[0].body(), &earlier_body);

        let inspection = machine.inspect();
        let [direct] = inspection.finality() else {
            panic!("one direct finality fact must select the sticky vote");
        };
        assert!(matches!(direct.id(), FinalityId::Direct(_)));
        assert_eq!(direct.votes(), 1);
        assert_eq!(direct.positions(), &[Position::new(1)]);
        assert_eq!(direct.blocks(), &[first_block]);
        assert_ne!(first_block, second_block);

        direct.clone()
    };

    assert_eq!(run([0, 1]), run([1, 0]));
}

#[test]
fn context_invalid_vote_does_not_poison_the_sticky_slot() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);

    let invalid_body = VoteBody::new(
        proposed.round(),
        proposed.digest::<Sha256>(),
        vec![Position::new(1); 6],
        vec![Extension::empty(); 6],
        machine.profile().codec(),
    )
    .unwrap();
    let invalid = observe(
        &mut machine,
        Artifact::Vote(Vote::new(invalid_body, attestation(0))),
    );
    let valid_body = view_vote(&machine, &proposed, 0).body().clone();
    let valid = observe(
        &mut machine,
        Artifact::Vote(Vote::new(valid_body.clone(), attestation(0))),
    );

    machine.verify(&valid, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().pools()[0].votes(), 0);
    machine.verify(&invalid, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().pools()[0].votes(), 1);

    for signer in 1..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let verification = observe(&mut machine, vote);
        let step = machine.verify(&verification, true, Until::CursorAdvance);
        if signer != 4 {
            continue;
        }
        let effects = machine.drain_persisting(step);
        let aggregate = effects
            .find(|effect| match effect {
                Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job),
                _ => None,
            })
            .unwrap();
        assert_eq!(aggregate.votes().next().unwrap().body(), &valid_body);
    }
}

#[test]
fn authenticated_peer_artifact_cannot_rewrite_a_local_vote_choice() {
    let (mut machine, _) = Harness::validator(0).participants(6).start();
    let proposed = leader(&machine, 2);
    let local = view_vote(&machine, &proposed, 0).body().clone();
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::Vote(local)))
        .unwrap();
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    // A peer can relay any authenticated artifact, including an equivocation signed by this
    // process's identity in a Twins execution. Network admission must not reinterpret it as a new
    // local signing decision; only the journal can establish that decision.
    let conflicting = Artifact::NoVote(no_vote(&machine, View::new(2), 0));
    let conflicting = observe(&mut machine, conflicting);
    let completed = machine.verify(&conflicting, true, Until::CursorAdvance);
    assert!(matches!(completed.status(), StepStatus::Verified { .. }));
}

#[test]
fn independent_finality_pools_aggregate_in_parallel() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    // Same-view twins keep both pools within the retained diagnostic window, so neither
    // aggregation can be retired as moot while the other is still scheduling.
    let base = leader(&machine, 2);
    let twin = LeaderBlock::new(
        base.round(),
        machine.profile().protocol().genesis().vqc(),
        genesis_tip_history(machine.profile().protocol()),
        {
            let mut proposals = base.proposals().to_vec();
            proposals[0] = ChainProposal::new(
                proposals[0].anchor().chain(),
                proposals[0].anchor().clone(),
                vec![digest(b"twin payload")],
                machine.profile().codec().pipeline_depth(),
            )
            .unwrap();
            proposals
        },
        machine.profile().codec(),
    )
    .unwrap();
    let leaders = [base, twin];
    for proposed in &leaders {
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        machine.verify(&verification, true, Until::CursorAdvance);
        for signer in 0..4 {
            let vote = Artifact::Vote(view_vote(&machine, proposed, signer));
            let verification = observe(&mut machine, vote);
            machine.verify(&verification, true, Until::CursorAdvance);
        }
    }

    let step = machine
        .step(cohort::<Sha256, _>(
            leaders
                .iter()
                .map(|proposed| Artifact::Vote(view_vote(&machine, proposed, 4)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verify(job)] = step.capabilities() else {
        panic!("the final votes must share one verification cohort");
    };
    let completed = machine.verify(job, true, Until::CursorAdvance);
    // Ordering interleaves with aggregation scheduling and may pause on header resolution, so
    // count aggregation jobs across a bounded number of scheduler turns instead of expecting
    // both in one pass.
    let mut jobs = 0;
    let mut effects = completed.into_capabilities();
    for _ in 0..32 {
        let mut staged = None;
        for effect in effects {
            match effect {
                Capability::Crypto(CryptoJob::AggregateLqc(_)) => jobs += 1,
                Capability::Journal(PersistDirective { job, .. }) => staged = Some(job),
                _ => {}
            }
        }
        if let Some(job) = staged {
            machine.persist(&job, Until::Step);
        }
        if jobs == 2 {
            break;
        }
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = machine.work_remaining();
        effects = result.into_capabilities();
        if effects.is_empty() && !work_remaining {
            break;
        }
    }
    assert_eq!(jobs, 2);
}

#[test]
fn inbound_lqc_finalizes_without_parent_resolution() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 2);
    let proposed = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"missing parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let certificate_id = certificate.id::<Sha256>();
    let verification = observe(&mut machine, certificate);
    let completed = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(completed);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    let inspection = machine.inspect();
    let fact = inspection
        .finality()
        .iter()
        .find(|fact| fact.id() == FinalityId::Lqc(certificate_id))
        .expect("an authenticated L-QC must establish finality immediately");
    assert_eq!(fact.id(), FinalityId::Lqc(certificate_id));
    assert_eq!(fact.votes(), 5);
    assert_eq!(inspection.pools()[0].votes(), 5);
    assert!(inspection.pools()[0].finalized());

    let retried = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(
        retried
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_))))
    );
}

#[test]
fn raw_witnesses_after_an_inbound_lqc_do_not_schedule_aggregation() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let verification = observe(&mut machine, certificate);
    let completed = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(completed);
    let inspection = machine.inspect();
    let [pool] = inspection.pools() else {
        panic!("one exact leader must have one direct pool");
    };
    assert!(pool.finalized());
    assert!(!pool.lqc_pending());

    // The held L-QC completed the pool's L-QC progress, so witnesses for its whole quorum attach
    // without scheduling a second aggregation.
    for vote in votes {
        let verification = observe(&mut machine, Artifact::Vote(vote));
        let step = machine.verify(&verification, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(step);
        assert!(
            effects
                .iter()
                .all(|effect| !matches!(effect, Capability::Crypto(CryptoJob::AggregateLqc(_))))
        );
    }
    assert!(!machine.inspect().pools()[0].lqc_pending());
}

#[test]
fn inbound_lqc_votes_extend_the_arrival_first_pool() {
    let run = |raw_vote_first: bool| {
        let profile = Harness::observer().participants(6).profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let mut votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let mut extensions = vec![Extension::empty(); 6];
        extensions[0] = Extension::new(vec![digest(b"beyond final tip")], 1).unwrap();
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(0); 6],
            extensions,
            machine.profile().codec(),
        )
        .unwrap();
        votes[0] = Vote::new(body, attestation(0));

        let raw = Artifact::Vote(view_vote(&machine, &proposed, 5));
        let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
        let (first, second) = if raw_vote_first {
            (raw, certificate)
        } else {
            (certificate, raw)
        };
        for artifact in [first, second] {
            let verification = observe(&mut machine, artifact);
            machine.verify(&verification, true, Until::CursorAdvance);
        }

        let inspection = machine.inspect();
        let certified = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .unwrap();
        let direct = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .unwrap();
        assert_eq!(certified.votes(), 5);
        assert!(!certified.settled()[0]);
        assert_eq!(direct.votes(), 6);
        assert!(direct.settled()[0]);
        assert_eq!(inspection.pools()[0].votes(), 6);
        direct.clone()
    };

    assert_eq!(run(false), run(true));
}

#[test]
fn finality_retains_one_certificate_witness_per_pool() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);

    for signers in [0..5, 1..6] {
        let votes = signers
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let certificate = Artifact::Lqc(lqc(&machine, proposed.clone(), &votes));
        let verification = observe(&mut machine, certificate);
        machine.verify(&verification, true, Until::CursorAdvance);
    }

    let inspection = machine.inspect();
    assert_eq!(inspection.pools().len(), 1);
    assert_eq!(inspection.pools()[0].votes(), 6);
    assert_eq!(
        inspection
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .count(),
        1
    );
}

#[test]
fn inbound_lqc_reserves_its_votes_before_verification() {
    let run = |complete_raw_first: bool| {
        let profile = Harness::observer().participants(6).profile();
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let mut votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let mut extensions = vec![Extension::empty(); 6];
        extensions[0] = Extension::new(vec![digest(b"certificate vote")], 1).unwrap();
        let certificate_body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(0); 6],
            extensions,
            machine.profile().codec(),
        )
        .unwrap();
        votes[0] = Vote::new(certificate_body, attestation(0));

        let certificate = Artifact::Lqc(lqc(&machine, proposed.clone(), &votes));
        let certificate = observe(&mut machine, certificate);
        let raw = Artifact::Vote(view_vote(&machine, &proposed, 0));
        let raw = observe(&mut machine, raw);
        if complete_raw_first {
            machine.verify(&raw, true, Until::CursorAdvance);
            assert!(machine.inspect().pools().is_empty());
            machine.verify(&certificate, true, Until::CursorAdvance);
        } else {
            machine.verify(&certificate, true, Until::CursorAdvance);
            machine.verify(&raw, true, Until::CursorAdvance);
        }

        let inspection = machine.inspect();
        let direct = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .unwrap();
        assert_eq!(direct.votes(), 5);
        (inspection.pools()[0], direct.clone())
    };

    assert_eq!(run(false), run(true));
}

#[test]
fn vqc_constituents_preserve_finality_observation_order() {
    let run = |certificate_valid: bool| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            2,
            NonZeroUsize::new(64).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = Harness::observer()
            .participants(6)
            .resources(limits)
            .profile();
        let (mut machine, _) = start_profile(profile);
        let config = machine.profile().codec();
        let base = leader(&machine, 2);
        let with_payload = |label: &[u8]| {
            let mut proposals = base.proposals().to_vec();
            proposals[0] = ChainProposal::new(
                proposals[0].anchor().chain(),
                proposals[0].anchor().clone(),
                vec![digest(label)],
                config.pipeline_depth(),
            )
            .unwrap();
            LeaderBlock::new(
                base.round(),
                base.parent(),
                base.history(),
                proposals,
                config,
            )
            .unwrap()
        };
        let designated = with_payload(b"designated payload");
        let other = with_payload(b"other payload");

        let vote_at = |leader: &LeaderBlock<MinPk, Digest>, signer: u32, position: u32| {
            let mut positions = vec![Position::new(0); config.chains()];
            positions[0] = Position::new(position);
            Vote::new(
                VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(leader),
                    positions,
                    vec![Extension::empty(); config.chains()],
                    config,
                )
                .unwrap(),
                attestation(signer),
            )
        };

        let designated_votes = (0..3)
            .map(|signer| vote_at(&designated, signer, 0))
            .collect::<Vec<_>>();
        let tally = Tally::from_votes(
            DigestedLeader::new::<Sha256>(&designated),
            designated_votes
                .iter()
                .map(|vote| (vote.signer(), vote.body().clone())),
            config,
        )
        .unwrap();
        let conflicting = (3..5)
            .map(|signer| {
                let vote = vote_at(&other, signer, 0);
                ConflictingVote::new(vote.signer(), vote.body().ballot().clone(), config).unwrap()
            })
            .collect();
        let certificate = Vqc::new(
            designated.clone(),
            tally,
            Signers::new(u32::try_from(config.participants()).unwrap(), []).unwrap(),
            conflicting,
            aggregate::Signature::<MinPk>::zero(),
            config,
        )
        .unwrap();
        let certificate = observe(&mut machine, Artifact::Vqc(certificate));

        for proposed in [&designated, &other] {
            let leader = observe(
                &mut machine,
                Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
            );
            machine.verify(&leader, true, Until::CursorAdvance);

            for signer in 0..5 {
                let vote = observe(&mut machine, Artifact::Vote(vote_at(proposed, signer, 1)));
                machine.verify(&vote, true, Until::CursorAdvance);
            }
        }

        assert!(
            machine.inspect().finality().is_empty(),
            "later direct votes must wait for every earlier V-QC constituent"
        );

        machine.verify(&certificate, certificate_valid, Until::CursorAdvance);
        let positions = machine
            .inspect()
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .map(|fact| (fact.leader(), fact.positions()[0]))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(positions.len(), 2);
        (
            positions[&designated.digest::<Sha256>()],
            positions[&other.digest::<Sha256>()],
        )
    };

    assert_eq!(run(true), (Position::new(0), Position::new(0)));
    assert_eq!(run(false), (Position::new(1), Position::new(1)));
}

#[test]
fn aggregate_vote_witnesses_freeze_the_exact_finality_quorum() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        2,
        NonZeroUsize::new(64).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let signed = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&signed, true, Until::CursorAdvance);

    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let certificate = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
    let certificate = observe(&mut machine, certificate);
    let witnesses = votes
        .iter()
        .cloned()
        .map(|vote| observe(&mut machine, Artifact::Vote(vote)))
        .collect::<Vec<_>>();
    let extra = Artifact::Vote(view_vote(&machine, &proposed, 5));
    let extra = observe(&mut machine, extra);
    machine.verify(&extra, true, Until::CursorAdvance);
    machine.verify(&certificate, true, Until::CursorAdvance);
    assert_eq!(machine.inspect().pools()[0].votes(), 6);

    let mut aggregate = None;
    for witness in witnesses {
        let completed = machine.verify(&witness, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(completed);
        aggregate = aggregate.or_else(|| {
            effects.into_iter().find_map(|effect| match effect {
                Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job),
                _ => None,
            })
        });
    }
    let aggregate = aggregate.expect("the exact witnessed quorum must schedule L-QC assembly");
    assert_eq!(
        aggregate
            .votes()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
}

#[test]
fn matching_aggregate_witness_survives_an_earlier_mismatch() {
    let profile = Harness::observer().profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let signed = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&signed, true, Until::CursorAdvance);

    let selected = view_vote(&machine, &proposed, 0);
    let certificate = vqc(
        &machine,
        proposed.clone(),
        &[ViewMessage::Vote(selected.clone())],
    );
    let certificate = observe(&mut machine, Artifact::Vqc(certificate));
    machine.verify(&certificate, true, Until::CursorAdvance);

    let mut extensions = vec![Extension::empty(); 1];
    extensions[0] = Extension::new(vec![digest(b"mismatching witness")], 1).unwrap();
    let mismatch = Vote::new(
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&proposed),
            vec![Position::new(0)],
            extensions,
            machine.profile().codec(),
        )
        .unwrap(),
        attestation(0),
    );
    let mismatch = observe(&mut machine, Artifact::Vote(mismatch));
    let matching = observe(&mut machine, Artifact::Vote(selected));

    machine.verify(&matching, true, Until::CursorAdvance);
    machine.verify(&mismatch, true, Until::CursorAdvance);
    assert!(
        machine.inspect().pools()[0].lqc_pending(),
        "the queued matching witness must make L-QC assembly ready"
    );
}

#[test]
fn finality_equivocation_detail_is_bounded_after_verification() {
    let limits = TEST_RESOURCES.with_max_finality_pools(NonZeroUsize::new(8).unwrap());
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 2);
    let config = machine.profile().codec();

    let proposal = |parent: &[u8]| {
        let block = LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(parent)),
            base.history(),
            base.proposals().to_vec(),
            config,
        )
        .unwrap();
        Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(0)))
    };
    let step = machine
        .step(cohort::<Sha256, _>(vec![
            proposal(b"first parent"),
            proposal(b"second parent"),
            proposal(b"third parent"),
        ]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("observation must report each pool reservation");
    };
    assert_eq!(results[0].status(), ObservationStatus::Scheduled);
    assert_eq!(results[1].status(), ObservationStatus::Scheduled);
    assert_eq!(results[2].status(), ObservationStatus::Scheduled);
    let [Capability::Verify(job)] = step.capabilities() else {
        panic!("the proposals must share one verification job");
    };
    machine.verify(job, true, Until::CursorAdvance);

    assert_eq!(machine.inspect().pools().len(), 2);
}

#[test]
fn finality_owner_reservation_waits_for_the_earliest_claim() {
    let limits = TEST_RESOURCES.with_max_finality_pools(NonZeroUsize::new(8).unwrap());
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let config = machine.profile().codec();

    let earlier = leader(&machine, 1);
    let earlier_digest = earlier.digest::<Sha256>();
    let later = LeaderBlock::new(
        earlier.round(),
        CertificateId::new(digest(b"later claim parent")),
        earlier.history(),
        earlier.proposals().to_vec(),
        config,
    )
    .unwrap();
    let later_digest = later.digest::<Sha256>();
    let designated_votes = (0..3)
        .map(|signer| view_vote(&machine, &earlier, signer))
        .collect::<Vec<_>>();
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&earlier),
        designated_votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        config,
    )
    .unwrap();
    let conflicting = (3..5)
        .map(|signer| {
            let vote = view_vote(&machine, &later, signer);
            ConflictingVote::new(vote.signer(), vote.body().ballot().clone(), config).unwrap()
        })
        .collect();
    let earlier_certificate = Artifact::Vqc(
        Vqc::new(
            earlier,
            tally,
            Signers::new(u32::try_from(config.participants()).unwrap(), []).unwrap(),
            conflicting,
            aggregate::Signature::<MinPk>::zero(),
            config,
        )
        .unwrap(),
    );
    let earlier_claim = observe(&mut machine, earlier_certificate);

    let owner = machine.profile().protocol().leader(View::new(1));
    let later_claim = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(later, attestation(owner.get()))),
    );

    let completed = machine.verify(&later_claim, true, Until::CursorAdvance);
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 0,
        }
    );
    assert!(
        machine.inspect().pools().is_empty(),
        "a later verdict cannot consume an unresolved earlier reservation"
    );

    machine.verify(&earlier_claim, true, Until::CursorAdvance);
    let inspection = machine.inspect();
    let earlier_pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.leader() == earlier_digest)
        .expect("the aggregate's earlier leader claim must be installed first");
    assert_eq!(earlier_pool.votes(), 3);
    let later_pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.leader() == later_digest)
        .expect("the later valid detail may install only after the aggregate resolves");
    assert_eq!(later_pool.votes(), 2);
}

#[test]
fn rejected_finality_owner_reservation_releases_the_next_verdict() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 1);
    let config = machine.profile().codec();
    let proposal = |parent: &[u8]| {
        let block = LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(parent)),
            base.history(),
            base.proposals().to_vec(),
            config,
        )
        .unwrap();
        let digest = block.digest::<Sha256>();
        let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(1)));
        (digest, artifact)
    };
    let (_, earlier) = proposal(b"invalid earlier owner claim");
    let (later_digest, later) = proposal(b"valid later owner claim");
    let earlier = observe(&mut machine, earlier);
    let later = observe(&mut machine, later);

    machine.verify(&later, true, Until::CursorAdvance);
    assert!(machine.inspect().pools().is_empty());

    machine.verify(&earlier, false, Until::CursorAdvance);
    let inspection = machine.inspect();
    let pools = inspection.pools();
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].leader(), later_digest);
}

#[test]
fn lqc_output_waits_for_earlier_owner_claim() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut finality = FinalityState::new(&profile);
    let base = leader(&machine, 1);
    let owner = machine.profile().protocol().leader(View::new(1));
    let earlier = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        base.clone(),
        attestation(owner.get()),
    )));
    let later = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"later L-QC parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, later, &votes);
    let later = Arc::new(Artifact::Lqc(certificate));
    let earlier_id = earlier.id::<Sha256>();
    let later_id = later.id::<Sha256>();
    let earlier_observation = Observation::new(1, 0);
    let later_observation = Observation::new(2, 0);
    for (artifact_id, observation, artifact) in [
        (earlier_id, earlier_observation, Arc::clone(&earlier)),
        (later_id, later_observation, Arc::clone(&later)),
    ] {
        finality
            .claim_finality::<Sha256>(artifact_id, observation, artifact, &profile)
            .unwrap();
    }

    let blocked = finality
        .validate_finality_claim::<Sha256>(later_id, later_observation, &later, &profile, None)
        .unwrap();
    assert!(blocked.is_empty());

    let released = finality
        .reject_finality_claim::<Sha256>(earlier_id, earlier_observation, &earlier, &profile)
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [FinalityOutput {
            observation,
            certificate,
            ..
        }] if certificate.id::<Sha256>() == later_id
            && *observation == later_observation
            && certificate.as_ref() == later.as_ref()
    ));
}

#[test]
fn later_duplicate_completion_preserves_an_earlier_finality_observation() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut finality = FinalityState::new(&profile);
    let base = leader(&machine, 1);
    let owner = machine.profile().protocol().leader(View::new(1));
    let blocker = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        base.clone(),
        attestation(owner.get()),
    )));
    let later = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"duplicate L-QC parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().codec(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later, signer))
        .collect::<Vec<_>>();
    let certificate = Arc::new(Artifact::Lqc(lqc(&machine, later, &votes)));
    let blocker_id = blocker.id::<Sha256>();
    let certificate_id = certificate.id::<Sha256>();
    let blocker_observation = Observation::new(1, 0);
    let first_observation = Observation::new(2, 0);
    let duplicate_observation = Observation::new(3, 0);

    finality
        .claim_finality::<Sha256>(
            blocker_id,
            blocker_observation,
            Arc::clone(&blocker),
            &profile,
        )
        .unwrap();
    finality
        .claim_finality::<Sha256>(
            certificate_id,
            first_observation,
            Arc::clone(&certificate),
            &profile,
        )
        .unwrap();

    let blocked = finality
        .validate_finality_claim::<Sha256>(
            certificate_id,
            first_observation,
            &certificate,
            &profile,
            None,
        )
        .unwrap();
    assert!(blocked.is_empty());
    finality
        .claim_finality::<Sha256>(
            certificate_id,
            duplicate_observation,
            Arc::clone(&certificate),
            &profile,
        )
        .unwrap();
    let duplicate = finality
        .validate_finality_claim::<Sha256>(
            certificate_id,
            duplicate_observation,
            &certificate,
            &profile,
            None,
        )
        .unwrap();
    assert!(duplicate.is_empty());

    let released = finality
        .reject_finality_claim::<Sha256>(blocker_id, blocker_observation, &blocker, &profile)
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [FinalityOutput {
            observation,
            certificate: artifact,
            ..
        }] if artifact.id::<Sha256>() == certificate_id
            && *observation == first_observation
            && artifact.as_ref() == certificate.as_ref()
    ));
}

#[test]
fn retiring_pending_finality_claim_releases_later_certificate() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut finality = FinalityState::new(&profile);
    let earlier_leader = leader(&machine, 1);
    let later_leader = leader(&machine, 7);
    let earlier_owner = profile.protocol().leader(earlier_leader.round().view());
    assert_eq!(
        earlier_owner,
        profile.protocol().leader(later_leader.round().view())
    );
    let earlier = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        earlier_leader,
        attestation(earlier_owner.get()),
    )));
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later_leader, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, later_leader, &votes);
    let later = Arc::new(Artifact::Lqc(certificate));
    let earlier_id = earlier.id::<Sha256>();
    let later_id = later.id::<Sha256>();
    let earlier_observation = Observation::new(1, 0);
    let later_observation = Observation::new(2, 0);
    for (artifact_id, observation, artifact) in [
        (earlier_id, earlier_observation, Arc::clone(&earlier)),
        (later_id, later_observation, Arc::clone(&later)),
    ] {
        finality
            .claim_finality::<Sha256>(artifact_id, observation, artifact, &profile)
            .unwrap();
    }
    let blocked = finality
        .validate_finality_claim::<Sha256>(later_id, later_observation, &later, &profile, None)
        .unwrap();
    assert!(blocked.is_empty());

    let released = finality
        .retire_through::<Sha256>(&profile, View::new(1))
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [FinalityOutput {
            observation,
            certificate,
            ..
        }] if certificate.id::<Sha256>() == later_id
            && *observation == later_observation
            && certificate.as_ref() == later.as_ref()
    ));
}

#[test]
fn finality_facts_list_each_pool_direct_then_certified() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut finality = FinalityState::new(&profile);
    // An L-QC certifies its leader and settles its votes into the direct pool.
    for view in [2, 1] {
        let proposed = leader(&machine, view);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let certificate = Arc::new(Artifact::Lqc(lqc(&machine, proposed, &votes)));
        let id = certificate.id::<Sha256>();
        let observation = Observation::new(view, 0);
        finality
            .claim_finality::<Sha256>(id, observation, Arc::clone(&certificate), &profile)
            .unwrap();
        finality
            .validate_finality_claim::<Sha256>(id, observation, &certificate, &profile, None)
            .unwrap();
    }

    let facts = finality
        .facts()
        .iter()
        .map(|fact| (fact.round().view(), matches!(fact.id(), FinalityId::Lqc(_))))
        .collect::<Vec<_>>();
    assert_eq!(
        facts,
        [
            (View::new(1), false),
            (View::new(1), true),
            (View::new(2), false),
            (View::new(2), true),
        ]
    );
}

#[test]
fn only_an_lqc_becomes_the_finality_proof() {
    let profile = Harness::observer().participants(6).profile();
    let (machine, _) = start_profile(profile.clone());
    let mut finality = FinalityState::new(&profile);
    let proposed = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let certificate = Arc::new(Artifact::Vqc(vqc(&machine, proposed.clone(), &messages)));
    assert_eq!(
        finality.retain_proof::<Sha256>(&certificate, None),
        Err(FinalityError::Invariant)
    );
    assert_eq!(finality.retained_finality_proofs(), 0);

    let certificate = Arc::new(Artifact::Lqc(lqc(&machine, proposed, &votes)));
    assert_eq!(
        finality.retain_proof::<Sha256>(&certificate, None),
        Ok(true)
    );
    assert_eq!(
        finality.retain_proof::<Sha256>(&certificate, None),
        Ok(false)
    );
    assert_eq!(finality.retained_finality_proofs(), 1);
}

#[test]
fn byzantine_leader_variants_do_not_starve_a_correct_owner() {
    const MAX_POOLS: usize = 19;
    let limits = TEST_RESOURCES
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_future_view_distance(12)
        .with_max_future_artifacts(NZUsize!(16))
        .with_max_finality_pools(NonZeroUsize::new(MAX_POOLS).unwrap());
    let profile = Harness::observer()
        .participants(6)
        .resources(limits)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let protocol = machine.profile().protocol().clone();

    let byzantine = protocol.leader(View::new(1));
    let mut byzantine_digests = BTreeSet::new();
    for index in 0..=MAX_POOLS {
        let view = if index == MAX_POOLS { 7 } else { 1 };
        assert_eq!(protocol.leader(View::new(view)), byzantine);
        let base = leader(&machine, view);
        let mut proposals = base.proposals().to_vec();
        proposals[0] = ChainProposal::new(
            proposals[0].anchor().chain(),
            proposals[0].anchor().clone(),
            vec![digest(&index.to_be_bytes())],
            protocol.codec_config().pipeline_depth(),
        )
        .unwrap();
        let proposed = LeaderBlock::new(
            base.round(),
            base.parent(),
            base.history(),
            proposals,
            protocol.codec_config(),
        )
        .unwrap();
        assert!(byzantine_digests.insert(proposed.digest::<Sha256>()));
        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(byzantine.get()),
            )),
        );
        let completed = machine.verify(&proposal, true, Until::CursorAdvance);
        assert_eq!(
            completed.status(),
            &StepStatus::Verified {
                valid: 1,
                invalid: 0,
            }
        );
        assert!(machine.inspect().pools().len() <= MAX_POOLS);
    }
    assert_eq!(byzantine_digests.len(), MAX_POOLS + 1);
    assert!(View::new(7) > machine.inspect().view());

    let correct = protocol.leader(View::new(2));
    assert_ne!(correct, byzantine);
    let proposed = leader(&machine, 2);
    let proposed_round = proposed.round();
    let proposed_digest = proposed.digest::<Sha256>();
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(correct.get()),
        )),
    );
    let completed = machine.verify(&proposal, true, Until::CursorAdvance);
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 0,
        }
    );
    let inspection = machine.inspect();
    let admitted = inspection
        .pools()
        .iter()
        .find(|pool| pool.round() == proposed_round && pool.leader() == proposed_digest)
        .expect("the correct owner's leader must be admitted");
    assert_eq!(admitted.votes(), 0);

    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        machine.verify(&vote, true, Until::CursorAdvance);
    }

    let inspection = machine.inspect();
    let pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.round() == proposed_round && pool.leader() == proposed_digest)
        .expect("the correct owner's pool must remain exact");
    assert_eq!(pool.votes(), 5);
    assert!(pool.finalized());
    let fact = inspection
        .finality()
        .iter()
        .find(|fact| {
            fact.round() == proposed_round
                && fact.leader() == proposed_digest
                && matches!(fact.id(), FinalityId::Direct(_))
        })
        .expect("the correct owner's leader must finalize");
    assert_eq!(fact.votes(), 5);
}

#[test]
fn finality_primaries_rotate_across_correct_owners_and_views() {
    const MAX_POOLS: usize = 23;
    let limits = TEST_RESOURCES
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_future_view_distance(16)
        .with_max_future_artifacts(NZUsize!(16))
        .with_max_finality_pools(NonZeroUsize::new(MAX_POOLS).unwrap());
    let profile = Harness::observer()
        .participants(11)
        .resources(limits)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let protocol = machine.profile().protocol().clone();
    let admit = |machine: &mut TestMachine, proposed: LeaderBlock<MinPk, Digest>| {
        let owner = protocol.leader(proposed.round().view());
        let digest = proposed.digest::<Sha256>();
        let proposal = observe(
            machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(owner.get()))),
        );
        let completed = machine.verify(&proposal, true, Until::CursorAdvance);
        assert_eq!(
            completed.status(),
            &StepStatus::Verified {
                valid: 1,
                invalid: 0,
            }
        );
        digest
    };

    let first_byzantine = leader(&machine, 8);
    let mut equivocation_proposals = first_byzantine.proposals().to_vec();
    equivocation_proposals[0] = ChainProposal::new(
        equivocation_proposals[0].anchor().chain(),
        equivocation_proposals[0].anchor().clone(),
        vec![digest(b"full best effort")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let equivocation = LeaderBlock::new(
        first_byzantine.round(),
        first_byzantine.parent(),
        first_byzantine.history(),
        equivocation_proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let second_byzantine_leader = leader(&machine, 9);
    let stale_correct_leader = leader(&machine, 1);
    let first_byzantine = admit(&mut machine, first_byzantine);
    let second_byzantine = admit(&mut machine, second_byzantine_leader);
    let stale_correct = admit(&mut machine, stale_correct_leader);
    let best_effort = admit(&mut machine, equivocation);
    assert_eq!(machine.inspect().pools().len(), 4);
    assert_eq!(
        [View::new(8), View::new(9), View::new(1)]
            .map(|view| protocol.leader(view))
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );

    let later_correct_leader = leader(&machine, 2);
    let later_correct = admit(&mut machine, later_correct_leader);
    let leaders = machine
        .inspect()
        .pools()
        .iter()
        .map(|pool| pool.leader())
        .collect::<BTreeSet<_>>();
    assert!(leaders.contains(&first_byzantine));
    assert!(leaders.contains(&second_byzantine));
    assert!(leaders.contains(&best_effort));
    assert!(leaders.contains(&later_correct));
    assert!(!leaders.contains(&stale_correct));

    assert_eq!(
        protocol.leader(View::new(2)),
        protocol.leader(View::new(13))
    );
    let repeated_owner_leader = leader(&machine, 13);
    let repeated_owner = admit(&mut machine, repeated_owner_leader);
    let leaders = machine
        .inspect()
        .pools()
        .iter()
        .map(|pool| pool.leader())
        .collect::<BTreeSet<_>>();
    assert!(leaders.contains(&repeated_owner));
    assert!(!leaders.contains(&later_correct));
    assert_eq!(leaders.len(), 4);
}

#[test]
fn lqc_completion_must_match_the_selected_vote_transcript() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let (vqc_aggregate, aggregate) = drive_unanimous_votes(&mut machine, &proposed);

    let wrong_votes = (1..=5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let wrong = lqc(&machine, proposed.clone(), &wrong_votes);
    let parked = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(&aggregate, wrong, machine.profile.codec())
                .unwrap(),
        ))))
        .unwrap();
    assert_eq!(parked.status(), &StepStatus::Accepted);
    // The mismatch surfaces exactly once when the parked completion drains; the aggregation
    // job survives for the corrected transcript.
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    // Resolve the earlier V-QC aggregation before admitting the L-QC. The observation frontier
    // intentionally prevents a later derived certificate from overtaking this crypto job.
    let view_messages = vqc_aggregate.messages().collect::<Vec<_>>();
    let view_certificate = vqc(&machine, vqc_aggregate.leader().clone(), &view_messages);
    let completed_vqc = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &vqc_aggregate,
                view_certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed_vqc = machine.settle(completed_vqc, Until::CursorAdvance);
    let retained_vqc = machine.persist(&completed_vqc.persist_job(), Until::CursorAdvance);
    let forwarding = retained_vqc.persist_job();
    // Fold the forwarding acknowledgement's own release here so the next window holds only
    // the L-QC staging effects.
    machine.persist(&forwarding, Until::CursorAdvance);

    let selected = aggregate.votes().cloned().collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed, &selected);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                certificate,
                machine.profile.codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::Accepted);
    let completed = machine.settle(completed, Until::CursorAdvance);
    let job = completed.persist_job();
    assert!(matches!(
        job.events()[0].change(),
        Change::ViewCertificateCreated { artifact } if matches!(artifact.as_ref(), Artifact::Lqc(_))
    ));
    // The corrected transcript is retained finality evidence rather than a message this node
    // owes its peers, so neither staging nor persistence releases a publication for it.
    assert!(
        completed.capabilities().iter().all(|effect| {
            !durable_effect(effect)
                .and_then(EffectExt::broadcast_one)
                .is_some()
        }),
        "staging must not publish the assembled certificate"
    );
    let persisted = machine.persist(&job, Until::CursorAdvance);
    assert!(
        persisted.capabilities().iter().all(|effect| {
            !durable_effect(effect)
                .and_then(EffectExt::broadcast_one)
                .is_some()
        }),
        "persistence must not publish the assembled certificate"
    );
    assert!(matches!(machine.signing_floor(), Some(Artifact::Lqc(_))));
}

#[test]
fn canceled_lqc_completion_is_not_committed_after_forwarding() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let (vqc_aggregate, lqc_aggregate) = drive_unanimous_votes(&mut machine, &proposed);

    let messages = vqc_aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, proposed.clone(), &messages);
    machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &vqc_aggregate,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();

    let selected = lqc_aggregate.votes().cloned().collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed.clone(), &selected);
    machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &lqc_aggregate,
                certificate,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();

    machine.poll(NonZeroUsize::MIN).unwrap();
    // Isolate the crypto completion boundary before the component drives can forward the
    // certificate, so cancellation interrupts a prepared L-QC awaiting its second phase.
    let deferred = core::iter::from_fn(|| machine.scheduler.pop()).collect::<Vec<_>>();
    machine.scheduler.enqueue(WorkKey::CompleteCrypto);
    for key in deferred {
        machine.scheduler.enqueue(key);
    }
    machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(machine.completions.prepared_lqc.is_some());

    let replacement_votes = (1..=5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let replacement = Artifact::Lqc(lqc(&machine, proposed, &replacement_votes));
    let replacement = observe(&mut machine, replacement);
    machine.verify(&replacement, true, Until::Step);
    assert_eq!(machine.finality.aggregate_reservations(), 0);

    let cursor = machine.durable.state.cursor;
    machine.poll(NonZeroUsize::MIN).unwrap();
    assert_eq!(machine.durable.state.cursor, cursor);
    assert!(machine.completions.prepared_lqc.is_none());
}

#[test]
fn finality_state_retains_its_lqc_after_artifact_cache_compaction() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));
    let proof_id = proof.id::<Sha256>();

    assert!(!machine.store.artifacts.contains_key(&proof_id));
    machine
        .finality
        .retain_proof::<Sha256>(&proof, None)
        .expect("finality admits only authenticated L-QCs to the view state");

    let change = machine
        .next_finality_floor_change()
        .expect("the admitted L-QC raises the signing floor");
    assert!(matches!(
        change,
        Change::FinalityFloorAdvanced { proof: retained, .. }
            if retained.as_ref() == proof.as_ref()
    ));
}

#[test]
fn covered_finality_update_does_not_retain_its_lqc() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));

    let verification = observe(&mut machine, proof.as_ref().clone());
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(admitted);
    assert!(matches!(
        machine.signing_floor(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));
    assert_eq!(machine.finality.retained_finality_proofs(), 0);
    let retained_parents = machine.views.retained_parents();

    machine
        .apply_finality(Observation::new(2, 0), proof, None)
        .expect("the covered L-QC remains valid finality evidence");

    assert_eq!(machine.finality.retained_finality_proofs(), 0);
    assert_eq!(machine.views.retained_parents(), retained_parents);
}

#[test]
fn inspection_reports_known_unfinalized_chain_tips() {
    let profile = Harness::observer().profile();
    let (mut machine, _) = start_profile(profile);
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"known but unfinalized"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(header, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    machine.verify(&verification, true, Until::CursorAdvance);

    let inspection = machine.inspect();
    let [progress] = inspection.chain_progress() else {
        panic!("the one-chain profile must report one chain");
    };
    assert_eq!(progress.chain(), genesis.chain());
    assert_eq!(progress.finalized(), Height::zero());
    assert_eq!(progress.certified(), Height::new(1));
    assert_eq!(progress.known(), Height::new(1));
}

#[test]
fn stale_lqc_completion_returns_the_pool_to_the_ready_set() {
    let (mut machine, _) = Harness::observer().participants(6).start();
    let proposed = leader(&machine, 2);
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
            aggregate = effects.aggregate_lqc();
        }
    }
    let aggregate = aggregate.expect("the n-f vote must schedule L-QC assembly");
    assert_eq!(machine.finality.lqc_aggregate_jobs.len(), 1);
    assert!(machine.finality.ready_lqcs.is_empty());

    // A generation advance strands the dispatched aggregation. Consuming its completion must
    // return the pool to the ready set, not leave it pending behind a job nobody will complete.
    let votes = aggregate.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, aggregate.leader().clone(), &votes);
    let profile = machine.profile().clone();
    let completion =
        LqcAggregateCompletion::prepare::<Sha256>(&aggregate, assembled, profile.codec()).unwrap();
    let released = machine
        .finality
        .prepare_lqc::<Sha256>(
            &profile,
            completion,
            Generation::new(aggregate.issued().generation().get() + 1),
        )
        .unwrap();
    assert!(released.is_none());
    assert_eq!(machine.finality.lqc_aggregate_jobs.len(), 0);
    assert_eq!(machine.finality.ready_lqcs.len(), 1);
}

#[test]
fn finality_floor_preserves_an_lqc_aggregation_reservation() {
    let resources = TEST_RESOURCES
        .with_max_cached_artifacts(NZUsize!(32))
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_outbox_effects(NZUsize!(64));
    let profile = Harness::observer()
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 3);
    let proposal_signer = machine.profile().protocol().leader(View::new(3));
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
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        let admitted = machine.verify(&vote, true, Until::CursorAdvance);
        let effects = machine.drain_persisting(admitted);
        for effect in effects {
            match effect {
                Capability::Crypto(CryptoJob::AggregateVqc(job)) => vqc_job = Some(job),
                Capability::Crypto(CryptoJob::AggregateLqc(job)) => lqc_job = Some(job),
                _ => {}
            }
        }
    }
    let vqc_job = vqc_job.expect("the quorum must schedule V-QC assembly");
    let lqc_job = lqc_job.expect("the quorum must schedule L-QC assembly");
    machine.views.finish_vqc(vqc_job.issued().id());
    assert_eq!(machine.inspect().view(), View::new(1));
    assert_eq!(machine.finality.aggregate_reservations(), 1);
    assert_eq!(machine.views.certificate_reservations(), 0);

    let limit = machine.profile().resources().max_cached_artifacts();
    let mut filler_view = 10;
    while machine.durable.artifact_references.len() < limit - 2 {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        let reserved = machine
            .reserve_test_effect(DurableEffect::broadcast(filler))
            .expect("the filler must fit before the reserved boundary");
        machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    }
    assert_eq!(machine.durable.artifact_references.len(), limit - 2);
    assert_eq!(
        machine.durable.artifact_references.len() + machine.finality.aggregate_reservations(),
        limit - 1
    );

    let competing = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &competing, signer))
        .collect::<Vec<_>>();
    let competing = Arc::new(Artifact::Lqc(lqc(&machine, competing, &votes)));
    machine
        .finality
        .retain_proof::<Sha256>(&competing, None)
        .unwrap();
    let Artifact::Lqc(certificate) = competing.as_ref() else {
        unreachable!()
    };
    let derived = Arc::new(Artifact::Vqc(
        certificate.derive_vqc(machine.profile().codec()).unwrap(),
    ));
    machine
        .views
        .observe::<Sha256>(
            derived.id::<Sha256>(),
            Observation::new(1, 0),
            &derived,
            None,
        )
        .unwrap();
    assert!(matches!(
        machine.next_finality_floor_change(),
        Some(Change::FinalityFloorAdvanced {
            retired_publications: publication_retired,
            ..
        }) if publication_retired.is_empty()
    ));
    let wake = machine.step(Input::ProducerWake).unwrap();
    machine.drain_persisting(wake);
    assert!(machine.signing_floor().is_none());
    assert_eq!(machine.durable.artifact_references.len(), limit - 1);

    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let completed = machine
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(
                &lqc_job,
                assembled.clone(),
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let job = completed.persist_job();
    assert!(matches!(
        job.events()[0].change(),
        Change::ViewCertificateCreated { artifact }
            if artifact.as_ref() == &Artifact::Lqc(assembled)
    ));
    let persisted = machine.persist(&job, Until::CursorAdvance);
    machine.drain_persisting(persisted);

    assert_eq!(machine.finality.aggregate_reservations(), 0);
    assert!(
        machine.durable.artifact_references.len()
            <= machine.profile().resources().max_cached_artifacts()
    );
}
