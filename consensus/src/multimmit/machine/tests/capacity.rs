//! Bounded capacity tests for self-certifying view proofs, re-anchoring, and chain positions.

use super::fixtures::{
    Harness, TEST_RESOURCES, TestMachine, attestation, digest, drain_da_choices, frontier_chain,
    leader, lqc, no_vote, nullify, observe, offer_eligible, self_certifying_view_proofs, sign_job,
    start_profile, symbolic_da_certificate, symbolic_nullification, threshold_share, view_vote,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{HEIGHT_WINDOW_PIPELINES, ResourceLimits, VERIFIED_BLOCKS_PER_HEIGHT},
        machine::{
            capability::{Capabilities, Capability, ObservedBlock, ValidatorCommand},
            durability::{DurableEffect, EffectCompletion, SignEffect, SignRequest},
            input::{Input, ObservationStatus, Rejection, Step, StepStatus},
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, MachineExt as _,
                SymbolicVerifier, Until, cohort,
            },
        },
        types::{
            Artifact, ChainId, DaVote, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader,
        },
    },
    types::{Height, Participant, Round, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::sync::Arc;

#[test]
fn far_future_lqc_reanchors_a_lagging_machine() {
    // The n=50 straggler: a validator stuck at its boot views receives an L-QC from a
    // view far past its retention window. L-QCs are self-certifying finality evidence,
    // so possession alone must re-anchor the machine at the newer frontier.
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    assert_eq!(machine.inspect().view(), View::new(1));

    let proposed = leader(&machine, 300);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let verification = observe(&mut machine, certificate);
    let completed = machine.verify(&verification, true, Until::CursorAdvance);
    machine.drain_persisting(completed);

    let inspection = machine.inspect();
    assert!(
        inspection.finality_floor() >= View::new(300),
        "far-future L-QC did not re-anchor: floor {} view {}",
        inspection.finality_floor(),
        inspection.view()
    );
}

#[test]
fn future_vote_flood_does_not_starve_reanchoring_lqcs() {
    // The n=50 straggler wedge: a node far behind the cluster receives a flood of
    // future-view votes that fills the bounded future index before the once-per-view
    // L-QC arrives. Finality evidence must still be admissible: rejecting it leaves
    // the node deaf forever, since only an anchor can drain the future index.
    let limits = TEST_RESOURCES
        .with_max_inflight_verifications(NZUsize!(3))
        .with_max_future_view_distance(64)
        .with_max_future_artifacts(NZUsize!(8))
        .with_max_finality_pools(NonZeroUsize::new(69).unwrap());
    let profile = Harness::validator(5)
        .participants(6)
        .resources(limits)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    assert_eq!(machine.inspect().view(), View::new(1));

    // Eight future votes for distinct far views exhaust the future index.
    for view in 30..38u64 {
        let proposed = leader(&machine, view);
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, 0));
        let verification = observe(&mut machine, artifact);
        machine.verify(&verification, true, Until::CursorAdvance);
    }

    // The re-anchoring L-QC arrives after the flood. It must be admitted and must
    // advance the machine, not be rejected for a full future index.
    let proposed = leader(&machine, 60);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let step = machine
        .step(cohort::<Sha256, _>(vec![certificate]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    assert_eq!(
        results[0].status(),
        ObservationStatus::Scheduled,
        "a full future index must not reject self-certifying finality evidence"
    );
    let [Capability::Verify(job)] = step.capabilities() else {
        panic!("the admitted L-QC must emit one verification job");
    };
    let job = job.clone();
    let completed = machine.verify(&job, true, Until::CursorAdvance);
    machine.drain_persisting(completed);
    let inspection = machine.inspect();
    assert!(
        inspection.finality_floor() >= View::new(60),
        "admitted L-QC did not re-anchor: floor {} view {}",
        inspection.finality_floor(),
        inspection.view()
    );
}

#[test]
fn producer_saturation_preserves_critical_and_proof_admission() {
    for (cache, jobs, rejection) in [
        (32, 3, Rejection::VerificationJobsFull),
        (9, 32, Rejection::ArtifactCacheFull),
    ] {
        for proof in 0..3 {
            let resources = ResourceLimits::new(
                NonZeroUsize::new(16 * 1024).unwrap(),
                NonZeroUsize::new(cache).unwrap(),
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(jobs).unwrap(),
                2,
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(32).unwrap(),
                NonZeroUsize::new(64).unwrap(),
            );
            let (mut machine, _) = Harness::observer()
                .participants(6)
                .resources(resources)
                .start();
            let mut saturated = false;
            for header in frontier_chain(&machine, 32) {
                let artifact = Artifact::DaCertificate(symbolic_da_certificate(header, 0));
                let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
                let StepStatus::Observed(results) = step.status() else {
                    panic!("one observed certificate");
                };
                if results[0].status() == ObservationStatus::Rejected(rejection) {
                    saturated = true;
                    break;
                }
                assert_eq!(results[0].status(), ObservationStatus::Scheduled);
            }
            assert!(saturated);
            let message = Artifact::NoVote(no_vote(&machine, View::new(1), 0));
            let proof = self_certifying_view_proofs(&machine, View::new(2))[proof].clone();
            for artifact in [message, proof] {
                let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
                let StepStatus::Observed(results) = step.status() else {
                    panic!("one observed view artifact");
                };
                assert_eq!(results[0].status(), ObservationStatus::Scheduled);
                assert!(machine.inspect().cached_artifacts() <= cache);
                assert!(machine.inspect().verification_jobs().len() <= jobs);
            }
        }
    }
}

#[test]
fn verification_capacity_does_not_starve_self_certifying_view_proofs() {
    for proof in 0..3 {
        let profile = Harness::validator(5)
            .participants(6)
            .resources(TEST_RESOURCES.with_max_inflight_verifications(NZUsize!(2)))
            .profile();
        let (mut machine, _) = start_profile(profile);

        let first = machine
            .step(cohort::<Sha256, _>(vec![Artifact::NoVote(no_vote(
                &machine,
                View::new(1),
                0,
            ))]))
            .unwrap();
        assert!(matches!(
            first.status(),
            StepStatus::Observed(results)
                if results[0].status() == ObservationStatus::Scheduled
        ));

        let second = machine
            .step(cohort::<Sha256, _>(vec![Artifact::Nullify(nullify(
                &machine,
                View::new(1),
                1,
            ))]))
            .unwrap();
        assert!(matches!(
            second.status(),
            StepStatus::Observed(results)
                if results[0].status()
                    == ObservationStatus::Rejected(Rejection::VerificationJobsFull)
        ));

        let artifact = self_certifying_view_proofs(&machine, View::new(2))[proof].clone();
        let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
        assert!(matches!(
            step.status(),
            StepStatus::Observed(results)
                if results[0].status() == ObservationStatus::Scheduled
        ));
        assert_eq!(machine.inspect().verification_jobs().len(), 2);
    }
}

#[test]
fn artifact_capacity_does_not_starve_self_certifying_view_proofs() {
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(9).unwrap(),
        NonZeroUsize::new(9).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    for proof in 0..3 {
        let (mut machine, _) = Harness::validator(5)
            .participants(6)
            .resources(resources)
            .start();
        let view = View::new(1);
        let mut artifacts = (0..6)
            .map(|signer| Artifact::NoVote(no_vote(&machine, view, signer)))
            .collect::<Vec<_>>();
        artifacts.extend((0..3).map(|signer| Artifact::Nullify(nullify(&machine, view, signer))));
        let step = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
        assert!(matches!(
            step.status(),
            StepStatus::Observed(results)
                if results.iter().filter(|result| {
                    result.status() == ObservationStatus::Scheduled
                }).count() == 6
                    && results[6].status()
                        == ObservationStatus::Rejected(Rejection::ArtifactCacheFull)
        ));
        let inspection = machine.inspect();
        assert_eq!(inspection.cached_artifacts(), 6);
        assert_eq!(inspection.future_artifacts(), 0);

        let round = Round::new(machine.profile().protocol().epoch(), view);
        machine
            .reserve_test_effect(DurableEffect::Sign(SignEffect::new(Arc::from([
                SignRequest::NoVote { round },
                SignRequest::Nullify { round },
            ]))))
            .unwrap();
        assert_eq!(machine.local_artifact_reservations(), 2);

        let artifact = self_certifying_view_proofs(&machine, View::new(2))[proof].clone();
        let step = machine
            .step(cohort::<Sha256, _>(vec![artifact.clone()]))
            .unwrap();
        assert!(matches!(
            step.status(),
            StepStatus::Observed(results)
                if results[0].status() == ObservationStatus::Scheduled
        ));
        let inspection = machine.inspect();
        assert_eq!(
            inspection.cached_artifacts() + machine.local_artifact_reservations(),
            resources.max_cached_artifacts()
        );
        assert!(inspection.verification_jobs().len() <= resources.max_inflight_verifications());
        machine
            .reserve_test_effect(DurableEffect::broadcast(Arc::new(artifact)))
            .expect("the proof's reserved cache slot must cover durable publication");
    }
}

#[test]
fn proof_capacity_does_not_invalidate_reserved_local_completion() {
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(9).unwrap(),
        NonZeroUsize::new(9).unwrap(),
        NonZeroUsize::new(4).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let (mut machine, _) = Harness::validator(5)
        .participants(6)
        .resources(resources)
        .start();
    let view = View::new(1);
    let ordinary = (0..6)
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(ordinary)).unwrap();
    assert!(matches!(
        observed.status(),
        StepStatus::Observed(results)
            if results.iter().all(|result| result.status() == ObservationStatus::Scheduled)
    ));

    let proof = self_certifying_view_proofs(&machine, View::new(2))[0].clone();
    let observed = machine.step(cohort::<Sha256, _>(vec![proof])).unwrap();
    assert!(matches!(
        observed.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Scheduled
    ));

    let round = Round::new(machine.profile().protocol().epoch(), view);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::NoVote { round }))
        .unwrap();
    let sign = sign_job(&reserved);
    assert_eq!(machine.local_artifact_reservations(), 1);

    let proof = self_certifying_view_proofs(&machine, View::new(3))[2].clone();
    let observed = machine.step(cohort::<Sha256, _>(vec![proof])).unwrap();
    assert!(matches!(
        observed.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Scheduled
    ));
    assert_eq!(
        machine.inspect().cached_artifacts() + machine.local_artifact_reservations(),
        resources.max_cached_artifacts()
    );

    let artifact = Artifact::NoVote(no_vote(&machine, view, 5));
    let id = artifact.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact)],
        )))
        .unwrap();
    machine.settle(completed, Until::CursorAdvance);
    assert!(machine.inspect().ready_artifacts().contains(&id));
    assert!(
        machine.inspect().cached_artifacts() + machine.local_artifact_reservations()
            <= resources.max_cached_artifacts()
    );
}

/// Observes `artifact` and, when it is scheduled, verifies it and drives the resulting work.
///
/// Returns the observation status and every capability the admission released.
fn admit(
    machine: &mut TestMachine,
    artifact: Artifact<MinPk, Digest>,
) -> (ObservationStatus, Capabilities<MinPk, Digest>) {
    let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    let status = results[0].status();
    let Some(job) = step.find(|capability| match capability {
        Capability::Verify(job) => Some(job.clone()),
        _ => None,
    }) else {
        return (status, step.into_capabilities());
    };
    let completed = machine.verify(&job, true, Until::CursorAdvance);
    (status, machine.drain_persisting(completed))
}

/// Floods `chain` with a linked run of headers far above its certified tip, each observed as the
/// artifact `pin` builds, then checks that honest work is still admitted.
///
/// A chain artifact retires only once its chain certifies its height, and only the chain's
/// producer can extend that chain. The run rests on a withheld parent and its heights share no
/// slot or neighbor with real headers, so it proves no fault and nothing else can ever retire it.
fn assert_pinning_preserves_honest_progress(
    chain: ChainId,
    pin: impl Fn(TransactionBlockHeader<Digest>) -> Artifact<MinPk, Digest>,
) {
    const PINNED_HEIGHT: u64 = 1 << 40;
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    let protocol = machine.profile().protocol().clone();
    let flood = 2 * machine.profile().resources().max_cached_artifacts() as u64;
    let mut parent = digest(b"withheld parent");
    let mut pinned = 0;
    for height in PINNED_HEIGHT..PINNED_HEIGHT + flood {
        let header = TransactionBlockHeader::new(
            protocol.epoch(),
            chain,
            Height::new(height),
            parent,
            digest(format!("pinned body {height}").as_bytes()),
        )
        .unwrap();
        parent = header.digest::<Sha256>();
        let (status, capabilities) = admit(&mut machine, pin(header));
        assert!(
            !capabilities.has(|capability| capability.is_quarantine()),
            "a linked run of headers proves no fault"
        );
        if status != ObservationStatus::Scheduled {
            break;
        }
        pinned += 1;
    }
    assert_honest_progress(&mut machine, pinned);
}

/// Checks that a machine holding `pinned` Byzantine chain artifacts still makes honest progress:
/// it follows the network through external view proofs, assembles a view certificate from a
/// quorum of honest votes, and admits another producer's block.
fn assert_honest_progress(machine: &mut TestMachine, pinned: usize) {
    let protocol = machine.profile().protocol().clone();

    // The machine must still follow the network through external view proofs.
    let target = View::new(9);
    let mut proof_statuses = Vec::new();
    for view in 1..target.get() {
        let proof = symbolic_nullification(machine, View::new(view), view);
        let (status, _) = admit(machine, Artifact::Nullification(proof));
        proof_statuses.push(status);
    }
    let view = machine.inspect().view();

    // A quorum of honest votes must still assemble a view certificate in the current view.
    let proposed = leader(machine, view.get());
    let proposal = SignedLeaderBlock::new(proposed.clone(), attestation(0));
    let (proposal_status, _) = admit(machine, Artifact::LeaderBlock(proposal));
    let mut vote_statuses = Vec::new();
    let mut aggregated = false;
    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(machine, &proposed, signer));
        let (status, capabilities) = admit(machine, vote);
        vote_statuses.push(status);
        aggregated |= capabilities.has(|capability| capability.is_aggregate_vqc());
    }

    // Another producer's chain must still make progress.
    let honest_chain = ChainId::new(2);
    let honest_producer = protocol.producer(honest_chain).unwrap();
    let honest = TransactionBlockHeader::new(
        protocol.epoch(),
        honest_chain,
        Height::new(1),
        protocol.genesis().tips()[honest_chain.index()].digest(),
        digest(b"honest body"),
    )
    .unwrap();
    let honest = SignedTransactionBlock::new(honest, attestation(honest_producer.get()));
    let (honest_status, _) = admit(machine, Artifact::TransactionBlock(honest));

    let scheduled = |status: &ObservationStatus| *status == ObservationStatus::Scheduled;
    assert!(
        view >= target
            && scheduled(&proposal_status)
            && vote_statuses.iter().all(scheduled)
            && aggregated
            && scheduled(&honest_status),
        "{pinned} pinned artifacts from one participant starve honest admission: nullifications \
         {proof_statuses:?} reach view {view}; view {view} proposal {proposal_status:?}, votes \
         {vote_statuses:?}, V-QC aggregation {aggregated}; chain {} block {honest_status:?}",
        honest_chain.get(),
    );
}

#[test]
fn a_byzantine_producer_holds_at_most_its_height_window() {
    // The worst in-window case: the producer of chain 1 forks at every height of its window, more
    // times than a position keeps.
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    let protocol = machine.profile().protocol().clone();
    let chain = ChainId::new(1);
    let producer = protocol.producer(chain).unwrap();
    let window = protocol.codec_config().pipeline_depth() as u64 * HEIGHT_WINDOW_PIPELINES;
    let fork = |height: u64, marker: usize| {
        let header = TransactionBlockHeader::new(
            protocol.epoch(),
            chain,
            Height::new(height),
            digest(format!("fork parent {height}").as_bytes()),
            digest(format!("fork {height} {marker}").as_bytes()),
        )
        .unwrap();
        Artifact::TransactionBlock(SignedTransactionBlock::new(
            header,
            attestation(producer.get()),
        ))
    };
    for height in 1..=window {
        let forks = (0..=VERIFIED_BLOCKS_PER_HEIGHT)
            .map(|marker| fork(height, marker))
            .collect::<Vec<_>>();
        let step = machine.step(cohort::<Sha256, _>(forks)).unwrap();
        let job = step
            .find(|capability| match capability {
                Capability::Verify(job) => Some(job.clone()),
                _ => None,
            })
            .expect("in-window forks enter verification");
        machine.verify(&job, true, Until::CursorAdvance);
    }
    let (beyond, _) = admit(&mut machine, fork(window + 1, 0));
    assert_eq!(beyond, ObservationStatus::Rejected(Rejection::FutureHeight));

    let pinned = machine.inspect().cached_artifacts();
    assert_eq!(pinned, VERIFIED_BLOCKS_PER_HEIGHT * window as usize);
    assert_honest_progress(&mut machine, pinned);
}

#[test]
fn byzantine_producer_cannot_pin_the_artifact_cache() {
    let chain = ChainId::new(1);
    let producer = Harness::observer()
        .participants(6)
        .profile()
        .protocol()
        .producer(chain)
        .unwrap();
    assert_pinning_preserves_honest_progress(chain, |header| {
        Artifact::TransactionBlock(SignedTransactionBlock::new(
            header,
            attestation(producer.get()),
        ))
    });
}

#[test]
fn byzantine_da_voter_cannot_pin_the_artifact_cache() {
    // Any participant may DA-vote on any chain. The flood targets the chain the observing node
    // produces, the one chain whose votes it keeps.
    let chain = ChainId::new(5);
    let voter = 3;
    assert_ne!(
        Harness::observer()
            .participants(6)
            .profile()
            .protocol()
            .producer(chain),
        Some(Participant::new(voter))
    );
    assert_pinning_preserves_honest_progress(chain, |header| {
        Artifact::DaVote(DaVote::new(header, threshold_share(voter)))
    });
}

#[test]
fn verified_forks_per_height_are_bounded() {
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    let protocol = machine.profile().protocol().clone();
    let chain = ChainId::new(1);
    let producer = protocol.producer(chain).unwrap();
    let parent = protocol.genesis().tips()[chain.index()].digest();
    let fork = |marker: usize| {
        let header = TransactionBlockHeader::new(
            protocol.epoch(),
            chain,
            Height::new(1),
            parent,
            digest(format!("fork {marker}").as_bytes()),
        )
        .unwrap();
        Artifact::TransactionBlock(SignedTransactionBlock::new(
            header,
            attestation(producer.get()),
        ))
    };

    // Unverified blocks do not count toward the bound, so a whole batch of forks is scheduled.
    let forks = (0..=VERIFIED_BLOCKS_PER_HEIGHT)
        .map(fork)
        .collect::<Vec<_>>();
    let step = machine.step(cohort::<Sha256, _>(forks)).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("observed forks must return observation results");
    };
    assert!(
        results
            .iter()
            .all(|result| result.status() == ObservationStatus::Scheduled)
    );
    let verified = machine.verify(&step.verify_job(), true, Until::CursorAdvance);

    // The forks prove the producer equivocated, and only the bound stays retained.
    assert!(verified.has(|capability| matches!(
        capability,
        Capability::Quarantine(participants) if participants == &[producer]
    )));
    assert_eq!(
        machine.inspect().cached_artifacts(),
        VERIFIED_BLOCKS_PER_HEIGHT
    );
    let step = machine
        .step(cohort::<Sha256, _>(vec![fork(
            VERIFIED_BLOCKS_PER_HEIGHT + 1,
        )]))
        .unwrap();
    assert!(matches!(
        step.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Rejected(Rejection::PositionFull)
    ));
}

#[test]
fn forged_pending_blocks_cannot_crowd_out_the_honest_block() {
    let (mut machine, _) = Harness::validator(5).participants(6).start();
    let protocol = machine.profile().protocol().clone();
    let chain = ChainId::new(1);
    let producer = protocol.producer(chain).unwrap();
    let parent = protocol.genesis().tips()[chain.index()].digest();
    let header = |label: &str| {
        TransactionBlockHeader::new(
            protocol.epoch(),
            chain,
            Height::new(1),
            parent,
            digest(label.as_bytes()),
        )
        .unwrap()
    };
    let block = |header| {
        Artifact::TransactionBlock(SignedTransactionBlock::new(
            header,
            attestation(producer.get()),
        ))
    };
    let verify_job = |step: &Step<MinPk, Digest>| {
        let StepStatus::Observed(results) = step.status() else {
            panic!("observed blocks must return observation results");
        };
        assert!(
            results
                .iter()
                .all(|result| result.status() == ObservationStatus::Scheduled)
        );
        step.verify_job()
    };

    // Before the honest block verifies, a forger sends more blocks than the bound, each claiming
    // the producer's signature.
    let forged = (0..=VERIFIED_BLOCKS_PER_HEIGHT)
        .map(|marker| block(header(&format!("forged {marker}"))))
        .collect::<Vec<_>>();
    let forged_job = verify_job(&machine.step(cohort::<Sha256, _>(forged.clone())).unwrap());

    // Pending blocks do not count toward the bound, so the honest block is still admitted.
    let honest = header("honest");
    let honest_job = verify_job(
        &machine
            .step(cohort::<Sha256, _>(vec![block(honest.clone())]))
            .unwrap(),
    );
    let mut verifier = SymbolicVerifier::new(true);
    for artifact in &forged {
        verifier.set(artifact.id::<Sha256>(), false);
    }
    let rejected = machine
        .step(Input::Verified(verifier.complete(&forged_job)))
        .unwrap();
    machine.settle(rejected, Until::CursorAdvance);
    let verified = machine
        .step(Input::Verified(verifier.complete(&honest_job)))
        .unwrap();
    let verified = machine.settle(verified, Until::CursorAdvance);
    assert_eq!(machine.inspect().cached_artifacts(), 1);

    // The node DA-votes the honest block.
    let routed = verified
        .find(|capability| match capability {
            Capability::Validator(
                _,
                ValidatorCommand::Observe(ObservedBlock {
                    id,
                    observation,
                    block,
                    custodied,
                }),
            ) => Some((*id, *observation, Arc::clone(block), *custodied)),
            _ => None,
        })
        .expect("the verified honest block routes to its chain plane");
    let opened = offer_eligible(&mut machine, chain.get(), &[routed]);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, opened, &mut choices);
    assert_eq!(choices, vec![honest]);
}
