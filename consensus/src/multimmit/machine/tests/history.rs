//! Leader history reporting: every admitted or finalized leader reports its safe-tip history
//! record exactly once, as soon as the record is reconstructible.

use super::fixtures::{
    Harness, TestMachine, attestation, leader, leader_extending_view_one_vqc, lqc, observe,
    start_profile, symbolic_nullification, view_one_vqc, view_vote,
};
use crate::{
    Viewable as _,
    multimmit::{
        config::Profile,
        machine::{
            input::{Input, ObservationStatus, StepStatus},
            testing::{CapabilitiesExt as _, Drive, Driver, SymbolicPersistence, Until, cohort},
        },
        mocks::Bls,
        types::{Activity, Artifact, LeaderBlock, SignedLeaderBlock},
    },
    types::{View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

type TestActivity = Activity<Bls<MinPk>, Digest>;
type TestArtifact = Artifact<Bls<MinPk>, Digest>;
type TestLeader = LeaderBlock<Bls<MinPk>, Digest>;

/// Observes, verifies, and settles `artifact`, returning every activity the machine reported.
fn admit(
    machine: &mut impl Drive<Bls<MinPk>, Digest>,
    artifact: TestArtifact,
) -> Vec<TestActivity> {
    let observed = machine.submit(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = observed.status() else {
        panic!("one observed artifact must return an observation result");
    };
    assert_eq!(results[0].status(), ObservationStatus::Scheduled);
    let verification = observed.verify_job();
    let (effects, mut activities) = observed.into_parts();
    machine.drain_reporting(
        &mut SymbolicPersistence,
        effects,
        Until::CursorAdvance,
        &mut activities,
    );
    let verified = machine.verify(&verification, true, Until::CursorAdvance);
    let (effects, reported) = verified.into_parts();
    activities.extend(reported);
    machine.drain_reporting(
        &mut SymbolicPersistence,
        effects,
        Until::CursorAdvance,
        &mut activities,
    );
    activities
}

/// Returns the view and leader of every reported history record, checking that each record
/// opens the commitment it is reported with.
fn histories(activities: &[TestActivity]) -> Vec<(View, Digest)> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::HistoryAccepted {
                view,
                leader,
                commitment,
                record,
            } => {
                assert_eq!(record.commitment::<Sha256>(), *commitment);
                Some((*view, *leader))
            }
            _ => None,
        })
        .collect()
}

/// Returns the view and leader of every leader the machine finalized.
fn finalized(activities: &[TestActivity]) -> Vec<(View, Digest)> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::LeaderFinalized { fact } => Some((fact.round().view(), fact.leader())),
            _ => None,
        })
        .collect()
}

/// Returns the view and digest that identify `block` in finality facts and history records.
fn key(block: &TestLeader) -> (View, Digest) {
    (block.view(), block.digest::<Sha256>())
}

fn observer() -> Profile<Digest> {
    Harness::observer().participants(6).profile()
}

fn proposal(machine: &TestMachine, block: &TestLeader) -> TestArtifact {
    let signer = machine.profile().protocol().leader(block.view());
    Artifact::LeaderBlock(SignedLeaderBlock::new(
        block.clone(),
        attestation(signer.get()),
    ))
}

fn certificate(machine: &TestMachine, block: &TestLeader) -> TestArtifact {
    let votes = (0..5)
        .map(|signer| view_vote(machine, block, signer))
        .collect::<Vec<_>>();
    Artifact::Lqc(lqc(machine, block.clone(), &votes))
}

/// Regression: an L-QC raises the retired view to its own view, so the leader's proposal,
/// arriving afterwards, is promoted and forgotten in one pass. History used to be reported only
/// from a surviving proposal promotion, so this finalized leader never reported its record.
#[test]
fn history_is_reported_for_a_leader_finalized_before_its_proposal() {
    let (mut machine, _) = start_profile(observer());
    let block = leader(&machine, 1);
    let lqc = certificate(&machine, &block);
    let mut activities = admit(&mut machine, lqc);
    assert_eq!(finalized(&activities), [key(&block)]);
    assert!(machine.inspect().view() > View::new(1));

    let signed = proposal(&machine, &block);
    activities.extend(admit(&mut machine, signed));
    assert_eq!(histories(&activities), [key(&block)]);
}

#[test]
fn history_is_reported_for_certificate_only_finality() {
    let (mut machine, _) = start_profile(observer());
    let block = leader(&machine, 1);
    let lqc = certificate(&machine, &block);
    let activities = admit(&mut machine, lqc);
    assert_eq!(finalized(&activities), [key(&block)]);
    assert_eq!(histories(&activities), [key(&block)]);
}

/// A V-QC designates the leader and votes finalize it; its proposal never arrives.
#[test]
fn history_is_reported_for_a_leader_finalized_from_a_vqc_and_votes() {
    let (mut machine, _) = start_profile(observer());
    let parent = view_one_vqc(&machine);
    let block = parent.leader().clone();
    let mut activities = admit(&mut machine, Artifact::Vqc(parent));
    assert!(finalized(&activities).is_empty());
    for signer in [3, 4] {
        let vote = Artifact::Vote(view_vote(&machine, &block, signer));
        activities.extend(admit(&mut machine, vote));
    }
    assert_eq!(finalized(&activities), [key(&block)]);
    assert_eq!(histories(&activities), [key(&block)]);
}

/// A leader whose view an L-QC for a later view already retired is finalized by its votes; its
/// proposal is authenticated but forgotten as soon as it is ready.
#[test]
fn history_is_reported_for_a_leader_finalized_after_its_view_retired() {
    let (mut machine, _) = start_profile(observer());
    let later = leader(&machine, 3);
    let lqc = certificate(&machine, &later);
    admit(&mut machine, lqc);
    assert!(machine.inspect().view() > View::new(3));

    let block = leader(&machine, 2);
    let signed = proposal(&machine, &block);
    let mut activities = admit(&mut machine, signed);
    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(&machine, &block, signer));
        activities.extend(admit(&mut machine, vote));
    }
    assert_eq!(finalized(&activities), [key(&block)]);
    assert_eq!(histories(&activities), [key(&block)]);
}

/// The finality floor an L-QC raises retires the finalized leader's parent, so the record must be
/// reconstructed when the leader finalizes rather than when its proposal arrives.
#[test]
fn history_is_reported_before_the_finality_floor_retires_the_parent() {
    let (mut machine, _) = start_profile(observer());
    let parent = view_one_vqc(&machine);
    admit(&mut machine, Artifact::Vqc(parent.clone()));
    let (block, history) = leader_extending_view_one_vqc(&machine, 3, &parent);
    assert_eq!(
        machine
            .views
            .leader_history::<Sha256>(&block)
            .unwrap()
            .commitment::<Sha256>(),
        history
    );

    let lqc = certificate(&machine, &block);
    let activities = admit(&mut machine, lqc);
    assert_eq!(finalized(&activities), [key(&block)]);
    assert_eq!(histories(&activities), [key(&block)]);
    assert!(machine.views.leader_history::<Sha256>(&block).is_err());
}

#[test]
fn history_waits_for_a_late_parent() {
    let (mut machine, _) = start_profile(observer());
    let parent = view_one_vqc(&machine);
    let (block, _) = leader_extending_view_one_vqc(&machine, 3, &parent);
    let lqc = certificate(&machine, &block);
    let activities = admit(&mut machine, lqc);
    assert_eq!(finalized(&activities), [key(&block)]);
    assert!(histories(&activities).is_empty());

    let mut activities = admit(&mut machine, Artifact::Vqc(parent));
    assert_eq!(histories(&activities), [key(&block)]);

    // The proposal arriving afterwards offers a leader already reported.
    let signed = proposal(&machine, &block);
    activities = admit(&mut machine, signed);
    assert!(histories(&activities).is_empty());
}

#[test]
fn history_is_reported_once_per_leader() {
    let (mut machine, _) = start_profile(observer());
    let block = leader(&machine, 1);
    let signed = proposal(&machine, &block);
    let mut activities = admit(&mut machine, signed);
    assert_eq!(histories(&activities), [key(&block)]);

    for signer in 0..6 {
        let vote = Artifact::Vote(view_vote(&machine, &block, signer));
        activities.extend(admit(&mut machine, vote));
    }
    let lqc = certificate(&machine, &block);
    activities.extend(admit(&mut machine, lqc));
    let votes = (1..6)
        .map(|signer| view_vote(&machine, &block, signer))
        .collect::<Vec<_>>();
    let another = Artifact::Lqc(super::fixtures::lqc(&machine, block.clone(), &votes));
    activities.extend(admit(&mut machine, another));

    assert_eq!(finalized(&activities), [key(&block)]);
    assert_eq!(histories(&activities), [key(&block)]);
}

/// An L-QC whose finality claim the retention floor discards before its verification completes
/// still reports its leader's history.
#[test]
fn history_is_reported_for_an_lqc_verified_below_the_finality_floor() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let block = leader(&machine, 2);
    let lqc = certificate(&machine, &block);
    let pending = observe(&mut machine, lqc);

    let mut activities = Vec::new();
    for view in 1..=4 {
        let exit = symbolic_nullification(&machine, View::new(view), view);
        activities.extend(admit(&mut machine, Artifact::Nullification(exit)));
    }
    assert!(machine.retention_floor() >= View::new(2));

    let verified = machine.verify(&pending, true, Until::CursorAdvance);
    let (effects, reported) = verified.into_parts();
    activities.extend(reported);
    machine.drain_reporting(
        &mut SymbolicPersistence,
        effects,
        Until::CursorAdvance,
        &mut activities,
    );
    assert!(finalized(&activities).is_empty());
    assert_eq!(histories(&activities), [key(&block)]);
}

/// Replay reports nothing. A restarted engine starts without markers, so it may report a leader
/// its retained state still proves once more, and only once.
#[test]
fn restart_reports_a_retained_leader_once_more() {
    let mut driver = Driver::new(observer());
    let started = driver.submit(Input::Start).unwrap();
    driver.drain(
        &mut SymbolicPersistence,
        started.into_capabilities(),
        Until::Step,
    );
    let block = leader(driver.machine(), 1);
    let lqc = certificate(driver.machine(), &block);
    let activities = admit(&mut driver, lqc);
    assert_eq!(histories(&activities), [key(&block)]);

    let recovery = driver.crash_and_restore().unwrap();
    let (effects, mut activities) = recovery.into_parts();
    driver.drain_reporting(
        &mut SymbolicPersistence,
        effects,
        Until::CursorAdvance,
        &mut activities,
    );
    assert_eq!(histories(&activities), [key(&block)]);

    let signed = proposal(driver.machine(), &block);
    activities.extend(admit(&mut driver, signed));
    assert_eq!(histories(&activities), [key(&block)]);
}
