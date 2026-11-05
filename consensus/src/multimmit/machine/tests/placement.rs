//! Placement of producer blocks reported from local finality.

use super::{
    fixtures::{
        Harness, TestMachine, attestation, digest, leader, lqc, observe, start_profile,
        symbolic_nullification,
    },
    history::admit,
};
use crate::{
    multimmit::{
        machine::testing::{Drive as _, SymbolicPersistence, Until},
        mocks::Bls,
        types::{
            Activity, Artifact, CertificateId, DigestedLeader, Extension, FinalityId, LeaderBlock,
            Placement, Position, SignedLeaderBlock, Vote, VoteBody,
        },
    },
    types::{Height, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

type TestActivity = Activity<Bls<MinPk>, Digest>;

/// A vote for `proposed` that extends chain 0 by one block above its proposed tip.
fn extending_vote(
    machine: &TestMachine,
    proposed: &LeaderBlock<Bls<MinPk>, Digest>,
    signer: u32,
) -> Vote<Bls<MinPk>, Digest> {
    let codec = machine.profile().codec();
    let mut extensions = vec![Extension::empty(); codec.chains()];
    extensions[0] = Extension::new(vec![digest(b"extension")], 1).unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(proposed),
        vec![Position::new(0); codec.chains()],
        extensions,
        codec,
    )
    .unwrap();
    Vote::new(body, attestation(signer))
}

fn placed(activities: &[TestActivity]) -> Vec<&TestActivity> {
    activities
        .iter()
        .filter(|activity| matches!(activity, Activity::Placed { .. }))
        .collect()
}

/// Returns the identifier, fact and record commitments of every reported proof.
fn proven(activities: &[TestActivity]) -> Vec<(CertificateId<Digest>, FinalityId<Digest>, Vec<Digest>)> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::Proven {
                proof,
                fact,
                records,
            } => {
                assert_eq!(proof.lqc().id::<Sha256>(), proof.id());
                Some((
                    proof.id(),
                    fact.id(),
                    records
                        .iter()
                        .map(|record| record.commitment::<Sha256>())
                        .collect(),
                ))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn direct_finality_places_the_final_sweep_above_the_leaders_history() {
    let profile = Harness::observer().participants(6).profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    let accepted = machine.verify(&proposal, true, Until::CursorAdvance);
    assert!(accepted.activities().iter().any(|activity| matches!(
        activity,
        Activity::HistoryAccepted { view, .. } if *view == View::new(2)
    )));
    assert!(placed(accepted.activities()).is_empty());

    let mut reports = Vec::new();
    for signer in 0..6 {
        let vote = Artifact::Vote(extending_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        reports.extend(step.activities().iter().cloned());
        machine.drain_persisting(step);
    }
    let fact = reports
        .iter()
        .rev()
        .find_map(|activity| match activity {
            Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
                Some(fact)
            }
            _ => None,
        })
        .expect("a quorum of votes must finalize the leader");
    assert!(fact.settled()[0], "every voter supports the extension");
    let extension = fact.blocks()[0];
    assert_eq!(extension.height(), Height::new(1));

    // Placement is reported once, for the only chain the sweep moves.
    let [Activity::Placed {
        view,
        evidence: _,
        history,
        placed,
    }] = placed(&reports)[..]
    else {
        panic!("finality must report placement once: {reports:?}");
    };
    assert_eq!(*view, View::new(2));
    assert_eq!(*history, proposed.history());
    assert_eq!(placed, &vec![Placement::new(extension, Height::zero(), Height::new(1))]);

    // A later certificate for the leader reports the record that direct finality placed, once.
    let report = |machine: &mut TestMachine, signers: core::ops::Range<u32>| {
        let votes = signers
            .map(|signer| extending_vote(machine, &proposed, signer))
            .collect::<Vec<_>>();
        let certificate = Artifact::Lqc(lqc(machine, proposed.clone(), &votes));
        let id = certificate.id::<Sha256>().certificate();
        let pending = observe(machine, certificate);
        let step = machine.verify(&pending, true, Until::CursorAdvance);
        let reported = proven(step.activities());
        machine.drain_persisting(step);
        (id, reported)
    };
    let (id, reported) = report(&mut machine, 0..5);
    assert_eq!(
        reported,
        vec![(id, FinalityId::Lqc(id), vec![proposed.history()])]
    );
    let (id, reported) = report(&mut machine, 1..6);
    assert_eq!(reported, vec![(id, FinalityId::Lqc(id), Vec::new())]);
}

#[test]
fn certificate_finality_places_only_once_the_leaders_history_is_known() {
    let run = |known_parent: bool| {
        let profile = Harness::observer().participants(6).profile();
        let (mut machine, _) = start_profile(profile);
        let mut proposed = leader(&machine, 2);
        if known_parent {
            let proposal = Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed.clone(),
                attestation(0),
            ));
            let proposal = observe(&mut machine, proposal);
            let step = machine.verify(&proposal, true, Until::CursorAdvance);
            machine.drain_persisting(step);
        } else {
            // Without the parent, the leader's history cannot be reconstructed.
            proposed = LeaderBlock::new(
                proposed.round(),
                CertificateId::new(digest(b"missing parent")),
                proposed.history(),
                proposed.proposals().to_vec(),
                machine.profile().codec(),
            )
            .unwrap();
        }
        let votes = (0..5)
            .map(|signer| extending_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let history = proposed.history();
        let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
        let id = certificate.id::<Sha256>().certificate();
        let certificate = observe(&mut machine, certificate);
        let step = machine.verify(&certificate, true, Until::CursorAdvance);
        assert!(
            step.activities()
                .iter()
                .any(|activity| matches!(activity, Activity::LeaderFinalized { .. }))
        );
        // The certificate is reported either way, with the leader's record only when known.
        let records = if known_parent { vec![history] } else { Vec::new() };
        assert_eq!(
            proven(step.activities()),
            vec![(id, FinalityId::Lqc(id), records)]
        );
        placed(step.activities()).len()
    };
    assert_eq!(run(true), 1);
    assert_eq!(run(false), 0);
}

#[test]
fn an_lqc_verified_below_the_finality_floor_still_places() {
    let profile = Harness::observer()
        .participants(6)
        .retention(ViewDelta::new(2))
        .profile();
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| extending_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let history = proposed.history();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let id = certificate.id::<Sha256>();
    let pending = observe(&mut machine, certificate);

    // Nullifications retire the certificate's view before its verification completes.
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

    // The retired certificate updates no pool, but its own fact still places the extension.
    assert!(
        activities
            .iter()
            .all(|activity| !matches!(activity, Activity::LeaderFinalized { .. }))
    );
    let [Activity::Placed {
        view,
        evidence,
        placed,
        ..
    }] = placed(&activities)[..]
    else {
        panic!("the verified certificate must report placement once: {activities:?}");
    };
    assert_eq!(*view, View::new(2));
    assert_eq!(*evidence, FinalityId::Lqc(id.certificate()));
    assert_eq!(
        proven(&activities),
        vec![(id.certificate(), *evidence, vec![history])]
    );
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].tip().height(), Height::new(1));
    assert_eq!(placed[0].above(), Height::zero());
}
