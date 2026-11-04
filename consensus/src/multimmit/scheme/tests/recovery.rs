//! Optimistic data-availability recovery and share attribution.

use super::*;

/// An honest quorum must certify from shares no verification ever touched individually.
fn optimistic_recovery_certifies_an_unverified_quorum<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 300);
    let votes = fixture.da_votes(&header);
    let quorum = &votes[..fixture.codec.da_quorum()];
    for vote in quorum {
        assert!(
            fixture.verifier.precheck_da_vote(vote),
            "an honest share passes admission without its signature check"
        );
    }
    let mut rng = test_rng();
    let certificate = fixture
        .verifier
        .assemble_da_certificate_optimistic(&mut rng, quorum, &Sequential)
        .expect("an honest quorum certifies");
    assert_eq!(certificate.header(), &header);
    assert!(
        fixture
            .verifier
            .verify_da_certificate(&mut rng, &certificate, &Sequential)
    );
    assert_eq!(
        certificate,
        fixture
            .verifier
            .assemble_da_certificate(&mut rng, quorum, &Sequential)
            .unwrap()
    );
}

/// Admission checks structure only, so a forged share is admitted and left to recovery, while
/// a structurally invalid one is not.
fn da_share_admission_ignores_its_signature<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 301);
    let elsewhere = fixture.signers[1]
        .sign_da_vote(fixture.header(1, 302))
        .unwrap();
    let forged = DaVote::new(header.clone(), elsewhere.attestation().clone());
    assert!(fixture.verifier.precheck_da_vote(&forged));
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &[&Artifact::DaVote(forged)],
            &[],
            &Sequential
        ),
        [false],
        "the share itself is invalid, so only recovery may accept it"
    );
    // A share by a non-member, for another epoch, or for an unconfigured chain fails admission.
    let outsider = DaVote::new(
        header,
        certificate::Attestation {
            signer: Participant::new(PARTICIPANTS),
            signature: elsewhere.attestation().signature.clone(),
        },
    );
    assert!(!fixture.verifier.precheck_da_vote(&outsider));
    let other_epoch = DaVote::new(
        TransactionBlockHeader::new(
            Epoch::new(fixture.round.epoch().get() + 1),
            ChainId::new(1),
            Height::new(1),
            digest(b"parent", 301),
            digest(b"commitment", 301),
        )
        .unwrap(),
        elsewhere.attestation().clone(),
    );
    assert!(!fixture.verifier.precheck_da_vote(&other_epoch));
    let unconfigured = DaVote::new(
        fixture.header(PARTICIPANTS, 301),
        elsewhere.attestation().clone(),
    );
    assert!(!fixture.verifier.precheck_da_vote(&unconfigured));
}

/// One invalid share must fail the quorum once and name exactly its signer.
fn optimistic_recovery_attributes_one_invalid_share<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 304);
    let votes = fixture.da_votes(&header);
    let mut rng = test_rng();
    for unreadable in [false, true] {
        let mut quorum = votes[..fixture.codec.da_quorum()].to_vec();
        let culprit = Participant::new(1);
        quorum[1] = if unreadable {
            DaVote::new(
                header.clone(),
                certificate::Attestation {
                    signer: culprit,
                    signature: malformed(),
                },
            )
        } else {
            let elsewhere = fixture.signers[1]
                .sign_da_vote(fixture.header(1, 305))
                .unwrap();
            DaVote::new(header.clone(), elsewhere.attestation().clone())
        };
        assert!(fixture.verifier.precheck_da_vote(&quorum[1]));
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate_optimistic(&mut rng, &quorum, &Sequential),
            Err(DaRecoveryError::InvalidShares(vec![culprit])),
        );
    }
    // Dropping the named signer and re-selecting from the surviving shares certifies on the
    // next attempt.
    let survivors = votes
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, vote)| vote.clone())
        .take(fixture.codec.da_quorum())
        .collect::<Vec<_>>();
    let certificate = fixture
        .verifier
        .assemble_da_certificate_optimistic(&mut rng, &survivors, &Sequential)
        .expect("the surviving shares still form a quorum");
    assert!(
        fixture
            .verifier
            .verify_da_certificate(&mut rng, &certificate, &Sequential)
    );
}

/// Every invalid share in one quorum must be named by a single attribution pass.
fn optimistic_recovery_attributes_every_invalid_share<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 306);
    let quorum = fixture.signers[..fixture.codec.da_quorum()]
        .iter()
        .enumerate()
        .map(|(index, signer)| {
            if index == 0 {
                return signer.sign_da_vote(header.clone()).unwrap();
            }
            let elsewhere = signer
                .sign_da_vote(fixture.header(1, 307 + index as u64))
                .unwrap();
            DaVote::new(header.clone(), elsewhere.attestation().clone())
        })
        .collect::<Vec<_>>();
    let expected = (1..fixture.codec.da_quorum() as u32)
        .map(Participant::new)
        .collect::<Vec<_>>();
    let Err(DaRecoveryError::InvalidShares(mut named)) = fixture
        .verifier
        .assemble_da_certificate_optimistic(&mut test_rng(), &quorum, &Sequential)
    else {
        panic!("a quorum of forged shares must be attributed");
    };
    named.sort_unstable();
    assert_eq!(named, expected);
}

/// Wrong-sized and mixed-header quorums are rejected before any attribution.
fn optimistic_recovery_rejects_malformed_quorums<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 310);
    let votes = fixture.da_votes(&header);
    let quorum = fixture.codec.da_quorum();
    let mut rng = test_rng();
    assert_eq!(
        fixture.verifier.assemble_da_certificate_optimistic(
            &mut rng,
            &votes[..quorum - 1],
            &Sequential
        ),
        Err(DaRecoveryError::Scheme(Error::Quorum))
    );
    let mut mixed = votes[..quorum].to_vec();
    mixed[0] = fixture.signers[0]
        .sign_da_vote(fixture.header(1, 311))
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate_optimistic(&mut rng, &mixed, &Sequential),
        Err(DaRecoveryError::Scheme(Error::Transcript))
    );
}

#[test]
fn optimistic_da_recovery_certifies_honest_quorums_for_both_variants() {
    for_each_suite!(optimistic_recovery_certifies_an_unverified_quorum);
}

#[test]
fn da_share_admission_ignores_signatures_for_both_variants() {
    for_each_suite!(da_share_admission_ignores_its_signature);
}

#[test]
fn optimistic_da_recovery_attributes_one_invalid_share_for_both_variants() {
    for_each_suite!(optimistic_recovery_attributes_one_invalid_share);
}

#[test]
fn optimistic_da_recovery_attributes_every_invalid_share_for_both_variants() {
    for_each_suite!(optimistic_recovery_attributes_every_invalid_share);
}

#[test]
fn optimistic_da_recovery_rejects_malformed_quorums_for_every_suite() {
    for_each_suite!(optimistic_recovery_rejects_malformed_quorums);
}
