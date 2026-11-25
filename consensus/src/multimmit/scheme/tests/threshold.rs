//! Data-availability and nullification quorums and embedded DA certificates.

use super::*;

fn da_certificates_need_an_exact_quorum_of_valid_shares<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(0, 4);
    let da_votes = fixture.da_votes(&header);
    let da_quorum = fixture.codec.da_quorum();
    let mut rng = test_rng();
    for count in [da_quorum - 1, da_quorum + 1] {
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate(&mut rng, &da_votes[..count], &Sequential)
                .unwrap_err(),
            Error::Quorum
        );
    }
    let da_certificate = fixture
        .verifier
        .assemble_da_certificate(&mut rng, &da_votes[..da_quorum], &Sequential)
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate_with(
                &mut rng,
                &da_votes[..da_quorum],
                SignatureVerification::Preverified,
                &Sequential
            )
            .unwrap(),
        da_certificate
    );
    assert!(
        fixture
            .verifier
            .verify_da_certificate(&mut rng, &da_certificate, &Sequential)
    );

    let mut duplicate = da_votes[..da_quorum].to_vec();
    duplicate[1] = duplicate[0].clone();
    let mut invalid = da_votes[..da_quorum].to_vec();
    invalid[0] = DaVote::new(
        header.clone(),
        fixture.signers[0]
            .sign_da_vote(fixture.header(0, 5))
            .unwrap()
            .attestation()
            .clone(),
    );
    let mut unreadable = da_votes[..da_quorum].to_vec();
    unreadable[0] = DaVote::new(
        header,
        certificate::Attestation {
            signer: Participant::new(0),
            signature: malformed(),
        },
    );
    for votes in [duplicate, invalid, unreadable] {
        for verification in [
            SignatureVerification::Checked,
            SignatureVerification::Preverified,
        ] {
            assert_eq!(
                fixture
                    .verifier
                    .assemble_da_certificate_with(&mut rng, &votes, verification, &Sequential)
                    .unwrap_err(),
                Error::Signature
            );
        }
    }

    // Votes for different headers never form one certificate.
    let mut mixed = da_votes[..da_quorum].to_vec();
    mixed[1] = fixture.signers[1]
        .sign_da_vote(fixture.header(0, 6))
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate(&mut rng, &mixed, &Sequential)
            .unwrap_err(),
        Error::Transcript
    );
}

#[test]
fn da_certificates_need_an_exact_quorum_of_valid_shares_for_both_variants() {
    for_each_suite!(da_certificates_need_an_exact_quorum_of_valid_shares);
}

fn nullifications_need_an_exact_quorum<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let nullify = fixture.nullifies(fixture.round);
    let quorum = fixture.codec.nullification_quorum();
    let mut rng = test_rng();
    for count in [quorum - 1, quorum + 1] {
        assert_eq!(
            fixture
                .verifier
                .assemble_nullification(&mut rng, &nullify[..count], &Sequential)
                .unwrap_err(),
            Error::Quorum
        );
    }
    let nullification = fixture
        .verifier
        .assemble_nullification(&mut rng, &nullify[..quorum], &Sequential)
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_nullification_with(
                &mut rng,
                &nullify[..quorum],
                SignatureVerification::Preverified,
                &Sequential
            )
            .unwrap(),
        nullification
    );
    assert!(
        fixture
            .verifier
            .verify_nullification(&mut rng, &nullification, &Sequential)
    );

    let other_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let mut duplicate = nullify[..quorum].to_vec();
    duplicate[1] = duplicate[0].clone();
    let mut invalid = nullify[..quorum].to_vec();
    invalid[0] = Nullify::new(
        fixture.round,
        fixture.signers[0]
            .sign_nullify(other_round)
            .unwrap()
            .attestation()
            .clone(),
    )
    .unwrap();
    for shares in [duplicate, invalid] {
        for verification in [
            SignatureVerification::Checked,
            SignatureVerification::Preverified,
        ] {
            assert_eq!(
                fixture
                    .verifier
                    .assemble_nullification_with(&mut rng, &shares, verification, &Sequential)
                    .unwrap_err(),
                Error::Signature
            );
        }
    }
    let mut mixed = nullify[..quorum].to_vec();
    mixed[1] = fixture.signers[1].sign_nullify(other_round).unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_nullification(&mut rng, &mixed, &Sequential)
            .unwrap_err(),
        Error::Transcript
    );
}

#[test]
fn nullifications_need_an_exact_quorum_for_both_variants() {
    for_each_suite!(nullifications_need_an_exact_quorum);
}

fn threshold_certificates_verify_only_under_their_keys<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let da_certificate = fixture.da_certificate(&fixture.header(0, 4));
    let nullification = fixture.nullification(fixture.round);
    let other = other_verifier(&fixture, 9_999);
    let mut rng = test_rng();
    assert!(!other.verify_da_certificate(&mut rng, &da_certificate, &Sequential));
    assert!(!other.verify_nullification(&mut rng, &nullification, &Sequential));
}

#[test]
fn threshold_roles_verify_only_their_own_certificates_for_both_variants() {
    for_each_suite!(threshold_certificates_verify_only_under_their_keys);
}

fn leader_verification_checks_embedded_da_certificates<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let certificate = fixture.da_certificate(&fixture.header(0, 501));
    let signed = fixture.sign_leader(fixture.anchored_leader(700, certificate.clone()));
    let mut rng = test_rng();
    assert!(
        fixture
            .verifier
            .verify_leader_block(&mut rng, &signed, &Sequential)
    );

    // The leader's own signature verifies, but the anchored certificate is for other keys.
    let other = other_verifier(&fixture, 7_777);
    assert!(!other.verify_leader_block(&mut rng, &signed, &Sequential));

    // A tampered anchor fails a correctly signed block.
    let tampered = fixture
        .sign_leader(fixture.anchored_leader(700, corrupt_tail(&certificate, &fixture.codec)));
    assert!(
        !fixture
            .verifier
            .verify_leader_block(&mut rng, &tampered, &Sequential)
    );
    // An anchor on a chain outside the epoch's configuration fails structurally.
    let foreign = fixture.da_certificate(&fixture.header(0, 502));
    let wrong_epoch = DaCertificate::<S, Digest>::new(
        TransactionBlockHeader::new(
            Epoch::new(fixture.round.epoch().get() + 1),
            ChainId::new(0),
            Height::new(1),
            digest(b"parent", 502),
            digest(b"commitment", 502),
        )
        .unwrap(),
        foreign.certificate().clone(),
    );
    assert!(
        !fixture
            .verifier
            .verify_da_certificate(&mut rng, &wrong_epoch, &Sequential)
    );
}

#[test]
fn leader_verification_checks_embedded_da_certificates_for_both_variants() {
    for_each_suite!(leader_verification_checks_embedded_da_certificates);
}
