//! Threshold certificate quorums and embedded DA certificates.

use super::*;

/// Returns every signer's DA share over `header`.
fn da_votes<V: Variant>(
    fixture: &Fixture<V>,
    header: &TransactionBlockHeader<Digest>,
) -> Vec<DaVote<V, Digest>> {
    fixture
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect()
}

/// Returns every signer's nullify share for the fixture round.
fn nullifies<V: Variant>(fixture: &Fixture<V>) -> Vec<Nullify<V>> {
    fixture
        .signers
        .iter()
        .map(|signer| signer.sign_nullify(fixture.round).unwrap())
        .collect()
}

fn da_certificates_need_an_exact_quorum_of_valid_shares<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 4);
    let da_votes = da_votes(&fixture, &header);
    let da_quorum = fixture.codec.da_quorum();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate(&da_votes[..da_quorum - 1], &Sequential)
            .unwrap_err(),
        Error::Quorum
    );
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate(&da_votes[..=da_quorum], &Sequential)
            .unwrap_err(),
        Error::Quorum
    );
    let da_certificate = fixture
        .verifier
        .assemble_da_certificate(&da_votes[..da_quorum], &Sequential)
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate_with(
                &da_votes[..da_quorum],
                SignatureVerification::Preverified,
                &Sequential
            )
            .unwrap(),
        da_certificate
    );
    assert!(fixture.verifier.verify_da_certificate(&da_certificate));

    let mut duplicate = da_votes[..da_quorum].to_vec();
    duplicate[1] = duplicate[0].clone();
    let mut invalid = da_votes[..da_quorum].to_vec();
    invalid[0] = DaVote::new(
        header,
        ThresholdShare::new(Participant::new(0), Lazy::from(V::Signature::zero())),
    );
    for votes in [duplicate, invalid] {
        for verification in [
            SignatureVerification::Checked,
            SignatureVerification::Preverified,
        ] {
            assert_eq!(
                fixture
                    .verifier
                    .assemble_da_certificate_with(&votes, verification, &Sequential)
                    .unwrap_err(),
                Error::Signature
            );
        }
    }
}

#[test]
fn da_certificates_need_an_exact_quorum_of_valid_shares_for_both_variants() {
    da_certificates_need_an_exact_quorum_of_valid_shares::<MinPk>();
    da_certificates_need_an_exact_quorum_of_valid_shares::<MinSig>();
}

fn nullifications_need_an_exact_quorum<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let nullify = nullifies(&fixture);
    let nullification_quorum = fixture.codec.nullification_quorum();
    assert_eq!(
        fixture
            .verifier
            .assemble_nullification(&nullify[..nullification_quorum - 1], &Sequential)
            .unwrap_err(),
        Error::Quorum
    );
    assert_eq!(
        fixture
            .verifier
            .assemble_nullification(&nullify[..=nullification_quorum], &Sequential)
            .unwrap_err(),
        Error::Quorum
    );
    let nullification = fixture
        .verifier
        .assemble_nullification(&nullify[..nullification_quorum], &Sequential)
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .assemble_nullification_with(
                &nullify[..nullification_quorum],
                SignatureVerification::Preverified,
                &Sequential
            )
            .unwrap(),
        nullification
    );
    assert!(fixture.verifier.verify_nullification(&nullification));
}

#[test]
fn nullifications_need_an_exact_quorum_for_both_variants() {
    nullifications_need_an_exact_quorum::<MinPk>();
    nullifications_need_an_exact_quorum::<MinSig>();
}

fn threshold_roles_verify_only_their_own_certificates<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let da_votes = da_votes(&fixture, &fixture.header(0, 4));
    let da_quorum = fixture.codec.da_quorum();
    let da_certificate = fixture
        .verifier
        .assemble_da_certificate(&da_votes[..da_quorum], &Sequential)
        .unwrap();
    let nullify = nullifies(&fixture);
    let nullification = fixture
        .verifier
        .assemble_nullification(
            &nullify[..fixture.codec.nullification_quorum()],
            &Sequential,
        )
        .unwrap();

    let wrong_nullification =
        Nullification::new(fixture.round, da_certificate.certificate().clone()).unwrap();
    assert!(!fixture.verifier.verify_nullification(&wrong_nullification));
    let wrong_da = DaCertificate::new(
        da_certificate.header().clone(),
        nullification.certificate().clone(),
    );
    assert!(!fixture.verifier.verify_da_certificate(&wrong_da));

    let certificate_verifier = fixture.certificate_verifier();
    assert!(certificate_verifier.da_sharing().is_none());
    assert!(certificate_verifier.nullification_sharing().is_none());
    assert!(certificate_verifier.verify_da_certificate(&da_certificate));
    assert!(certificate_verifier.verify_nullification(&nullification));
    assert!(!certificate_verifier.verify_da_vote(&da_votes[0]));
    assert!(!certificate_verifier.verify_nullify(&nullify[0]));
    assert_eq!(
        certificate_verifier
            .assemble_da_certificate(&da_votes[..da_quorum], &Sequential)
            .unwrap_err(),
        Error::SharingUnavailable
    );

    let mut other_rng = TestRng::new(9_999);
    let other_da = sharing::<V>(
        &mut other_rng,
        PARTICIPANTS,
        fixture.codec.da_quorum() as u32,
    )
    .sharing;
    let other_nullification = sharing::<V>(
        &mut other_rng,
        PARTICIPANTS,
        fixture.codec.nullification_quorum() as u32,
    )
    .sharing;
    let other = Scheme::verifier(
        fixture.epoch_config.parameters(),
        fixture.roster.clone(),
        other_da,
        other_nullification,
    )
    .unwrap();
    assert!(!other.verify_da_certificate(&da_certificate));
    assert!(!other.verify_nullification(&nullification));
}

#[test]
fn threshold_roles_verify_only_their_own_certificates_for_both_variants() {
    threshold_roles_verify_only_their_own_certificates::<MinPk>();
    threshold_roles_verify_only_their_own_certificates::<MinSig>();
}

fn leader_verification_checks_embedded_da_certificates<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 501);
    let votes = fixture
        .signers
        .iter()
        .take(fixture.codec.da_quorum())
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let certificate = fixture
        .verifier
        .assemble_da_certificate(&votes, &Sequential)
        .unwrap();
    let proposals = fixture
        .tips
        .iter()
        .enumerate()
        .map(|(index, tip)| {
            let anchor = if index == 0 {
                Anchor::Certificate(certificate.clone())
            } else {
                Anchor::Tip(*tip)
            };
            ChainProposal::new(
                ChainId::new(index as u32),
                anchor,
                Vec::new(),
                fixture.codec.pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        fixture.round,
        CertificateId::new(digest(b"parent vqc", 700)),
        digest(b"history", 700),
        proposals,
        fixture.codec,
    )
    .unwrap();
    let scheduled = usize::from(
        LeaderSchedule::round_robin(fixture.codec.participants())
            .unwrap()
            .leader(leader.view()),
    );
    let signed = fixture.signers[scheduled]
        .sign_leader_block(leader)
        .unwrap();
    assert!(fixture.verifier.verify_leader_block(&signed, &Sequential));

    let mut other_rng = TestRng::new(7_777);
    let other_da = sharing::<V>(
        &mut other_rng,
        PARTICIPANTS,
        fixture.codec.da_quorum() as u32,
    )
    .sharing;
    let other_nullification = sharing::<V>(
        &mut other_rng,
        PARTICIPANTS,
        fixture.codec.nullification_quorum() as u32,
    )
    .sharing;
    let other = Scheme::verifier(
        fixture.epoch_config.parameters(),
        fixture.roster.clone(),
        other_da,
        other_nullification,
    )
    .unwrap();
    assert!(!other.verify_leader_block(&signed, &Sequential));
}

#[test]
fn leader_verification_checks_embedded_da_certificates_for_both_variants() {
    leader_verification_checks_embedded_da_certificates::<MinPk>();
    leader_verification_checks_embedded_da_certificates::<MinSig>();
}
