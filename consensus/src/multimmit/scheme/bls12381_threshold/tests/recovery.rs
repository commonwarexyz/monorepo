//! Optimistic data-availability recovery and share attribution.

use super::*;

/// An honest quorum must certify from shares no pairing ever touched individually.
///
/// Ingress admits a share on [`Scheme::precheck_da_vote`] alone, so this is the only
/// signature check the whole quorum pays for.
fn optimistic_recovery_certifies_an_unverified_quorum<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(1, 300);
    let votes = fixture
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let quorum = &votes[..fixture.codec.da_quorum()];
    for vote in quorum {
        assert!(
            fixture.verifier.precheck_da_vote(vote),
            "an honest share passes admission without its pairing"
        );
    }
    let certificate = fixture
        .verifier
        .assemble_da_certificate_optimistic(quorum, &Sequential)
        .expect("an honest quorum interpolates the group signature");
    assert_eq!(certificate.header(), &header);
    assert!(fixture.verifier.verify_da_certificate(&certificate));
    assert!(
        fixture
            .verifier
            .invalid_da_shares(quorum, &Sequential)
            .unwrap()
            .is_empty(),
        "the attribution pass has nothing to report for an honest quorum"
    );
}

/// Admission must accept a share whose signature is invalid, leaving recovery to catch it.
///
/// This is what makes the quorum cost one pairing instead of one per signer, so it is also
/// what the recovery fallback exists to backstop.
fn da_share_admission_ignores_its_signature<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(1, 301);
    let elsewhere = fixture.signers[1]
        .sign_da_vote(fixture.header(1, 302))
        .unwrap();
    // A share signed over another header is structurally perfect and cryptographically wrong.
    let forged = DaVote::new(header, elsewhere.share().clone());
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
    // A share with no usable signature still fails admission outright.
    let empty = DaVote::new(
        fixture.header(1, 303),
        ThresholdShare::new(Participant::new(1), Lazy::from(V::Signature::zero())),
    );
    assert!(!fixture.verifier.precheck_da_vote(&empty));
}

/// One invalid share must fail the quorum once and name exactly its signer.
fn optimistic_recovery_attributes_one_invalid_share<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(1, 304);
    let mut quorum = fixture.signers[..fixture.codec.da_quorum()]
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let culprit = Participant::new(1);
    let elsewhere = fixture.signers[1]
        .sign_da_vote(fixture.header(1, 305))
        .unwrap();
    quorum[1] = DaVote::new(header.clone(), elsewhere.share().clone());
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate_optimistic(&quorum, &Sequential),
        Err(DaRecoveryError::InvalidShares(vec![culprit])),
    );
    // Dropping the named signer and re-selecting from the surviving shares certifies on the
    // next attempt, so one adversarial share costs exactly one extra recovery.
    let survivors = fixture
        .signers
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, signer)| signer.sign_da_vote(header.clone()).unwrap())
        .take(fixture.codec.da_quorum())
        .collect::<Vec<_>>();
    let certificate = fixture
        .verifier
        .assemble_da_certificate_optimistic(&survivors, &Sequential)
        .expect("the surviving shares still form a quorum");
    assert!(fixture.verifier.verify_da_certificate(&certificate));
}

/// Every invalid share in one quorum must be named by a single attribution pass.
///
/// A flood therefore costs one bounded pass, not one recovery attempt per bad share.
fn optimistic_recovery_attributes_every_invalid_share<V: Variant>() {
    let fixture = Fixture::<V>::new();
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
            DaVote::new(header.clone(), elsewhere.share().clone())
        })
        .collect::<Vec<_>>();
    let expected = (1..fixture.codec.da_quorum() as u32)
        .map(Participant::new)
        .collect::<Vec<_>>();
    assert_eq!(
        fixture
            .verifier
            .assemble_da_certificate_optimistic(&quorum, &Sequential),
        Err(DaRecoveryError::InvalidShares(expected)),
    );
}

#[test]
fn optimistic_da_recovery_certifies_honest_quorums_for_both_variants() {
    optimistic_recovery_certifies_an_unverified_quorum::<MinPk>();
    optimistic_recovery_certifies_an_unverified_quorum::<MinSig>();
}

#[test]
fn da_share_admission_ignores_signatures_for_both_variants() {
    da_share_admission_ignores_its_signature::<MinPk>();
    da_share_admission_ignores_its_signature::<MinSig>();
}

#[test]
fn optimistic_da_recovery_attributes_one_invalid_share_for_both_variants() {
    optimistic_recovery_attributes_one_invalid_share::<MinPk>();
    optimistic_recovery_attributes_one_invalid_share::<MinSig>();
}

#[test]
fn optimistic_da_recovery_attributes_every_invalid_share_for_both_variants() {
    optimistic_recovery_attributes_every_invalid_share::<MinPk>();
    optimistic_recovery_attributes_every_invalid_share::<MinSig>();
}
