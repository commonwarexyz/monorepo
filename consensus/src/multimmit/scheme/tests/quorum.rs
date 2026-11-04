//! Data-availability quorums, payment epochs, and receipts across suites.

use super::*;

#[test]
fn fault_models_match_the_codec_quorums() {
    for n in 1..=64usize {
        let codec = CodecConfig::new(n, 1, PathLimits::new(1, 0)).unwrap();
        assert_eq!(Available::quorum(n) as usize, codec.da_quorum(), "n = {n}");
        assert_eq!(
            N5f1Nullification::quorum(n) as usize,
            codec.nullification_quorum(),
            "n = {n}"
        );
        assert_eq!(N5f1::quorum(n) as usize, codec.view_quorum(), "n = {n}");
        // A DA certificate always has a correct signer holding the block, and a receipt needs
        // more signers than a certificate unless the committee tolerates no faults.
        assert!(codec.da_quorum() > codec.max_faults(), "n = {n}");
        assert!(codec.da_quorum() <= codec.view_quorum(), "n = {n}");
    }
}

/// Returns the fixture's parameters, with payment chains when §payments§ is set.
fn parameters(payments: bool) -> std::sync::Arc<Parameters> {
    let config = keys::test_config(
        SEED,
        NAMESPACE,
        PARTICIPANTS,
        (0..PARTICIPANTS).map(Participant::new).collect(),
        PathLimits::new(2, 2),
    );
    std::sync::Arc::new(
        std::sync::Arc::unwrap_or_clone(config.parameters().clone()).with_payments(payments),
    )
}

fn identities() -> (
    Vec<Ed25519PrivateKey>,
    commonware_utils::ordered::Set<Ed25519PublicKey>,
) {
    let mut keys = (0..PARTICIPANTS)
        .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 1))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.public_key());
    let set = commonware_utils::ordered::Set::try_from(
        keys.iter().map(|key| key.public_key()).collect::<Vec<_>>(),
    )
    .unwrap();
    (keys, set)
}

#[test]
fn ed25519_runs_payment_epochs() {
    let (keys, participants) = identities();
    for payments in [false, true] {
        let parameters = parameters(payments);
        assert!(ed25519_suite::Scheme::verifier(&parameters, participants.clone()).is_ok());
        assert!(
            ed25519_suite::Scheme::signer(&parameters, participants.clone(), keys[0].clone())
                .is_ok()
        );
    }
}

#[test]
fn generic_new_checks_the_committee_and_the_local_signer() {
    let (_, participants) = identities();
    let namespace = NAMESPACE;
    let available = parameters(false);
    let (ordinary, da, nullify) = (
        ed25519_suite::ordinary::Scheme::verifier(namespace, participants.clone()),
        ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
        ed25519_suite::nullify::Scheme::verifier(namespace, participants.clone()),
    );
    assert!(Generic::<Ed25519>::new(&available, ordinary, da, nullify).is_ok());

    // Roles over another committee size, or disagreeing on the local signer, are rejected.
    let (keys, _) = identities();
    let small = commonware_utils::ordered::Set::try_from(
        keys[..PARTICIPANTS as usize - 1]
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::verifier(namespace, small),
            ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::nullify::Scheme::verifier(namespace, participants.clone()),
        )
        .unwrap_err(),
        Error::Participants
    );
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
            ed25519_suite::da::Scheme::signer(namespace, participants.clone(), keys[1].clone())
                .unwrap(),
            ed25519_suite::nullify::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
        )
        .unwrap_err(),
        Error::Membership
    );
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
            ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::nullify::Scheme::signer(namespace, participants, keys[0].clone())
                .unwrap(),
        )
        .unwrap_err(),
        Error::Membership
    );
}

/// Checks that a BLS-family suite runs payment epochs only with aggregate DA certificates.
macro_rules! bls_payments_test {
    ($name:ident, $suite:ident) => {
        #[test]
        fn $name() {
            fn check<V: Variant>() {
                let (_, identities) = identities();
                let ordinary = parameters(false);
                let payments = parameters(true);
                let mut rng = TestRng::new(SEED);
                // Threshold DA certificates hide their signers, so they cannot form receipts.
                assert!(
                    $suite::Scheme::<Ed25519PublicKey, V, $suite::Threshold>::deal(
                        &mut rng,
                        &ordinary,
                        &identities
                    )
                    .is_ok()
                );
                assert!(matches!(
                    $suite::Scheme::<Ed25519PublicKey, V, $suite::Threshold>::deal(
                        &mut rng,
                        &payments,
                        &identities
                    ),
                    Err(Error::Receipts)
                ));
                let dealt = $suite::Scheme::<Ed25519PublicKey, V, $suite::Threshold>::deal(
                    &mut rng,
                    &ordinary,
                    &identities,
                )
                .unwrap();
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, $suite::Threshold>::verifier(
                        &payments,
                        dealt.roster.clone(),
                        dealt.da.clone(),
                        dealt.nullification.clone(),
                    )
                    .unwrap_err(),
                    Error::Receipts
                );
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, $suite::Threshold>::certificate_verifier(
                        &payments,
                        dealt.roster.clone(),
                        *dealt.da.public(),
                        *dealt.nullification.public(),
                    )
                    .unwrap_err(),
                    Error::Receipts
                );

                // Aggregate DA certificates run either epoch, from the ordinary roster and the
                // nullification sharing alone.
                for parameters in [&ordinary, &payments] {
                    let dealt = $suite::Scheme::<Ed25519PublicKey, V, $suite::Aggregate>::deal(
                        &mut rng,
                        parameters,
                        &identities,
                    )
                    .unwrap();
                    assert_eq!(dealt.signers.len(), PARTICIPANTS as usize);
                    assert!(
                        $suite::Scheme::<Ed25519PublicKey, V, $suite::Aggregate>::certificate_verifier(
                            parameters,
                            dealt.roster.clone(),
                            *dealt.nullification.public(),
                        )
                        .is_ok()
                    );
                    // A nullification sharing of the wrong threshold is rejected.
                    let wrong = bls12381::deal_sharing::<V>(&mut rng, PARTICIPANTS, 2);
                    assert_eq!(
                        $suite::Scheme::<Ed25519PublicKey, V, $suite::Aggregate>::verifier(
                            parameters,
                            dealt.roster.clone(),
                            wrong.sharing,
                        )
                        .unwrap_err(),
                        Error::Sharing
                    );
                }
            }
            check::<MinPk>();
            check::<MinSig>();
        }
    };
}

bls_payments_test!(bls12381_runs_payment_epochs_only_with_aggregate_da, bls12381);
bls_payments_test!(
    bls12381_sas_runs_payment_epochs_only_with_aggregate_da,
    bls12381_sas
);

/// Checks that an attributable suite forms receipts from exactly `n - f` votes, and that a receipt
/// verifies as a certificate while a certificate below `n - f` signers is no receipt.
fn receipts_count_n_minus_f_signers<S: Suite>() {
    let committee = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .payments(true)
        .build();
    let codec = committee.codec();
    let (certificate_quorum, receipt_quorum) = (codec.da_quorum(), codec.view_quorum());
    assert!(certificate_quorum < receipt_quorum);
    assert_eq!(committee.verifier.receipt_quorum(), receipt_quorum);

    let header = committee.transaction_header(ChainId::new(0), digest(b"commitment", 0));
    let votes = committee
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let mut rng = test_rng();
    let verifier = &committee.verifier;

    // A certificate counts its signers but is no receipt.
    let certificate = verifier
        .assemble_da_certificate(&mut rng, &votes[..certificate_quorum], &Sequential)
        .unwrap();
    assert_eq!(
        verifier.da_signers(certificate.certificate()),
        Some(certificate_quorum)
    );
    assert!(!verifier.is_receipt(certificate.certificate()));
    assert!(verifier.verify_da_certificate(&mut rng, &certificate, &Sequential));
    assert!(!verifier.verify_receipt(&mut rng, &certificate, &Sequential));

    // A receipt needs exactly n - f votes.
    for count in [certificate_quorum, receipt_quorum - 1, receipt_quorum + 1] {
        assert_eq!(
            verifier
                .assemble_receipt(&mut rng, &votes[..count], &Sequential)
                .unwrap_err(),
            Error::Quorum,
            "count = {count}"
        );
    }
    let receipt = verifier
        .assemble_receipt(&mut rng, &votes[..receipt_quorum], &Sequential)
        .unwrap();
    assert_eq!(verifier.da_signers(receipt.certificate()), Some(receipt_quorum));
    assert!(verifier.is_receipt(receipt.certificate()));
    assert!(verifier.verify_receipt(&mut rng, &receipt, &Sequential));
    assert!(verifier.verify_da_certificate(&mut rng, &receipt, &Sequential));

    // Every signer verifies the receipt, and it does not verify for another header.
    for signer in &committee.signers {
        assert!(signer.verify_receipt(&mut rng, &receipt, &Sequential));
    }
    let other = committee.transaction_header(ChainId::new(0), digest(b"commitment", 1));
    let moved = DaCertificate::<S, Digest>::new(other, receipt.certificate().clone());
    assert!(!verifier.verify_receipt(&mut rng, &moved, &Sequential));

    // A duplicated vote does not count twice.
    let mut duplicated = votes[..receipt_quorum - 1].to_vec();
    duplicated.push(votes[0].clone());
    assert!(
        verifier
            .assemble_receipt(&mut rng, &duplicated, &Sequential)
            .is_err()
    );
}

#[test]
fn attributable_suites_form_receipts_from_n_minus_f_votes() {
    receipts_count_n_minus_f_signers::<Bls<MinPk, bls12381::Aggregate>>();
    receipts_count_n_minus_f_signers::<Bls<MinSig, bls12381::Aggregate>>();
    receipts_count_n_minus_f_signers::<Sas<MinPk, bls12381::Aggregate>>();
    receipts_count_n_minus_f_signers::<Sas<MinSig, bls12381::Aggregate>>();
    receipts_count_n_minus_f_signers::<Ed25519>();
    receipts_count_n_minus_f_signers::<Mock>();
}

/// Checks that a suite with threshold DA certificates neither forms nor recognizes receipts.
fn threshold_suites_form_no_receipts<S: Suite>() {
    let committee = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .build();
    let header = committee.transaction_header(ChainId::new(0), digest(b"commitment", 0));
    let votes = committee
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let mut rng = test_rng();
    let verifier = &committee.verifier;
    let receipt_quorum = verifier.receipt_quorum();
    assert_eq!(
        verifier
            .assemble_receipt(&mut rng, &votes[..receipt_quorum], &Sequential)
            .unwrap_err(),
        Error::Receipts
    );
    let certificate = verifier
        .assemble_da_certificate(
            &mut rng,
            &votes[..committee.codec().da_quorum()],
            &Sequential,
        )
        .unwrap();
    assert_eq!(verifier.da_signers(certificate.certificate()), None);
    assert!(!verifier.verify_receipt(&mut rng, &certificate, &Sequential));
}

#[test]
fn threshold_suites_form_no_receipts_for_both_variants() {
    threshold_suites_form_no_receipts::<Bls<MinPk>>();
    threshold_suites_form_no_receipts::<Bls<MinSig>>();
    threshold_suites_form_no_receipts::<Sas<MinPk>>();
    threshold_suites_form_no_receipts::<Sas<MinSig>>();
}
