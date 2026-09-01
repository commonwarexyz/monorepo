//! Key-material and configuration checks in the scheme constructors.

use super::*;

fn schemes_reject_rosters_from_other_namespaces<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let config = &fixture.epoch_config;
    let codec = config.codec_config();
    for namespace in [
        &NAMESPACE[..NAMESPACE.len() - 1],
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER",
    ] {
        let other = Protocol::new(
            namespace,
            codec.participants(),
            config.producers().to_vec(),
            codec.limits(),
            config.genesis().clone(),
        )
        .unwrap();
        assert_eq!(
            Scheme::verifier(
                other.parameters(),
                fixture.roster.clone(),
                fixture.da.clone(),
                fixture.nullification.clone(),
            )
            .unwrap_err(),
            Error::Namespace
        );
        assert_eq!(
            Scheme::certificate_verifier(
                other.parameters(),
                fixture.roster.clone(),
                *fixture.da.public(),
                *fixture.nullification.public(),
            )
            .unwrap_err(),
            Error::Namespace
        );
    }
    assert_eq!(fixture.verifier.namespace, Namespace::new(NAMESPACE));
    assert_ne!(
        fixture.verifier.namespace,
        Namespace::new(&NAMESPACE[..NAMESPACE.len() - 1])
    );
}

#[test]
fn schemes_reject_rosters_from_other_namespaces_for_both_variants() {
    schemes_reject_rosters_from_other_namespaces::<MinPk>();
    schemes_reject_rosters_from_other_namespaces::<MinSig>();
}

fn schemes_bind_their_epoch<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let block = fixture.signers[0]
        .sign_transaction_block(fixture.header(0, 1))
        .unwrap();
    let other_config = keys::test_config(
        10,
        NAMESPACE,
        PARTICIPANTS,
        fixture.epoch_config.producers().to_vec(),
        fixture.codec.limits(),
    );
    let other_context = Scheme::verifier(
        other_config.parameters(),
        fixture.roster.clone(),
        fixture.da.clone(),
        fixture.nullification,
    )
    .unwrap();
    assert!(!other_context.verify_transaction_block(&block));
}

#[test]
fn schemes_bind_their_epoch_for_both_variants() {
    schemes_bind_their_epoch::<MinPk>();
    schemes_bind_their_epoch::<MinSig>();
}

fn signer_keys_must_match_the_roster_and_sharings<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let mut rng = TestRng::new(8_888);
    let (unlisted, _) = ops::keypair::<_, V>(&mut rng);
    let DealtSharing {
        sharing: fresh_da,
        shares: fresh_da_shares,
    } = sharing::<V>(&mut rng, PARTICIPANTS, fixture.codec.da_quorum() as u32);
    let DealtSharing {
        sharing: fresh_nullification,
        shares: fresh_nullification_shares,
    } = sharing::<V>(
        &mut rng,
        PARTICIPANTS,
        fixture.codec.nullification_quorum() as u32,
    );
    let unlisted = SignerKeys {
        ordinary: unlisted,
        da: fresh_da_shares[0].clone(),
        nullification: fresh_nullification_shares[0].clone(),
    };
    assert_eq!(
        Scheme::signer(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            unlisted,
            fresh_da.clone(),
            fresh_nullification.clone(),
        )
        .unwrap_err(),
        Error::UnknownKey
    );

    // The fixture draws participant 0's ordinary key first from its seed.
    let (ordinary, _) = ops::keypair::<_, V>(&mut TestRng::new(SEED));
    let misindexed = SignerKeys {
        ordinary: ordinary.clone(),
        da: fresh_da_shares[1].clone(),
        nullification: fresh_nullification_shares[1].clone(),
    };
    assert_eq!(
        Scheme::signer(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            misindexed,
            fresh_da,
            fresh_nullification,
        )
        .unwrap_err(),
        Error::Share
    );
    let foreign = SignerKeys {
        ordinary,
        da: fresh_da_shares[0].clone(),
        nullification: fresh_nullification_shares[0].clone(),
    };
    assert_eq!(
        Scheme::signer(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            foreign,
            fixture.da.clone(),
            fixture.nullification.clone(),
        )
        .unwrap_err(),
        Error::Share
    );
}

#[test]
fn signer_keys_must_match_the_roster_and_sharings_for_both_variants() {
    signer_keys_must_match_the_roster_and_sharings::<MinPk>();
    signer_keys_must_match_the_roster_and_sharings::<MinSig>();
}

fn threshold_material_must_fit_the_committee<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let mut rng = TestRng::new(8_889);
    let wrong_da = sharing::<V>(&mut rng, PARTICIPANTS, fixture.codec.view_quorum() as u32).sharing;
    assert_eq!(
        Scheme::verifier(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            wrong_da,
            fixture.nullification.clone(),
        )
        .unwrap_err(),
        Error::Sharing
    );
    assert_eq!(
        Scheme::certificate_verifier(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            V::Public::zero(),
            *fixture.nullification.public(),
        )
        .unwrap_err(),
        Error::Sharing
    );
    assert_eq!(
        Scheme::certificate_verifier(
            fixture.epoch_config.parameters(),
            fixture.roster.clone(),
            *fixture.da.public(),
            *fixture.da.public(),
        )
        .unwrap_err(),
        Error::SharedIdentity
    );

    let one = keys::test_config(
        20,
        NAMESPACE,
        1,
        vec![Participant::new(0)],
        fixture.codec.limits(),
    );
    assert_eq!(
        Scheme::verifier(
            one.parameters(),
            fixture.roster.clone(),
            fixture.da.clone(),
            fixture.nullification,
        )
        .unwrap_err(),
        Error::Participants
    );
    let identity = Ed25519PrivateKey::from_seed(1).public_key();
    let (ordinary, public) = ops::keypair::<_, V>(&mut rng);
    let proof = Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &ordinary);
    let roster =
        Roster::verify(NAMESPACE, 1, vec![(identity, public, proof)], &Sequential).unwrap();
    let DealtSharing {
        sharing: same,
        shares,
    } = sharing::<V>(&mut rng, 1, 1);
    let keys = SignerKeys {
        ordinary,
        da: shares[0].clone(),
        nullification: shares[0].clone(),
    };
    assert_eq!(
        Scheme::signer(one.parameters(), roster, keys, same.clone(), same).unwrap_err(),
        Error::SharedIdentity
    );
}

#[test]
fn threshold_material_must_fit_the_committee_for_both_variants() {
    threshold_material_must_fit_the_committee::<MinPk>();
    threshold_material_must_fit_the_committee::<MinSig>();
}

fn roles_expose_only_their_material<V: Variant>() {
    let fixture = Fixture::<V>::new();
    for (index, signer) in fixture.signers.iter().enumerate() {
        assert_eq!(signer.me(), Some(Participant::from_usize(index)));
        assert!(signer.da_sharing().is_some());
    }
    assert_eq!(fixture.verifier.me(), None);
    assert!(fixture.verifier.nullification_sharing().is_some());
    assert_eq!(
        fixture.verifier.sign_novote(fixture.round).unwrap_err(),
        Error::VerifierOnly
    );
    let certificate_verifier = fixture.certificate_verifier();
    assert_eq!(certificate_verifier.me(), None);
    assert!(certificate_verifier.da_sharing().is_none());
    assert_eq!(certificate_verifier.da_identity(), fixture.da.public());
    assert_eq!(
        certificate_verifier.nullification_identity(),
        fixture.nullification.public()
    );
}

#[test]
fn roles_expose_only_their_material_for_both_variants() {
    roles_expose_only_their_material::<MinPk>();
    roles_expose_only_their_material::<MinSig>();
}
