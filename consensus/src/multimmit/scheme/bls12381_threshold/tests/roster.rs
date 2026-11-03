//! Roster construction and rogue-key rejection.

use super::*;

fn roster_rejects_rogue_keys<V: Variant>() {
    let mut rng = TestRng::new(4_242);
    let honest_identity = Ed25519PrivateKey::from_seed(1).public_key();
    let attacker_identity = Ed25519PrivateKey::from_seed(2).public_key();
    let (honest_private, honest_public) = sas::keypair::<_, V>(&mut rng);
    let (attacker_private, attacker_public) = sas::keypair::<_, V>(&mut rng);
    let rogue_public = sas::PublicKey::<V>::new(
        *attacker_public.x() - honest_public.x(),
        *attacker_public.y() - honest_public.y(),
    );

    // Without a proof of knowledge, the attacker alone produces an aggregate over both keys.
    let period = b"rogue-key-period";
    let namespace = b"rogue-key-vector";
    let message = b"same vote";
    let claim = sas::Claim::<V> {
        period,
        signature: sas::sign_message::<V>(&attacker_private, period, namespace, message),
        terms: vec![
            sas::Term {
                public: honest_public,
                namespace,
                message,
            },
            sas::Term {
                public: rogue_public,
                namespace,
                message,
            },
        ],
    };
    assert!(sas::verify_claims(&mut rng, &[claim], &Sequential).is_empty());

    // The attacker cannot prove knowledge of the rogue key's secrets.
    let participants = vec![
        (
            honest_identity.clone(),
            honest_public,
            Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
                &mut rng,
                NAMESPACE,
                &honest_identity,
                &honest_private,
            ),
        ),
        (
            attacker_identity.clone(),
            rogue_public,
            Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
                &mut rng,
                NAMESPACE,
                &attacker_identity,
                &attacker_private,
            ),
        ),
    ];
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, participants, &Sequential).unwrap_err(),
        Error::ProofOfKnowledge
    );
}

#[test]
fn roster_rejects_rogue_keys_for_both_variants() {
    roster_rejects_rogue_keys::<MinPk>();
    roster_rejects_rogue_keys::<MinSig>();
}

fn roster_binds_proofs_to_identities<V: Variant>() {
    let mut rng = TestRng::new(4_244);
    let first_identity = Ed25519PrivateKey::from_seed(1).public_key();
    let second_identity = Ed25519PrivateKey::from_seed(2).public_key();
    let (first_private, first_public) = sas::keypair::<_, V>(&mut rng);
    let (second_private, second_public) = sas::keypair::<_, V>(&mut rng);
    let first_proof = Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        &mut rng,
        NAMESPACE,
        &first_identity,
        &first_private,
    );
    let second_proof = Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        &mut rng,
        NAMESPACE,
        &second_identity,
        &second_private,
    );

    // Proofs verify for the identities they were made for.
    let valid = vec![
        (first_identity.clone(), first_public, first_proof.clone()),
        (second_identity.clone(), second_public, second_proof.clone()),
    ];
    assert!(Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, valid, &Sequential).is_ok());

    // A key and proof registered under another identity must be rejected.
    let swapped = vec![
        (first_identity.clone(), second_public, second_proof.clone()),
        (second_identity.clone(), first_public, first_proof.clone()),
    ];
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, swapped, &Sequential).unwrap_err(),
        Error::ProofOfKnowledge
    );

    // A proof made under another namespace must be rejected.
    let foreign = vec![
        (first_identity, first_public, first_proof),
        (second_identity, second_public, second_proof),
    ];
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER",
            2,
            foreign,
            &Sequential
        )
        .unwrap_err(),
        Error::ProofOfKnowledge
    );
}

#[test]
fn roster_binds_proofs_to_identities_for_both_variants() {
    roster_binds_proofs_to_identities::<MinPk>();
    roster_binds_proofs_to_identities::<MinSig>();
}

fn roster_bounds_and_deduplicates_manifests<V: Variant>() {
    let mut rng = TestRng::new(4_243);
    let (first_private, first_public) = sas::keypair::<_, V>(&mut rng);
    let (second_private, second_public) = sas::keypair::<_, V>(&mut rng);
    let first_identity = Ed25519PrivateKey::from_seed(1).public_key();
    let second_identity = Ed25519PrivateKey::from_seed(2).public_key();
    let first_proof = Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        &mut rng,
        NAMESPACE,
        &first_identity,
        &first_private,
    );
    let second_proof = Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        &mut rng,
        NAMESPACE,
        &second_identity,
        &second_private,
    );
    let valid = vec![
        (first_identity.clone(), first_public, first_proof.clone()),
        (second_identity.clone(), second_public, second_proof.clone()),
    ];

    assert!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, valid.clone(), &Sequential).is_ok()
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 1, valid, &Sequential).unwrap_err(),
        Error::Participants
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                (first_identity.clone(), first_public, first_proof.clone()),
                (first_identity.clone(), second_public, second_proof),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::DuplicateParticipant
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                (first_identity, first_public, first_proof.clone()),
                (second_identity, first_public, first_proof),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::DuplicateParticipant
    );
}

#[test]
fn roster_bounds_and_deduplicates_manifests_for_both_variants() {
    roster_bounds_and_deduplicates_manifests::<MinPk>();
    roster_bounds_and_deduplicates_manifests::<MinSig>();
}
