//! Roster construction and rogue-key rejection.

use super::*;
use commonware_codec::Read as _;
use commonware_cryptography::bls12381::primitives::ops::batch as pairing;

fn roster_rejects_rogue_keys<V: Variant>() {
    let mut rng = TestRng::new(4_242);
    let (honest_private, honest_public) = ops::keypair::<_, V>(&mut rng);
    let (attacker_private, attacker_public) = ops::keypair::<_, V>(&mut rng);
    let rogue_public = attacker_public - &honest_public;
    let namespace = b"rogue-key-vector";
    let message = b"same vote";
    let forged = ops::sign_message::<V>(&attacker_private, namespace, message);
    let mut forged = forged.encode();
    let forged = aggregate::Signature::<V>::read_cfg(&mut forged, &()).unwrap();

    // Without proofs of possession, the rogue key forges an aggregate for the honest key.
    let claim = pairing::Claim::<V> {
        signature: *forged.inner(),
        terms: vec![
            pairing::Term {
                public: honest_public,
                namespace,
                message,
            },
            pairing::Term {
                public: rogue_public,
                namespace,
                message,
            },
        ],
    };
    assert!(pairing::verify_claims(&mut rng, &[claim], &Sequential).is_empty());

    let participants = vec![
        (
            Ed25519PrivateKey::from_seed(1).public_key(),
            honest_public,
            Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &honest_private),
        ),
        (
            Ed25519PrivateKey::from_seed(2).public_key(),
            rogue_public,
            Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &attacker_private),
        ),
    ];
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, participants, &Sequential).unwrap_err(),
        Error::ProofOfPossession
    );
}

both_variants!(
    roster_rejects_rogue_keys_for_both_variants,
    roster_rejects_rogue_keys
);

fn roster_bounds_and_deduplicates_manifests<V: Variant>() {
    let mut rng = TestRng::new(4_243);
    let (first_private, first_public) = ops::keypair::<_, V>(&mut rng);
    let (second_private, second_public) = ops::keypair::<_, V>(&mut rng);
    let first_identity = Ed25519PrivateKey::from_seed(1).public_key();
    let second_identity = Ed25519PrivateKey::from_seed(2).public_key();
    let first_proof = Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &first_private);
    let second_proof =
        Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &second_private);
    let valid = vec![
        (first_identity.clone(), first_public, first_proof),
        (second_identity.clone(), second_public, second_proof),
    ];

    assert!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, valid.clone(), &Sequential).is_ok()
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 1, valid.clone(), &Sequential)
            .unwrap_err(),
        Error::Participants
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(b"other", 2, valid, &Sequential).unwrap_err(),
        Error::ProofOfPossession
    );
    assert_eq!(
        Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                (first_identity.clone(), first_public, first_proof),
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
                (first_identity, first_public, first_proof),
                (second_identity, first_public, first_proof),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::DuplicateParticipant
    );
}

both_variants!(
    roster_bounds_and_deduplicates_manifests_for_both_variants,
    roster_bounds_and_deduplicates_manifests
);
