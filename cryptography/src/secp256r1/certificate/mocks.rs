//! Test fixtures for Secp256r1 certificate signing schemes.

use crate::{
    certificate::{mocks::Fixture, Scheme},
    ed25519,
    secp256r1::standard::{PrivateKey, PublicKey},
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::BiMap, TryCollect as _};
use rand::{CryptoRng, RngCore};

/// Builds ed25519 identities and matching Secp256r1 signing schemes.
pub fn fixture<S, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
    signer: impl Fn(&[u8], BiMap<ed25519::PublicKey, PublicKey>, PrivateKey) -> Option<S>,
    verifier: impl Fn(&[u8], BiMap<ed25519::PublicKey, PublicKey>) -> S,
) -> Fixture<S>
where
    R: RngCore + CryptoRng,
    S: Scheme<PublicKey = ed25519::PublicKey>,
{
    assert!(n > 0);

    let associated = crate::ed25519::certificate::mocks::participants(rng, n);
    let participants = associated.keys().clone();
    let participants_vec: Vec<_> = participants.clone().into();
    let private_keys: Vec<_> = participants_vec
        .iter()
        .map(|pk| {
            associated
                .get_value(pk)
                .expect("participant key must have an associated private key")
                .clone()
        })
        .collect();

    let secp_privates: Vec<_> = (0..n).map(|_| PrivateKey::random(&mut *rng)).collect();
    let secp_publics: Vec<_> = secp_privates.iter().map(|sk| sk.public_key()).collect();

    let signers: BiMap<_, _> = participants
        .into_iter()
        .zip(secp_publics)
        .try_collect()
        .expect("ed25519 public keys are unique");

    let schemes = secp_privates
        .into_iter()
        .map(|sk| {
            signer(namespace, signers.clone(), sk).expect("scheme signer must be a participant")
        })
        .collect();
    let verifier = verifier(namespace, signers);

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
