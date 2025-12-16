//! Test fixtures for Ed25519 certificate signing schemes.

use crate::{
    certificate::{mocks::Fixture, Scheme},
    ed25519::{PrivateKey, PublicKey},
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::BiMap, TryCollect as _};
use rand::{CryptoRng, RngCore};

/// Generates ed25519 identity participants.
pub fn participants<R>(rng: &mut R, n: u32) -> BiMap<PublicKey, PrivateKey>
where
    R: RngCore + CryptoRng,
{
    (0..n)
        .map(|_| {
            let private_key = PrivateKey::random(&mut *rng);
            let public_key = private_key.public_key();
            (public_key, private_key)
        })
        .try_collect()
        .expect("ed25519 public keys are unique")
}

/// Builds ed25519 identities alongside a caller-provided ed25519 certificate scheme wrapper.
pub fn fixture<S, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(commonware_utils::ordered::Set<PublicKey>, PrivateKey) -> Option<S>,
    verifier: impl Fn(commonware_utils::ordered::Set<PublicKey>) -> S,
) -> Fixture<S>
where
    R: RngCore + CryptoRng,
    S: Scheme<PublicKey = PublicKey>,
{
    assert!(n > 0);

    let associated = participants(rng, n);
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

    let schemes = private_keys
        .iter()
        .cloned()
        .map(|sk| signer(participants.clone(), sk).expect("scheme signer must be a participant"))
        .collect();
    let verifier = verifier(participants);

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
