//! Test fixtures for Secp256r1 certificate signing schemes.

use crate::{
    Signer as _,
    certificate::{Scheme, mocks::Fixture},
    ed25519,
    secp256r1::standard::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random;
use commonware_utils::{
    TryCollect as _,
    ordered::{BiMap, Committee},
};
use rand_core::CryptoRng;

/// Builds ed25519 identities and matching Secp256r1 signing schemes.
pub fn fixture<S, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
    signer: impl Fn(
        &[u8],
        Committee<ed25519::PublicKey>,
        BiMap<ed25519::PublicKey, PublicKey>,
        PrivateKey,
    ) -> Option<S>,
    verifier: impl Fn(
        &[u8],
        Committee<ed25519::PublicKey>,
        BiMap<ed25519::PublicKey, PublicKey>,
    ) -> Option<S>,
) -> Fixture<S>
where
    R: CryptoRng,
    S: Scheme<PublicKey = ed25519::PublicKey>,
{
    assert!(n > 0);

    let associated = crate::ed25519::certificate::mocks::participants(rng, n);
    let participants = associated.keys().clone();
    let committee: Committee<_> = participants
        .iter()
        .cloned()
        .map(|participant| (participant, 1))
        .try_collect()
        .expect("fixture committee is non-empty");
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
            signer(namespace, committee.clone(), signers.clone(), sk)
                .expect("scheme signer must be a participant")
        })
        .collect();
    let verifier = verifier(namespace, committee, signers)
        .expect("signing keys must match the fixture committee");

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
