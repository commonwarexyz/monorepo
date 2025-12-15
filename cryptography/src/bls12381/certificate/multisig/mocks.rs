//! Test fixtures for BLS12-381 multi-signature certificate schemes.

use crate::{
    bls12381::primitives::{group::Private, ops::compute_public, variant::Variant},
    certificate::{mocks::Fixture, Scheme},
    ed25519,
};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::BiMap, TryCollect as _};
use rand::{CryptoRng, RngCore};

/// Builds ed25519 identities and matching BLS12-381 multisig schemes.
pub fn fixture<S, V, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(BiMap<ed25519::PublicKey, V::Public>, Private) -> Option<S>,
    verifier: impl Fn(BiMap<ed25519::PublicKey, V::Public>) -> S,
) -> Fixture<S>
where
    V: Variant,
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

    let bls_privates: Vec<_> = (0..n).map(|_| Private::random(&mut *rng)).collect();
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| compute_public::<V>(sk))
        .collect();

    let signers: BiMap<_, _> = participants
        .into_iter()
        .zip(bls_public)
        .try_collect()
        .expect("ed25519 public keys are unique");

    let schemes = bls_privates
        .into_iter()
        .map(|sk| signer(signers.clone(), sk).expect("scheme signer must be a participant"))
        .collect();
    let verifier = verifier(signers);

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
