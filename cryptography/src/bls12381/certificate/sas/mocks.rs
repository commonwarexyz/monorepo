//! Test fixtures for BLS12-381 synchronized aggregate certificate schemes.

use crate::{
    bls12381::primitives::{ops::sas, variant::Variant},
    certificate::{Scheme, mocks::Fixture},
    ed25519,
};
use commonware_utils::{TryCollect as _, ordered::BiMap};
use rand_core::CryptoRng;

/// Builds ed25519 identities and matching BLS12-381 synchronized aggregate schemes.
pub fn fixture<S, V, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
    signer: impl Fn(&[u8], BiMap<ed25519::PublicKey, sas::PublicKey<V>>, sas::PrivateKey) -> Option<S>,
    verifier: impl Fn(&[u8], BiMap<ed25519::PublicKey, sas::PublicKey<V>>) -> S,
) -> Fixture<S>
where
    V: Variant,
    R: CryptoRng,
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

    let keys: Vec<_> = (0..n).map(|_| sas::keypair::<_, V>(&mut *rng)).collect();
    let signers: BiMap<_, _> = participants
        .into_iter()
        .zip(keys.iter().map(|(_, public)| *public))
        .try_collect()
        .expect("ed25519 public keys are unique");

    let schemes = keys
        .into_iter()
        .map(|(private, _)| {
            signer(namespace, signers.clone(), private)
                .expect("scheme signer must be a participant")
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
