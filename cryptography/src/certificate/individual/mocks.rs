//! Test fixtures for individually verified certificate schemes.

use crate::{
    Signer,
    certificate::{Scheme, mocks::Fixture},
    ed25519,
};
use commonware_utils::{TryCollect as _, ordered::BiMap};
use rand_core::CryptoRng;

/// Builds ed25519 identities and matching signing schemes that sign with randomly generated
/// `K` keys.
pub fn fixture<S, K, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
    signer: impl Fn(&[u8], BiMap<ed25519::PublicKey, K::PublicKey>, K) -> Option<S>,
    verifier: impl Fn(&[u8], BiMap<ed25519::PublicKey, K::PublicKey>) -> S,
) -> Fixture<S>
where
    R: CryptoRng,
    K: Signer,
    S: Scheme<PublicKey = ed25519::PublicKey>,
{
    assert!(n > 0);

    let associated = ed25519::certificate::mocks::participants(rng, n);
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

    let signing_privates: Vec<_> = (0..n).map(|_| K::random(&mut *rng)).collect();
    let signing_publics: Vec<_> = signing_privates.iter().map(|sk| sk.public_key()).collect();

    let signers: BiMap<_, _> = participants
        .into_iter()
        .zip(signing_publics)
        .try_collect()
        .expect("ed25519 public keys are unique");

    let schemes = signing_privates
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
