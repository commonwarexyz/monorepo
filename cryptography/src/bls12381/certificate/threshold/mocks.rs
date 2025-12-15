//! Test fixtures for BLS12-381 threshold certificate schemes.

use crate::{
    bls12381::{
        dkg::deal,
        primitives::{sharing::Sharing, variant::Variant},
    },
    certificate::{mocks::Fixture, Scheme},
    ed25519,
};
use commonware_utils::ordered::Set;
use rand::{CryptoRng, RngCore};

/// Builds ed25519 identities and matching BLS12-381 threshold schemes.
pub fn fixture<S, V, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(
        Set<ed25519::PublicKey>,
        Sharing<V>,
        crate::bls12381::primitives::group::Share,
    ) -> Option<S>,
    verifier: impl Fn(Set<ed25519::PublicKey>, Sharing<V>) -> S,
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

    let (output, shares) =
        deal::<V, _>(rng, Default::default(), participants.clone()).expect("deal should succeed");
    let polynomial = output.public().clone();

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            signer(participants.clone(), polynomial.clone(), share)
                .expect("scheme signer must be a participant")
        })
        .collect();
    let verifier = verifier(participants, polynomial);

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
