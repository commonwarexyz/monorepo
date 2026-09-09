//! Test fixtures for BLS12-381 threshold certificate schemes.

use crate::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{
            group::Share,
            sharing::{Mode, Sharing},
            variant::Variant,
        },
    },
    certificate::{Scheme, mocks::Fixture},
    ed25519,
};
use commonware_utils::{Faults, ordered::Committee};
use rand_core::CryptoRng;

/// Builds ed25519 identities and matching BLS12-381 threshold schemes.
pub fn fixture<S, V, R, M>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
    signer: impl Fn(&[u8], Committee<ed25519::PublicKey>, Sharing<V>, Share) -> Option<S>,
    verifier: impl Fn(&[u8], Committee<ed25519::PublicKey>, Sharing<V>) -> Option<S>,
) -> Fixture<S>
where
    V: Variant,
    R: CryptoRng,
    M: Faults,
    S: Scheme<Faults = M, PublicKey = ed25519::PublicKey>,
{
    assert!(n > 0);

    let associated = ed25519::certificate::mocks::participants(rng, n);
    let participant_set = associated.keys().clone();
    let participants_vec: Vec<_> = participant_set.clone().into();
    let participants = Committee::try_from(
        participants_vec
            .iter()
            .cloned()
            .map(|participant| (participant, 1))
            .collect::<Vec<_>>(),
    )
    .expect("participants are unique and non-empty");
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
        deal::<V, _, M>(rng, Mode::NonZeroCounter, participant_set).expect("deal should succeed");
    let polynomial = output.public().clone();

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            signer(namespace, participants.clone(), polynomial.clone(), share)
                .expect("scheme signer must be a participant")
        })
        .collect();
    let verifier = verifier(namespace, participants, polynomial)
        .expect("uniform committee must produce a verifier");

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
}
