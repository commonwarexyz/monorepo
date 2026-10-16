//! Deterministic key material and epoch configuration for test committees.
//!
//! Everything derives from a seed with no attempt to protect key material.

use crate::{
    multimmit::{
        config::{Parameters, Protocol},
        scheme::bls12381::{Roster, Scheme},
        types::{EpochGenesis, Window},
    },
    types::Epoch,
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::{group::Private, ops, variant::Variant},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{Participant, TestRng, ordered::Set};
use std::sync::Arc;

/// Deterministic key material for one committee.
pub struct Keys<V: Variant> {
    /// The proof-of-possession checked ordinary-key roster.
    pub roster: Roster<ed25519::PublicKey, V>,
    /// Each participant's ordinary private key, in participant order.
    pub privates: Vec<Private>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<ed25519::PublicKey, V>>,
    /// A keyless verification scheme for observers.
    pub verifier: Scheme<ed25519::PublicKey, V>,
}

/// Returns a digest of `label` and `marker`.
pub fn digest(label: &[u8], marker: u64) -> Sha256Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

/// Builds the configuration of epoch `seed` with one producer chain per entry of `producers`.
pub fn test_config(
    seed: u64,
    namespace: &[u8],
    participants: u32,
    producers: Vec<Participant>,
    window: Window,
) -> Protocol<Sha256Digest> {
    let genesis = EpochGenesis::new::<Sha256>(Epoch::new(seed), producers.len())
        .expect("mock committees have at least one chain");
    Protocol::new(namespace, participants as usize, producers, window, genesis)
        .expect("mock configuration is valid")
}

/// Generates one ordinary key per identity of `identities`, in order, and the schemes using them.
pub fn keys<V: Variant>(
    rng: &mut TestRng,
    parameters: &Arc<Parameters>,
    identities: &Set<ed25519::PublicKey>,
) -> Keys<V> {
    let (privates, manifest): (Vec<_>, Vec<_>) = identities
        .iter()
        .map(|identity| {
            let (private, public) = ops::keypair::<_, V>(&mut *rng);
            let proof = Roster::<ed25519::PublicKey, V>::proof_of_possession(
                parameters.namespace(),
                &private,
            );
            (private, (identity.clone(), public, proof))
        })
        .unzip();
    let roster = Roster::verify(
        parameters.namespace(),
        identities.len(),
        manifest,
        &Sequential,
    )
    .expect("generated keys carry valid proofs");
    let signers = privates
        .iter()
        .map(|private| {
            Scheme::signer(parameters, roster.clone(), private.clone())
                .expect("generated key is in the roster")
        })
        .collect();
    let verifier =
        Scheme::verifier(parameters, roster.clone()).expect("roster matches the committee");
    Keys {
        roster,
        privates,
        signers,
        verifier,
    }
}
