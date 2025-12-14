//! Deterministic test fixtures for `ordered_broadcast` signing scheme.

use crate::{
    ordered_broadcast::scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme},
    scheme::SchemeProvider,
    types::Epoch,
};
use commonware_cryptography::{
    bls12381::{
        dkg::deal,
        primitives::{group, variant::Variant},
    },
    certificate::Scheme,
    ed25519, Signer,
};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::BiMap, TryCollect};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// A test fixture consisting of ed25519 keys and signing schemes for each validator, and a single
/// scheme verifier.
pub struct Fixture<S> {
    /// A sorted vector of participant public keys.
    pub participants: Vec<ed25519::PublicKey>,
    /// A sorted vector of participant private keys (matching order with participants).
    pub private_keys: Vec<ed25519::PrivateKey>,
    /// A vector of signing schemes for each participant.
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

/// Generates ed25519 participants.
pub fn ed25519_participants<R>(
    rng: &mut R,
    n: u32,
) -> BiMap<ed25519::PublicKey, ed25519::PrivateKey>
where
    R: RngCore + CryptoRng,
{
    (0..n)
        .map(|_| {
            let private_key = ed25519::PrivateKey::random(&mut *rng);
            let public_key = private_key.public_key();
            (public_key, private_key)
        })
        .try_collect()
        .expect("ed25519 public keys are unique")
}

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn ed25519<R>(rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let ed25519_associated = ed25519_participants(rng, n);
    let participants = ed25519_associated.keys().clone();
    let (private_keys, schemes): (Vec<_>, Vec<_>) = ed25519_associated
        .into_iter()
        .map(|(_, sk)| {
            (
                sk.clone(),
                ed_scheme::Scheme::signer(participants.clone(), sk).unwrap(),
            )
        })
        .unzip();
    let verifier = ed_scheme::Scheme::verifier(participants.clone());

    Fixture {
        participants: participants.into(),
        schemes,
        private_keys,
        verifier,
    }
}

/// Builds ed25519 identities and matching BLS multisig schemes for tests.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn bls12381_multisig<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_multisig::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let ed25519_associated = ed25519_participants(rng, n);
    let participants = ed25519_associated.keys().clone();
    // Collect into vec to extract private keys
    let associated_vec: Vec<_> = ed25519_associated.into_iter().collect();
    let private_keys: Vec<_> = associated_vec.iter().map(|(_, sk)| sk.clone()).collect();
    let bls_privates: Vec<_> = (0..n).map(|_| group::Private::random(&mut *rng)).collect();
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
        .collect();

    let signers: BiMap<_, _> = participants
        .clone()
        .into_iter()
        .zip(bls_public)
        .try_collect()
        .expect("ed25519 public keys are unique");
    let schemes: Vec<_> = bls_privates
        .into_iter()
        .map(|sk| bls12381_multisig::Scheme::signer(signers.clone(), sk).unwrap())
        .collect();
    let verifier = bls12381_multisig::Scheme::verifier(signers);

    Fixture {
        participants: participants.into(),
        schemes,
        private_keys,
        verifier,
    }
}

/// Builds ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn bls12381_threshold<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_threshold::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let ed25519_associated = ed25519_participants(rng, n);
    let participants = ed25519_associated.keys().clone();
    // Collect into vec to extract private keys
    let associated_vec: Vec<_> = ed25519_associated.into_iter().collect();
    let private_keys: Vec<_> = associated_vec.iter().map(|(_, sk)| sk.clone()).collect();
    let (output, shares) =
        deal::<V, _>(rng, Default::default(), participants.clone()).expect("deal should succeed");

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            bls12381_threshold::Scheme::signer(participants.clone(), output.public().clone(), share)
                .unwrap()
        })
        .collect();
    let verifier =
        bls12381_threshold::Scheme::verifier(participants.clone(), output.public().clone());

    Fixture {
        participants: participants.into(),
        schemes,
        private_keys,
        verifier,
    }
}

/// A simple scheme provider that always returns the same scheme regardless of epoch.
///
/// Useful for unit tests that don't need to test epoch transitions.
#[derive(Clone)]
pub struct SingleSchemeProvider<S: Scheme> {
    scheme: Arc<S>,
}

impl<S: Scheme> SingleSchemeProvider<S> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
        }
    }
}

impl<S: Scheme> SchemeProvider for SingleSchemeProvider<S> {
    type Scheme = S;

    fn scheme(&self, _epoch: Epoch) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }
}
