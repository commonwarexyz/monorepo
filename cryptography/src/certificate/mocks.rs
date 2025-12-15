//! Test fixtures for certificate signing schemes.

use crate::{
    bls12381::{
        dkg::deal,
        primitives::{group, ops::compute_public, sharing::Sharing, variant::Variant},
    },
    certificate::{Provider, Scheme},
    ed25519, Signer as _,
};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::BiMap, TryCollect as _};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// A deterministic test fixture containing identities, identity private keys, per-participant
/// signing schemes, and a single verifier scheme.
#[derive(Clone, Debug)]
pub struct Fixture<S> {
    /// A sorted vector of participant public identity keys.
    pub participants: Vec<ed25519::PublicKey>,
    /// A sorted vector of participant private identity keys (matching order with `participants`).
    pub private_keys: Vec<ed25519::PrivateKey>,
    /// A vector of per-participant scheme instances (matching order with `participants`).
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

/// Generates ed25519 identity participants.
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

/// Builds ed25519 identities alongside a caller-provided ed25519 certificate scheme wrapper.
pub fn ed25519<S, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(
        commonware_utils::ordered::Set<ed25519::PublicKey>,
        ed25519::PrivateKey,
    ) -> Option<S>,
    verifier: impl Fn(commonware_utils::ordered::Set<ed25519::PublicKey>) -> S,
) -> Fixture<S>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let associated = ed25519_participants(rng, n);
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

/// Builds ed25519 identities and matching BLS12-381 multisig schemes.
pub fn bls12381_multisig<S, V, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(BiMap<ed25519::PublicKey, V::Public>, group::Private) -> Option<S>,
    verifier: impl Fn(BiMap<ed25519::PublicKey, V::Public>) -> S,
) -> Fixture<S>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let associated = ed25519_participants(rng, n);
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

    let bls_privates: Vec<_> = (0..n).map(|_| group::Private::random(&mut *rng)).collect();
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

/// Builds ed25519 identities and matching BLS12-381 threshold schemes.
pub fn bls12381_threshold<S, V, R>(
    rng: &mut R,
    n: u32,
    signer: impl Fn(
        commonware_utils::ordered::Set<ed25519::PublicKey>,
        Sharing<V>,
        group::Share,
    ) -> Option<S>,
    verifier: impl Fn(commonware_utils::ordered::Set<ed25519::PublicKey>, Sharing<V>) -> S,
) -> Fixture<S>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let associated = ed25519_participants(rng, n);
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

/// A scheme provider that always returns the same scheme regardless of epoch.
///
/// Useful for unit tests that don't need to test epoch transitions.
#[derive(Clone, Debug)]
pub struct ConstantProvider<S: Scheme> {
    scheme: Arc<S>,
}

impl<S: Scheme> ConstantProvider<S> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
        }
    }
}

impl<S: Scheme, E> Provider<E> for ConstantProvider<S> {
    type Scheme = S;

    fn scheme(&self, _epoch: E) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }

    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}

/// A provider that allows dynamically setting the returned scheme.
///
/// Useful for tests that need to modify the scheme during execution (e.g., to simulate
/// epoch transitions or scheme failures).
#[derive(Clone, Debug)]
pub struct MockProvider<S: Scheme> {
    scheme: Arc<std::sync::RwLock<Option<Arc<S>>>>,
}

impl<S: Scheme> Default for MockProvider<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scheme> MockProvider<S> {
    /// Creates a new mock provider with no scheme set.
    pub fn new() -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Creates a new mock provider with the given scheme.
    pub fn with_scheme(scheme: S) -> Self {
        Self {
            scheme: Arc::new(std::sync::RwLock::new(Some(Arc::new(scheme)))),
        }
    }

    /// Sets the scheme to return.
    pub fn set(&self, scheme: Option<S>) {
        *self.scheme.write().unwrap() = scheme.map(Arc::new);
    }
}

impl<S: Scheme, E> Provider<E> for MockProvider<S> {
    type Scheme = S;

    fn scheme(&self, _epoch: E) -> Option<Arc<S>> {
        self.scheme.read().unwrap().clone()
    }
}
