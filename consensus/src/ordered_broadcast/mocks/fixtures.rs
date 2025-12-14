//! Deterministic test fixtures for `ordered_broadcast` signing scheme.

use crate::{
    ordered_broadcast::scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme},
    scheme::SchemeProvider,
    types::Epoch,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant,
    certificate::{mocks as certificate_mocks, Scheme},
    ed25519,
};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

pub use certificate_mocks::{ed25519_participants, Fixture};

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn ed25519<R>(rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    certificate_mocks::ed25519(
        rng,
        n,
        ed_scheme::Scheme::signer,
        ed_scheme::Scheme::verifier,
    )
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
    certificate_mocks::bls12381_multisig::<_, V, _>(
        rng,
        n,
        bls12381_multisig::Scheme::signer,
        bls12381_multisig::Scheme::verifier,
    )
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
    certificate_mocks::bls12381_threshold::<_, V, _>(
        rng,
        n,
        bls12381_threshold::Scheme::signer,
        bls12381_threshold::Scheme::verifier,
    )
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
