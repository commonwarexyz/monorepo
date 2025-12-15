//! Deterministic test fixtures for `aggregation` signing schemes.

use crate::aggregation::scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme};
pub use certificate_mocks::{ed25519_participants, Fixture};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::mocks as certificate_mocks, ed25519,
};
use rand::{CryptoRng, RngCore};

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
