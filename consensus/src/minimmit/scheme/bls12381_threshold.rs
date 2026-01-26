//! BLS12-381 threshold signature implementation of the [`Scheme`] trait for `minimmit`.
//!
//! [`Scheme`] is **non-attributable**: individual partial signatures cannot be safely
//! presented to some third party as evidence of either liveness or of committing a fault.
//! Possession of any `t` valid partial signatures can be used to forge a partial signature
//! for any other player.
//!
//! This scheme produces constant-size threshold signatures regardless of the number of signers,
//! making certificates extremely compact. However, it requires a Distributed Key Generation (DKG)
//! ceremony for setup.
//!
//! # Embedded VRF
//!
//! The threshold signature naturally provides verifiable randomness that can be used for
//! bias-resistant leader election. The seed can be extracted from notarization certificates
//! using the [`Seedable`] trait.

// Re-export the core types from the simplex implementation since the cryptographic
// primitives are identical. Only the Subject type (which has no Finalize variant) differs.
use crate::minimmit::types::Notarization;
#[cfg(feature = "mocks")]
pub use crate::simplex::scheme::bls12381_threshold::vrf::fixture;
pub use crate::simplex::scheme::bls12381_threshold::vrf::{
    decrypt, encrypt, Certificate, Scheme, Seed, Seedable, Signature,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest, PublicKey};

// Implement Seedable for minimmit's Notarization type
impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Notarization<Scheme<P, V>, D> {
    fn seed(&self) -> Seed<V> {
        let cert = self
            .certificate
            .get()
            .expect("verified certificate must decode");
        Seed::new(self.proposal.round, cert.seed_signature)
    }
}
