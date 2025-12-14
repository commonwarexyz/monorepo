//! Re-export of cryptographic certificate schemes and consensus-specific providers.
//!
//! This module re-exports types from [`commonware_cryptography::certificate`] and adds
//! consensus-specific traits like [`SchemeProvider`] that depend on consensus types.

use crate::types::Epoch;
pub use commonware_cryptography::{
    certificate::{
        bls12381_multisig, bls12381_threshold, ed25519, utils, Context, Scheme, Signature,
        SignatureVerification,
    },
    impl_bls12381_multisig_certificate as impl_bls12381_multisig_scheme,
    impl_bls12381_threshold_certificate as impl_bls12381_threshold_scheme,
    impl_ed25519_certificate as impl_ed25519_scheme,
};
use std::sync::Arc;

/// Supplies the signing scheme the marshal should use for a given epoch.
pub trait SchemeProvider: Clone + Send + Sync + 'static {
    /// The signing scheme to provide.
    type Scheme: Scheme;

    /// Return the signing scheme that corresponds to `epoch`.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>>;

    /// Return a certificate verifier that can validate certificates independent of epoch.
    ///
    /// This method allows implementations to provide a verifier that can validate
    /// certificates from any epoch (without epoch-specific state). For example,
    /// `bls12381_threshold::Scheme` maintains
    /// a static public key across epochs that can be used to verify certificates from any
    /// epoch, even after the committee has rotated and the underlying secret shares have
    /// been refreshed.
    ///
    /// The default implementation returns `None`. Callers should fall back to
    /// [`SchemeProvider::scheme`] for epoch-specific verification.
    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        None
    }
}
