//! Signing scheme implementations for `ordered_broadcast`.
//!
//! This module provides protocol-specific wrappers around the generic signing schemes
//! in [`crate::scheme`]. Each wrapper binds the scheme's context type to
//! [`AckContext`], which is used for signing and verifying chunk acknowledgments.
//!
//! # Available Schemes
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification.
//!   Compact certificates while preserving attribution.
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Constant-size
//!   certificates regardless of committee size.

use super::types::AckContext;
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

/// Marker trait for signing schemes compatible with `ordered_broadcast`.
///
/// This trait binds a [`Scheme`] to the [`AckContext`] context type used by the
/// ordered broadcast protocol. It is automatically implemented for any scheme
/// whose context type matches `AckContext<'a, P, D>`.
pub trait OrderedBroadcastScheme<P: PublicKey, D: Digest>:
    for<'a> Scheme<Context<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}

impl<P: PublicKey, D: Digest, S> OrderedBroadcastScheme<P, D> for S where
    S: for<'a> Scheme<Context<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}
