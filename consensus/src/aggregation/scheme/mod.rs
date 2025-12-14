//! Signing scheme implementations for `aggregation`.
//!
//! This module provides protocol-specific wrappers around the generic signing schemes
//! in [`crate::scheme`]. Each wrapper binds the scheme's context type to
//! [`Item`], which represents the data being aggregated and signed.
//!
//! # Available Schemes
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification.
//!   Compact certificates while preserving attribution.
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Constant-size
//!   certificates regardless of committee size.

use super::types::Item;
use commonware_cryptography::{certificate::Scheme, Digest};

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

/// Marker trait for signing schemes compatible with `aggregation`.
///
/// This trait binds a [`Scheme`] to the [`Item`] context type used by the
/// aggregation protocol. It is automatically implemented for any scheme
/// whose context type matches `&'a Item<D>`.
pub trait AggregationScheme<D: Digest>: for<'a> Scheme<Context<'a, D> = &'a Item<D>> {}

impl<D: Digest, S> AggregationScheme<D> for S where S: for<'a> Scheme<Context<'a, D> = &'a Item<D>> {}
