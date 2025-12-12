//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `ordered_broadcast`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be
//! used by an external observer as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside an aggregated signature,
//! enabling secure per-validator activity tracking and conflict detection.

use crate::{ordered_broadcast::types::AckContext, scheme::impl_bls12381_multisig_scheme};

impl_bls12381_multisig_scheme!(AckContext<'a, P, D>);
