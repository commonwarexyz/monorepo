//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `ordered_broadcast`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! used by an external observer as evidence of either liveness or of committing a fault.

use crate::{ordered_broadcast::types::AckContext, signing_scheme::impl_bls12381_multisig_scheme};

impl_bls12381_multisig_scheme!(AckContext<'a, P, D>);
