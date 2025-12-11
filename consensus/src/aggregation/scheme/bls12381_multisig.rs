//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `aggregation`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! used by an external observer as evidence of either liveness or of committing a fault.

use crate::{aggregation::types::Item, scheme::impl_bls12381_multisig_scheme};

impl_bls12381_multisig_scheme!(&'a Item<D>);
