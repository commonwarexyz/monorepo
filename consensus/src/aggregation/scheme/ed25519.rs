//! Ed25519 implementation of the [`Scheme`] trait for `aggregation`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault.

use crate::{aggregation::types::Item, scheme::impl_ed25519_scheme};

impl_ed25519_scheme!(&'a Item<D>);
