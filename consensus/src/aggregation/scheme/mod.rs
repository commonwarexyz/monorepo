//! Signing schemes for aggregation.

use super::types::Item;
use crate::scheme::Scheme;
use commonware_cryptography::Digest;

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

pub trait AggregationScheme<D: Digest>: for<'a> Scheme<Context<'a, D> = &'a Item<D>> {}

impl<D: Digest, S> AggregationScheme<D> for S where S: for<'a> Scheme<Context<'a, D> = &'a Item<D>> {}
