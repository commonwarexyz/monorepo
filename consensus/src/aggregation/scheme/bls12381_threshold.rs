//! BLS12-381 threshold signature scheme for aggregation.

use crate::{aggregation::types::Item, scheme::impl_bls12381_threshold_scheme};

impl_bls12381_threshold_scheme!(&'a Item<D>);
