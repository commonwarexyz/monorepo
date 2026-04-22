//! MMB-specific batch layer built on the shared [`merkle::batch`](crate::merkle::batch)
//! infrastructure.
//!
//! Provides type aliases that fix the family parameter to [`Family`]. All mutation,
//! merkleization, and proof methods are inherited from the shared [`crate::merkle::batch`] module.

use crate::merkle::{batch, mmb::Family};

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<D> = batch::UnmerkleizedBatch<Family, D>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<D> = batch::MerkleizedBatch<Family, D>;
