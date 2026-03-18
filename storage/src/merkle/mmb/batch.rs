//! MMB-specific batch layer built on the shared [`merkle::batch`](crate::merkle::batch)
//! infrastructure.
//!
//! Provides type aliases that fix the family parameter to [`Family`]. All mutation,
//! merkleization, and proof methods are inherited from the shared [`crate::merkle::batch`] module.

use crate::merkle::{batch, mmb::Family, Proof};

/// MMB-specific type alias for `merkle::proof::Proof`.
pub type MmbProof<D> = Proof<Family, D>;

pub use batch::BatchChainInfo;

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = batch::UnmerkleizedBatch<'a, Family, D, P>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, D, P> = batch::MerkleizedBatch<'a, Family, D, P>;

/// Owned set of changes against a base MMB.
pub type Changeset<D> = batch::Changeset<Family, D>;
