//! Shared compact QMDB helpers.

pub(crate) mod batch;
pub(crate) mod db;
mod sync;
mod variant;
pub(crate) mod witness;

use crate::journal::contiguous::variable;
use commonware_parallel::Strategy;
pub use db::{Db, MerkleizedBatch, UnmerkleizedBatch, initial_root};
pub use variant::Variant;
pub(in crate::qmdb) use variant::sealed;

/// Configuration for a compact authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: variable::Config<C>,
}
