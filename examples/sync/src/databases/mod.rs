//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::Encode;
use commonware_storage::{
    merkle::{self, Location, Proof},
    qmdb,
};
use std::{future::Future, num::NonZeroU64};

pub mod any;
pub mod current;
pub mod immutable;
pub mod keyless;

/// Database type to sync.
#[derive(Debug, Clone, Copy)]
pub enum DatabaseType {
    Any,
    Current,
    Immutable,
    Keyless,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "current" => Ok(Self::Current),
            "immutable" => Ok(Self::Immutable),
            "keyless" => Ok(Self::Keyless),
            _ => Err(format!(
                "Invalid database type: '{s}'. Must be 'any', 'current', 'immutable', or 'keyless'",
            )),
        }
    }
}

impl DatabaseType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Current => "current",
            Self::Immutable => "immutable",
            Self::Keyless => "keyless",
        }
    }
}

/// Helper trait for databases that can be synced.
#[allow(clippy::type_complexity)]
pub trait Syncable: Sized {
    /// The merkle family used by this database.
    type Family: merkle::Family;

    /// The type of operations in the database.
    type Operation: Encode + Sync + 'static;

    /// Create test operations with the given count and seed.
    /// The returned operations must end with a commit operation.
    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation>;

    /// Add operations to the database, ignoring any input that doesn't end with a commit
    /// operation.
    fn add_operations(
        &mut self,
        operations: Vec<Self::Operation>,
    ) -> impl Future<Output = Result<(), qmdb::Error<Self::Family>>>;

    /// Get the database's root digest.
    fn root(&self) -> Key;

    /// Get the total number of operations in the database (including pruned operations).
    fn size(&self) -> impl Future<Output = Location<Self::Family>> + Send;

    /// Get the inactivity floor, the location below which all operations are inactive.
    fn inactivity_floor(&self) -> impl Future<Output = Location<Self::Family>> + Send;

    /// Get historical proof and operations.
    fn historical_proof(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
    ) -> impl Future<
        Output = Result<
            (Proof<Self::Family, Key>, Vec<Self::Operation>),
            qmdb::Error<Self::Family>,
        >,
    > + Send;

    /// Get the pinned nodes for a lower operation boundary of `loc`.
    fn pinned_nodes_at(
        &self,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Vec<Key>, qmdb::Error<Self::Family>>> + Send;

    /// Get the database type name for logging.
    fn name() -> &'static str;
}
