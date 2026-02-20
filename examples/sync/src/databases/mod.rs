//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::Encode;
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{self, operation::Operation},
};
use std::{future::Future, num::NonZeroU64};

pub mod any;
pub mod current;
pub mod immutable;

/// Database type to sync.
#[derive(Debug, Clone, Copy)]
pub enum DatabaseType {
    Any,
    Current,
    Immutable,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "current" => Ok(Self::Current),
            "immutable" => Ok(Self::Immutable),
            _ => Err(format!(
                "Invalid database type: '{s}'. Must be 'any', 'current', or 'immutable'",
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
        }
    }
}

/// Helper trait for databases that can be synced.
pub trait Syncable: Sized {
    /// The type of operations in the database.
    type Operation: Operation + Encode + Sync + 'static;

    /// Create test operations with the given count and seed.
    /// The returned operations must end with a commit operation.
    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation>;

    /// Add operations to the database and return the clean database, ignoring any input that
    /// doesn't end with a commit operation (since without a commit, we can't return a clean DB).
    fn add_operations(
        self,
        operations: Vec<Self::Operation>,
    ) -> impl Future<Output = Result<Self, qmdb::Error>>;

    /// Get the database's root digest.
    fn root(&self) -> Key;

    /// Get the total number of operations in the database (including pruned operations).
    fn size(&self) -> impl Future<Output = Location> + Send;

    /// Get the inactivity floor, the location below which all operations are inactive.
    fn inactivity_floor(&self) -> impl Future<Output = Location> + Send;

    /// Get historical proof and operations.
    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error>> + Send;

    /// Get the database type name for logging.
    fn name() -> &'static str;
}
