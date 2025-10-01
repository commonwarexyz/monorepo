//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::{Encode, Read};
use commonware_storage::{
    adb,
    mmr::{Location, Proof, StandardHasher as Standard},
};
use std::{future::Future, num::NonZeroU64};

pub mod any;
pub mod immutable;

/// Database type to sync.
#[derive(Debug, Clone, Copy)]
pub enum DatabaseType {
    Any,
    Immutable,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(DatabaseType::Any),
            "immutable" => Ok(DatabaseType::Immutable),
            _ => Err(format!(
                "Invalid database type: '{s}'. Must be 'any' or 'immutable'",
            )),
        }
    }
}

impl DatabaseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseType::Any => "any",
            DatabaseType::Immutable => "immutable",
        }
    }
}

/// Helper trait for databases that can be synced.
pub trait Syncable {
    /// The type of operations in the database.
    type Operation: Clone + Read<Cfg = ()> + Encode + Send + Sync + 'static;

    /// Create test operations with the given count and seed.
    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation>;

    /// Add operations to the database.
    fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> impl Future<Output = Result<(), adb::Error>>;

    /// Commit pending operations to the database.
    fn commit(&mut self) -> impl Future<Output = Result<(), adb::Error>>;

    /// Get the database's root digest.
    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key;

    /// Get the operation count of the database.
    fn op_count(&self) -> Location;

    /// Get the lower bound for operations (inactivity floor or oldest retained location).
    fn lower_bound(&self) -> Location;

    /// Get historical proof and operations.
    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send;

    /// Get the database type name for logging.
    fn name() -> &'static str;
}
