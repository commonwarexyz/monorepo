//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::{Encode, Read};
use commonware_storage::{
    adb,
    mmr::{Proof, StandardHasher as Standard},
};
use std::{future::Future, num::NonZeroU64};

pub mod fixed;
pub mod immutable;
pub mod variable;

/// Database type to sync.
#[derive(Debug, Clone, Copy)]
pub enum DatabaseType {
    Fixed,
    Variable,
    Immutable,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any::fixed" => Ok(DatabaseType::Fixed),
            "any::variable" => Ok(DatabaseType::Variable),
            "immutable" => Ok(DatabaseType::Immutable),
            _ => Err(format!(
                "Invalid database type: '{s}'. Must be 'any::fixed', 'any::variable', or 'immutable'",
            )),
        }
    }
}

impl DatabaseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseType::Fixed => "any::fixed",
            DatabaseType::Variable => "any::variable",
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
    fn op_count(&self) -> u64;

    /// Get the lower bound for operations (inactivity floor or oldest retained location).
    fn lower_bound_ops(&self) -> u64;

    /// Get historical proof and operations.
    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send;

    /// Get the database type name for logging.
    fn name() -> &'static str;
}
