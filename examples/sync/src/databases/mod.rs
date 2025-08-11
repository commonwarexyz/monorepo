//! Database-specific modules for the sync example.

use std::future::Future;

use commonware_storage::{
    adb,
    mmr::{hasher::Standard, verification::Proof},
};

use crate::Key;

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
                "Invalid database type: '{}'. Must be 'any' or 'immutable'",
                s
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
    type Operation: Clone
        + commonware_codec::Read<Cfg = ()>
        + commonware_codec::Encode
        + Send
        + Sync
        + 'static;

    /// Create test operations with the given count and seed.
    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation>;

    /// Add operations to the database.
    fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> impl Future<Output = Result<(), commonware_storage::adb::Error>>;

    /// Commit pending operations to the database.
    fn commit(&mut self) -> impl Future<Output = Result<(), commonware_storage::adb::Error>>;

    /// Get the root hash of the database.
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
        max_ops: u64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send;

    /// Get the database type name for logging.
    fn database_name() -> &'static str;
}
