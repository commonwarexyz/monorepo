//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::{Encode, Read};
use commonware_storage::{
    adb,
    mmr::{hasher::Standard, verification::Proof},
};
use std::future::Future;

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
    /// The type of data in the database.
    type Data: Clone + Read<Cfg = ()> + Encode + Send + Sync + 'static;

    /// Create test data with the given count and seed.
    fn create_test_data(count: usize, seed: u64) -> Vec<Self::Data>;

    /// Add data to the database.
    fn add_data(
        database: &mut Self,
        data: Vec<Self::Data>,
    ) -> impl Future<Output = Result<(), adb::Error>>;

    /// Commit pending data to the database.
    fn commit(&mut self) -> impl Future<Output = Result<(), adb::Error>>;

    /// Get the database's root digest.
    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key;

    /// Get the number of items in the database.
    fn size(&self) -> u64;

    /// Get the lower bound for data (inactivity floor or oldest retained location).
    fn lower_bound(&self) -> u64;

    /// Get historical proof and data.
    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_data: u64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Data>), adb::Error>> + Send;

    /// Get the database type name for logging.
    fn name() -> &'static str;
}
