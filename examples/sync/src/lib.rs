//! Synchronize state between a server and client.
//!
//! This library how to use [sync](commonware_storage::adb::any::sync) to synchronize a client's
//! [Any](commonware_storage::adb::any::Any) database to a server's database.
//!
//! It includes network protocols, database configuration, and utilities for creating test data.
//!
//! The sync example showcases how to:
//! - Create and configure an [Any](commonware_storage::adb::any::Any) database
//! - Implement a network-based [Resolver](commonware_storage::adb::sync::resolver::Resolver) for fetching operations
//! - Use [sync](commonware_storage::adb::any::sync) to synchronize the client's database state with the server's state

pub mod error;
pub use error::Error;
pub mod databases;
pub mod net;

pub use databases::{any, immutable};

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Hasher type used in the database.
pub type Hasher = commonware_cryptography::sha256::Sha256;

/// Digest type used in the database.
pub type Digest = commonware_cryptography::sha256::Digest;

/// Key type used in the database.
pub type Key = commonware_cryptography::sha256::Digest;

/// Value type used in the database.
pub type Value = commonware_cryptography::sha256::Digest;

/// Translator type for the database.
pub type Translator = commonware_storage::translator::EightCap;
