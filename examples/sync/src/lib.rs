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

pub use databases::any;
pub use databases::immutable;

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
