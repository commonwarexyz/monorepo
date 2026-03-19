//! Synchronize state between a server and client.
//!
//! This example shows how to synchronize a client database to a remote server's database
//! using [commonware_storage::qmdb::any], [commonware_storage::qmdb::current], or
//! [commonware_storage::qmdb::immutable].
//!
//! It includes network protocols, database configuration, and utilities for creating test data.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod error;
pub use error::Error;
pub mod databases;
pub mod net;
pub use databases::{any, current, immutable};

/// Returns the version of the crate.
pub const fn crate_version() -> &'static str {
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
