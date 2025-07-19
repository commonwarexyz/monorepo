//! A simple append-only key-value store backed by a log of state-change operations.
//!
//! This store provides append-only functionality without requiring MMR (Merkle Mountain Range) for
//! authentication. It's designed for efficient local storage scenarios where cryptographic proofs
//! are not required, making it more performant than [`crate::adb::Any`] for non-authenticated use cases.
//!
//! # Terminology
//!
//! A _key_ in the store either has a _value_ or it doesn't. Two types of _operations_ can be applied
//! to modify the state of a specific key:
//!
//! - **Update operation**: Assigns a value to a key, whether it previously had no value or a different value
//! - **Delete operation**: Removes a key's value, making it inactive
//!
//! Keys with values are called _active_. An operation is called _active_ if:
//! 1. Its key is active
//! 2. It is an update operation
//! 3. It is the most recent operation for that key
//!
//! # Architecture
//!
//! The store maintains two main components:
//!
//! - **Log**: A [journal](crate::journal) of all operations applied in chronological order
//! - **Snapshot**: An [index](crate::index) mapping each active key to its current value's location in the log
//!
//! The store also tracks an "inactivity floor" - a location before which all operations are considered
//! inactive (superseded by more recent operations on the same keys).
//!
//! # Usage
//!
//! ```rust,ignore
//! use commonware_storage::store::{Store, Config};
//! use commonware_storage::translator::TwoCap;
//!
//! // Initialize store configuration
//! let config = Config {
//!     log_journal_partition: "my_store_log".to_string(),
//!     log_items_per_blob: 1000,
//!     log_write_buffer: 64 * 1024,
//!     translator: TwoCap,
//!     buffer_pool: pool_ref,
//! };
//!
//! // Create and use the store
//! let mut store = Store::init(context, config).await?;
//! store.update(key, value).await?;
//! let retrieved_value = store.get(&key).await?;
//! store.commit().await?; // Persist changes
//! ```

use thiserror::Error;

pub mod base;
pub mod operation;

/// The result of a database `update` operation.
pub enum UpdateResult {
    /// Tried to set a key to its current value.
    NoOp,
    /// Key was not previously in the snapshot & its new loc is the wrapped value.
    Inserted(u64),
    /// Key was previously in the snapshot & its (old, new) loc pair is wrapped.
    Updated(u64, u64),
}

/// Errors that can occur when interacting with a store.
#[derive(Error, Debug)]
pub enum Error {
    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,
}
