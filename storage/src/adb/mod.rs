//! A collection of authenticated databases (ADB).
//!
//! # Terminology
//!
//! A _key_ in an authenticated database either has a _value_ or it doesn't. Two types of
//! _operations_ can be applied to the db to modify the state of a specific key. A key that has a
//! value can change to one without a value through the _delete_ operation. The _update_ operation
//! gives a key a specific value whether it previously had no value or had a different value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is an update operation, and (3) it is the most recent operation for that key.

use thiserror::Error;

pub mod any;
pub mod current;
pub mod immutable;

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    MmrError(#[from] crate::mmr::Error),

    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),

    #[error("operation pruned: {0}")]
    OperationPruned(u64),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,
}
