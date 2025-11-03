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

use crate::mmr::Location;
use thiserror::Error;

pub mod any;
pub mod current;
pub mod immutable;
pub mod keyless;
pub mod operation;
pub mod store;
pub mod sync;
pub mod verify;
pub use verify::{
    create_multi_proof, create_proof, create_proof_store, create_proof_store_from_digests,
    digests_required_for_proof, extract_pinned_nodes, verify_multi_proof, verify_proof,
    verify_proof_and_extract_digests,
};

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    Mmr(#[from] crate::mmr::Error),

    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    #[error("operation pruned: {0}")]
    OperationPruned(Location),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,

    /// The key exists in the db, so we cannot prove its exclusion.
    #[error("key exists")]
    KeyExists,

    #[error("unexpected data at location: {0}")]
    UnexpectedData(Location),

    #[error("location out of bounds: {0} >= {1}")]
    LocationOutOfBounds(Location, Location),

    #[error("prune location {0} beyond last commit {1}")]
    PruneBeyondCommit(Location, Location),

    #[error("prune location {0} beyond inactivity floor {1}")]
    PruneBeyondInactivityFloor(Location, Location),

    #[error("uncommitted operations present")]
    UncommittedOperations,
}
