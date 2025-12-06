//! Operations that can be applied to a database to modify its state.
//!
//! The various operation types implement the [commonware_codec::Codec] trait, allowing for a
//! persistent log of operations based on a `crate::Journal`. The _fixed_ variants additionally
//! implement [commonware_codec::CodecFixed].

use crate::mmr::Location;
use commonware_codec::{Codec, Error as CodecError};
use commonware_utils::Array;
use std::fmt::Debug;
use thiserror::Error;

pub mod fixed;
pub mod variable;

// Context byte prefixes for identifying the operation type.
const DELETE_CONTEXT: u8 = 0;
const UPDATE_CONTEXT: u8 = 1;
const COMMIT_FLOOR_CONTEXT: u8 = 2;
const SET_CONTEXT: u8 = 3;
const COMMIT_CONTEXT: u8 = 4;
const APPEND_CONTEXT: u8 = 5;

/// Errors returned by operation functions.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid key: {0}")]
    InvalidKey(CodecError),
    #[error("invalid value: {0}")]
    InvalidValue(CodecError),
    #[error("invalid context byte")]
    InvalidContextByte,
    #[error("delete operation has non-zero value")]
    InvalidDeleteOp,
    #[error("commit floor operation has non-zero bytes after location")]
    InvalidCommitFloorOp,
}

/// A trait for operations used by database variants that support mutable keyed values.
pub trait Keyed: Codec {
    /// The key type for this operation.
    type Key: Array;

    /// The value type for this operation.
    type Value: Codec + Clone;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// If this operation updates its key's value.
    fn is_update(&self) -> bool;

    /// If this operation deletes its key's value.
    fn is_delete(&self) -> bool;

    /// The inactivity floor location if this operation is a commit operation with a floor value,
    /// None otherwise.
    fn has_floor(&self) -> Option<Location>;

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    fn value(&self) -> Option<&Self::Value>;

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    fn into_value(self) -> Option<Self::Value>;
}

/// A trait for operations used by database variants that support commit operations.
pub trait Committable {
    /// If this operation is a commit operation.
    fn is_commit(&self) -> bool;
}

pub trait Ordered: Keyed {
    /// Return this operation's key data, or None if this operation variant doesn't have any.
    fn key_data(&self) -> Option<&KeyData<Self::Key, Self::Value>>;

    /// Convert this operation into its key data, or None if this operation variant doesn't have
    /// any.
    fn into_key_data(self) -> Option<KeyData<Self::Key, Self::Value>>;
}

/// Data about a key in an ordered database or an ordered database operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyData<K: Array + Ord, V: Codec> {
    /// The key that exists in the database or in the database operation.
    pub key: K,
    /// The value of `key` in the database or operation.
    pub value: V,
    /// The next-key of `key` in the database or operation.
    ///
    /// The next-key is the next active key that lexicographically follows it in the key space. If
    /// the key is the lexicographically-last active key, then next-key is the
    /// lexicographically-first of all active keys (in a DB with only one key, this means its
    /// next-key is itself)
    pub next_key: K,
}
