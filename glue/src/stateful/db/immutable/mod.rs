//! [`ManagedDb`](super::ManagedDb) implementations for QMDB immutable databases.
//!
//! [`standard`] retains the operation log. [`compact`] retains only the current Merkle peaks.

pub mod compact;
pub mod standard;
