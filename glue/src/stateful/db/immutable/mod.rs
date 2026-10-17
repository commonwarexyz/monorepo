//! [`ManagedDb`](super::ManagedDb) implementations for QMDB immutable databases.
//!
//! [`standard`] retains the operation log. [`compact`] adds `set` to the shared
//! [compact adapter](super::compact), which retains only the current Merkle peaks.

pub mod compact;
pub mod standard;
