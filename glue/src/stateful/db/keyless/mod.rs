//! [`ManagedDb`](super::ManagedDb) implementations for QMDB keyless databases.
//!
//! [`standard`] retains the operation log. [`compact`] retains only the current Merkle peaks.

pub mod compact;
pub mod standard;
