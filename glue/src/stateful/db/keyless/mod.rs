//! [`ManagedDb`](super::ManagedDb) implementations for QMDB keyless databases.
//!
//! [`standard`] retains the operation log. [`compact`] adds `append` to the shared
//! [compact adapter](super::compact), which retains only the current Merkle peaks.

pub mod compact;
pub mod standard;
