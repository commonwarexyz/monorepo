//! P2P implementations of the QMDB sync resolvers.
//!
//! - [`standard`]: resolver for standard QMDBs that fetch operations from peers.
//! - [`compact`]: resolver for compact-storage QMDBs that fetch one
//!   authenticated frontier state instead of replaying operations.

pub mod compact;
pub mod standard;
