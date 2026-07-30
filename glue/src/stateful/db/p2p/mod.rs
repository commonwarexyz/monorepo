//! P2P implementation of the QMDB sync resolver.
//!
//! - [`standard`]: resolver for QMDBs that fetch operations from peers. Compact-storage
//!   QMDBs use it too: their sync is a one-operation fetch over the same wire.

mod cancel;
pub mod standard;
