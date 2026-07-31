//! P2P implementation of the QMDB sync resolver.
//!
//! - [`standard`]: resolver for QMDBs that fetch operations from peers. Compact-storage
//!   QMDBs use it too, since their sync is a one-operation fetch over the same wire.

mod cancel;
pub mod standard;
