//! [`Qmdb`](super::qmdb::Qmdb) support for QMDB [`immutable`](commonware_storage::qmdb::immutable)
//! databases.
//!
//! [`standard`] retains the operation log. [`compact`] adds `set` to the shared
//! [compact adapter](super::compact), which retains only the current Merkle peaks.

mod compact;
mod standard;
