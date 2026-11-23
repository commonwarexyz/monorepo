//! [`Qmdb`](super::qmdb::Qmdb) support for QMDB [`keyless`](commonware_storage::qmdb::keyless)
//! databases.
//!
//! [`standard`] retains the operation log. [`compact`] adds `append` to the shared
//! [compact adapter](super::compact), which retains only the current Merkle peaks.

mod compact;
mod standard;
