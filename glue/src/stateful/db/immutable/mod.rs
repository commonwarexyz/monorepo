//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! [`standard`] retains the operation log. [`compact`] retains only the current Merkle peaks.

mod compact;
mod standard;
