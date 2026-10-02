//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! [`standard`] retains the operation log. [`compact`] retains only the current Merkle peaks.

mod compact;
mod standard;
