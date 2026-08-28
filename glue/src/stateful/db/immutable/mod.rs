//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! `standard` holds the journaled implementations, `compact` the ones that retain
//! only current Merkle peaks.

mod compact;
mod standard;
