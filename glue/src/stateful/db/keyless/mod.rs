//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! `standard` holds the journaled implementations, `compact` the ones that retain
//! only current Merkle peaks.

mod compact;
mod standard;
