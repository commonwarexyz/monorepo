//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Use [`standard`] for the journaled implementation and [`compact`] for the
//! compact implementation that retains only current Merkle peaks.

mod compact;
mod standard;
