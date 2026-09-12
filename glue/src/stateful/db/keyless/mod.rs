//! [`Qmdb`](crate::stateful::db::qmdb::Qmdb) implementations for
//! [`qmdb::keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! Use [`standard`] for the journaled implementation and [`compact`] for the
//! compact implementation that retains only current Merkle peaks.

mod compact;
mod standard;
