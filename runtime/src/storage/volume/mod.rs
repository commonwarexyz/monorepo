//! A single-file storage backend with atomic group commit.
//!
//! `volume` packs every blob of a [`crate::Storage`] workload into ONE inner
//! blob (the "volume file") and provides a strictly stronger crash contract
//! than the trait requires: after a crash and reopen, every blob's readable
//! state is exactly the state captured by one commit, chosen as the last
//! confirmed commit or a newer fully-landed one. Storage structures above the
//! volume can therefore delete their own torn-write detection and recovery
//! machinery.
//!
//! The commit protocol is formally specified and exhaustively checked in
//! [`model`] (see its module docs); the implementation must match the model.

#[cfg(test)]
mod model;
