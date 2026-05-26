//! Stateful adapters for QMDB immutable databases.
//!
//! Use [`standard`] for the journaled implementation and [`compact`] for the
//! compact implementation that retains only current Merkle peaks.

pub mod compact;
pub mod standard;
