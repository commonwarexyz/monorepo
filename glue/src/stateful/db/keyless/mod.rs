//! Stateful adapters for QMDB keyless databases.
//!
//! Use [`standard`] for the journaled implementation and [`compact`] for the
//! compact implementation that retains only current Merkle peaks.

pub mod compact;
pub mod standard;
