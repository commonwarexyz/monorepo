//! A write-once key-value store where each key is associated with a unique index.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`. This is useful for storing ordered data either
//! [for a limited time](crate::archive::prunable) or [indefinitely](crate::archive::immutable).

pub mod immutable;
pub mod prunable;
