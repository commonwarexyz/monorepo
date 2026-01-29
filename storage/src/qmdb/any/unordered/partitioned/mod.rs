//! Partitioned index variants of unordered Any QMDBs.
//!
//! These variants use a partitioned index for the snapshot, which reduces memory overhead when
//! indexing large datasets by dividing the key space into `2^(P*8)` partitions based on the first
//! `P` bytes of each key.
//!
//! # Example Usage
//!
//! ```ignore
//! use commonware_storage::qmdb::any::unordered::partitioned::fixed::Db;
//!
//! // Create a DB with 64K partitions (P=2)
//! let db = Db::<Context, Key, Value, Sha256, TwoCap, 2>::init(ctx, cfg).await?;
//! ```
//!
//! # Convenience Aliases
//!
//! For common partition sizes, use the submodules:
//! - [p256]: 256 partitions (P=1)
//! - [p64k]: 65,536 partitions (P=2)

pub mod fixed;
pub mod variable;

/// Convenience type aliases for 256 partitions (P=1).
///
/// This partition count is suitable for smaller datasets or when you want minimal upfront
/// memory cost from partition pre-allocation.
pub mod p256 {
    /// Fixed-value DB with 256 partitions.
    pub type FixedDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::fixed::Db<E, K, V, H, T, 1, S, D>;

    /// Variable-value DB with 256 partitions.
    pub type VariableDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::variable::Db<E, K, V, H, T, 1, S, D>;
}

/// Convenience type aliases for 65,536 partitions (P=2).
///
/// This partition count is suitable for larger datasets (>> 64K keys) where memory savings
/// from the 2-byte prefix compression are significant.
pub mod p64k {
    /// Fixed-value DB with 65,536 partitions.
    pub type FixedDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::fixed::Db<E, K, V, H, T, 2, S, D>;

    /// Variable-value DB with 65,536 partitions.
    pub type VariableDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::variable::Db<E, K, V, H, T, 2, S, D>;
}
