//! Partitioned index variants of ordered Any QMDBs.
//!
//! These variants use a partitioned index for the snapshot, which reduces memory overhead when
//! indexing large datasets by dividing the key space into `2^(P*8)` partitions based on the first
//! `P` bytes of each key.
//!
//! See [crate::qmdb::any::unordered::partitioned] for more details on partitioned indices.

pub mod fixed;
pub mod variable;

/// Convenience type aliases for 256 partitions (P=1).
pub mod p256 {
    /// Fixed-value ordered DB with 256 partitions.
    pub type FixedDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::fixed::Db<E, K, V, H, T, 1, S, D>;

    /// Variable-value ordered DB with 256 partitions.
    pub type VariableDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::variable::Db<E, K, V, H, T, 1, S, D>;
}

/// Convenience type aliases for 65,536 partitions (P=2).
pub mod p64k {
    /// Fixed-value ordered DB with 65,536 partitions.
    pub type FixedDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::fixed::Db<E, K, V, H, T, 2, S, D>;

    /// Variable-value ordered DB with 65,536 partitions.
    pub type VariableDb<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
        super::variable::Db<E, K, V, H, T, 2, S, D>;
}
