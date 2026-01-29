//! Partitioned variants of [super] that use a partitioned index for the snapshot.
//!
//! See [crate::qmdb::any::unordered::partitioned::fixed] for details on partitioned indices and
//! when to use them.

pub mod fixed;
pub mod variable;

/// Convenience type aliases for common partition sizes (256 partitions).
pub mod p256 {
    pub type FixedDb<E, K, V, H, T, const N: usize> = super::fixed::Db<E, K, V, H, T, 1, N>;
    pub type VariableDb<E, K, V, H, T, const N: usize> = super::variable::Db<E, K, V, H, T, 1, N>;
}

/// Convenience type aliases for common partition sizes (64K partitions).
pub mod p64k {
    pub type FixedDb<E, K, V, H, T, const N: usize> = super::fixed::Db<E, K, V, H, T, 2, N>;
    pub type VariableDb<E, K, V, H, T, const N: usize> = super::variable::Db<E, K, V, H, T, 2, N>;
}
