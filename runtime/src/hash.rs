//! Runtime-aware HashMap and HashSet collections.
//!
//! These types should be used instead of `std::collections::{HashMap, HashSet}` throughout
//! the codebase. They automatically use the appropriate hashing strategy based on the runtime:
//!
//! - **Deterministic runtime**: Fixed seed for reproducible iteration order
//! - **Tokio runtime**: Random seed for DoS resistance (same as std)
//!
//! # Usage
//!
//! ```ignore
//! use commonware_runtime::{HashMap, HashSet};
//! ```

use rand::Rng;
use siphasher::sip::SipHasher13;
use std::{cell::Cell, hash::BuildHasher};

thread_local! {
    /// Thread-local hash seed.
    /// - `None` = production mode (use random seed for DoS resistance)
    /// - `Some(seed)` = deterministic mode (use fixed seed for reproducibility)
    static HASH_SEED: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Set the hash seed for the current thread.
///
/// Called by the deterministic runtime at startup to enable reproducible hashing.
/// All HashMaps/HashSets created after this call will use the specified seed.
pub fn set_seed(seed: u64) {
    HASH_SEED.with(|s| s.set(Some(seed)));
}

/// Get the current hash seed for the current thread.
///
/// Returns `None` if no seed has been set (production mode).
/// Used when creating checkpoints to preserve the seed for recovery.
pub fn get_seed() -> Option<u64> {
    HASH_SEED.with(|s| s.get())
}

/// Clear the hash seed for the current thread.
///
/// After this call, new HashMaps will use random seeds (production mode).
pub fn clear_seed() {
    HASH_SEED.with(|s| s.set(None));
}

/// A BuildHasher that uses the TLS seed if set, otherwise random keys.
///
/// Uses SipHash-1-3 for DoS resistance (same algorithm as std HashMap).
#[derive(Clone)]
pub struct RandomState {
    k0: u64,
    k1: u64,
}

impl Default for RandomState {
    fn default() -> Self {
        let (k0, k1) = HASH_SEED.with(|s| {
            s.get().map_or_else(
                || {
                    // Production mode: random keys for DoS resistance
                    let mut rng = rand::thread_rng();
                    (rng.gen(), rng.gen())
                },
                |seed| {
                    // Deterministic mode: derive keys from seed
                    (seed, seed.wrapping_add(1))
                },
            )
        });
        Self { k0, k1 }
    }
}

impl BuildHasher for RandomState {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> Self::Hasher {
        SipHasher13::new_with_keys(self.k0, self.k1)
    }
}

/// A HashMap that uses deterministic hashing when a seed is set via TLS.
///
/// In production mode (no seed set), behaves identically to std HashMap with
/// random keys for DoS resistance.
pub type HashMap<K, V> = std::collections::HashMap<K, V, RandomState>;

/// A HashSet that uses deterministic hashing when a seed is set via TLS.
///
/// In production mode (no seed set), behaves identically to std HashSet with
/// random keys for DoS resistance.
pub type HashSet<K> = std::collections::HashSet<K, RandomState>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hashmap_iteration_order() {
        // Set a seed
        set_seed(12345);

        // Create and populate a HashMap
        let mut map1: HashMap<i32, &str> = HashMap::default();
        for i in 0..100 {
            map1.insert(i, "value");
        }

        // Collect iteration order
        let order1: Vec<i32> = map1.keys().copied().collect();

        // Create another HashMap with the same seed
        clear_seed();
        set_seed(12345);

        let mut map2: HashMap<i32, &str> = HashMap::default();
        for i in 0..100 {
            map2.insert(i, "value");
        }

        let order2: Vec<i32> = map2.keys().copied().collect();

        // Iteration order should be identical
        assert_eq!(order1, order2);

        // Clean up
        clear_seed();
    }

    #[test]
    fn test_different_seeds_different_order() {
        set_seed(11111);
        let mut map1: HashMap<i32, &str> = HashMap::default();
        for i in 0..100 {
            map1.insert(i, "value");
        }
        let order1: Vec<i32> = map1.keys().copied().collect();

        clear_seed();
        set_seed(22222);
        let mut map2: HashMap<i32, &str> = HashMap::default();
        for i in 0..100 {
            map2.insert(i, "value");
        }
        let order2: Vec<i32> = map2.keys().copied().collect();

        // Different seeds should produce different iteration orders
        // (with very high probability for 100 elements)
        assert_ne!(order1, order2);

        clear_seed();
    }

    #[test]
    fn test_no_seed_uses_random() {
        clear_seed();

        // Without a seed, each HashMap should get random keys
        // We can't easily test randomness, but we can verify it doesn't panic
        let mut map: HashMap<i32, &str> = HashMap::default();
        map.insert(1, "one");
        map.insert(2, "two");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_get_seed() {
        clear_seed();
        assert_eq!(get_seed(), None);

        set_seed(42);
        assert_eq!(get_seed(), Some(42));

        clear_seed();
        assert_eq!(get_seed(), None);
    }
}
