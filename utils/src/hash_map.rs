//! Fast hash map for lookups.
//!
//! Prefer [HashMap] over [std::collections::HashMap].

use hashbrown::HashMap as InnerHashMap;

pub use hashbrown::hash_map::Entry;

/// Hasher used by [HashMap].
pub type BuildHasher = ahash::RandomState;

/// A hash map optimized for fast lookups.
pub type HashMap<K, V> = InnerHashMap<K, V, BuildHasher>;

/// Creates an empty [HashMap].
pub fn new<K, V>() -> HashMap<K, V> {
    HashMap::with_hasher(BuildHasher::default())
}

/// Creates an empty [HashMap] with at least the specified capacity.
pub fn with_capacity<K, V>(capacity: usize) -> HashMap<K, V> {
    HashMap::with_capacity_and_hasher(capacity, BuildHasher::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_empty_map() {
        assert!(new::<u8, u8>().is_empty());
    }
}
