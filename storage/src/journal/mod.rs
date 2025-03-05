//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::iter::IntoIterator;
use thiserror::Error;
use tracing::{debug, warn};

pub mod fixed;
pub mod variable;

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("checksum mismatch: expected={0} actual={1}")]
    ChecksumMismatch(u32, u32),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("usize too small")]
    UsizeTooSmall,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("unexpected size: expected={0} actual={1}")]
    UnexpectedSize(u32, u32),
    #[error("missing blob: {0}")]
    MissingBlob(u64),
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    #[error("invalid item: {0}")]
    InvalidItem(u64),
    #[error("invalid rewind: {0}")]
    InvalidRewind(u64),
}

/// Wraps the cached values with a reference count.
struct MapValue<V> {
    value: V,

    /// The number of unreleased references to this value. If non-zero, the value will not be
    /// ejected from the cache.
    rc: u32,
}

/// A dumb but fast LRU implementation that probabilistically tries to eject the least recently used
/// item. It is based on a VecDequeue instead of a (more typical)
// doubly-linked-list, because [std::collections::LinkedList] doesn't support O(1) removal of
/// arbitrary elements, making it unsuitable for the task.
///
/// The implementation simply checks to see if the most recently accessed item is among the
/// `oldest_to_check` oldest items in the dequeue, and if so, it moves it to the newest. This is a
/// very bad approximation of LRU, but it is simple and fast.
///
/// Newest & most recently accessed items found among the oldest are pushed onto the back of the
/// queue, so older items will accumulate at the front over time. If ejection is required to
/// maintain the capacity limit, the front-most item is removed.
pub(crate) struct LruApprox<K, V> {
    map: HashMap<K, MapValue<V>>,
    queue: VecDeque<K>,
    capacity: usize,
    oldest_to_check: usize,
}

impl<K, V> LruApprox<K, V>
where
    K: std::hash::Hash + Eq + Clone + Display,
{
    pub fn new(capacity: usize, oldest_to_check: usize) -> Self {
        assert!(capacity > 0);
        assert!(oldest_to_check <= capacity);
        Self {
            map: std::collections::HashMap::new(),
            queue: VecDeque::with_capacity(capacity),
            capacity,
            oldest_to_check,
        }
    }

    /// Get the value associated with `key` if it exists. The implementation is mutable because it
    /// may update internal structures that provide the LRU capability. The user must call
    /// release() on the key when done with any returned item to allow it to be ejected.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let maplen = self.map.len();
        let value = self.map.get_mut(key)?;

        // Search up to `self.oldest_to_check` elements in the front of the queue, and if the key is
        // found among them, remove it and push it to the back to implement our LRU approximation.
        for i in 0..std::cmp::min(self.oldest_to_check, maplen) {
            if self.queue[i] == *key {
                let k = self.queue.remove(i).unwrap();
                self.queue.push_back(k);
                break;
            }
        }
        assert!(self.queue.len() == maplen);
        value.rc += 1;

        Some(&value.value)
    }

    /// Release a previously gotten value by key. Panics if the element is not in the cache or if it
    /// it not in use.
    pub fn release(&mut self, key: &K) {
        let value = self.map.get_mut(key);
        if value.is_none() {
            panic!("attempted to release key not found in cache: {}", key);
        }
        let value = value.unwrap();
        assert!(value.rc > 0, "cannot release unused value: {}", key);
        value.rc -= 1;
    }

    /// Attempt to put the value associated with `key` into the cache. Possible outcomes are:
    ///   1. Success: the cache has spare capacity, None is returned.
    ///   2. Success: the cache was at capacity but an entry could be ejected to make room. The
    ///      ejected value is returned.
    ///   3. Failure: the key is already associated with some value in the cache, the provided value
    ///      is returned.
    ///   4. Failure: the cache is at capacity and there is no value to eject, the provided value is
    ///      returned.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let mut result = self.map.insert(key.clone(), MapValue { value, rc: 0 });
        if result.is_some() {
            // Outcome #3: `key` was already in the cache, re-insert the previous value and return
            // the provided one.
            warn!(key = %key, "key already in cache");
            return Some(self.map.insert(key, result.unwrap()).unwrap().value);
        }

        if self.queue.len() < self.capacity {
            // Outcome #1
            self.queue.push_back(key);
            return None;
        }
        assert_eq!(self.queue.len(), self.capacity);

        // The cache is at capacity, so eject (our approximation of) the least recently used item if
        // possible.  TODO: We could look at the OLDEST_TO_CHECK items for eviction instead of just
        // looking at the very oldest one, but this situation may be too rare to bother optimizing.
        let eject_me = self.queue.pop_front().unwrap();
        let v = self.map.get(&eject_me).unwrap();
        if v.rc > 0 {
            // Outcome #4: the item we selected for ejection is still in use. Put it back in the
            // queue and return the provided value back to the caller. We put it back in the
            // "recently used" section to avoid attempting (and potentially failing) to eject it
            // again.
            debug!(key = %key, rc = v.rc, "cannot eject in-use value from cache");
            self.queue.push_back(eject_me);
            let original = self.map.remove(&key).unwrap();
            return Some(original.value);
        }

        // Outcome #2: We can safely ejected an old cache value.
        result = self.map.remove(&eject_me);

        self.queue.push_back(key);
        assert!(self.queue.len() == self.map.len());

        result.map(|mv| mv.value)
    }

    /// Remove the specified value from the cache and return it if present. Panics if the element is
    /// in use.
    ///
    /// Note that this operation is linear in the capacity of the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let v = self.map.remove(key).map(|mv| {
            if mv.rc != 0 {
                panic!("cannot remove, key still in use: {}", key);
            }
            mv.value
        });
        if v.is_some() {
            // O(n) removal of the key from the queue.
            let pos = self.queue.iter().position(|x| x == key).unwrap();
            self.queue.remove(pos);
        }
        v
    }

    /// Creates a consuming iterator over all elements in the cache in arbitrary order. The cache
    /// cannot be used after this. Iteration will panic if the element is still in use.
    fn into_iter(self) -> impl Iterator<Item = (K, V)> {
        self.map.into_iter().map(|kv| {
            if kv.1.rc != 0 {
                panic!("into_iter failed, key still in use: {}", kv.0);
            }
            (kv.0, kv.1.value)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: usize = 10;
    const OLDEST_TO_CHECK: usize = 2;

    #[test]
    fn test_lru_approx() {
        let mut cache = LruApprox::new(CAPACITY, OLDEST_TO_CHECK);
        for i in 1..=10 {
            assert_eq!(cache.put(i, i), None);
        }
        for i in 11..=15 {
            assert_eq!(cache.put(i, i), Some(i - CAPACITY));
        }
        // Grab the oldest item remaining in the cache (6) to make sure it properly gets moved to
        // the most-recent position.
        let key = &6;
        assert_eq!(cache.get(key), Some(key));
        cache.release(key);

        // Make sure we can still evict an item, but that it's not the one we just accessed since
        // that should be the most recent.
        assert_eq!(cache.put(16, 16), Some(7));

        // Refill the cache with fresh items.
        for i in 101..=110 {
            let resp = cache.put(i, i);
            assert!(resp.is_some());
        }
        // Now pin all the items by accessing them without release.
        for i in 101..=110 {
            assert_eq!(cache.get(&i), Some(&i));
        }

        // Now trying to put a new item should give us the same item back since nothing can be
        // ejected.
        assert_eq!(cache.put(111, 111), Some(111));

        // Release all but the oldest item (102, since 101 was moved to front by the above call).
        cache.release(&101);
        for i in 103..=110 {
            cache.release(&i);
        }
        // Oldest item being referenced should still prevent eviction.
        assert_eq!(cache.put(111, 111), Some(111));
        // A second attempt should identify an item for eviction since the unreleased item will have
        // been moved to front by previous call.
        assert_eq!(cache.put(111, 111), Some(103));
        cache.release(&102);

        // Try re-inserting a key and make sure we get back the provided value not the originally
        // inserted value.
        assert_eq!(cache.put(111, 999), Some(999));

        // Test into_iter() for shutting down the cache.
        assert_eq!(cache.into_iter().collect::<Vec<_>>().len(), CAPACITY);
    }

    #[test]
    #[should_panic(expected = "key still in use")]
    fn test_lru_into_iter_with_unreleased_element() {
        // Confirm that trying to shut down a cache with unreleased items results in panic.
        let mut cache = LruApprox::new(CAPACITY, OLDEST_TO_CHECK);
        cache.put(1, 1);
        cache.get(&1);
        let iter = cache.into_iter();
        let _: Vec<(usize, usize)> = iter.collect();
    }

    #[test]
    #[should_panic(expected = "key still in use")]
    fn test_lru_remove_unreleased_element() {
        // Try to remove a key that's still in use, which should panic.
        let mut cache = LruApprox::new(CAPACITY, OLDEST_TO_CHECK);
        cache.put(1, 1);
        cache.get(&1);
        cache.remove(&1);
    }

    #[test]
    #[should_panic(expected = "cannot release unused value")]
    fn test_lru_release_unused_element() {
        let mut cache = LruApprox::new(1, 1);
        cache.put(1, 1);
        cache.release(&1);
    }

    #[test]
    #[should_panic(expected = "key not found")]
    fn test_lru_release_nonexistent_element() {
        let mut cache = LruApprox::new(1, 1);
        cache.put(1, 1);
        cache.release(&2);
    }
}
