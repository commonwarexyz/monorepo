//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use std::collections::{HashMap, VecDeque};
use std::iter::IntoIterator;
use thiserror::Error;

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

pub(crate) struct LruApprox<K, V> {
    map: HashMap<K, V>,
    queue: VecDeque<K>,
    capacity: usize,
    oldest_to_check: usize,
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
impl<K, V> LruApprox<K, V>
where
    K: std::hash::Hash + Eq + Clone,
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
    /// may update internal structures that provide the LRU capability.
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
        assert!(self.queue.len() >= maplen);

        Some(value)
    }

    /// Put the value associated with `key` into the cache, returning:
    ///   1. the old value if the key is already associated with some value in the cache, or
    ///   2. the value of any ejected item if the cache was at capacity, or
    ///   3. None otherwise.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let mut result = self.map.insert(key.clone(), value);
        if result.is_some() {
            // This key was already in the cache and we replaced its old value. We now update its
            // state to "recently used", and return the old value.
            self.get(&key);
            return result;
        }
        if self.queue.len() >= self.capacity {
            // The cache is at capacity, so eject (our approximation of) the least recently used
            // item.
            let eject_me = self.queue.pop_front().unwrap();
            result = self.map.remove(&eject_me);
        }

        self.queue.push_back(key);
        assert!(self.queue.len() >= self.map.len());

        result
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        // Note that we do not remove the key from the queue since that would require an O(n) seek.
        // We instead simply let it "expire" organically through LRU ejection after removing it only
        // from the map.
        self.map.remove(key)
    }
}

impl<K, V> IntoIterator for LruApprox<K, V> {
    type Item = (K, V);
    type IntoIter =
        std::iter::Map<std::collections::hash_map::IntoIter<K, V>, fn((K, V)) -> (K, V)>;

    /// Creates a consuming iterator over all elements in the cache in arbitrary order. The cache
    /// cannot be used after this.
    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter().map(|kv| (kv.0, kv.1))
    }
}
