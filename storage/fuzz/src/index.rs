//! Index operations and a reference model shared by the index fuzz targets.
//!
//! The model keys values by their capped key: the first `width` bytes of the key, zero-padded on
//! the right. A cap translator behind a `P`-byte partition prefix produces exactly this key, so
//! distinct keys that share it collide in both the index and the model. The values of one key
//! form a multiset, since an index may return them in any order and a cursor edits whichever
//! value it visits. Cursor operations therefore record the visited value rather than a position.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::telemetry::metrics::metric_samples;
use commonware_storage::index::{Cursor as _, Ordered, Unordered};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    ops::Bound,
};

/// The most keys a [Operation::Grind] inserts, enough to spill an ordered partition.
const MAX_GRIND: u16 = 1024;

/// The most values a [Operation::InsertMany] inserts: two of them under one key reach the 512
/// entries at which an ordered partition spills.
const MAX_MANY: u16 = 256;

/// Length of the key [Operation::InsertLargeKey] inserts, past every capped key.
const LARGE_KEY: usize = 1000;

/// Bytes sampled keys are made of: both ends and the middle of the byte range, so sampled keys
/// share partitions and capped keys, zero-padded short keys meet longer ones, and navigation
/// reaches the first and the last partition and wraps.
const KEY_BYTES: [u8; 4] = [0x00, 0x01, 0x80, 0xff];

/// The longest sampled key. Keys of two or more bytes make a [Operation::Grind] put all its keys
/// in one partition also when the partition prefix is two bytes.
const MAX_KEY: usize = 4;

/// The most keys one [Operation::GetMany] reads: more than the probes an ordered index prefetches
/// ahead, so one read runs the whole look-ahead and is checked key by key in the middle of a run.
const MAX_KEYS: usize = 16;

/// Sampled values are below this bound, so prunes meet values that inserts, grinds and
/// [Operation::InsertMany] wrote.
const VALUES: u64 = 8;

/// A key of at most [MAX_KEY] bytes drawn from [KEY_BYTES].
fn key(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    (0..u.int_in_range(0..=MAX_KEY)?)
        .map(|_| u.choose(&KEY_BYTES).copied())
        .collect()
}

/// At most [MAX_KEYS] keys.
fn keys(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Vec<u8>>> {
    (0..u.int_in_range(0..=MAX_KEYS)?).map(|_| key(u)).collect()
}

/// A value below [VALUES].
fn value(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(0..=VALUES - 1)
}

/// A count of at most [MAX_MANY] values.
fn many(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(0..=MAX_MANY)
}

/// An operation applied to both an index and the [Model].
#[derive(Arbitrary, Debug, Clone)]
pub enum Operation {
    Insert {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        value: u64,
    },
    Get {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    GetMut {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    GetMutOrInsert {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        value: u64,
    },
    GetMany {
        #[arbitrary(with = keys)]
        keys: Vec<Vec<u8>>,
    },
    Remove {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    Prune {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        prune_value: u64,
    },
    InsertAndPrune {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        value: u64,
        #[arbitrary(with = value)]
        prune_value: u64,
    },
    // Edge case operations
    InsertLargeKey {
        #[arbitrary(with = value)]
        value: u64,
    },
    InsertMany {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = many)]
        count: u16,
    },
    PruneAll {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    // Insert `count` keys that extend `key` with a two-byte counter, so they share a partition
    // and, when `key` already fills the cap, one capped key.
    Grind {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        count: u16,
    },
    // Cursor operations
    CursorUpdate {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        new_value: u64,
    },
    CursorDelete {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    CursorInsert {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        value: u64,
    },
    CursorReplace {
        #[arbitrary(with = key)]
        key: Vec<u8>,
        #[arbitrary(with = value)]
        value: u64,
    },
}

/// A read of an ordered index's capped key order.
#[derive(Arbitrary, Debug, Clone)]
pub enum Navigation {
    First,
    Last,
    Next {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
    Prev {
        #[arbitrary(with = key)]
        key: Vec<u8>,
    },
}

/// The values an index should hold, by capped key.
pub struct Model {
    width: usize,
    entries: BTreeMap<Vec<u8>, Vec<u64>>,
}

/// `values` in ascending order, so multisets compare regardless of iteration order.
fn sorted<'a>(values: impl IntoIterator<Item = &'a u64>) -> Vec<u64> {
    let mut values: Vec<u64> = values.into_iter().copied().collect();
    values.sort_unstable();
    values
}

impl Model {
    /// An empty model capping keys to `width` bytes.
    pub const fn new(width: usize) -> Self {
        Self {
            width,
            entries: BTreeMap::new(),
        }
    }

    /// The capped key of `key`.
    fn cap(&self, key: &[u8]) -> Vec<u8> {
        let mut capped = vec![0; self.width];
        let len = key.len().min(self.width);
        capped[..len].copy_from_slice(&key[..len]);
        capped
    }

    fn push(&mut self, key: &[u8], value: u64) {
        self.entries.entry(self.cap(key)).or_default().push(value);
    }

    fn retain(&mut self, key: &[u8], mut should_retain: impl FnMut(&u64) -> bool) {
        if let Entry::Occupied(mut entry) = self.entries.entry(self.cap(key)) {
            entry.get_mut().retain(|value| should_retain(value));
            if entry.get().is_empty() {
                entry.remove();
            }
        }
    }

    /// Replace one occurrence of `old` under `key` with `new`, or remove it if `new` is `None`.
    fn replace(&mut self, key: &[u8], old: u64, new: Option<u64>) {
        let Entry::Occupied(mut entry) = self.entries.entry(self.cap(key)) else {
            panic!("cursor visited a value of unmodeled key {key:?}");
        };
        let values = entry.get_mut();
        let i = values
            .iter()
            .position(|value| *value == old)
            .unwrap_or_else(|| panic!("cursor visited unmodeled value {old} of key {key:?}"));
        match new {
            Some(new) => values[i] = new,
            None => {
                values.swap_remove(i);
                if values.is_empty() {
                    entry.remove();
                }
            }
        }
    }

    /// Assert that `values` are exactly the values modeled under `key`, in any order.
    fn assert_values<'a>(&self, key: &[u8], values: impl IntoIterator<Item = &'a u64>) {
        let expected = self
            .entries
            .get(&self.cap(key))
            .map_or_else(Vec::new, sorted);
        assert_eq!(sorted(values), expected, "values diverged for key {key:?}");
    }

    /// Assert that the model holds no values for `key`, as the index reported by offering no
    /// cursor over it.
    fn assert_absent(&self, key: &[u8]) {
        assert!(
            !self.entries.contains_key(&self.cap(key)),
            "index has no cursor for modeled key {key:?}"
        );
    }

    /// Apply `op` to `index` and the model, checking every value the index returns.
    pub fn apply<I: Unordered<Value = u64>>(&mut self, index: &mut I, op: &Operation) {
        match op {
            Operation::Insert { key, value } => {
                index.insert(key, *value);
                self.push(key, *value);
            }

            Operation::Get { key } => {
                self.assert_values(key, index.get(key));
            }

            Operation::GetMut { key } => {
                let Some(mut cursor) = index.get_mut(key) else {
                    return self.assert_absent(key);
                };
                let mut values = Vec::new();
                while let Some(value) = cursor.next() {
                    values.push(*value);
                }
                assert!(
                    cursor.next().is_none(),
                    "exhausted cursor over {key:?} yielded a value"
                );
                assert!(!values.is_empty(), "cursor over {key:?} has no values");
                self.assert_values(key, &values);
            }

            Operation::GetMutOrInsert { key, value } => {
                let Some(mut cursor) = index.get_mut_or_insert(key, *value) else {
                    self.assert_absent(key);
                    return self.push(key, *value);
                };
                let mut values = Vec::new();
                while let Some(value) = cursor.next() {
                    values.push(*value);
                }
                assert!(!values.is_empty(), "cursor over {key:?} has no values");
                self.assert_values(key, &values);
            }

            Operation::GetMany { keys } => {
                let mut visited = vec![Vec::new(); keys.len()];
                index.get_many(keys, |i, value| visited[i].push(*value));
                for (key, values) in keys.iter().zip(&visited) {
                    self.assert_values(key, values);
                }
            }

            Operation::Remove { key } => {
                index.remove(key);
                self.entries.remove(&self.cap(key));
            }

            Operation::Prune { key, prune_value } => {
                index.retain(key, |v| *v != *prune_value);
                self.retain(key, |v| *v != *prune_value);
            }

            Operation::InsertAndPrune {
                key,
                value,
                prune_value,
            } => {
                index.insert_and_retain(key, *value, |v| *v != *prune_value);
                self.retain(key, |v| *v != *prune_value);
                if *value != *prune_value {
                    self.push(key, *value);
                }
            }

            Operation::InsertLargeKey { value } => {
                // Create a large key to test translator behavior
                let large_key = vec![0u8; LARGE_KEY];
                index.insert(&large_key, *value);
                self.push(&large_key, *value);
            }

            Operation::InsertMany { key, count } => {
                // Insert multiple values for the same key to test collisions
                for i in 0..u64::from(*count) {
                    index.insert(key, i);
                    self.push(key, i);
                }
            }

            Operation::PruneAll { key } => {
                // Remove all values for a key
                index.retain(key, |_| false);
                self.entries.remove(&self.cap(key));
            }

            Operation::Grind { key, count } => {
                for i in 0..*count % (MAX_GRIND + 1) {
                    let mut ground = key.clone();
                    ground.extend_from_slice(&i.to_be_bytes());
                    index.insert(&ground, u64::from(i));
                    self.push(&ground, u64::from(i));
                }
            }

            Operation::CursorUpdate { key, new_value } => {
                let Some(mut cursor) = index.get_mut(key) else {
                    return self.assert_absent(key);
                };
                let old = *cursor
                    .next()
                    .expect("cursor over an existing key has a value");
                cursor.update(*new_value);
                self.replace(key, old, Some(*new_value));
            }

            Operation::CursorDelete { key } => {
                let Some(mut cursor) = index.get_mut(key) else {
                    return self.assert_absent(key);
                };
                let old = *cursor
                    .next()
                    .expect("cursor over an existing key has a value");
                cursor.delete();
                self.replace(key, old, None);
            }

            Operation::CursorInsert { key, value } => {
                if let Some(mut cursor) = index.get_mut_or_insert(key, *value) {
                    cursor
                        .next()
                        .expect("cursor over an existing key has a value");
                    cursor.insert(*value);
                } else {
                    self.assert_absent(key);
                }
                self.push(key, *value);
            }

            Operation::CursorReplace { key, value } => {
                // Delete every value, then insert into the emptied key before the cursor drops.
                let Some(mut cursor) = index.get_mut(key) else {
                    return self.assert_absent(key);
                };
                while cursor.next().is_some() {
                    cursor.delete();
                }
                cursor.insert(*value);
                self.entries.insert(self.cap(key), vec![*value]);
            }
        }
    }

    /// Check `nav` against the model's capped key order, including wraparound.
    pub fn navigate<I: Ordered<Value = u64>>(&self, index: &I, nav: &Navigation) {
        let first = || self.entries.values().next().map(sorted);
        let last = || self.entries.values().next_back().map(sorted);
        match nav {
            Navigation::First => {
                let got = index.first_translated_key().map(sorted);
                assert_eq!(got, first(), "first translated key diverged");
            }

            Navigation::Last => {
                let got = index.last_translated_key().map(sorted);
                assert_eq!(got, last(), "last translated key diverged");
            }

            Navigation::Next { key } => {
                let capped = self.cap(key);
                let expected = self
                    .entries
                    .range::<[u8], _>((Bound::Excluded(capped.as_slice()), Bound::Unbounded))
                    .next()
                    .map(|(_, values)| (sorted(values), false))
                    .or_else(|| first().map(|values| (values, true)));
                let got = index
                    .next_translated_key(key)
                    .map(|(values, cycled)| (sorted(values), cycled));
                assert_eq!(got, expected, "next translated key diverged for {key:?}");
            }

            Navigation::Prev { key } => {
                let capped = self.cap(key);
                let expected = self
                    .entries
                    .range::<[u8], _>((Bound::Unbounded, Bound::Excluded(capped.as_slice())))
                    .next_back()
                    .map(|(_, values)| (sorted(values), false))
                    .or_else(|| last().map(|values| (values, true)));
                let got = index
                    .prev_translated_key(key)
                    .map(|(values, cycled)| (sorted(values), cycled));
                assert_eq!(got, expected, "prev translated key diverged for {key:?}");
            }
        }
    }

    /// Assert that `index` holds every modeled value, looking up each capped key (which caps to
    /// itself) in one batch.
    pub fn assert_index<I: Unordered<Value = u64>>(&self, index: &I) {
        let keys: Vec<&Vec<u8>> = self.entries.keys().collect();
        let mut visited = vec![Vec::new(); keys.len()];
        index.get_many(&keys, |i, value| visited[i].push(*value));
        for (key, values) in keys.into_iter().zip(&visited) {
            self.assert_values(key, values);
        }
    }

    /// Assert that the `keys` and `items` gauges in `encoded` metrics, summed over partitions,
    /// count the modeled keys and values.
    pub fn assert_metrics(&self, encoded: &str) {
        let total = |name| -> i64 {
            metric_samples(encoded, name)
                .map(|(_, value)| value.parse::<i64>().expect("gauge value"))
                .sum()
        };
        let items: usize = self.entries.values().map(Vec::len).sum();
        assert_eq!(
            total("keys"),
            self.entries.len() as i64,
            "keys gauge diverged"
        );
        assert_eq!(total("items"), items as i64, "items gauge diverged");
    }
}
