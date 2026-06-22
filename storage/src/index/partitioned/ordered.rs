//! A partitioned index that stores each partition as sorted struct-of-arrays (see the
//! `super::partition` module).
//!
//! The first `P` bytes of the (untranslated) key select a partition; the translator maps the
//! remaining bytes to the partition-local key. Because the partitions are ordered by prefix and each
//! partition's entries are sorted by translated key, this index is inherently ordered. It trades
//! lookup/insert speed for memory density at scale; the unordered variant ([`super::unordered`])
//! uses hash sub-indices instead and is faster when ordering is not required.

use crate::{
    index::{
        partitioned::{partition::Partition, partition_index_and_sub_key},
        Cursor as CursorTrait, Factory, Ordered, Unordered,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::ops::Range;

const MUST_CALL_NEXT: &str = "must call Cursor::next()";
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of a [Cursor] within its key's value run (offsets are newest-first, 0 = newest).
enum State {
    /// Before the first `next()` or after an `insert()`/`delete()`: the next `next()` returns the
    /// value at run offset `from`.
    NeedNext { from: usize },
    /// `next()` returned the value at run offset `offset`; `update`/`delete`/`insert` are valid.
    Active { offset: usize },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    Done,
}

/// A [crate::index::Cursor] over the values of a single translated key within a partition.
///
/// The key's values occupy a contiguous `run` of indices in the partition's sorted arrays, cached
/// here (resolved once when the cursor is created) so each operation avoids re-searching for it.
/// The cursor borrows the partition exclusively, so it is the only writer: `run.start` never moves,
/// and `insert`/`delete` adjust `run.end` by one in lockstep with the array, keeping the cached run
/// exact without another `lower_bound`.
pub struct Cursor<'a, K: Ord + Copy, V> {
    partition: &'a mut Partition<K, V>,
    key: K,
    run: Range<usize>,
    state: State,
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, K: Ord + Copy, V> Cursor<'a, K, V> {
    const fn new(
        partition: &'a mut Partition<K, V>,
        key: K,
        run: Range<usize>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            partition,
            key,
            run,
            state: State::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync> CursorTrait for Cursor<'_, K, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let off = match self.state {
            State::Done => return None,
            State::NeedNext { from } => from,
            State::Active { offset } => offset + 1,
        };
        if off >= self.run.len() {
            self.state = State::Done;
            return None;
        }
        self.state = State::Active { offset: off };
        Some(self.partition.value_at(self.run.start + off))
    }

    fn update(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => self.partition.set(self.run.start + offset, value),
        }
    }

    fn insert(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { offset } => {
                // Place immediately after the current value; `next()` then returns the value after
                // the inserted one (skipping both the current and the inserted).
                self.partition
                    .insert_at(self.run.start + offset + 1, self.key, value);
                self.run.end += 1;
                self.items.inc();
                self.state = State::NeedNext { from: offset + 2 };
            }
            State::Done => {
                // Append at the oldest position (run end), re-creating the key if it was emptied.
                if self.run.is_empty() {
                    self.keys.inc();
                }
                self.partition.insert_at(self.run.end, self.key, value);
                self.run.end += 1;
                self.items.inc();
            }
        }
    }

    fn delete(&mut self) {
        let offset = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => offset,
        };
        self.partition.remove(self.run.start + offset);
        self.run.end -= 1;
        self.items.dec();
        self.pruned.inc();
        if self.run.is_empty() {
            // Removed the key's last value; the key is gone.
            self.keys.dec();
        }
        // The value after the deleted one shifted into `offset`.
        self.state = State::NeedNext { from: offset };
    }
}

/// A partitioned index storing each partition as sorted struct-of-arrays.
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    translator: T,
    partitions: Box<[Partition<T::Key, V>]>,
    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given metrics context and translator.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        const {
            assert!(P > 0 && P <= 3, "P must be in 1..=3");
        }
        let count = 1usize << (P * 8);
        let partitions = (0..count)
            .map(|_| Partition::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            translator,
            partitions,
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Factory<T> for Index<T, V, P> {
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Unordered for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        self.partitions[i].values(&k).iter()
    }

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
        // Probe in (partition, translated-key) order so consecutive probes hit the same partition
        // (one region of the 2^(8*P)-entry partition array) and the same value run within it,
        // instead of scattering across partitions in input order.
        let mut order: Vec<(usize, T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| {
                let (partition, sub) = partition_index_and_sub_key::<P>(key.as_ref());
                (partition, self.translator.transform(sub), key_idx)
            })
            .collect();
        order.sort_unstable();
        for (partition, translated, key_idx) in order {
            for value in self.partitions[partition].values(&translated) {
                visit(key_idx, value);
            }
        }
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let partition = &mut self.partitions[i];
        let run = partition.run_range(&k);
        if run.is_empty() {
            return None;
        }
        Some(Cursor::new(
            partition,
            k,
            run,
            &self.keys,
            &self.items,
            &self.pruned,
        ))
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let partition = &mut self.partitions[i];
        let run = partition.run_range(&k);
        if run.is_empty() {
            partition.insert_at(run.start, k, value);
            self.keys.inc();
            self.items.inc();
            return None;
        }
        Some(Cursor::new(
            partition,
            k,
            run,
            &self.keys,
            &self.items,
            &self.pruned,
        ))
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let partition = &mut self.partitions[i];
        let run = partition.run_range(&k);
        partition.insert_at(run.start, k, value);
        self.items.inc();
        if run.is_empty() {
            self.keys.inc();
        }
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: Self::Value,
        should_retain: impl Fn(&Self::Value) -> bool,
    ) {
        if let Some(mut cursor) = self.get_mut(key) {
            cursor.retain(&should_retain);
            if should_retain(&value) {
                cursor.insert(value);
            }
        } else if should_retain(&value) {
            self.insert(key, value);
        }
    }

    fn remove(&mut self, key: &[u8]) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let partition = &mut self.partitions[i];
        let run = partition.run_range(&k);
        if run.is_empty() {
            return;
        }
        let n = run.len();
        partition.remove_run(run);
        self.keys.dec();
        self.items.dec_by(n as i64);
        self.pruned.inc_by(n as u64);
    }

    #[cfg(test)]
    fn keys(&self) -> usize {
        self.keys.get() as usize
    }

    #[cfg(test)]
    fn items(&self) -> usize {
        self.items.get() as usize
    }

    #[cfg(test)]
    fn pruned(&self) -> usize {
        self.pruned.get() as usize
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Ordered for Index<T, V, P> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        // The largest translated key strictly less than `k`: within the partition first, then the
        // last key of the nearest lower partition, else cycle to the global last key.
        if let Some(vals) = self.partitions[i].prev_values_before(&k) {
            return Some((vals.iter(), false));
        }
        for p in self.partitions[..i].iter().rev() {
            if let Some(vals) = p.last_values() {
                return Some((vals.iter(), false));
            }
        }
        self.partitions
            .iter()
            .rev()
            .find_map(|p| p.last_values())
            .map(|vals| (vals.iter(), true))
    }

    fn next_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        // The smallest translated key strictly greater than `k`: within the partition first, then
        // the first key of the nearest higher partition, else cycle to the global first key.
        if let Some(vals) = self.partitions[i].next_values_after(&k) {
            return Some((vals.iter(), false));
        }
        for p in &self.partitions[i + 1..] {
            if let Some(vals) = p.first_values() {
                return Some((vals.iter(), false));
            }
        }
        self.partitions
            .iter()
            .find_map(|p| p.first_values())
            .map(|vals| (vals.iter(), true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.partitions
            .iter()
            .find_map(|p| p.first_values())
            .map(|vals| vals.iter())
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.partitions
            .iter()
            .rev()
            .find_map(|p| p.last_values())
            .map(|vals| vals.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::OneCap;
    use commonware_formatting::hex;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn new_index(context: deterministic::Context) -> Index<OneCap, u64, 1> {
        Index::new(context, OneCap)
    }

    #[test_traced]
    fn test_soa_basic() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            assert_eq!(index.keys(), 0);

            let key = b"duplicate".as_slice();
            index.insert(key, 1);
            index.insert(key, 2);
            index.insert(key, 3);
            assert_eq!(index.keys(), 1);
            assert_eq!(index.items(), 3);
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![3, 2, 1]);

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert_eq!(*cursor.next().unwrap(), 3);
                assert_eq!(*cursor.next().unwrap(), 2);
                assert_eq!(*cursor.next().unwrap(), 1);
                assert!(cursor.next().is_none());
            }

            index.insert(key, 3);
            index.insert(key, 4);
            index.retain(key, |i| *i != 3);
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![4, 2, 1]);

            index.retain(key, |_| false);
            assert_eq!(
                index.get(key).copied().collect::<Vec<_>>(),
                Vec::<u64>::new()
            );
            assert_eq!(index.keys(), 0);
            assert!(index.get_mut(key).is_none());

            // No-op on a missing key.
            index.retain(key, |_| false);
        });
    }

    #[test_traced]
    fn test_soa_cursor_find() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            let key = b"test_key";
            for v in [10u64, 20, 30, 40] {
                index.insert(key, v);
            }

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(cursor.find(|&v| v == 30));
                cursor.update(35);
            }
            let values: Vec<u64> = index.get(key).copied().collect();
            assert!(values.contains(&35) && !values.contains(&30));

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(!cursor.find(|&v| v == 100));
                assert!(cursor.next().is_none());
            }

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(cursor.find(|&v| v == 20));
                cursor.delete();
            }
            let values: Vec<u64> = index.get(key).copied().collect();
            assert!(!values.contains(&20));
            assert_eq!(values.len(), 3);
        });
    }

    #[test_traced]
    fn test_soa_get_many_and_partitions() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            // "ab"/"abX" share a partition+translated key; "zz" is a different partition.
            index.insert(b"ab", 1);
            index.insert(b"ab", 2);
            index.insert(b"abX", 3);
            index.insert(b"zz", 4);

            let keys: Vec<&[u8]> = vec![b"zz", b"missing", b"ab", b"zz"];
            let mut visits: Vec<Vec<u64>> = vec![Vec::new(); keys.len()];
            index.get_many(&keys, |key_idx, value| visits[key_idx].push(*value));
            assert_eq!(visits[0], vec![4]);
            assert!(visits[1].is_empty());
            assert_eq!(visits[2], vec![3, 2, 1]);
            assert_eq!(visits[3], vec![4]);
        });
    }

    #[test_traced]
    fn test_soa_insert_and_retain() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            // Keep both: new value joins as oldest.
            index.insert(b"k", 1u64);
            index.insert_and_retain(b"k", 2, |_| true);
            assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![1, 2]);

            // Drop the new value: no-op.
            index.insert_and_retain(b"k", 9, |v| *v != 9);
            assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![1, 2]);

            // Drop everything.
            index.insert_and_retain(b"k", 9, |_| false);
            assert!(index.get_mut(b"k").is_none());
            assert_eq!(index.keys(), 0);

            // Vacant key: insert only if retained.
            index.insert_and_retain(b"new", 7, |_| true);
            assert_eq!(index.get(b"new").copied().collect::<Vec<_>>(), vec![7]);
            assert_eq!(index.keys(), 1);
        });
    }

    #[test_traced]
    fn test_soa_remove() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            index.insert(b"k", 1u64);
            index.insert(b"k", 2);
            index.insert(b"other", 3);
            assert_eq!(index.items(), 3);
            assert_eq!(index.keys(), 2);

            index.remove(b"k");
            assert!(index.get_mut(b"k").is_none());
            assert_eq!(index.keys(), 1);
            assert_eq!(index.items(), 1);
            assert_eq!(index.pruned(), 2);
            assert_eq!(index.get(b"other").copied().collect::<Vec<_>>(), vec![3]);

            index.remove(b"missing"); // no-op
            assert_eq!(index.keys(), 1);
        });
    }

    #[test_traced]
    fn test_soa_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.next_translated_key(b"key").is_none());
            assert!(index.prev_translated_key(b"key").is_none());

            // With OneCap + P=1, the full key orders as (prefix byte, first sub-key byte).
            let k1 = &hex!("0x0b02AA"); // -> partition 0b, sub-key 02
            let k2 = &hex!("0x1c04CC"); // -> partition 1c, sub-key 04
            let k2_collides = &hex!("0x1c0411"); // same (1c, 04) as k2
            let k3 = &hex!("0x2d06EE"); // -> partition 2d, sub-key 06
            index.insert(k1, 1);
            index.insert(k2, 21);
            index.insert(k2_collides, 22);
            index.insert(k3, 3);
            assert_eq!(index.keys(), 3);

            assert_eq!(index.first_translated_key().unwrap().next(), Some(&1));
            assert_eq!(index.last_translated_key().unwrap().next(), Some(&3));

            // From before the first key: the first key, not wrapped.
            let (mut it, wrapped) = index.next_translated_key(&[0x00]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&1));
            assert_eq!(it.next(), None);

            // From k1's bucket: jumps partitions to k2's collision run (newest first).
            let (mut it, wrapped) = index.next_translated_key(&hex!("0x0b02F2")).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&22));
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), None);

            // From the last key: cycles to the first.
            let (mut it, wrapped) = index.next_translated_key(k3).unwrap();
            assert!(wrapped);
            assert_eq!(it.next(), Some(&1));

            // From the first key going backwards: cycles to the last.
            let (mut it, wrapped) = index.prev_translated_key(k1).unwrap();
            assert!(wrapped);
            assert_eq!(it.next(), Some(&3));

            // Previous bucket below 1d is 1c's collision run.
            let (mut it, wrapped) = index.prev_translated_key(&hex!("0x1d0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&22));
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), None);
        });
    }

    #[test_traced]
    fn test_soa_ordered_exhaustive_traversal() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);

            // A grid of (prefix, sub-key) keys spanning several partitions, including the edge
            // bytes 0x00/0xFF, each a distinct translated key (OneCap + P=1 orders by
            // (prefix, first sub-key byte)). `keys` is built in ascending order.
            let prefixes = [0x00u8, 0x05, 0xAA, 0xFF];
            let subkeys = [0x00u8, 0x80, 0xFF];
            let mut keys: Vec<[u8; 2]> = Vec::new();
            for &p in &prefixes {
                for &s in &subkeys {
                    keys.push([p, s]);
                }
            }
            let value_of = |k: &[u8; 2]| ((k[0] as u64) << 8) | k[1] as u64;
            let n = keys.len();

            // Insert scrambled to exercise sorted-array maintenance regardless of insertion order.
            let mut scrambled = keys.clone();
            scrambled.reverse();
            scrambled.rotate_left(5);
            for k in &scrambled {
                index.insert(k, value_of(k));
            }
            assert_eq!(index.keys(), n);

            assert_eq!(
                index.first_translated_key().unwrap().next(),
                Some(&value_of(&keys[0]))
            );
            assert_eq!(
                index.last_translated_key().unwrap().next(),
                Some(&value_of(&keys[n - 1]))
            );

            // For every key, `next` is its successor and `prev` its predecessor, wrapping at the
            // ends. This walks run_starting_at / run_ending_at across every partition boundary.
            for i in 0..n {
                let next = value_of(&keys[(i + 1) % n]);
                let (mut it, wrapped) = index.next_translated_key(&keys[i]).unwrap();
                assert_eq!(wrapped, i + 1 == n, "next wrap at index {i}");
                assert_eq!(it.next(), Some(&next), "next at {i}");
                assert_eq!(it.next(), None);

                let prev = value_of(&keys[(i + n - 1) % n]);
                let (mut it, wrapped) = index.prev_translated_key(&keys[i]).unwrap();
                assert_eq!(wrapped, i == 0, "prev wrap at index {i}");
                assert_eq!(it.next(), Some(&prev), "prev at {i}");
                assert_eq!(it.next(), None);
            }
        });
    }
}
