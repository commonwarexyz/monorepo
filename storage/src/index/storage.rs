use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{hash_map::Entry, HashMap},
    ptr::NonNull,
};

/// The initial capacity of the hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Each key is mapped to a `Record` that contains either the value or a pointer to a `Vec` of values.
///
/// In the common case (where a single value is associated with a key), we store the value directly in the `Record`
/// to avoid both indirection (heap jumping) and unnecessary allocations (storing `Vec` directly would make all
/// `Record`s larger).
#[allow(clippy::box_collection)]
enum Record<V> {
    One(V),
    Many(Box<Vec<V>>),
}

/// An iterator over the value at some translated key.
pub struct Iterator<'a, V> {
    slice: &'a [V],
    idx: usize,
}

impl<V> Iterator<'_, V> {
    #[inline]
    fn empty() -> Self {
        Self { slice: &[], idx: 0 }
    }
}

impl<'a, V> std::iter::Iterator for Iterator<'a, V> {
    type Item = &'a V;
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == 0 {
            return None;
        }
        self.idx -= 1;
        self.slice.get(self.idx)
    }
}

impl<V> Record<V> {
    /// Return an iterator over the values in the `Record`.
    fn iter(&self) -> Iterator<'_, V> {
        match self {
            Record::One(v) => Iterator {
                slice: std::slice::from_ref(v),
                idx: 1,
            },
            Record::Many(boxed) => Iterator {
                slice: boxed,
                idx: boxed.len(),
            },
        }
    }

    /// Return a mutable reference to the `Vec` of values in the `Record`,
    /// migrating from `One` to `Many` if necessary.
    fn as_vec_mut(&mut self) -> &mut Vec<V> {
        match self {
            Record::Many(ref mut boxed) => boxed.as_mut(),
            Record::One(_) => unsafe {
                // Move the value out of `self` without running its destructor.
                let v = match std::ptr::read(self) {
                    Record::One(val) => val,
                    _ => unreachable!(),
                };

                // Overwrite `self` with a fresh Many(vec![v]).
                *self = Record::Many(Box::new(vec![v]));

                // Return a mutable ref to that new vector.
                match self {
                    Record::Many(boxed) => boxed.as_mut(),
                    _ => unreachable!(),
                }
            },
        }
    }
}

/// A mutable iterator over the values at some translated key.
pub struct MutableIterator<'a, T: Translator, V> {
    map: NonNull<HashMap<T::Key, Record<V>, T>>,
    key: T::Key,
    values: &'a mut Vec<V>,

    idx: usize,
    last_idx: Option<usize>,

    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V> std::iter::Iterator for MutableIterator<'a, T, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        // Walk backwards over the `Vec` (preferring the most recently added value).
        if self.idx == 0 || self.values.is_empty() {
            return None;
        }
        self.idx -= 1;
        let i = self.idx;

        // SAFETY: i is in‐bounds, and we hold exclusive &mut to the Vec
        let elem = unsafe { &mut *self.values.as_mut_ptr().add(i) };
        self.last_idx = Some(i);
        Some(elem)
    }
}

impl<T: Translator, V> MutableIterator<'_, T, V> {
    /// Insert a new value at the start of the iterator.
    ///
    /// This operation will prevent the iterator from being used again (although
    /// it is possible to call `insert()` multiple times).
    ///
    /// If you want to instead update some existing value, use `next()` to get a mutable reference
    /// and then update it directly.
    ///
    /// This is more efficient than calling `index::insert()` after iteration.
    pub fn insert(&mut self, v: V) {
        self.values.push(v);
        let values_len = self.values.len();
        if values_len > 1 {
            self.collisions.inc();
        }

        // Stop the iterator.
        self.idx = 0;
        self.last_idx = None;
    }

    /// Remove the last value returned by `next()` (swapping it with the most recently added value for the
    /// translated key).
    ///
    /// This is a no-op if `next()` has not been called or `remove()` is called multiple times without
    /// calling `next()` after each `remove()`.
    pub fn remove(&mut self) {
        let Some(i) = self.last_idx.take() else {
            return;
        };
        self.values.swap_remove(i);
        self.pruned.inc();
        if i < self.idx {
            self.idx -= 1;
        }
    }
}

impl<T: Translator, V> Drop for MutableIterator<'_, T, V> {
    /// When the iterator is dropped, check if the `Vec` is empty (delete from the map) or
    /// if it has only one value (demote to `One`).
    fn drop(&mut self) {
        unsafe {
            let map = self.map.as_mut();
            match self.values.len() {
                0 => {
                    // We have no values left, so remove the entry from the map.
                    map.remove(&self.key);
                }
                1 => {
                    // We have only one value left, so demote to `One`.
                    let v = self.values.pop().unwrap();
                    *map.get_mut(&self.key).unwrap() = Record::One(v);
                }
                _ => {
                    // We have more than one value left, so do nothing.
                }
            }
        }
    }
}

/// A memory-efficient index that maps translated keys to arbitrary values.
pub struct Index<T: Translator, V> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,
    collisions: Counter,
    keys_pruned: Counter,
}

impl<T: Translator, V> Index<T, V> {
    /// Create a new index with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),
            collisions: Counter::default(),
            keys_pruned: Counter::default(),
        };
        ctx.register("pruned", "Number of keys pruned", s.keys_pruned.clone());
        ctx.register(
            "collisions",
            "Number of translated key collisions",
            s.collisions.clone(),
        );
        s
    }

    /// Return the number of translated keys in the index (there may
    /// be many more total entries, with multiple keys per translated
    /// key).
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return whether the index is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Create an immutable iterator over the values at the given translated key.
    pub fn iter(&self, key: &[u8]) -> Iterator<V> {
        self.map
            .get(&self.translator.transform(key))
            .map(|r| r.iter())
            .unwrap_or_else(Iterator::empty)
    }

    /// Create a mutable iterator over the values at the given translated key.
    pub fn mut_iter(&mut self, key: &[u8]) -> MutableIterator<'_, T, V> {
        let key = self.translator.transform(key);
        let mut map = NonNull::from(&mut self.map);
        let values = unsafe {
            map.as_mut()
                .entry(key)
                .or_insert_with(|| Record::Many(Box::new(Vec::new())))
                .as_vec_mut()
        };
        let idx = values.len();
        MutableIterator {
            map,
            key,
            values,

            idx,
            last_idx: None,

            collisions: &self.collisions,
            pruned: &self.keys_pruned,
        }
    }

    /// Insert a value at the given translated key.
    ///
    /// If no value exists at the key, inserting via `insert()` will be more efficient than
    /// `mut_iter()` + `insert()`.
    pub fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut occ) => {
                occ.get_mut().as_vec_mut().push(v);
                self.collisions.inc();
            }
            Entry::Vacant(vac) => {
                vac.insert(Record::One(v));
            }
        }
    }

    /// Insert a value at the given translated key, and prune any values that are no longer valid.
    ///
    /// If no value exists at the key or only 1 value exists at a key, inserting via `insert_and_prune()`
    /// will be more efficient than `mut_iter()` + `remove()` + `insert()`.
    pub fn insert_and_prune(&mut self, key: &[u8], v: V, prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut occ) => {
                // Track collision regardless of what happens.
                self.collisions.inc();

                // If there is only 1 value and that value should be pruned, we can just replace it.
                let entry = occ.get_mut();
                if let Record::One(ref mut v1) = entry {
                    if prune(v1) {
                        *v1 = v;
                        self.keys_pruned.inc();
                        return;
                    }
                }

                // If there is more than 1 value, we need to iterate.
                let vec = entry.as_vec_mut();

                // Remove any items that are no longer valid (to avoid extending vec unnecessarily)
                let previous = vec.len();
                vec.retain(|v| !prune(v));
                let pruned = previous - vec.len();
                if pruned > 0 {
                    self.keys_pruned.inc_by(pruned as u64);
                }

                // Add the new value to the end of the vector.
                vec.push(v);

                // If there is only 1 value left, we can demote to `One`.
                if vec.len() == 1 {
                    let v = vec.pop().unwrap();
                    *entry = Record::One(v);
                }
            }
            Entry::Vacant(vac) => {
                vac.insert(Record::One(v));
            }
        }
    }

    /// Remove a value at the given translated key, and prune any values that are no longer valid.
    ///
    /// If no value exists at the key or only 1 value exists at a key, this is more efficient than
    /// `mut_iter()` + `remove()`.
    pub fn remove(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut occ) => {
                // If there is only 1 value and that value should be pruned, we can just remove it.
                let entry = occ.get_mut();
                if let Record::One(ref mut v1) = entry {
                    if prune(v1) {
                        occ.remove_entry();
                        self.keys_pruned.inc();
                        return;
                    }
                }

                // If there is more than 1 value, we need to iterate.
                let vec = entry.as_vec_mut();
                let previous = vec.len();
                vec.retain(|v| !prune(v));
                let pruned = previous - vec.len();
                if pruned > 0 {
                    self.keys_pruned.inc_by(pruned as u64);
                }

                // If there are no values left, we can remove the entry.
                // If there is only 1 value left, we can demote to `One`.
                match vec.len() {
                    0 => {
                        occ.remove_entry();
                        self.keys_pruned.inc();
                    }
                    1 => {
                        let v = vec.pop().unwrap();
                        *entry = Record::One(v);
                    }
                    _ => {}
                }
            }
            Entry::Vacant(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{translator::TwoCap, Translator};
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic;

    #[test_traced]
    fn demote_many_to_one() {
        let ctx = deterministic::Context::default();
        let mut ix = Index::<TwoCap, u64>::init(ctx, TwoCap);
        let kb = b"k";

        ix.insert(kb, 1);
        ix.insert(kb, 2);

        {
            let mut it = ix.mut_iter(kb);
            it.next();
            it.remove(); // remove newest
        } // drop should demote

        let key = TwoCap.transform(kb);
        match ix.map.get(&key).unwrap() {
            Record::One(v) => assert_eq!(*v, 1),
            _ => panic!("expected One"),
        }
    }
}
