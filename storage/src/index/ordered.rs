//! Implementation of [Ordered] that uses an ordered map internally to map translated keys to
//! arbitrary values. Beyond the standard [Unordered] implementation, this variant adds the
//! capability to retrieve values associated with both next and previous translated keys of a given
//! key. There is no ordering guarantee provided over the values associated with each key. Ordering
//! applies only to the _translated_ key space.

use crate::{
    index::{storage::RunCursor, Ordered, OrderedReadable, Readable, Snapshottable, Unordered},
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{
    collections::BTreeMap,
    ops::Bound::{Excluded, Unbounded},
    sync::Arc,
};

/// A [crate::index::Cursor] over the values associated with a translated key.
pub type Cursor<'a, V> = RunCursor<'a, V>;

/// A memory-efficient index that uses ordered maps internally to map translated keys to arbitrary
/// values.
///
/// Snapshots use sparse run-level overlays, so the first mutation of a key after a snapshot clones
/// only that key's visible value run.
pub struct Index<T: Translator, V: Send + Sync> {
    translator: T,
    base: Arc<BTreeMap<T::Key, Vec<V>>>,
    sealed: Arc<Epoch<T::Key, V>>,
    head: Overlay<T::Key, V>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

/// Read-only snapshot of an ordered index.
#[derive(Clone)]
pub struct Snapshot<T: Translator, V: Send + Sync> {
    translator: T,
    base: Arc<BTreeMap<T::Key, Vec<V>>>,
    sealed: Arc<Epoch<T::Key, V>>,
}

struct Overlay<K, V> {
    runs: BTreeMap<K, Vec<V>>,
}

impl<K, V> Default for Overlay<K, V> {
    fn default() -> Self {
        Self {
            runs: BTreeMap::new(),
        }
    }
}

struct Epoch<K, V> {
    parent: Option<Arc<Self>>,
    overlay: Overlay<K, V>,
    depth: u16,
    changed_runs: usize,
}

const MAX_EPOCH_DEPTH: u16 = 8;

impl<K: Ord + Copy, V> Overlay<K, V> {
    fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    fn changed_runs(&self) -> usize {
        self.runs.len()
    }

    fn run(&self, key: &K) -> Option<&[V]> {
        self.runs.get(key).map(Vec::as_slice)
    }

    fn next_key(&self, after: Option<K>) -> Option<K> {
        after.map_or_else(
            || self.runs.first_key_value().map(|(key, _)| *key),
            |key| {
                self.runs
                    .range((Excluded(key), Unbounded))
                    .next()
                    .map(|(key, _)| *key)
            },
        )
    }

    fn prev_key(&self, before: Option<K>) -> Option<K> {
        before.map_or_else(
            || self.runs.last_key_value().map(|(key, _)| *key),
            |key| self.runs.range(..key).next_back().map(|(key, _)| *key),
        )
    }

    fn apply_to(&self, runs: &mut BTreeMap<K, Vec<V>>)
    where
        V: Clone,
    {
        for (key, values) in &self.runs {
            // Empty runs are tombstones that mask older/base values.
            if values.is_empty() {
                runs.remove(key);
            } else {
                runs.insert(*key, values.clone());
            }
        }
    }
}

impl<K: Ord + Copy, V> Epoch<K, V> {
    fn empty() -> Self {
        Self {
            parent: None,
            overlay: Overlay::default(),
            depth: 0,
            changed_runs: 0,
        }
    }

    fn run(&self, key: &K) -> Option<&[V]> {
        self.overlay
            .run(key)
            .or_else(|| self.parent.as_deref().and_then(|parent| parent.run(key)))
    }

    fn parent_changed_runs(parent: &Option<Arc<Self>>) -> usize {
        parent.as_ref().map_or(0, |parent| parent.changed_runs)
    }

    fn next_key(&self, after: Option<K>) -> Option<K> {
        let parent = self
            .parent
            .as_deref()
            .and_then(|parent| parent.next_key(after));
        next_candidate(after, [self.overlay.next_key(after), parent])
    }

    fn prev_key(&self, before: Option<K>) -> Option<K> {
        let parent = self
            .parent
            .as_deref()
            .and_then(|parent| parent.prev_key(before));
        prev_candidate(before, [self.overlay.prev_key(before), parent])
    }

    fn apply_to(&self, runs: &mut BTreeMap<K, Vec<V>>)
    where
        V: Clone,
    {
        // Apply oldest to newest so later overlays win.
        if let Some(parent) = &self.parent {
            parent.apply_to(runs);
        }
        self.overlay.apply_to(runs);
    }
}

fn base_next_key<K: Ord + Copy, V>(base: &BTreeMap<K, Vec<V>>, after: Option<K>) -> Option<K> {
    after.map_or_else(
        || base.first_key_value().map(|(key, _)| *key),
        |key| {
            base.range((Excluded(key), Unbounded))
                .next()
                .map(|(key, _)| *key)
        },
    )
}

fn base_prev_key<K: Ord + Copy, V>(base: &BTreeMap<K, Vec<V>>, before: Option<K>) -> Option<K> {
    before.map_or_else(
        || base.last_key_value().map(|(key, _)| *key),
        |key| base.range(..key).next_back().map(|(key, _)| *key),
    )
}

fn next_candidate<K: Ord + Copy>(
    after: Option<K>,
    candidates: impl IntoIterator<Item = Option<K>>,
) -> Option<K> {
    candidates
        .into_iter()
        .flatten()
        .filter(|candidate| after.is_none_or(|after| *candidate > after))
        .min()
}

fn prev_candidate<K: Ord + Copy>(
    before: Option<K>,
    candidates: impl IntoIterator<Item = Option<K>>,
) -> Option<K> {
    candidates
        .into_iter()
        .flatten()
        .filter(|candidate| before.is_none_or(|before| *candidate < before))
        .max()
}

impl<T: Translator, V: Send + Sync> Index<T, V> {
    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator,
            base: Arc::new(BTreeMap::new()),
            sealed: Arc::new(Epoch::empty()),
            head: Overlay::default(),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Returns an iterator over all values associated with an already-translated key.
    pub(super) fn get_translated(&self, key: T::Key) -> std::slice::Iter<'_, V> {
        self.run(&key).iter()
    }

    fn run(&self, key: &T::Key) -> &[V] {
        self.head
            .run(key)
            .or_else(|| self.sealed.run(key))
            .unwrap_or_else(|| self.base.get(key).map_or(&[], Vec::as_slice))
    }

    fn next_key(&self, after: Option<T::Key>) -> Option<T::Key> {
        next_candidate(
            after,
            [
                self.head.next_key(after),
                self.sealed.next_key(after),
                base_next_key(&self.base, after),
            ],
        )
    }

    fn prev_key(&self, before: Option<T::Key>) -> Option<T::Key> {
        prev_candidate(
            before,
            [
                self.head.prev_key(before),
                self.sealed.prev_key(before),
                base_prev_key(&self.base, before),
            ],
        )
    }

    /// Returns an iterator over the values of the translated key that lexicographically follows
    /// `after`, or None if no such key exists.
    fn next_values(&self, after: Option<T::Key>) -> Option<std::slice::Iter<'_, V>> {
        let mut after = after;
        while let Some(candidate) = self.next_key(after) {
            let values = self.run(&candidate);
            // Overlay keys can be tombstones, so skip empty visible runs.
            if !values.is_empty() {
                return Some(values.iter());
            }
            after = Some(candidate);
        }
        None
    }

    /// Returns an iterator over the values of the translated key that lexicographically precedes
    /// `before`, or None if no such key exists.
    fn prev_values(&self, before: Option<T::Key>) -> Option<std::slice::Iter<'_, V>> {
        let mut before = before;
        while let Some(candidate) = self.prev_key(before) {
            let values = self.run(&candidate);
            if !values.is_empty() {
                return Some(values.iter());
            }
            before = Some(candidate);
        }
        None
    }
}

impl<T: Translator, V: Clone + Send + Sync> Index<T, V> {
    fn ensure_run(&mut self, key: T::Key) -> &mut Vec<V> {
        if self.head.runs.contains_key(&key) {
            return self.head.runs.get_mut(&key).unwrap();
        }

        // First mutation after a snapshot clones the visible run.
        let run = self
            .sealed
            .run(&key)
            .unwrap_or_else(|| self.base.get(&key).map_or(&[], Vec::as_slice))
            .to_vec();
        self.head.runs.entry(key).or_insert(run)
    }

    /// Returns whether sealed overlays should be merged into the base soon.
    pub fn needs_compaction(&self) -> bool {
        self.sealed.depth >= MAX_EPOCH_DEPTH
            || self.sealed.changed_runs >= (self.keys.get() as usize).max(1)
    }

    /// Merge sealed overlays and the live head into a new base.
    pub fn compact(&mut self) {
        let mut runs = self.base.as_ref().clone();
        self.sealed.apply_to(&mut runs);
        self.head.apply_to(&mut runs);
        self.base = Arc::new(runs);
        self.sealed = Arc::new(Epoch::empty());
        self.head = Overlay::default();
    }
}

impl<T: Translator, V: Send + Sync> Snapshot<T, V> {
    fn run(&self, key: &T::Key) -> &[V] {
        self.sealed
            .run(key)
            .unwrap_or_else(|| self.base.get(key).map_or(&[], Vec::as_slice))
    }

    fn get_translated(&self, key: T::Key) -> std::slice::Iter<'_, V> {
        self.run(&key).iter()
    }

    fn next_key(&self, after: Option<T::Key>) -> Option<T::Key> {
        next_candidate(
            after,
            [
                self.sealed.next_key(after),
                base_next_key(&self.base, after),
            ],
        )
    }

    fn prev_key(&self, before: Option<T::Key>) -> Option<T::Key> {
        prev_candidate(
            before,
            [
                self.sealed.prev_key(before),
                base_prev_key(&self.base, before),
            ],
        )
    }

    /// Returns an iterator over the values of the translated key that lexicographically follows
    /// `after`, or None if no such key exists.
    fn next_values(&self, after: Option<T::Key>) -> Option<std::slice::Iter<'_, V>> {
        let mut after = after;
        while let Some(candidate) = self.next_key(after) {
            let values = self.run(&candidate);
            if !values.is_empty() {
                return Some(values.iter());
            }
            after = Some(candidate);
        }
        None
    }

    /// Returns an iterator over the values of the translated key that lexicographically precedes
    /// `before`, or None if no such key exists.
    fn prev_values(&self, before: Option<T::Key>) -> Option<std::slice::Iter<'_, V>> {
        let mut before = before;
        while let Some(candidate) = self.prev_key(before) {
            let values = self.run(&candidate);
            if !values.is_empty() {
                return Some(values.iter());
            }
            before = Some(candidate);
        }
        None
    }
}

impl<T: Translator, V: Send + Sync> Readable for Snapshot<T, V> {
    type Value = V;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        self.get_translated(self.translator.transform(key))
    }

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
        let mut order: Vec<(T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| (self.translator.transform(key.as_ref()), key_idx))
            .collect();
        order.sort_unstable();
        for (translated, key_idx) in order {
            for value in self.get_translated(translated) {
                visit(key_idx, value);
            }
        }
    }
}

impl<T: Translator, V: Send + Sync> OrderedReadable for Snapshot<T, V> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        if let Some(values) = self.prev_values(Some(k)) {
            return Some((values, false));
        }
        self.prev_values(None).map(|values| (values, true))
    }

    fn next_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        if let Some(values) = self.next_values(Some(k)) {
            return Some((values, false));
        }
        self.next_values(None).map(|values| (values, true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.next_values(None)
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.prev_values(None)
    }
}

impl<T: Translator, V: Clone + Send + Sync + 'static> Snapshottable for Index<T, V> {
    type Value = V;
    type Snapshot = Snapshot<T, V>;

    fn snapshot(&mut self) -> Self::Snapshot {
        if !self.head.is_empty() {
            // Avoid linking the empty root epoch.
            let parent = (self.sealed.depth > 0).then(|| Arc::clone(&self.sealed));
            let overlay = std::mem::take(&mut self.head);
            self.sealed = Arc::new(Epoch {
                changed_runs: Epoch::parent_changed_runs(&parent) + overlay.changed_runs(),
                depth: self.sealed.depth + 1,
                parent,
                overlay,
            });
        }
        Snapshot {
            translator: self.translator.clone(),
            base: Arc::clone(&self.base),
            sealed: Arc::clone(&self.sealed),
        }
    }
}

impl<T: Translator, V: Clone + Send + Sync> Ordered for Index<T, V> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        if let Some(values) = self.prev_values(Some(k)) {
            return Some((values, false));
        }
        self.prev_values(None).map(|values| (values, true))
    }

    fn next_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        if let Some(values) = self.next_values(Some(k)) {
            return Some((values, false));
        }
        self.next_values(None).map(|values| (values, true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.next_values(None)
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.prev_values(None)
    }
}

impl<T: Translator, V: Clone + Send + Sync> super::Factory<T> for Index<T, V> {
    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Clone + Send + Sync> Unordered for Index<T, V> {
    type Value = V;

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
        // Probe in translated-key order: consecutive tree descents share upper node paths,
        // which stay cache-resident across the batch.
        let mut order: Vec<(T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| (self.translator.transform(key.as_ref()), key_idx))
            .collect();
        order.sort_unstable();
        for (translated, key_idx) in order {
            for value in self.get_translated(translated) {
                visit(key_idx, value);
            }
        }
    }
    type Cursor<'a>
        = Cursor<'a, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a
    where
        V: 'a,
    {
        self.get_translated(self.translator.transform(key))
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        if self.run(&k).is_empty() {
            return None;
        }
        let keys = self.keys.clone();
        let items = self.items.clone();
        let pruned = self.pruned.clone();
        Some(RunCursor::new(self.ensure_run(k), keys, items, pruned))
    }

    fn get_mut_or_insert<'a>(&'a mut self, key: &[u8], value: V) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        if !self.run(&k).is_empty() {
            let keys = self.keys.clone();
            let items = self.items.clone();
            let pruned = self.pruned.clone();
            return Some(RunCursor::new(self.ensure_run(k), keys, items, pruned));
        }
        self.ensure_run(k).push(value);
        self.keys.inc();
        self.items.inc();
        None
    }

    fn insert(&mut self, key: &[u8], value: V) {
        let k = self.translator.transform(key);
        let run = self.ensure_run(k);
        let new_key = run.is_empty();
        run.insert(0, value);
        self.items.inc();
        if new_key {
            self.keys.inc();
        }
    }

    fn insert_and_retain(&mut self, key: &[u8], value: V, should_retain: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        let had_key = !self.run(&k).is_empty();
        let retain_new = should_retain(&value);
        let (pruned, created, emptied) = {
            let run = self.ensure_run(k);
            let before = run.len();
            run.retain(&should_retain);
            let pruned = before - run.len();
            let created = retain_new && !had_key && run.is_empty();
            if retain_new {
                run.push(value);
            }
            let emptied = !retain_new && had_key && run.is_empty();
            (pruned, created, emptied)
        };
        if pruned > 0 {
            self.items.dec_by(pruned as i64);
            self.pruned.inc_by(pruned as u64);
        }
        if retain_new {
            if created {
                self.keys.inc();
            }
            self.items.inc();
        } else if emptied {
            self.keys.dec();
        }
    }

    fn remove(&mut self, key: &[u8]) {
        let k = self.translator.transform(key);
        if self.run(&k).is_empty() {
            return;
        }
        let run = self.ensure_run(k);
        let n = run.len();
        run.clear();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::OneCap;
    use commonware_formatting::hex;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    impl<T: Translator, V: Clone + Send + Sync> Index<T, V> {
        pub(crate) fn epoch_depth(&self) -> u16 {
            self.sealed.depth
        }

        pub(crate) fn changed_runs(&self) -> usize {
            self.sealed.changed_runs
        }

        pub(crate) fn head_changed_runs(&self) -> usize {
            self.head.changed_runs()
        }
    }

    #[test_traced]
    fn test_ordered_empty_index() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let index = Index::<_, u64>::new(context, OneCap);

            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.prev_translated_key(b"key").is_none());
            assert!(index.next_translated_key(b"key").is_none());
        });
    }

    #[test_traced]
    fn test_ordered_index_ordering() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = Index::<_, u64>::new(context, OneCap);
            assert_eq!(index.keys(), 0);

            let k1 = &hex!("0x0b02AA"); // translated key 0b
            let k2 = &hex!("0x1c04CC"); // translated key 1c
            let k2_collides = &hex!("0x1c0311");
            let k3 = &hex!("0x2d06EE"); // translated key 2d
            index.insert(k1, 1);
            index.insert(k2, 21);
            index.insert(k2_collides, 22);
            index.insert(k3, 3);
            assert_eq!(index.keys(), 3);

            // First translated key is 0b.
            let mut next = index.first_translated_key().unwrap();
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Next translated key to 0x00 is 0b.
            let (mut next, wrapped) = index.next_translated_key(&[0x00]).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Next translated key to 0x0b is 1c.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x0b0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &22);
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next(), None);

            // Next translated key to 0x1b is 1c.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x1b010203")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &22);
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next(), None);

            // Next translated key to 0x2a is 2d.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x2a01020304")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &3);
            assert_eq!(next.next(), None);

            // Next translated key to 0x2d cycles around to 0x0b.
            let (mut next, wrapped) = index.next_translated_key(k3).unwrap();
            assert!(wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Another cycle-around case.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x2eFF")).unwrap();
            assert!(wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Previous translated key of first key is the last key.
            let (mut prev, wrapped) = index.prev_translated_key(k1).unwrap();
            assert!(wrapped);
            assert_eq!(prev.next().unwrap(), &3);
            assert_eq!(prev.next(), None);

            // Previous translated key is 0b.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0x0c0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &1);
            assert_eq!(prev.next(), None);

            // Previous translated key is 1c.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0x1d0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &22);
            assert_eq!(prev.next().unwrap(), &21);
            assert_eq!(prev.next(), None);

            // Previous translated key is 2d.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0xCC0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &3);
            assert_eq!(prev.next(), None);

            // Last translated key is 2d.
            let mut last = index.last_translated_key().unwrap();
            assert_eq!(last.next().unwrap(), &3);
            assert_eq!(last.next(), None);
        });
    }
}
