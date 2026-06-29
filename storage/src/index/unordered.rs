//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{storage::RunCursor, Readable, Snapshottable, Unordered},
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{collections::HashMap, sync::Arc};

/// The initial capacity of the internal hashmap. This is a guess at the number of unique keys we
/// will encounter. The hashmap will grow as needed, but this is a good starting point (covering the
/// entire [crate::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// A [crate::index::Cursor] over the values associated with a translated key.
pub type Cursor<'a, V> = RunCursor<'a, V>;

/// A memory-efficient index that uses unordered maps internally to map translated keys to arbitrary
/// values.
///
/// Snapshots use sparse run-level overlays, so the first mutation of a key after a snapshot clones
/// only that key's visible value run.
pub struct Index<T: Translator, V: Send + Sync> {
    translator: T,
    base: Arc<HashMap<T::Key, Vec<V>, T>>,
    sealed: Arc<Epoch<T, V>>,
    head: Overlay<T, V>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

/// Read-only snapshot of an unordered index.
#[derive(Clone)]
pub struct Snapshot<T: Translator, V: Send + Sync> {
    translator: T,
    base: Arc<HashMap<T::Key, Vec<V>, T>>,
    sealed: Arc<Epoch<T, V>>,
}

struct Overlay<T: Translator, V> {
    runs: HashMap<T::Key, Vec<V>, T>,
}

struct Epoch<T: Translator, V> {
    parent: Option<Arc<Self>>,
    overlay: Overlay<T, V>,
    depth: u16,
    changed_runs: usize,
}

const MAX_EPOCH_DEPTH: u16 = 8;

impl<T: Translator, V> Overlay<T, V> {
    const fn new(translator: T) -> Self {
        Self {
            runs: HashMap::with_hasher(translator),
        }
    }

    fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    fn changed_runs(&self) -> usize {
        self.runs.len()
    }

    fn run(&self, key: &T::Key) -> Option<&[V]> {
        self.runs.get(key).map(Vec::as_slice)
    }

    fn apply_to(&self, runs: &mut HashMap<T::Key, Vec<V>, T>)
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

impl<T: Translator, V> Epoch<T, V> {
    const fn empty(translator: T) -> Self {
        Self {
            parent: None,
            overlay: Overlay::new(translator),
            depth: 0,
            changed_runs: 0,
        }
    }

    fn run(&self, key: &T::Key) -> Option<&[V]> {
        self.overlay
            .run(key)
            .or_else(|| self.parent.as_deref().and_then(|parent| parent.run(key)))
    }

    fn parent_changed_runs(parent: &Option<Arc<Self>>) -> usize {
        parent.as_ref().map_or(0, |parent| parent.changed_runs)
    }

    fn apply_to(&self, runs: &mut HashMap<T::Key, Vec<V>, T>)
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

impl<T: Translator, V: Send + Sync> Index<T, V> {
    /// Create a new index with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator: translator.clone(),
            base: Arc::new(HashMap::with_capacity_and_hasher(
                INITIAL_CAPACITY,
                translator.clone(),
            )),
            sealed: Arc::new(Epoch::empty(translator.clone())),
            head: Overlay::new(translator),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    fn run(&self, key: &T::Key) -> &[V] {
        self.head
            .run(key)
            .or_else(|| self.sealed.run(key))
            .unwrap_or_else(|| self.base.get(key).map_or(&[], Vec::as_slice))
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
        self.sealed = Arc::new(Epoch::empty(self.translator.clone()));
        self.head = Overlay::new(self.translator.clone());
    }
}

impl<T: Translator, V: Send + Sync> Readable for Snapshot<T, V> {
    type Value = V;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        self.sealed
            .run(&k)
            .unwrap_or_else(|| self.base.get(&k).map_or(&[], Vec::as_slice))
            .iter()
    }
}

impl<T: Translator, V: Clone + Send + Sync + 'static> Snapshottable for Index<T, V> {
    type Value = V;
    type Snapshot = Snapshot<T, V>;

    fn snapshot(&mut self) -> Self::Snapshot {
        if !self.head.is_empty() {
            // Avoid linking the empty root epoch.
            let parent = (self.sealed.depth > 0).then(|| Arc::clone(&self.sealed));
            let overlay = std::mem::replace(&mut self.head, Overlay::new(self.translator.clone()));
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

impl<T: Translator, V: Clone + Send + Sync> super::Factory<T> for Index<T, V> {
    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Clone + Send + Sync> Unordered for Index<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        self.run(&k).iter()
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

    fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        let run = self.ensure_run(k);
        let new_key = run.is_empty();
        run.insert(0, v);
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
}
