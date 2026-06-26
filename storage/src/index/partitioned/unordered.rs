//! The unordered variant of a partitioned index.

use crate::{
    index::{
        partitioned::partition_index_and_sub_key, storage::RunCursor, Readable, Snapshottable,
        Unordered as UnorderedTrait,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{collections::HashMap, sync::Arc};

const MAX_EPOCH_DEPTH: u16 = 8;

type Partition<T, V> = HashMap<<T as Translator>::Key, Vec<V>, T>;

/// A partitioned index that maps translated keys to values. The first `P` bytes of the
/// untranslated key select a partition, and the translator maps the key after stripping this
/// prefix. The value of `P` should be small, typically 1 or 2. Anything larger than 3 will fail to
/// compile.
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    translator: T,
    base: Arc<Base<T, V>>,
    sealed: Arc<Epoch<T, V>>,
    head: Overlay<T, V>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

/// Read-only snapshot of a partitioned unordered index.
#[derive(Clone)]
pub struct Snapshot<T: Translator, V: Send + Sync, const P: usize> {
    translator: T,
    base: Arc<Base<T, V>>,
    sealed: Arc<Epoch<T, V>>,
}

struct Base<T: Translator, V> {
    partitions: Box<[Partition<T, V>]>,
}

struct Overlay<T: Translator, V> {
    // Used to build per-partition maps with the same hasher.
    translator: T,
    partitions: HashMap<usize, Partition<T, V>>,
}

struct Epoch<T: Translator, V> {
    parent: Option<Arc<Self>>,
    overlay: Overlay<T, V>,
    depth: u16,
    changed_runs: usize,
}

impl<T: Translator, V> Overlay<T, V> {
    fn new(translator: T) -> Self {
        Self {
            translator,
            partitions: HashMap::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    fn changed_runs(&self) -> usize {
        self.partitions.values().map(HashMap::len).sum()
    }

    fn run(&self, i: usize, key: &T::Key) -> Option<&[V]> {
        self.partitions
            .get(&i)
            .and_then(|partition| partition.get(key))
            .map(Vec::as_slice)
    }

    fn partition_mut(&mut self, i: usize) -> &mut Partition<T, V> {
        self.partitions
            .entry(i)
            .or_insert_with(|| HashMap::with_hasher(self.translator.clone()))
    }

    fn apply_to_partition(&self, i: usize, runs: &mut Partition<T, V>)
    where
        V: Clone,
    {
        let Some(partition) = self.partitions.get(&i) else {
            return;
        };
        for (key, values) in partition {
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
    fn empty(translator: T) -> Self {
        Self {
            parent: None,
            overlay: Overlay::new(translator),
            depth: 0,
            changed_runs: 0,
        }
    }

    fn run(&self, i: usize, key: &T::Key) -> Option<&[V]> {
        self.overlay
            .run(i, key)
            .or_else(|| self.parent.as_deref().and_then(|parent| parent.run(i, key)))
    }

    fn parent_changed_runs(parent: &Option<Arc<Self>>) -> usize {
        parent.as_ref().map_or(0, |parent| parent.changed_runs)
    }

    fn apply_to_partition(&self, i: usize, runs: &mut Partition<T, V>)
    where
        V: Clone,
    {
        // Apply oldest to newest so later overlays win.
        if let Some(parent) = &self.parent {
            parent.apply_to_partition(i, runs);
        }
        self.overlay.apply_to_partition(i, runs);
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        const {
            assert!(P > 0 && P <= 3, "P must be in 1..=3");
        }
        let count = 1usize << (P * 8);
        let partitions = (0..count)
            .map(|_| HashMap::with_hasher(translator.clone()))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            translator: translator.clone(),
            base: Arc::new(Base { partitions }),
            sealed: Arc::new(Epoch::empty(translator.clone())),
            head: Overlay::new(translator),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    const fn count(&self) -> usize {
        1usize << (P * 8)
    }

    fn run(&self, i: usize, key: &T::Key) -> &[V] {
        self.head
            .run(i, key)
            .or_else(|| self.sealed.run(i, key))
            .unwrap_or_else(|| self.base.partitions[i].get(key).map_or(&[], Vec::as_slice))
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> Index<T, V, P> {
    fn ensure_run(&mut self, i: usize, key: T::Key) -> &mut Vec<V> {
        if self
            .head
            .partitions
            .get(&i)
            .is_some_and(|partition| partition.contains_key(&key))
        {
            return self
                .head
                .partitions
                .get_mut(&i)
                .unwrap()
                .get_mut(&key)
                .unwrap();
        }

        // First mutation after a snapshot clones the visible run.
        let run = self
            .sealed
            .run(i, &key)
            .unwrap_or_else(|| self.base.partitions[i].get(&key).map_or(&[], Vec::as_slice))
            .to_vec();
        self.head.partition_mut(i).entry(key).or_insert(run)
    }

    /// Returns whether sealed overlays should be merged into the base soon.
    pub fn needs_compaction(&self) -> bool {
        self.sealed.depth >= MAX_EPOCH_DEPTH
            || self.sealed.changed_runs >= (self.keys.get() as usize).max(1)
    }

    /// Merge sealed overlays and the live head into a new base.
    pub fn compact(&mut self) {
        let count = self.count();
        let partitions = (0..count)
            .map(|i| {
                let mut runs = self.base.partitions[i].clone();
                self.sealed.apply_to_partition(i, &mut runs);
                self.head.apply_to_partition(i, &mut runs);
                runs
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.base = Arc::new(Base { partitions });
        self.sealed = Arc::new(Epoch::empty(self.translator.clone()));
        self.head = Overlay::new(self.translator.clone());
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Readable for Snapshot<T, V, P> {
    type Value = V;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + Send + 'a
    where
        V: 'a,
    {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        self.sealed
            .run(i, &k)
            .unwrap_or_else(|| self.base.partitions[i].get(&k).map_or(&[], Vec::as_slice))
            .iter()
    }
}

impl<T: Translator, V: Clone + Send + Sync + 'static, const P: usize> Snapshottable
    for Index<T, V, P>
{
    type Value = V;
    type Snapshot = Snapshot<T, V, P>;

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

impl<T: Translator, V: Clone + Send + Sync, const P: usize> super::super::Factory<T>
    for Index<T, V, P>
{
    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> UnorderedTrait for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = RunCursor<'a, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a,
    {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        self.run(i, &k).iter()
    }

    fn get_many<'a, K: AsRef<[u8]>>(
        &'a self,
        keys: &[K],
        mut visit: impl FnMut(usize, &'a Self::Value),
    ) where
        Self::Value: 'a,
    {
        let mut order: Vec<(usize, T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| {
                let (partition, sub_key) = partition_index_and_sub_key::<P>(key.as_ref());
                (partition, self.translator.transform(sub_key), key_idx)
            })
            .collect();
        order.sort_unstable();
        for (partition, translated, key_idx) in order {
            for value in self.run(partition, &translated) {
                visit(key_idx, value);
            }
        }
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        if self.run(i, &k).is_empty() {
            return None;
        }
        let keys = self.keys.clone();
        let items = self.items.clone();
        let pruned = self.pruned.clone();
        Some(RunCursor::new(self.ensure_run(i, k), keys, items, pruned))
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        if !self.run(i, &k).is_empty() {
            let keys = self.keys.clone();
            let items = self.items.clone();
            let pruned = self.pruned.clone();
            return Some(RunCursor::new(self.ensure_run(i, k), keys, items, pruned));
        }
        self.ensure_run(i, k).push(value);
        self.keys.inc();
        self.items.inc();
        None
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        let run = self.ensure_run(i, k);
        let new_key = run.is_empty();
        run.insert(0, value);
        self.items.inc();
        if new_key {
            self.keys.inc();
        }
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: Self::Value,
        should_retain: impl Fn(&Self::Value) -> bool,
    ) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        let had_key = !self.run(i, &k).is_empty();
        let retain_new = should_retain(&value);
        let (pruned, created, emptied) = {
            let run = self.ensure_run(i, k);
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
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub_key);
        if self.run(i, &k).is_empty() {
            return;
        }
        let run = self.ensure_run(i, k);
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

    impl<T: Translator, V: Clone + Send + Sync, const P: usize> Index<T, V, P> {
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
