use super::{Config, Translator};
use crate::{
    archive::{Error, Identifier},
    index::{unordered::Index, Unordered},
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    rmap::RMap,
};
use commonware_codec::{CodecShared, FixedSize, Read, ReadExt, Write};
use commonware_macros::boxed;
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
    Buf, BufMut, BufferPooler, Metrics, Storage,
};
use commonware_utils::{sync::Mutex, Array};
use futures::{future::try_join_all, pin_mut, StreamExt};
use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::debug;

/// Index entry for the archive.
#[derive(Debug, Clone, PartialEq)]
struct Record<K: Array> {
    /// The index for this entry.
    index: u64,
    /// The key for this entry.
    key: K,
    /// Byte offset in value journal (same section).
    value_offset: u64,
    /// Size of value data in the value journal.
    value_size: u32,
}

impl<K: Array> Record<K> {
    /// Create a new [Record].
    const fn new(index: u64, key: K, value_offset: u64, value_size: u32) -> Self {
        Self {
            index,
            key,
            value_offset,
            value_size,
        }
    }
}

impl<K: Array> Write for Record<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.key.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl<K: Array> Read for Record<K> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let index = u64::read(buf)?;
        let key = K::read(buf)?;
        let value_offset = u64::read(buf)?;
        let value_size = u32::read(buf)?;
        Ok(Self {
            index,
            key,
            value_offset,
            value_size,
        })
    }
}

impl<K: Array> FixedSize for Record<K> {
    // index + key + value_offset + value_size
    const SIZE: usize = u64::SIZE + K::SIZE + u64::SIZE + u32::SIZE;
}

impl<K: Array> OversizedRecord for Record<K> {
    fn value_location(&self) -> (u64, u32) {
        (self.value_offset, self.value_size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.value_offset = offset;
        self.value_size = size;
        self
    }
}

#[cfg(feature = "arbitrary")]
impl<K: Array> arbitrary::Arbitrary<'_> for Record<K>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            index: u64::arbitrary(u)?,
            key: K::arbitrary(u)?,
            value_offset: u64::arbitrary(u)?,
            value_size: u32::arbitrary(u)?,
        })
    }
}

struct State<T: Translator, K: Array> {
    pending: BTreeSet<u64>,
    /// Oldest allowed section to read from. Updated when `prune` is called.
    oldest_allowed: Option<u64>,
    /// Maps translated key representation to its corresponding index.
    keys: Index<T, u64>,
    /// Maps index to its first position in the index journal.
    indices: BTreeMap<u64, u64>,
    /// Additional positions for indices that have more than one entry.
    /// Only populated when used via [crate::archive::MultiArchive::put_multi].
    extra_indices: BTreeMap<u64, Vec<u64>>,
    /// Interval tracking for gap detection.
    intervals: RMap,
    _phantom: std::marker::PhantomData<K>,
}

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared> {
    items_per_section: u64,

    /// Combined index + value storage with crash recovery.
    oversized: Oversized<E, Record<K>, V>,

    state: Arc<Mutex<State<T, K>>>,

    // Metrics
    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

/// Cheap read handle for a prunable archive.
pub struct Reader<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared> {
    items_per_section: u64,
    oversized: crate::journal::segmented::oversized::Reader<E, Record<K>, V>,
    state: Arc<Mutex<State<T, K>>>,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
}

impl<T, E, K, V> Clone for Reader<T, E, K, V>
where
    T: Translator,
    E: BufferPooler + Storage + Metrics,
    K: Array,
    V: CodecShared,
{
    fn clone(&self) -> Self {
        Self {
            items_per_section: self.items_per_section,
            oversized: self.oversized.clone(),
            state: self.state.clone(),
            unnecessary_reads: self.unnecessary_reads.clone(),
            gets: self.gets.clone(),
            has: self.has.clone(),
        }
    }
}

impl<T: Translator, K: Array> State<T, K> {
    fn positions(&self, index: u64) -> Option<Vec<u64>> {
        let first = *self.indices.get(&index)?;
        let extra = self.extra_indices.get(&index).map_or(0, Vec::len);
        let mut positions = Vec::with_capacity(1 + extra);
        positions.push(first);
        if let Some(extra) = self.extra_indices.get(&index) {
            positions.extend(extra.iter().copied());
        }
        Some(positions)
    }

    fn len(&self) -> usize {
        self.indices.len()
    }
}

impl<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared>
    Archive<T, E, K, V>
{
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
    }

    /// Return a cheap read handle.
    pub fn reader(&self) -> Reader<T, E, K, V> {
        Reader {
            items_per_section: self.items_per_section,
            oversized: self.oversized.reader(),
            state: self.state.clone(),
            unnecessary_reads: self.unnecessary_reads.clone(),
            gets: self.gets.clone(),
            has: self.has.clone(),
        }
    }

    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying only the index journal (no values are read).
    pub async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        // Initialize oversized journal
        let oversized_cfg = OversizedConfig {
            index_partition: cfg.key_partition,
            value_partition: cfg.value_partition,
            index_page_cache: cfg.key_page_cache,
            index_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        };
        let oversized: Oversized<E, Record<K>, V> =
            Oversized::init(context.child("oversized"), oversized_cfg).await?;

        // Initialize keys and replay index journal (no values read!)
        let mut indices: BTreeMap<u64, u64> = BTreeMap::new();
        let mut extra_indices: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut keys = Index::new(context.child("index"), cfg.translator.clone());
        let mut intervals = RMap::new();
        {
            debug!("initializing archive from index journal");
            let stream = oversized.replay(0, 0, cfg.replay_buffer).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_section, position, entry) = result?;

                // Store index location (position in index journal)
                match indices.entry(entry.index) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert(position);
                    }
                    btree_map::Entry::Occupied(_) => {
                        extra_indices.entry(entry.index).or_default().push(position);
                    }
                }

                // Store index in keys
                keys.insert(&entry.key, entry.index);

                // Store index in intervals
                intervals.insert(entry.index);
            }
            debug!("archive initialized");
        }

        // Initialize metrics
        let items_tracked = context.gauge("items_tracked", "Number of items tracked");
        let indices_pruned = context.counter("indices_pruned", "Number of indices pruned");
        let unnecessary_reads = context.counter(
            "unnecessary_reads",
            "Number of unnecessary reads performed during key lookups",
        );
        let gets = context.counter("gets", "Number of gets performed");
        let has = context.counter("has", "Number of has performed");
        let syncs = context.counter("syncs", "Number of syncs called");
        let _ = items_tracked.try_set(indices.len());

        // Return populated archive
        Ok(Self {
            items_per_section: cfg.items_per_section.get(),
            oversized,
            state: Arc::new(Mutex::new(State {
                pending: BTreeSet::new(),
                oldest_allowed: None,
                keys,
                indices,
                extra_indices,
                intervals,
                _phantom: std::marker::PhantomData,
            })),
            items_tracked,
            indices_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
        })
    }

    async fn put_internal(
        &mut self,
        index: u64,
        key: K,
        data: V,
        skip_if_index_exists: bool,
    ) -> Result<(), Error> {
        // Check last pruned
        {
            let state = self.state.lock();
            let oldest_allowed = state.oldest_allowed.unwrap_or(0);
            if index < oldest_allowed {
                return Err(Error::AlreadyPrunedTo(oldest_allowed));
            }

            // Check for existing index when enforcing single-item semantics.
            if skip_if_index_exists && state.indices.contains_key(&index) {
                return Ok(());
            }
        }

        // Write value and index entry atomically (glob first, then index)
        let section = self.section(index);
        let entry = Record::new(index, key.clone(), 0, 0);
        let (position, _, _) = self.oversized.append(section, entry, &data).await?;

        let mut state = self.state.lock();
        let oldest_allowed = state.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedTo(oldest_allowed));
        }

        // Store index location
        match state.indices.entry(index) {
            btree_map::Entry::Vacant(e) => {
                e.insert(position);
            }
            btree_map::Entry::Occupied(_) => {
                state.extra_indices.entry(index).or_default().push(position);
            }
        }

        // Store interval
        state.intervals.insert(index);

        // Insert and prune any useless keys
        state
            .keys
            .insert_and_retain(&key, index, |v| *v >= oldest_allowed);

        // Add section to pending
        state.pending.insert(section);

        // Update metrics
        let _ = self.items_tracked.try_set(state.len());
        Ok(())
    }

    /// Prune `Archive` to the provided `min` (masked by the configured
    /// section mask).
    ///
    /// If this is called with a min lower than the last pruned, nothing
    /// will happen.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Update `min` to reflect section mask
        let min = self.section(min);

        // Check if min is less than last pruned
        if let Some(oldest_allowed) = self.state.lock().oldest_allowed {
            if min <= oldest_allowed {
                // We don't return an error in this case because the caller
                // shouldn't be burdened with converting `min` to some section.
                return Ok(());
            }
        }
        debug!(min, "pruning archive");

        // Prune oversized journal (handles both index and values)
        self.oversized.prune(min).await?;

        let mut state = self.state.lock();
        // Remove pending writes (no need to call `sync` as we are pruning)
        loop {
            let next = match state.pending.iter().next() {
                Some(section) if *section < min => *section,
                _ => break,
            };
            state.pending.remove(&next);
        }

        // Remove all indices that are less than min
        loop {
            let next = match state.indices.first_key_value() {
                Some((index, _)) if *index < min => *index,
                _ => break,
            };
            state.indices.remove(&next).unwrap();
            state.extra_indices.remove(&next);
            self.indices_pruned.inc();
        }

        // Remove all keys from interval tree less than min
        if min > 0 {
            state.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from pruned sections)
        state.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(state.len());
        Ok(())
    }
}

impl<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared>
    Reader<T, E, K, V>
{
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();
        let position = {
            let state = self.state.lock();
            match state.indices.get(&index) {
                Some(&position) => position,
                None => return Ok(None),
            }
        };

        let section = self.section(index);
        let entry = self.oversized.get(section, position).await?;
        let (value_offset, value_size) = entry.value_location();
        Ok(self
            .oversized
            .get_value(section, value_offset, value_size)
            .await
            .map(Some)?)
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();
        let candidates = {
            let state = self.state.lock();
            let min_allowed = state.oldest_allowed.unwrap_or(0);
            let mut candidates = Vec::new();
            for index in state.keys.get(key) {
                if *index < min_allowed {
                    continue;
                }
                let Some(positions) = state.positions(*index) else {
                    return Err(Error::RecordCorrupted);
                };
                candidates.push((*index, positions));
            }
            candidates
        };

        for (index, positions) in candidates {
            let section = self.section(index);
            for position in positions {
                let entry = self.oversized.get(section, position).await?;
                if entry.key.as_ref() == key.as_ref() {
                    let (value_offset, value_size) = entry.value_location();
                    let value = self
                        .oversized
                        .get_value(section, value_offset, value_size)
                        .await?;
                    return Ok(Some(value));
                }
                self.unnecessary_reads.inc();
            }
        }

        Ok(None)
    }

    fn has_index(&self, index: u64) -> bool {
        self.state.lock().indices.contains_key(&index)
    }

    /// Check if an item exists in [Archive].
    pub async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    /// Retrieve an item from [Archive].
    pub async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// Retrieve all values stored at the given index.
    pub async fn get_all(&self, index: u64) -> Result<Option<Vec<V>>, Error> {
        self.gets.inc();
        let positions = {
            let state = self.state.lock();
            let Some(positions) = state.positions(index) else {
                return Ok(None);
            };
            positions
        };

        let section = self.section(index);
        let mut values = Vec::with_capacity(positions.len());
        for position in positions {
            let entry = self.oversized.get(section, position).await?;
            let (value_offset, value_size) = entry.value_location();
            let value = self
                .oversized
                .get_value(section, value_offset, value_size)
                .await?;
            values.push(value);
        }
        Ok(Some(values))
    }

    /// Retrieve the end of the current range and the start of the next range.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.state.lock().intervals.next_gap(index)
    }

    /// Returns up to `max` missing items starting from `index`.
    pub fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.state.lock().intervals.missing_items(index, max)
    }

    /// Retrieve an iterator over all populated ranges.
    pub fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.state
            .lock()
            .intervals
            .iter()
            .map(|(&s, &e)| (s, e))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Retrieve an iterator over ranges that overlap or follow `from`.
    pub fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.state
            .lock()
            .intervals
            .iter_from(from)
            .map(|(&s, &e)| (s, e))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Retrieve the first index in the archive.
    pub fn first_index(&self) -> Option<u64> {
        self.state.lock().intervals.first_index()
    }

    /// Retrieve the last index in the archive.
    pub fn last_index(&self) -> Option<u64> {
        self.state.lock().intervals.last_index()
    }
}

impl<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared>
    crate::archive::Archive for Archive<T, E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        self.put_internal(index, key, data, true).await
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.reader().get(identifier).await
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.reader().has(identifier).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        // Collect pending sections and update metrics
        let pending: Vec<u64> = self.state.lock().pending.iter().copied().collect();
        self.syncs.inc_by(pending.len() as u64);

        // Sync oversized journal (handles both index and values)
        let syncs: Vec<_> = pending.iter().map(|s| self.oversized.sync(*s)).collect();
        try_join_all(syncs).await?;

        self.state.lock().pending.clear();
        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.reader().next_gap(index)
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.reader().missing_items(index, max)
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.reader().ranges()
    }

    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.reader().ranges_from(from)
    }

    fn first_index(&self) -> Option<u64> {
        self.reader().first_index()
    }

    fn last_index(&self) -> Option<u64> {
        self.reader().last_index()
    }

    #[boxed]
    async fn destroy(self) -> Result<(), Error> {
        Ok(self.oversized.destroy().await?)
    }
}

impl<T: Translator, E: BufferPooler + Storage + Metrics, K: Array, V: CodecShared>
    crate::archive::MultiArchive for Archive<T, E, K, V>
{
    async fn get_all(&self, index: u64) -> Result<Option<Vec<V>>, Error> {
        self.reader().get_all(index).await
    }

    async fn put_multi(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        self.put_internal(index, key, data, false).await
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;
    use commonware_utils::sequence::U64;

    commonware_conformance::conformance_tests! {
        CodecConformance<Record<U64>>
    }
}
