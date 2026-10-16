use super::{Config, Translator};
use crate::{
    Context,
    archive::{Error, Identifier},
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    rmap::RMap,
};
use commonware_codec::{Buf, CodecShared, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{
    BufMut, Handle,
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::{Array, handles::Table};
use std::collections::{BTreeMap, BTreeSet};
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

/// Journal position of the first record stored at each index of a section, by offset from the
/// section's start.
///
/// The vector spans every offset up to the highest one present, so a section costs `8` bytes
/// per index from its start to its highest stored index whether or not the indices between are
/// stored; records arrive in order in the common case, which keeps that proportional to the
/// records themselves.
pub(super) struct Positions {
    positions: Vec<u64>,
    present: u64,
}

/// Marks an absent offset in [Positions].
const NONE: u64 = u64::MAX;

impl Positions {
    pub(super) const fn new() -> Self {
        Self {
            positions: Vec::new(),
            present: 0,
        }
    }

    /// Returns the first position of `offset`, if present.
    pub(super) fn get(&self, offset: u64) -> Option<u64> {
        usize::try_from(offset)
            .ok()
            .and_then(|offset| self.positions.get(offset))
            .copied()
            .filter(|position| *position != NONE)
    }

    /// Returns the number of offsets present.
    pub(super) const fn len(&self) -> u64 {
        self.present
    }

    /// Records `position` as the first for `offset`, returning false if `offset` already has one.
    pub(super) fn insert(&mut self, offset: u64, position: u64) -> bool {
        let offset =
            usize::try_from(offset).expect("section offset must not exceed the address space");
        if offset >= self.positions.len() {
            self.positions.resize(offset + 1, NONE);
        }
        let slot = &mut self.positions[offset];
        if *slot != NONE {
            return false;
        }
        *slot = position;
        self.present += 1;
        true
    }
}

/// In-memory state of one retained section.
struct Section<K> {
    /// First index of the section.
    start: u64,
    /// Translated key of each record, by journal position.
    keys: Vec<K>,
    /// First journal position of each index, by offset from `start`.
    positions: Positions,
}

/// Retained sections, addressed by start index or by the slot held in a key handle.
struct Sections<K> {
    /// Slot of each retained section by its start index.
    by_start: BTreeMap<u64, usize>,
    /// Section state by slot; a pruned section's slot is `None` until a new section reuses it.
    slots: Vec<Option<Section<K>>>,
    /// Slots freed by pruning, reused before `slots` grows.
    free: Vec<usize>,
}

impl<K> Sections<K> {
    const fn new() -> Self {
        Self {
            by_start: BTreeMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Returns the slot of the section starting at `start`, if retained.
    fn slot_of(&self, start: u64) -> Option<usize> {
        self.by_start.get(&start).copied()
    }

    /// Returns the section starting at `start`, if retained.
    fn get(&self, start: u64) -> Option<&Section<K>> {
        self.slots[self.slot_of(start)?].as_ref()
    }

    /// Returns the section held in `slot`, which a key handle guarantees is retained.
    fn slot(&self, slot: usize) -> &Section<K> {
        self.slots[slot]
            .as_ref()
            .expect("key handle must reference a retained section")
    }

    /// Visits every retained section with its slot.
    fn iter(&self) -> impl Iterator<Item = (usize, &Section<K>)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, section)| Some((slot, section.as_ref()?)))
    }

    /// Adds the record at `position` of the section starting at `start`, creating the section
    /// if needed. Returns the section's slot and whether this is the first record at `offset`.
    fn add(&mut self, start: u64, offset: u64, position: u64, translated: K) -> (usize, bool) {
        let slot = match self.by_start.get(&start) {
            Some(&slot) => slot,
            None => {
                let slot = self.free.pop().unwrap_or_else(|| {
                    self.slots.push(None);
                    self.slots.len() - 1
                });
                assert!(
                    slot < 1 << (64 - POSITION_BITS),
                    "too many retained sections"
                );
                self.slots[slot] = Some(Section {
                    start,
                    keys: Vec::new(),
                    positions: Positions::new(),
                });
                self.by_start.insert(start, slot);
                slot
            }
        };
        let section = self.slots[slot].as_mut().expect("slot must be filled");
        debug_assert_eq!(
            section.keys.len() as u64,
            position,
            "records arrive in journal order"
        );
        section.keys.push(translated);
        (slot, section.positions.insert(offset, position))
    }

    /// Removes every section starting below `min`, freeing its slot.
    fn split_off(&mut self, min: u64) -> Vec<(usize, Section<K>)> {
        let retained = self.by_start.split_off(&min);
        std::mem::replace(&mut self.by_start, retained)
            .into_values()
            .map(|slot| {
                let section = self.slots[slot]
                    .take()
                    .expect("retained section must have state");
                self.free.push(slot);
                (slot, section)
            })
            .collect()
    }
}

/// Bits of a key handle holding the journal position; the rest hold the section slot.
const POSITION_BITS: u32 = 40;

/// Packs a record's section slot and journal position into a key handle.
///
/// A handle holds up to 2^40 positions per section, more than a section's blobs can store, and
/// 2^24 sections, which [Sections] enforces when it allocates a slot.
fn handle(slot: usize, position: u64) -> u64 {
    debug_assert!(
        position >> POSITION_BITS == 0,
        "section holds too many records"
    );
    ((slot as u64) << POSITION_BITS) | position
}

/// Splits a key handle into its section slot and journal position.
const fn unpack(handle: u64) -> (usize, u64) {
    (
        (handle >> POSITION_BITS) as usize,
        handle & ((1 << POSITION_BITS) - 1),
    )
}

/// Returns the function the key table uses to rehash a handle when it grows.
fn rehash<'a, T: Translator>(
    translator: &'a T,
    sections: &'a Sections<T::Key>,
) -> impl FnMut(u64) -> u64 + 'a {
    move |handle| {
        let (slot, position) = unpack(handle);
        translator.hash_one(sections.slot(slot).keys[position as usize])
    }
}

/// The archive's state, boxed so the public [Archive] handle stays pointer-sized.
struct Inner<T: Translator, E: Context, K: Array, V: CodecShared> {
    items_per_section: u64,

    /// Combined index + value storage with crash recovery.
    oversized: Oversized<E, Record<K>, V>,

    /// Sections with writes not yet included in any sync request. Moved into `requested` when a
    /// sync is requested; the `syncs` metric counts only this set, so each section of writes is
    /// counted once per request.
    pending: BTreeSet<u64>,

    /// Sections included in a sync request by [crate::archive::Archive::start_sync], retained
    /// until a full sync completes.
    ///
    /// Retention is load-bearing: a [crate::archive::Archive::start_sync] handle must cover
    /// every previously accepted write, even when the call itself wrote nothing (e.g. a
    /// duplicate put). Re-requesting these sections makes their buffers return the in-flight
    /// sync's handle (a completed sync resolves immediately; no new I/O is issued). Pruned
    /// sections must be removed from this set, or a later request would trip the journal's
    /// prune guard.
    requested: BTreeSet<u64>,

    /// Oldest allowed section to read from. Updated when `prune` is called.
    oldest_allowed: Option<u64>,

    /// Translates keys and hashes their translated form for `keys`.
    translator: T,

    /// Handles of every retained record (see [handle]) by the hash of its translated key.
    keys: Table<u64>,

    /// Retained sections, which hold each record's translated key and position.
    sections: Sections<T::Key>,

    /// Additional positions for indices that have more than one entry.
    /// Only populated when used via [crate::archive::MultiArchive::put_multi].
    extra_indices: BTreeMap<u64, Vec<u64>>,

    /// Interval tracking for gap detection.
    intervals: RMap,

    /// Number of indices with at least one record.
    items: u64,

    // Metrics
    items_tracked: Gauge,
    keys_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> Inner<T, E, K, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
    }

    /// Returns the section holding `index`, if any of its records are retained.
    fn section_of(&self, index: u64) -> Option<&Section<T::Key>> {
        self.sections.get(self.section(index))
    }

    /// Returns the first journal position of `index`, if present.
    fn first_position(&self, index: u64) -> Option<u64> {
        let section = self.section_of(index)?;
        section.positions.get(index - section.start)
    }

    /// Iterate over all positions for a given index (first + extras).
    fn iter_positions(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.first_position(index).into_iter().chain(
            self.extra_indices
                .get(&index)
                .into_iter()
                .flat_map(|v| v.iter().copied()),
        )
    }

    /// See [Archive::init].
    async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        let items_per_section = cfg.items_per_section.get();
        let oversized_cfg = OversizedConfig {
            index_partition: cfg.key_partition,
            value_partition: cfg.value_partition,
            index_page_cache: cfg.key_page_cache,
            index_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
            replay_buffer: cfg.replay_buffer,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        };
        let mut replay = Oversized::<E, Record<K>, V>::init_with_metadata(
            context.child("oversized"),
            oversized_cfg,
            cfg.metadata_partition,
            commonware_runtime::ReadOptions::default(),
        )
        .await?;

        // Rebuild the sections from the replay. It yields exactly the entries recovery retained,
        // in journal order, so one scan serves both recovery and indexing. A record outside the
        // section its index selects would be unreachable by index, so it is corruption.
        let translator = cfg.translator;
        let mut sections = Sections::new();
        let mut extra_indices: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut intervals = RMap::new();
        let mut items = 0u64;
        let mut records = 0usize;
        debug!("initializing archive from index journal");
        while let Some(result) = replay.next().await {
            let (start, position, entry) = result?;
            if entry.index / items_per_section * items_per_section != start {
                return Err(Error::RecordCorrupted);
            }
            let offset = entry.index - start;
            let translated = translator.transform(entry.key.as_ref());
            let (_, first) = sections.add(start, offset, position, translated);
            if first {
                items += 1;
            } else {
                extra_indices.entry(entry.index).or_default().push(position);
            }
            intervals.insert(entry.index);
            records += 1;
        }
        let oversized = replay.finish_tracked().await?;

        // Index every record by key in a table sized once for all of them.
        let mut keys = Table::with_capacity(records);
        for (slot, section) in sections.iter() {
            for (position, translated) in section.keys.iter().enumerate() {
                keys.insert(
                    translator.hash_one(translated),
                    handle(slot, position as u64),
                    rehash(&translator, &sections),
                );
            }
        }
        debug!("archive initialized");

        // Initialize metrics
        let items_tracked = context.gauge("items_tracked", "Number of items tracked");
        let keys_tracked = context.gauge("keys_tracked", "Number of keys tracked");
        let indices_pruned = context.counter("indices_pruned", "Number of indices pruned");
        let unnecessary_reads = context.counter(
            "unnecessary_reads",
            "Number of unnecessary reads performed during key lookups",
        );
        let gets = context.counter("gets", "Number of gets performed");
        let has = context.counter("has", "Number of has performed");
        let syncs = context.counter("syncs", "Number of syncs called");
        let _ = items_tracked.try_set(items);
        let _ = keys_tracked.try_set(keys.len());

        // Return populated archive
        Ok(Self {
            items_per_section,
            oversized,
            pending: BTreeSet::new(),
            requested: BTreeSet::new(),
            oldest_allowed: None,
            translator,
            keys,
            sections,
            extra_indices,
            intervals,
            items,
            items_tracked,
            keys_tracked,
            indices_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
        })
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get first position at this index
        let Some(position) = self.first_position(index) else {
            return Ok(None);
        };

        // Fetch index entry to get value location
        let section = self.section(index);
        let entry = self.oversized.get(section, position).await?;
        let (value_offset, value_size) = entry.value_location();

        // Fetch value directly from blob storage (bypasses page cache)
        let value = self
            .oversized
            .get_value(section, value_offset, value_size)
            .await?;
        Ok(Some(value))
    }

    /// Returns the section and index journal entry of a record storing `key`, if any.
    ///
    /// Candidates share the hash of their translated key; each is confirmed against the
    /// translated key in memory, then against the key in the index journal, never reading
    /// values.
    async fn find(&self, key: &K) -> Result<Option<(u64, Record<K>)>, Error> {
        let translated = self.translator.transform(key.as_ref());
        for candidate in self.keys.get(self.translator.hash_one(translated)) {
            let (slot, position) = unpack(candidate);
            let section = self.sections.slot(slot);
            if section.keys[position as usize] != translated {
                continue;
            }
            let entry = self.oversized.get(section.start, position).await?;
            if entry.key.as_ref() == key.as_ref() {
                return Ok(Some((section.start, entry)));
            }
            self.unnecessary_reads.inc();
        }
        Ok(None)
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        let Some((section, entry)) = self.find(key).await? else {
            return Ok(None);
        };

        // Fetch value directly from blob storage (bypasses page cache)
        let (value_offset, value_size) = entry.value_location();
        let value = self
            .oversized
            .get_value(section, value_offset, value_size)
            .await?;
        Ok(Some(value))
    }

    /// Check whether any retained index stores `key`.
    async fn has_key(&self, key: &K) -> Result<bool, Error> {
        Ok(self.find(key).await?.is_some())
    }

    fn has_index(&self, index: u64) -> bool {
        self.first_position(index).is_some()
    }

    async fn put_internal(
        mut self: Box<Self>,
        index: u64,
        key: K,
        data: &V,
        skip_if_index_exists: bool,
    ) -> Result<Box<Self>, Error> {
        // A put below the prune floor is satisfied without storing
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            debug!(index, oldest_allowed, "ignoring put below prune floor");
            return Ok(self);
        }

        // Check for existing index when enforcing single-item semantics.
        if skip_if_index_exists && self.has_index(index) {
            return Ok(self);
        }

        // Write value and index entry atomically (glob first, then index)
        let start = self.section(index);
        let entry = Record::new(index, key.clone(), 0, 0);
        let position;
        (self.oversized, position, _, _) = self.oversized.append(start, entry, data).await?;

        // Record the position by index and the translated key by position, then index the key.
        let translated = self.translator.transform(key.as_ref());
        let (slot, first) = self
            .sections
            .add(start, index - start, position, translated);
        if first {
            self.items += 1;
        } else {
            self.extra_indices.entry(index).or_default().push(position);
        }
        let hash = self.translator.hash_one(translated);
        self.keys.insert(
            hash,
            handle(slot, position),
            rehash(&self.translator, &self.sections),
        );

        // Store interval
        self.intervals.insert(index);

        // Include this section in the next sync request.
        self.pending.insert(start);

        // Update metrics
        let _ = self.items_tracked.try_set(self.items);
        let _ = self.keys_tracked.try_set(self.keys.len());
        Ok(self)
    }

    /// See [Archive::prune].
    async fn prune(mut self: Box<Self>, min: u64) -> Result<Box<Self>, Error> {
        // Update `min` to reflect section mask
        let min = self.section(min);

        // Check if min is less than last pruned
        if let Some(oldest_allowed) = self.oldest_allowed
            && min <= oldest_allowed
        {
            // We don't return an error in this case because the caller
            // shouldn't be burdened with converting `min` to some section.
            return Ok(self);
        }
        debug!(min, "pruning archive");

        // Prune the section's index, values, and recovery markers together.
        (self.oversized, _) = self.oversized.prune(min).await?;

        // Discard synchronization state owned by pruned sections.
        self.pending = self.pending.split_off(&min);
        self.requested = self.requested.split_off(&min);

        // Drop the pruned sections and retire their records from the key table. Each handle is
        // found by the hash of the translated key its section holds, so nothing is read.
        for (slot, section) in self.sections.split_off(min) {
            for (position, translated) in section.keys.iter().enumerate() {
                let hash = self.translator.hash_one(translated);
                let removed = self.keys.remove(hash, handle(slot, position as u64));
                debug_assert!(removed, "every retained record is indexed by key");
            }
            let pruned = section.positions.len();
            self.items -= pruned;
            self.indices_pruned.inc_by(pruned);
        }
        let retained = self.extra_indices.split_off(&min);
        self.extra_indices = retained;

        // Remove pruned indices from the retained range view.
        if min > 0 {
            self.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from pruned sections)
        self.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(self.items);
        let _ = self.keys_tracked.try_set(self.keys.len());
        Ok(self)
    }

    /// See [crate::archive::Archive::get].
    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// See [crate::archive::Archive::has].
    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.has_key(key).await,
        }
    }

    /// See [crate::archive::Archive::sync].
    async fn sync(mut self: Box<Self>) -> Result<Box<Self>, Error> {
        // Include each section once in the sync metric and retain prior pipelined requests until
        // this blocking call observes their completion.
        self.syncs.inc_by(self.pending.len() as u64);
        let active = self.pending.clone();
        self.requested.append(&mut self.pending);
        self.oversized = self
            .oversized
            .sync_tracked(&self.requested, &active)
            .await?;
        self.requested.clear();
        Ok(self)
    }

    /// See [crate::archive::Archive::start_sync].
    async fn start_sync(mut self: Box<Self>) -> Result<(Box<Self>, Handle<()>), Error> {
        // Update metrics
        self.syncs.inc_by(self.pending.len() as u64);

        // Retain requested sections until a blocking sync observes their outstanding work.
        let active = self.pending.clone();
        self.requested.append(&mut self.pending);

        let handle;
        (self.oversized, handle) = self
            .oversized
            .start_sync_tracked(&self.requested, &active)
            .await?;
        Ok((self, handle))
    }

    /// See [crate::archive::Archive::next_gap].
    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// See [crate::archive::Archive::missing_items].
    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(index, max)
    }

    /// See [crate::archive::Archive::ranges].
    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.intervals.iter().map(|(&s, &e)| (s, e))
    }

    /// See [crate::archive::Archive::ranges_from].
    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.intervals.iter_from(from).map(|(&s, &e)| (s, e))
    }

    /// See [crate::archive::Archive::first_index].
    fn first_index(&self) -> Option<u64> {
        self.intervals.first_index()
    }

    /// See [crate::archive::Archive::last_index].
    fn last_index(&self) -> Option<u64> {
        self.intervals.last_index()
    }

    /// See [crate::archive::Archive::destroy].
    async fn destroy(self) -> Result<(), Error> {
        Ok(self.oversized.destroy().await?)
    }

    /// See [crate::archive::MultiArchive::get_all].
    async fn get_all(&self, index: u64) -> Result<Option<Vec<V>>, Error> {
        // Update metrics
        self.gets.inc();

        // Check if the index exists.
        if !self.has_index(index) {
            return Ok(None);
        }

        // Get all positions at this index
        let section = self.section(index);
        let extra_count = self.extra_indices.get(&index).map_or(0, Vec::len);

        let mut values = Vec::with_capacity(1 + extra_count);
        for position in self.iter_positions(index) {
            // Fetch index entry from index journal to verify key
            let entry = self.oversized.get(section, position).await?;

            // Fetch value directly from blob storage (bypasses page cache)
            let (value_offset, value_size) = entry.value_location();
            let value = self
                .oversized
                .get_value(section, value_offset, value_size)
                .await?;
            values.push(value);
        }
        Ok(Some(values))
    }

    /// See [crate::archive::MultiArchive::has_at].
    async fn has_at(&self, index: u64, key: &K) -> Result<bool, Error> {
        self.has.inc();

        // A translated key absent from the key table is rejected without visiting the index.
        // A candidate counts only if it is one of the records at `index` holding this translated
        // key, and is then confirmed against the stored key (reads index journal entries, never
        // values).
        let start = self.section(index);
        let Some(slot) = self.sections.slot_of(start) else {
            return Ok(false);
        };
        let section = self.sections.slot(slot);
        let translated = self.translator.transform(key.as_ref());
        for candidate in self.keys.get(self.translator.hash_one(translated)) {
            let (candidate_slot, position) = unpack(candidate);
            if candidate_slot != slot
                || section.keys[position as usize] != translated
                || !self.iter_positions(index).any(|stored| stored == position)
            {
                continue;
            }
            let entry = self.oversized.get(start, position).await?;
            if entry.key.as_ref() == key.as_ref() {
                return Ok(true);
            }
            self.unnecessary_reads.inc();
        }
        Ok(false)
    }
}

/// Implementation of `Archive` storage.
///
/// Mutating functions consume the archive and return it only on success: an error (or a
/// dropped future) destroys the handle. Puts below the prune floor are satisfied without
/// storing (see [crate::archive::Archive]).
pub struct Archive<T: Translator, E: Context, K: Array, V: CodecShared>(Box<Inner<T, E, K, V>>);

impl<T: Translator, E: Context, K: Array, V: CodecShared> std::fmt::Debug for Archive<T, E, K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("first_index", &self.0.first_index())
            .field("last_index", &self.0.last_index())
            .finish_non_exhaustive()
    }
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> Archive<T, E, K, V> {
    /// Initialize a new `Archive` instance.
    ///
    /// Replays the index journal to rebuild the in-memory index, CRC-validating every value
    /// above its section's durable marker.
    pub async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg).await?)))
    }

    /// Prune `Archive` to the provided `min` (masked by the configured
    /// section mask).
    ///
    /// If this is called with a min lower than the last pruned, nothing
    /// will happen.
    pub async fn prune(mut self, min: u64) -> Result<Self, Error> {
        self.0 = self.0.prune(min).await?;
        Ok(self)
    }
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> crate::archive::Archive
    for Archive<T, E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(mut self, index: u64, key: K, data: &V) -> Result<Self, Error> {
        self.0 = self.0.put_internal(index, key, data, true).await?;
        Ok(self)
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.0.get(identifier).await
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.0.has(identifier).await
    }

    async fn sync(mut self) -> Result<Self, Error> {
        self.0 = self.0.sync().await?;
        Ok(self)
    }

    async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error> {
        let handle;
        (self.0, handle) = self.0.start_sync().await?;
        Ok((self, handle))
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.0.next_gap(index)
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.0.missing_items(index, max)
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.0.ranges()
    }

    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.0.ranges_from(from)
    }

    fn first_index(&self) -> Option<u64> {
        self.0.first_index()
    }

    fn last_index(&self) -> Option<u64> {
        self.0.last_index()
    }

    async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> crate::archive::MultiArchive
    for Archive<T, E, K, V>
{
    async fn get_all(&self, index: u64) -> Result<Option<Vec<V>>, Error> {
        self.0.get_all(index).await
    }

    async fn put_multi(mut self, index: u64, key: K, data: &V) -> Result<Self, Error> {
        self.0 = self.0.put_internal(index, key, data, false).await?;
        Ok(self)
    }

    async fn has_at(&self, index: u64, key: &K) -> Result<bool, Error> {
        self.0.has_at(index, key).await
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
