use super::{
    Config, Translator,
    reader::{Location, Reader, State, section},
};
use crate::{
    Context,
    archive::{Error, Identifier},
    index::{Unordered, unordered::Index},
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    rmap::RMap,
};
use commonware_codec::{CodecShared, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{
    Buf, BufMut, Handle,
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::{Array, sync::RwLock};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map},
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

    /// Maps translated key representation to its corresponding index. Not shared, since only
    /// the writer resolves keys.
    keys: Index<T, u64>,

    /// Where each item lives, and the captures readers serve from (see [super::reader]).
    state: Arc<RwLock<State<E::Blob, V>>>,

    /// Later locations for indices holding more than one item, populated only by
    /// [crate::archive::MultiArchive::put_multi]. Not shared, since readers serve the first.
    extras: BTreeMap<u64, Vec<Location>>,

    /// Interval tracking for gap detection. Not shared, since readers do not query gaps.
    intervals: RMap,

    // Metrics
    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> Inner<T, E, K, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        section(index, self.items_per_section)
    }

    /// See [Archive::init].
    async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
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
            Oversized::init(context.child("oversized"), oversized_cfg, None).await?;

        // Initialize keys and replay index journal (no values read!)
        let items_per_section = cfg.items_per_section.get();
        let mut locations: BTreeMap<u64, Location> = BTreeMap::new();
        let mut extras: BTreeMap<u64, Vec<Location>> = BTreeMap::new();
        let mut keys = Index::new(context.child("index"), cfg.translator.clone());
        let mut intervals = RMap::new();
        let mut oversized = {
            debug!("initializing archive from index journal");
            let mut replay = oversized.replay(0, 0, cfg.replay_buffer).await?;
            while let Some(result) = replay.next().await {
                let (_section, position, record) = result?;

                // Store where the item lives
                let location = Location {
                    value_offset: record.value_offset,
                    position: u32::try_from(position).map_err(|_| Error::SectionFull(position))?,
                    value_size: record.value_size,
                };
                match locations.entry(record.index) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert(location);
                    }
                    btree_map::Entry::Occupied(_) => {
                        extras.entry(record.index).or_default().push(location);
                    }
                }

                // Store index in keys
                keys.insert(&record.key, record.index);

                // Store index in intervals
                intervals.insert(record.index);
            }
            debug!("archive initialized");
            replay.finish()?
        };

        // Capture the recovered sections so readers work immediately after restart. Repair can
        // leave an index section whose values are gone, which captures as nothing.
        let mut captures = BTreeMap::new();
        for section in oversized.sections().collect::<Vec<_>>() {
            let capture;
            (oversized, capture) = oversized.capture_values(section).await?;
            if let Some(capture) = capture {
                captures.insert(section, capture);
            }
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
        let _ = items_tracked.try_set(locations.len());

        Ok(Self {
            items_per_section,
            oversized,
            pending: BTreeSet::new(),
            requested: BTreeSet::new(),
            oldest_allowed: None,
            keys,
            state: Arc::new(RwLock::new(State {
                locations,
                captures,
            })),
            extras,
            intervals,
            items_tracked,
            indices_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
        })
    }

    /// Capture `sections` and publish them to readers.
    ///
    /// Captures are taken before the guard, so no read waits on I/O. Callers publish after
    /// syncing, so each capture's flush has nothing to write.
    async fn publish(
        mut self: Box<Self>,
        sections: impl IntoIterator<Item = u64>,
    ) -> Result<Box<Self>, Error> {
        let mut captured = Vec::new();
        for section in sections {
            // A section with writes to publish still has its value blob open, so never `None`.
            let capture;
            (self.oversized, capture) = self.oversized.capture_values(section).await?;
            if let Some(capture) = capture {
                captured.push((section, capture));
            }
        }

        self.state.write().captures.extend(captured);
        Ok(self)
    }

    async fn put_internal(
        mut self: Box<Self>,
        index: u64,
        key: K,
        data: V,
        skip_if_index_exists: bool,
    ) -> Result<(Box<Self>, bool), Error> {
        // A put below the prune floor is satisfied without storing
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            debug!(index, oldest_allowed, "ignoring put below prune floor");
            return Ok((self, false));
        }

        // Check for existing index when enforcing single-item semantics.
        if skip_if_index_exists && self.state.read().locations.contains_key(&index) {
            return Ok((self, true));
        }

        // Refuse before appending, so a section that cannot be tracked is never written. A
        // `Location` holds its position in a u32, which bounds a section's record count.
        let section = self.section(index);
        let position = self.oversized.records(section)?;
        if u32::try_from(position).is_err() {
            return Err(Error::SectionFull(position));
        }

        // Write value and index entry atomically (glob first, then index)
        let record = Record::new(index, key.clone(), 0, 0);
        let (position, value_offset, value_size);
        (self.oversized, position, value_offset, value_size) =
            self.oversized.append(section, record, &data).await?;
        let location = Location {
            value_offset,
            position: u32::try_from(position).map_err(|_| Error::SectionFull(position))?,
            value_size,
        };

        // Store where the item lives. Readers see it once a sync publishes the section.
        let (extra, items) = {
            let mut state = self.state.write();
            let extra = match state.locations.entry(index) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(location);
                    None
                }
                // Readers serve the first item at an index, so later ones go to `extras`.
                btree_map::Entry::Occupied(_) => Some(location),
            };
            (extra, state.locations.len())
        };
        if let Some(location) = extra {
            self.extras.entry(index).or_default().push(location);
        }

        // Store interval
        self.intervals.insert(index);

        // Insert and prune any useless keys
        self.keys
            .insert_and_retain(&key, index, |v| *v >= oldest_allowed);

        // Add section to pending
        self.pending.insert(section);

        // Update metrics
        let _ = self.items_tracked.try_set(items);
        Ok((self, true))
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

        // Cut locations and their captures under one guard, before the journal drops anything, so
        // no reader can serve below the new floor. A read already under way finishes, since its
        // blob outlives the name.
        let (pruned, stale, items) = {
            let mut state = self.state.write();
            let State {
                locations,
                captures,
            } = &mut *state;
            let kept = locations.split_off(&min);
            let pruned = std::mem::replace(locations, kept);
            let kept = captures.split_off(&min);
            let stale = std::mem::replace(captures, kept);
            (pruned, stale, locations.len())
        };
        self.indices_pruned.inc_by(pruned.len() as u64);
        self.extras = self.extras.split_off(&min);

        // Releasing the last handle on a pruned blob closes it, so do that with no reader waiting.
        drop(stale);

        // Prune oversized journal (handles both index and values)
        (self.oversized, _) = self.oversized.prune(min).await?;

        // Remove pending and requested sync work (no need to call `sync` as we are pruning)
        self.pending = self.pending.split_off(&min);
        self.requested = self.requested.split_off(&min);

        // Remove all keys from interval tree less than min
        if min > 0 {
            self.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from pruned sections)
        self.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(items);
        Ok(self)
    }

    /// Where the first item at `index` lives, if any.
    ///
    /// Pruning trims `locations` under the same guard that raises the floor, so an index below
    /// the floor is already absent.
    fn locate(&self, index: u64) -> Option<Location> {
        self.state.read().locations.get(&index).copied()
    }

    /// Where every item at `index` lives, first one first.
    ///
    /// The trailing slice is empty unless `put_multi` stored more than one item here.
    fn locate_all(&self, index: u64) -> Option<(Location, &[Location])> {
        let first = self.locate(index)?;
        let rest = self.extras.get(&index).map_or(&[][..], Vec::as_slice);
        Some((first, rest))
    }

    /// Read the value at `location` in `section`.
    async fn read_value(&self, section: u64, location: &Location) -> Result<V, Error> {
        // Fetch value directly from blob storage (bypasses page cache)
        Ok(self
            .oversized
            .get_value(section, location.value_offset, location.value_size)
            .await?)
    }

    /// Which of `index`'s locations holds `key`, if any.
    ///
    /// Confirms translated-key candidates against index journal records, never reading values.
    async fn match_key(
        &self,
        index: u64,
        (first, rest): (Location, &[Location]),
        key: &K,
    ) -> Result<Option<Location>, Error> {
        let section = self.section(index);
        for location in std::iter::once(first).chain(rest.iter().copied()) {
            let record = self
                .oversized
                .get(section, u64::from(location.position))
                .await?;
            if record.key.as_ref() == key.as_ref() {
                return Ok(Some(location));
            }
            self.unnecessary_reads.inc();
        }
        Ok(None)
    }

    /// The section and location stored under `key` at one of its candidate indices.
    async fn locate_key(&self, key: &K) -> Result<Option<(u64, Location)>, Error> {
        // Keys are pruned lazily, so a candidate below the floor may still be listed.
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        for index in self.keys.get(key) {
            if *index < oldest_allowed {
                continue;
            }
            // The key index must never name an index with nothing stored at it.
            let Some(locations) = self.locate_all(*index) else {
                return Err(Error::RecordCorrupted);
            };
            if let Some(location) = self.match_key(*index, locations, key).await? {
                return Ok(Some((self.section(*index), location)));
            }
        }
        Ok(None)
    }

    /// See [crate::archive::Archive::get].
    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.gets.inc();
        match identifier {
            Identifier::Index(index) => {
                let Some(location) = self.locate(index) else {
                    return Ok(None);
                };
                Ok(Some(self.read_value(self.section(index), &location).await?))
            }
            Identifier::Key(key) => {
                let Some((section, location)) = self.locate_key(key).await? else {
                    return Ok(None);
                };
                Ok(Some(self.read_value(section, &location).await?))
            }
        }
    }

    /// See [crate::archive::Archive::has].
    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.locate(index).is_some()),
            Identifier::Key(key) => Ok(self.locate_key(key).await?.is_some()),
        }
    }

    /// See [crate::archive::Archive::sync].
    async fn sync(mut self: Box<Self>) -> Result<Box<Self>, Error> {
        // Update metrics (`requested` sections were already counted by `start_sync`)
        self.syncs.inc_by(self.pending.len() as u64);
        let dirty: Vec<u64> = self.pending.iter().copied().collect();
        self.requested.append(&mut self.pending);

        // Sync oversized journal (handles both index and values). Re-syncing `requested` sections
        // also waits for any of their syncs still in flight.
        self.oversized = self.oversized.sync(&self.requested).await?;

        self.requested.clear();

        self = self.publish(dirty).await?;
        Ok(self)
    }

    /// See [crate::archive::Archive::start_sync].
    async fn start_sync(mut self: Box<Self>) -> Result<(Box<Self>, Handle<()>), Error> {
        // Update metrics
        self.syncs.inc_by(self.pending.len() as u64);

        // Move sections into `requested` rather than dropping them: section buffers reuse
        // in-flight syncs, so re-requesting a section makes this handle observe outstanding work
        // without issuing a new sync.
        let dirty: Vec<u64> = self.pending.iter().copied().collect();
        self.requested.append(&mut self.pending);

        let handle;
        (self.oversized, handle) = self.oversized.start_sync(&self.requested).await?;

        // Publish without waiting for durability
        self = self.publish(dirty).await?;
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
        self.gets.inc();
        let Some((first, rest)) = self.locate_all(index) else {
            return Ok(None);
        };

        let section = self.section(index);
        let mut values = Vec::with_capacity(1 + rest.len());
        for location in std::iter::once(first).chain(rest.iter().copied()) {
            values.push(self.read_value(section, &location).await?);
        }
        Ok(Some(values))
    }

    /// See [crate::archive::MultiArchive::has_at].
    async fn has_at(&self, index: u64, key: &K) -> Result<bool, Error> {
        self.has.inc();

        // A key absent from the in-memory index is not stored anywhere, so absence is decided
        // without touching disk. A translated-key hit may be a collision, so confirm it.
        if !self.keys.get(key).any(|candidate| *candidate == index) {
            return Ok(false);
        }
        let Some(locations) = self.locate_all(index) else {
            return Ok(false);
        };
        Ok(self.match_key(index, locations, key).await?.is_some())
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
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying only the index journal (no values are read).
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

    /// A cloneable handle serving reads by index from the last published state.
    ///
    /// A put is invisible until a sync covers it. Both sync paths publish, since both flush
    /// before returning. Reads outlive the archive, still serving that state.
    ///
    /// Serves the first item at an index, so items added by
    /// [crate::archive::MultiArchive::put_multi] are unreachable through it.
    pub fn reader(&self) -> Reader<E::Blob, V> {
        Reader::new(
            self.0.state.clone(),
            self.0.items_per_section,
            self.0.gets.clone(),
        )
    }
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> crate::archive::Archive
    for Archive<T, E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        (self.0, _) = self.0.put_internal(index, key, data, true).await?;
        Ok(self)
    }

    async fn put_sync(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        // A put satisfied below the prune floor stored nothing, so skip the sync.
        let stored;
        (self.0, stored) = self.0.put_internal(index, key, data, true).await?;
        if !stored {
            return Ok(self);
        }
        self.sync().await
    }

    async fn put_start_sync(
        mut self,
        index: u64,
        key: K,
        data: V,
    ) -> Result<(Self, Handle<()>), Error> {
        // A put satisfied below the prune floor stored nothing, so skip the sync.
        let stored;
        (self.0, stored) = self.0.put_internal(index, key, data, true).await?;
        if !stored {
            return Ok((self, Handle::ready(Ok(()))));
        }
        self.start_sync().await
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

    async fn put_multi(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        (self.0, _) = self.0.put_internal(index, key, data, false).await?;
        Ok(self)
    }

    async fn put_multi_sync(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        // A put satisfied below the prune floor stored nothing, so skip the sync.
        let stored;
        (self.0, stored) = self.0.put_internal(index, key, data, false).await?;
        if !stored {
            return Ok(self);
        }
        crate::archive::Archive::sync(self).await
    }

    async fn put_multi_start_sync(
        mut self,
        index: u64,
        key: K,
        data: V,
    ) -> Result<(Self, Handle<()>), Error> {
        // A put satisfied below the prune floor stored nothing, so skip the sync.
        let stored;
        (self.0, stored) = self.0.put_internal(index, key, data, false).await?;
        if !stored {
            return Ok((self, Handle::ready(Ok(()))));
        }
        crate::archive::Archive::start_sync(self).await
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
