use super::{
    Config, Translator,
    checkpoint::{Checkpoint, Section as SectionCheckpoint},
};
use crate::{
    Context, SyncCompletion,
    archive::{Error, Identifier},
    index::{Unordered, unordered::Index},
    journal::{
        durability::Barrier,
        segmented::oversized::{Config as OversizedConfig, Oversized, Record as OversizedRecord},
    },
    rmap::RMap,
};
use commonware_codec::{CodecShared, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{
    Buf, BufMut, Handle,
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::Array;
use futures::{FutureExt as _, future::try_join};
use std::collections::{BTreeMap, BTreeSet, btree_map};
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

    /// Durable per-section value-validation checkpoints.
    checkpoint: Checkpoint<E>,

    /// Per-section boundaries that may be published once their data sync completes.
    barriers: BTreeMap<u64, Barrier>,

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

    /// Maps translated key representation to its corresponding index.
    keys: Index<T, u64>,

    /// Maps index to its first position in the index journal.
    indices: BTreeMap<u64, u64>,

    /// Additional positions for indices with multiple entries, from either multi-value puts or
    /// ordinary puts that repair unreadable occurrences.
    extra_indices: BTreeMap<u64, Vec<u64>>,

    /// Positions whose value frames failed startup CRC validation, keyed by section.
    invalid_positions: BTreeMap<u64, BTreeSet<u64>>,

    /// Logical indices with at least one CRC-valid value occurrence.
    intervals: RMap,

    /// Logical indices with at least one retained index-journal occurrence.
    indexed_intervals: RMap,

    // Metrics
    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,

    #[cfg(test)]
    values_validated_on_init: u64,
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> Inner<T, E, K, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
    }

    /// Returns true when `index` is below the prune floor.
    const fn pruned(&self, index: u64) -> bool {
        match self.oldest_allowed {
            Some(oldest_allowed) => index < oldest_allowed,
            None => false,
        }
    }

    /// Iterate over all positions for a given index (first + extras).
    fn iter_positions(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        self.indices.get(&index).into_iter().copied().chain(
            self.extra_indices
                .get(&index)
                .into_iter()
                .flat_map(|v| v.iter().copied()),
        )
    }

    /// Adds one translated-key candidate per readable index while discarding candidates below the
    /// floor.
    fn insert_key_index(
        keys: &mut Index<T, u64>,
        key: &K,
        index: u64,
        index_already_readable: bool,
        oldest_allowed: u64,
    ) {
        // A first readable occurrence cannot already have a candidate for this index. Insert it
        // directly so unrelated candidates in the translated-key bucket are not scanned.
        if !index_already_readable {
            if oldest_allowed == 0 {
                keys.insert(key, index);
            } else {
                keys.insert_and_retain(key, index, |candidate| *candidate >= oldest_allowed);
            }
            return;
        }

        if oldest_allowed > 0 {
            keys.retain(key, |candidate| *candidate >= oldest_allowed);
        }
        if !keys.get(key).any(|candidate| *candidate == index) {
            keys.insert(key, index);
        }
    }

    /// Returns whether a value occurrence failed startup validation.
    fn invalid_occurrence(&self, section: u64, position: u64) -> bool {
        self.invalid_positions
            .get(&section)
            .is_some_and(|positions| positions.contains(&position))
    }

    /// Stage a checkpoint at `validated`, including every known invalid position below it.
    fn stage_checkpoint(&mut self, section: u64, validated: u64) -> bool {
        if let Some(invalid) = self.invalid_positions.get(&section) {
            self.checkpoint.stage(section, validated, invalid)
        } else {
            self.checkpoint.stage(section, validated, &BTreeSet::new())
        }
    }

    /// Returns the first readable value at `index` in insertion order.
    async fn first_value(&self, index: u64) -> Result<Option<V>, Error> {
        if !self.has_index(index) {
            return Ok(None);
        }

        let section = self.section(index);
        for position in self.iter_positions(index) {
            if self.invalid_occurrence(section, position) {
                continue;
            }
            let entry = self.oversized.get(section, position).await?;
            let (value_offset, value_size) = entry.value_location();
            return self
                .oversized
                .get_value(section, value_offset, value_size)
                .await
                .map(Some)
                .map_err(Into::into);
        }
        Err(Error::RecordCorrupted)
    }

    /// See [Archive::init].
    async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        let Config {
            translator,
            key_partition,
            metadata_partition,
            key_page_cache,
            value_partition,
            compression,
            codec_config,
            items_per_section,
            key_write_buffer,
            value_write_buffer,
            replay_buffer,
        } = cfg;

        if metadata_partition == key_partition || metadata_partition == value_partition {
            return Err(crate::journal::Error::InvalidConfiguration(
                "archive metadata partition must be distinct from key and value partitions".into(),
            )
            .into());
        }
        let items_per_section = items_per_section.get();
        let (mut checkpoint, mut checkpoint_dirty) = Checkpoint::open(
            context.child("checkpoint"),
            metadata_partition,
            &key_partition,
            &value_partition,
            items_per_section,
        )
        .await?;

        let oversized_cfg = OversizedConfig {
            index_partition: key_partition,
            value_partition,
            index_page_cache: key_page_cache,
            index_write_buffer: key_write_buffer,
            value_write_buffer,
            compression,
            codec_config,
        };
        let oversized: Oversized<E, Record<K>, V> =
            Oversized::init(context.child("oversized"), oversized_cfg, None).await?;
        let section_lengths = oversized
            .sections()
            .map(|section| Ok((section, oversized.section_len(section)?)))
            .collect::<Result<BTreeMap<_, _>, crate::journal::Error>>()?;
        let sections = section_lengths.keys().copied().collect::<BTreeSet<_>>();

        checkpoint_dirty |= checkpoint.retain(&sections);
        let trusted = section_lengths
            .iter()
            .filter_map(|(&section, &length)| {
                let state = checkpoint.get(section)?;
                (state.validated <= length).then(|| (section, state.clone()))
            })
            .collect::<BTreeMap<u64, SectionCheckpoint>>();

        let mut indices: BTreeMap<u64, u64> = BTreeMap::new();
        let mut extra_indices: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut invalid_positions = trusted
            .iter()
            .filter(|(_, state)| !state.invalid.is_empty())
            .map(|(&section, state)| (section, state.invalid.iter().copied().collect()))
            .collect::<BTreeMap<u64, BTreeSet<u64>>>();
        let mut keys = Index::new(context.child("index"), translator);
        let mut intervals = RMap::new();
        let mut indexed_intervals = RMap::new();
        let mut scanned_sections = BTreeSet::new();
        #[cfg(test)]
        let mut values_validated_on_init = 0;
        let values_validated = context.counter(
            "values_validated",
            "Number of value frames CRC-validated during startup",
        );
        let oversized = {
            debug!("initializing archive from index journal");
            let mut replay = oversized
                .replay(
                    0,
                    0,
                    replay_buffer,
                    commonware_runtime::ReadOptions::default(),
                )
                .await?;
            while let Some(result) = replay.next().await {
                let (section, position, entry) = result?;

                match indices.entry(entry.index) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert(position);
                    }
                    btree_map::Entry::Occupied(_) => {
                        extra_indices.entry(entry.index).or_default().push(position);
                    }
                }
                indexed_intervals.insert(entry.index);

                let valid = match trusted.get(&section) {
                    Some(state) if position < state.validated => !state.invalid(position),
                    _ => {
                        scanned_sections.insert(section);
                        let (offset, size) = entry.value_location();
                        values_validated.inc();
                        #[cfg(test)]
                        {
                            values_validated_on_init += 1;
                        }
                        replay.verify_value(section, offset, size).await?
                    }
                };
                if valid {
                    let index_already_readable = intervals.get(&entry.index).is_some();
                    Self::insert_key_index(
                        &mut keys,
                        &entry.key,
                        entry.index,
                        index_already_readable,
                        0,
                    );
                    intervals.insert(entry.index);
                } else {
                    invalid_positions
                        .entry(section)
                        .or_default()
                        .insert(position);
                }
            }
            debug!("archive initialized");
            replay.finish()?
        };

        // A checkpoint must never describe data that is not durable. This sync is needed only
        // for sections whose uncheckpointed suffix was validated, including the one-time upgrade
        // from an archive without validation metadata.
        let oversized = if scanned_sections.is_empty() {
            oversized
        } else {
            oversized.sync(&scanned_sections).await?
        };
        for (&section, &length) in &section_lengths {
            let empty = BTreeSet::new();
            let invalid = invalid_positions.get(&section).unwrap_or(&empty);
            checkpoint_dirty |= checkpoint.stage(section, length, invalid);
        }
        if checkpoint_dirty {
            checkpoint = checkpoint.sync().await?;
        }
        let barriers = section_lengths
            .into_iter()
            .map(|(section, length)| (section, Barrier::new(length)))
            .collect();

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
            items_per_section,
            oversized,
            checkpoint,
            barriers,
            pending: BTreeSet::new(),
            requested: BTreeSet::new(),
            oldest_allowed: None,
            indices,
            extra_indices,
            invalid_positions,
            intervals,
            indexed_intervals,
            keys,
            items_tracked,
            indices_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
            #[cfg(test)]
            values_validated_on_init,
        })
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();
        self.first_value(index).await
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Fetch index
        for index in self.keys.get(key) {
            // Continue if index is no longer allowed due to pruning.
            if self.pruned(*index) {
                continue;
            }

            if !self.indices.contains_key(index) {
                return Err(Error::RecordCorrupted);
            }
            let section = self.section(*index);

            for position in self.iter_positions(*index) {
                if self.invalid_occurrence(section, position) {
                    continue;
                }

                let entry = self.oversized.get(section, position).await?;
                if entry.key.as_ref() == key.as_ref() {
                    let (offset, size) = entry.value_location();
                    return self
                        .oversized
                        .get_value(section, offset, size)
                        .await
                        .map(Some)
                        .map_err(Into::into);
                }
                self.unnecessary_reads.inc();
            }
        }

        Ok(None)
    }

    /// Check whether any retained index stores a readable value for `key`.
    async fn has_key(&self, key: &K) -> Result<bool, Error> {
        for index in self.keys.get(key) {
            // Continue if index is no longer allowed due to pruning.
            if self.pruned(*index) {
                continue;
            }

            if !self.indices.contains_key(index) {
                return Err(Error::RecordCorrupted);
            }
            let section = self.section(*index);

            for position in self.iter_positions(*index) {
                if self.invalid_occurrence(section, position) {
                    continue;
                }

                let entry = self.oversized.get(section, position).await?;
                if entry.key.as_ref() == key.as_ref() {
                    return Ok(true);
                }
                self.unnecessary_reads.inc();
            }
        }

        Ok(false)
    }

    fn has_index(&self, index: u64) -> bool {
        self.indices.contains_key(&index) && self.intervals.get(&index).is_some()
    }

    async fn put_internal(
        mut self: Box<Self>,
        index: u64,
        key: K,
        data: V,
        skip_if_index_exists: bool,
    ) -> Result<Box<Self>, Error> {
        // A put below the prune floor is satisfied without storing
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            debug!(index, oldest_allowed, "ignoring put below prune floor");
            return Ok(self);
        }

        // Startup validation makes this decision independent of the first read operation. An
        // index represented only by torn value frames remains replaceable by one retransmission.
        let index_already_readable = self.has_index(index);
        if skip_if_index_exists && index_already_readable {
            return Ok(self);
        }

        // Write value and index entry atomically (glob first, then index)
        let section = self.section(index);
        let entry = Record::new(index, key.clone(), 0, 0);
        let position;
        (self.oversized, position, _, _) = self.oversized.append(section, entry, &data).await?;

        // Store index location
        match self.indices.entry(index) {
            btree_map::Entry::Vacant(e) => {
                e.insert(position);
            }
            btree_map::Entry::Occupied(_) => {
                self.extra_indices.entry(index).or_default().push(position);
            }
        }

        self.intervals.insert(index);
        self.indexed_intervals.insert(index);

        // Insert one candidate for this translated key and prune useless candidates in its bucket.
        Self::insert_key_index(
            &mut self.keys,
            &key,
            index,
            index_already_readable,
            oldest_allowed,
        );

        // Add section to pending
        self.pending.insert(section);
        self.barriers
            .entry(section)
            .or_insert_with(|| Barrier::new(0));

        // Update metrics
        let _ = self.items_tracked.try_set(self.indices.len());
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

        // Invalidate checkpoints before deleting or reusing their section names. A crash after
        // this sync but before the journal prune merely causes the retained sections to be
        // revalidated at the next initialization.
        if self.checkpoint.remove_before(min) {
            self.checkpoint = self.checkpoint.sync().await?;
        }

        (self.oversized, _) = self.oversized.prune(min).await?;

        self.pending = self.pending.split_off(&min);
        self.requested = self.requested.split_off(&min);
        self.barriers = self.barriers.split_off(&min);
        self.invalid_positions = self.invalid_positions.split_off(&min);

        // Remove all indices that are less than min
        loop {
            let next = match self.indices.first_key_value() {
                Some((index, _)) if *index < min => *index,
                _ => break,
            };
            self.indices.remove(&next).unwrap();
            self.extra_indices.remove(&next);
            self.indices_pruned.inc();
        }

        if min > 0 {
            self.intervals.remove(0, min - 1);
            self.indexed_intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from pruned sections)
        self.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(self.indices.len());
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
        // Update metrics (`requested` sections were already counted by `start_sync`)
        self.syncs.inc_by(self.pending.len() as u64);
        self.requested.append(&mut self.pending);

        let lengths = self
            .requested
            .iter()
            .map(|&section| Ok((section, self.oversized.section_len(section)?)))
            .collect::<Result<Vec<_>, crate::journal::Error>>()?;
        self.oversized = self.oversized.sync(&self.requested).await?;

        for (section, length) in lengths {
            self.barriers
                .entry(section)
                .or_insert_with(|| Barrier::new(0))
                .mark_durable(length);
            self.stage_checkpoint(section, length);
        }
        if !self.requested.is_empty() {
            self.checkpoint = self.checkpoint.sync().await?;
        }
        self.requested.clear();
        Ok(self)
    }

    /// See [crate::archive::Archive::start_sync].
    async fn start_sync(mut self: Box<Self>) -> Result<(Box<Self>, Handle<()>), Error> {
        // Update metrics
        self.syncs.inc_by(self.pending.len() as u64);

        self.requested.append(&mut self.pending);
        let lengths = self
            .requested
            .iter()
            .map(|&section| Ok((section, self.oversized.section_len(section)?)))
            .collect::<Result<Vec<_>, crate::journal::Error>>()?;
        let data;
        (self.oversized, data) = self.oversized.start_sync(&self.requested).await?;
        if lengths.is_empty() {
            return Ok((self, data));
        }

        let completion: SyncCompletion = data.boxed().shared();
        let mut publish = Vec::with_capacity(lengths.len());
        for (section, length) in lengths {
            let barrier = self
                .barriers
                .entry(section)
                .or_insert_with(|| Barrier::new(0));
            barrier.record(length, completion.clone());
            publish.push((section, barrier.boundary()));
        }
        let mut checkpoint_dirty = false;
        for (section, validated) in publish {
            checkpoint_dirty |= self.stage_checkpoint(section, validated);
        }

        if !checkpoint_dirty && !self.checkpoint.pending() {
            return Ok((self, Handle::from_future(completion)));
        }
        let metadata;
        (self.checkpoint, metadata) = self.checkpoint.start_sync().await?;
        let handle =
            Handle::from_future(async move { try_join(completion, metadata).await.map(|_| ()) });
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
        self.intervals.iter().map(|(&start, &end)| (start, end))
    }

    /// See [crate::archive::Archive::ranges_from].
    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.intervals
            .iter_from(from)
            .map(|(&start, &end)| (start, end))
    }

    /// See [crate::archive::Archive::first_index].
    fn first_index(&self) -> Option<u64> {
        self.intervals.first_index()
    }

    /// See [crate::archive::Archive::last_index].
    fn last_index(&self) -> Option<u64> {
        self.intervals.last_index()
    }

    /// Return missing items in the retained index-journal view.
    fn indexed_missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.indexed_intervals.missing_items(index, max)
    }

    /// Return gap boundaries in the retained index-journal view.
    fn indexed_next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.indexed_intervals.next_gap(index)
    }

    /// Return retained index-journal ranges overlapping or following `from`.
    fn indexed_ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.indexed_intervals
            .iter_from(from)
            .map(|(&start, &end)| (start, end))
    }

    /// Return the highest retained index-journal occurrence.
    fn indexed_last_index(&self) -> Option<u64> {
        self.indexed_intervals.last_index()
    }

    /// See [crate::archive::Archive::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.checkpoint.destroy().await?;
        self.oversized.destroy().await?;
        Ok(())
    }

    /// See [crate::archive::MultiArchive::get_all].
    async fn get_all(&self, index: u64) -> Result<Option<Vec<V>>, Error> {
        // Update metrics
        self.gets.inc();

        // Check if the index exists and has not already been fully invalidated.
        if !self.has_index(index) {
            return Ok(None);
        }

        // Get all positions at this index
        let section = self.section(index);
        let extra_count = self.extra_indices.get(&index).map_or(0, Vec::len);

        let mut values = Vec::with_capacity(1 + extra_count);
        for position in self.iter_positions(index) {
            if self.invalid_occurrence(section, position) {
                continue;
            }

            let entry = self.oversized.get(section, position).await?;
            let (offset, size) = entry.value_location();
            values.push(self.oversized.get_value(section, offset, size).await?);
        }
        Ok((!values.is_empty()).then_some(values))
    }

    /// See [crate::archive::MultiArchive::has_at].
    async fn has_at(&self, index: u64, key: &K) -> Result<bool, Error> {
        self.has.inc();

        // Ignore pruned indices.
        if self.pruned(index) {
            return Ok(false);
        }

        // A key absent from the in-memory index is not stored at this index. A translated-key hit
        // may be a collision, so scan persisted full keys and validate each exact match.
        if !self.keys.get(key).any(|candidate| *candidate == index) {
            return Ok(false);
        }
        let section = self.section(index);
        for position in self.iter_positions(index) {
            if self.invalid_occurrence(section, position) {
                continue;
            }
            let entry = self.oversized.get(section, position).await?;
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
    /// Number of value frames validated while opening this handle.
    #[cfg(test)]
    pub(super) fn values_validated_on_init(&self) -> u64 {
        self.0.values_validated_on_init
    }

    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index is populated by replaying the index journal. Value frames not covered by
    /// a durable validation checkpoint are CRC-validated before this returns.
    pub async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg).await?)))
    }

    /// Prune `Archive` to the provided `min` (masked by the configured
    /// section mask).
    ///
    /// If this is called with a min lower than the last pruned, nothing
    /// will happen. The live handle remembers the floor; callers must reapply any durable
    /// application floor after reinitializing the archive before accepting old puts.
    pub async fn prune(mut self, min: u64) -> Result<Self, Error> {
        self.0 = self.0.prune(min).await?;
        Ok(self)
    }

    /// Return missing items from the physical index-journal view.
    ///
    /// Unlike [crate::archive::Archive::missing_items], an index whose every value occurrence
    /// failed CRC validation is treated as present. Recovery code can use this view to distinguish
    /// missing index metadata from an indexed value that must be fetched and replaced.
    pub fn indexed_missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.0.indexed_missing_items(index, max)
    }

    /// Return gap boundaries from the physical index-journal view.
    ///
    /// A returned range may contain values that failed startup validation. Call
    /// [crate::archive::Archive::get] before relying on a candidate's value.
    pub fn indexed_next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.0.indexed_next_gap(index)
    }

    /// Return physical index-journal ranges overlapping or following `from`.
    ///
    /// A returned range may contain values that failed startup validation. Call
    /// [crate::archive::Archive::get] before relying on a candidate's value.
    pub fn indexed_ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.0.indexed_ranges_from(from)
    }

    /// Return the highest index with a retained index-journal occurrence.
    ///
    /// The value at this index may have failed startup validation. Call
    /// [crate::archive::Archive::get] before relying on it.
    pub fn indexed_last_index(&self) -> Option<u64> {
        self.0.indexed_last_index()
    }
}

impl<T: Translator, E: Context, K: Array, V: CodecShared> crate::archive::Archive
    for Archive<T, E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        self.0 = self.0.put_internal(index, key, data, true).await?;
        Ok(self)
    }

    async fn put_sync(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        self.0 = self.0.put_internal(index, key, data, true).await?;
        self.sync().await
    }

    async fn put_start_sync(
        mut self,
        index: u64,
        key: K,
        data: V,
    ) -> Result<(Self, Handle<()>), Error> {
        self.0 = self.0.put_internal(index, key, data, true).await?;
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
        self.0 = self.0.put_internal(index, key, data, false).await?;
        Ok(self)
    }

    async fn put_multi_sync(mut self, index: u64, key: K, data: V) -> Result<Self, Error> {
        self.0 = self.0.put_internal(index, key, data, false).await?;
        crate::archive::Archive::sync(self).await
    }

    async fn put_multi_start_sync(
        mut self,
        index: u64,
        key: K,
        data: V,
    ) -> Result<(Self, Handle<()>), Error> {
        self.0 = self.0.put_internal(index, key, data, false).await?;
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
