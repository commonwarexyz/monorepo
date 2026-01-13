use super::{Config, Translator};
use crate::{
    archive::{Error, Identifier},
    index::{unordered::Index, Unordered},
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    rmap::RMap,
};
use bytes::{Buf, BufMut};
use commonware_codec::{CodecShared, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Metrics, Storage};
use commonware_utils::Array;
use futures::{future::try_join_all, pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
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

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, E: Storage + Metrics, K: Array, V: CodecShared> {
    items_per_section: u64,

    /// Combined index + value storage with crash recovery.
    oversized: Oversized<E, Record<K>, V>,

    pending: BTreeSet<u64>,

    /// Oldest allowed section to read from. Updated when `prune` is called.
    oldest_allowed: Option<u64>,

    /// Maps translated key representation to its corresponding index.
    keys: Index<T, u64>,

    /// Maps index to position in index journal.
    indices: BTreeMap<u64, u64>,

    /// Interval tracking for gap detection.
    intervals: RMap,

    // Metrics
    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, E: Storage + Metrics, K: Array, V: CodecShared> Archive<T, E, K, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
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
            index_buffer_pool: cfg.key_buffer_pool,
            index_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        };
        let oversized: Oversized<E, Record<K>, V> =
            Oversized::init(context.with_label("oversized"), oversized_cfg).await?;

        // Initialize keys and replay index journal (no values read!)
        let mut indices = BTreeMap::new();
        let mut keys = Index::new(context.with_label("index"), cfg.translator.clone());
        let mut intervals = RMap::new();
        {
            debug!("initializing archive from index journal");
            let stream = oversized.replay(0, cfg.replay_buffer).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_section, position, entry) = result?;

                // Store index location (position in index journal)
                indices.insert(entry.index, position);

                // Store index in keys
                keys.insert(&entry.key, entry.index);

                // Store index in intervals
                intervals.insert(entry.index);
            }
            debug!("archive initialized");
        }

        // Initialize metrics
        let items_tracked = Gauge::default();
        let indices_pruned = Counter::default();
        let unnecessary_reads = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register(
            "items_tracked",
            "Number of items tracked",
            items_tracked.clone(),
        );
        context.register(
            "indices_pruned",
            "Number of indices pruned",
            indices_pruned.clone(),
        );
        context.register(
            "unnecessary_reads",
            "Number of unnecessary reads performed during key lookups",
            unnecessary_reads.clone(),
        );
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());
        let _ = items_tracked.try_set(indices.len());

        // Return populated archive
        Ok(Self {
            items_per_section: cfg.items_per_section.get(),
            oversized,
            pending: BTreeSet::new(),
            oldest_allowed: None,
            indices,
            intervals,
            keys,
            items_tracked,
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

        // Get index location
        let position = match self.indices.get(&index) {
            Some(pos) => *pos,
            None => return Ok(None),
        };

        // Fetch index entry to get value location
        let section = self.section(index);
        let entry = self.oversized.get(section, position).await?;
        let (value_offset, value_size) = entry.value_location();

        // Fetch value directly from blob storage (bypasses buffer pool)
        let value = self
            .oversized
            .get_value(section, value_offset, value_size)
            .await?;
        Ok(Some(value))
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Fetch index
        let iter = self.keys.get(key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        for index in iter {
            // Continue if index is no longer allowed due to pruning.
            if *index < min_allowed {
                continue;
            }

            // Get index location
            let position = *self.indices.get(index).ok_or(Error::RecordCorrupted)?;

            // Fetch index entry from index journal to verify key
            let section = self.section(*index);
            let entry = self.oversized.get(section, position).await?;

            // Verify key matches
            if entry.key.as_ref() == key.as_ref() {
                // Fetch value directly from blob storage (bypasses buffer pool)
                let (value_offset, value_size) = entry.value_location();
                let value = self
                    .oversized
                    .get_value(section, value_offset, value_size)
                    .await?;
                return Ok(Some(value));
            }
            self.unnecessary_reads.inc();
        }

        Ok(None)
    }

    fn has_index(&self, index: u64) -> bool {
        // Check if index exists
        self.indices.contains_key(&index)
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
        if let Some(oldest_allowed) = self.oldest_allowed {
            if min <= oldest_allowed {
                // We don't return an error in this case because the caller
                // shouldn't be burdened with converting `min` to some section.
                return Ok(());
            }
        }
        debug!(min, "pruning archive");

        // Prune oversized journal (handles both index and values)
        self.oversized.prune(min).await?;

        // Remove pending writes (no need to call `sync` as we are pruning)
        loop {
            let next = match self.pending.iter().next() {
                Some(section) if *section < min => *section,
                _ => break,
            };
            self.pending.remove(&next);
        }

        // Remove all indices that are less than min
        loop {
            let next = match self.indices.first_key_value() {
                Some((index, _)) if *index < min => *index,
                _ => break,
            };
            self.indices.remove(&next).unwrap();
            self.indices_pruned.inc();
        }

        // Remove all keys from interval tree less than min
        if min > 0 {
            self.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from pruned sections)
        self.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(self.indices.len());
        Ok(())
    }
}

impl<T: Translator, E: Storage + Metrics, K: Array, V: CodecShared> crate::archive::Archive
    for Archive<T, E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedTo(oldest_allowed));
        }

        // Check for existing index
        if self.indices.contains_key(&index) {
            return Ok(());
        }

        // Write value and index entry atomically (glob first, then index)
        let section = self.section(index);
        let entry = Record::new(index, key.clone(), 0, 0);
        let (position, _, _) = self.oversized.append(section, entry, &data).await?;

        // Store index location
        self.indices.insert(index, position);

        // Store interval
        self.intervals.insert(index);

        // Insert and prune any useless keys
        self.keys
            .insert_and_prune(&key, index, |v| *v < oldest_allowed);

        // Add section to pending
        self.pending.insert(section);

        // Update metrics
        let _ = self.items_tracked.try_set(self.indices.len());
        Ok(())
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        // Collect pending sections and update metrics
        let pending: Vec<u64> = self.pending.iter().copied().collect();
        self.syncs.inc_by(pending.len() as u64);

        // Sync oversized journal (handles both index and values)
        let syncs: Vec<_> = pending.iter().map(|s| self.oversized.sync(*s)).collect();
        try_join_all(syncs).await?;

        self.pending.clear();
        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(index, max)
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.intervals.iter().map(|(&s, &e)| (s, e))
    }

    fn first_index(&self) -> Option<u64> {
        self.intervals.first_index()
    }

    fn last_index(&self) -> Option<u64> {
        self.intervals.last_index()
    }

    async fn destroy(self) -> Result<(), Error> {
        Ok(self.oversized.destroy().await?)
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
