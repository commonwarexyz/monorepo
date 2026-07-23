use super::{Config, Error};
use crate::{
    journal::segmented::variable::{Config as JConfig, Journal},
    rmap::RMap,
};
use commonware_codec::{CodecShared, EncodeSize, Read, ReadExt, Write, varint::UInt};
use commonware_runtime::{
    Buf, BufMut, Metrics, Storage,
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use std::collections::{BTreeMap, BTreeSet};
use tracing::debug;

/// Record stored in the `Cache`.
struct Record<V: CodecShared> {
    index: u64,
    value: V,
}

impl<V: CodecShared> Record<V> {
    /// Create a new `Record`.
    const fn new(index: u64, value: V) -> Self {
        Self { index, value }
    }
}

impl<V: CodecShared> Write for Record<V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.value.write(buf);
    }
}

impl<V: CodecShared> Read for Record<V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let index = UInt::read(buf)?.into();
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self { index, value })
    }
}

impl<V: CodecShared> EncodeSize for Record<V> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.value.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: CodecShared> arbitrary::Arbitrary<'_> for Record<V>
where
    V: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

/// The cache's state, boxed so the public [Cache] handle stays pointer-sized.
struct Inner<E: Storage + Metrics, V: CodecShared> {
    items_per_blob: u64,
    journal: Journal<E, Record<V>>,
    pending: BTreeSet<u64>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,
    indices: BTreeMap<u64, u64>,
    intervals: RMap,

    items_tracked: Gauge,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics, V: CodecShared> Inner<E, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_blob) * self.items_per_blob
    }

    /// See [Cache::init].
    async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize journal
        let journal = Journal::<E, Record<V>>::init(
            context.child("journal"),
            JConfig {
                partition: cfg.partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                page_cache: cfg.page_cache,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Initialize keys and run corruption check
        let mut indices = BTreeMap::new();
        let mut intervals = RMap::new();
        let journal = {
            debug!("initializing cache");
            let mut replay = journal.replay(0, 0, cfg.replay_buffer).await?;
            while let Some(result) = replay.next().await {
                // Extract key from record
                let (_, offset, _, data) = result?;

                // Store index
                indices.insert(data.index, offset);

                // Store index in intervals
                intervals.insert(data.index);
            }
            debug!(items = indices.len(), "cache initialized");
            replay.finish()?
        };

        // Initialize metrics
        let items_tracked = context.gauge("items_tracked", "Number of items tracked");
        let gets = context.counter("gets", "Number of gets performed");
        let has = context.counter("has", "Number of has performed");
        let syncs = context.counter("syncs", "Number of syncs called");
        let _ = items_tracked.try_set(indices.len());

        // Return populated cache
        Ok(Self {
            items_per_blob: cfg.items_per_blob.get(),
            journal,
            pending: BTreeSet::new(),
            oldest_allowed: None,
            indices,
            intervals,
            items_tracked,
            gets,
            has,
            syncs,
        })
    }

    /// See [Cache::get].
    async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get index location
        let offset = match self.indices.get(&index) {
            Some(offset) => *offset,
            None => return Ok(None),
        };

        // Fetch item from disk
        let section = self.section(index);
        let record = self.journal.get(section, offset).await?;
        Ok(Some(record.value))
    }

    /// See [Cache::next_gap].
    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// See [Cache::first].
    fn first(&self) -> Option<u64> {
        self.intervals.iter().next().map(|(&start, _)| start)
    }

    /// See [Cache::missing_items].
    fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(start, max)
    }

    /// See [Cache::has].
    fn has(&self, index: u64) -> bool {
        // Update metrics
        self.has.inc();

        // Check if index exists
        self.indices.contains_key(&index)
    }

    /// See [Cache::prune].
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
        debug!(min, "pruning cache");

        // Prune journal
        (self.journal, _) = self.journal.prune(min).await.map_err(Error::Journal)?;

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
        }

        // Remove all intervals that are less than min
        if min > 0 {
            self.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        let _ = self.items_tracked.try_set(self.indices.len());
        Ok(self)
    }

    /// See [Cache::put].
    async fn put(mut self: Box<Self>, index: u64, value: V) -> Result<(Box<Self>, bool), Error> {
        // A put below the prune floor is satisfied without storing
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            debug!(index, oldest_allowed, "ignoring put below prune floor");
            return Ok((self, false));
        }

        // Check for existing index
        if self.indices.contains_key(&index) {
            return Ok((self, true));
        }

        // Store item in journal
        let record = Record::new(index, value);
        let section = self.section(index);
        let offset;
        (self.journal, offset, _) = self.journal.append(section, &record).await?;

        // Store index
        self.indices.insert(index, offset);

        // Add index to intervals
        self.intervals.insert(index);

        // Add section to pending
        self.pending.insert(section);

        // Update metrics
        let _ = self.items_tracked.try_set(self.indices.len());
        Ok((self, true))
    }

    /// See [Cache::sync].
    async fn sync(mut self: Box<Self>) -> Result<Box<Self>, Error> {
        self.syncs.inc_by(self.pending.len() as u64);
        self.journal = self.journal.sync(&self.pending).await?;
        self.pending.clear();
        Ok(self)
    }

    /// See [Cache::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await.map_err(Error::Journal)
    }
}

/// Implementation of `Cache` storage.
///
/// Mutating functions consume the cache and return it only on success: an error (or a dropped
/// future) destroys the handle.
pub struct Cache<E: Storage + Metrics, V: CodecShared>(Box<Inner<E, V>>);

impl<E: Storage + Metrics, V: CodecShared> std::fmt::Debug for Cache<E, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("first_index", &self.0.intervals.first_index())
            .field("last_index", &self.0.intervals.last_index())
            .finish_non_exhaustive()
    }
}

impl<E: Storage + Metrics, V: CodecShared> Cache<E, V> {
    /// Initialize a new `Cache` instance.
    ///
    /// The in-memory index for `Cache` is populated during this call
    /// by replaying the journal.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg).await?)))
    }

    /// Retrieve an item from the [Cache].
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        self.0.get(index).await
    }

    /// Retrieve the next gap in the [Cache].
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.0.next_gap(index)
    }

    /// Returns the first index in the [Cache].
    pub fn first(&self) -> Option<u64> {
        self.0.first()
    }

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    pub fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        self.0.missing_items(start, max)
    }

    /// Check if an item exists in the [Cache].
    pub fn has(&self, index: u64) -> bool {
        self.0.has(index)
    }

    /// Prune [Cache] to the provided `min`.
    ///
    /// If this is called with a min lower than the last pruned, nothing
    /// will happen.
    pub async fn prune(mut self, min: u64) -> Result<Self, Error> {
        self.0 = self.0.prune(min).await?;
        Ok(self)
    }

    /// Store an item in the [Cache].
    ///
    /// If the index already exists, put does nothing and returns. A put below the prune
    /// floor is satisfied without storing: pruning declared that range obsolete, so nothing
    /// is mutated and nothing below the floor is ever readable.
    pub async fn put(mut self, index: u64, value: V) -> Result<Self, Error> {
        (self.0, _) = self.0.put(index, value).await?;
        Ok(self)
    }

    /// Sync all pending writes.
    pub async fn sync(mut self) -> Result<Self, Error> {
        self.0 = self.0.sync().await?;
        Ok(self)
    }

    /// Stores an item in the [Cache] and syncs it, plus any other pending writes, to disk.
    ///
    /// If the index already exists, the cache is just synced. A put satisfied below the
    /// prune floor stored nothing, so it skips the sync.
    pub async fn put_sync(mut self, index: u64, value: V) -> Result<Self, Error> {
        let stored;
        (self.0, stored) = self.0.put(index, value).await?;
        if !stored {
            return Ok(self);
        }
        self.sync().await
    }

    /// Remove all persistent data created by this [Cache].
    pub async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Record<u64>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::deterministic::Context;

    type TestCache = Cache<Context, u64>;

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_cache_futures_are_send(cache: &TestCache, key: &u64) {
        is_send(cache.get(*key));
    }

    #[allow(dead_code)]
    fn assert_cache_destroy_is_send(cache: TestCache) {
        is_send(cache.destroy());
    }
}
