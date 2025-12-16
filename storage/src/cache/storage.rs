use super::{Config, Error};
use crate::{
    journal::segmented::variable::{Config as JConfig, Journal},
    rmap::RMap,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, ReadExt, Write};
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Metrics, Storage};
use futures::{future::try_join_all, pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{BTreeMap, BTreeSet};
use tracing::debug;

/// Location of a record in `Journal`.
struct Location {
    offset: u32,
    len: u32,
}

/// Record stored in the `Cache`.
struct Record<V: Codec> {
    index: u64,
    value: V,
}

impl<V: Codec> Record<V> {
    /// Create a new `Record`.
    const fn new(index: u64, value: V) -> Self {
        Self { index, value }
    }
}

impl<V: Codec> Write for Record<V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.value.write(buf);
    }
}

impl<V: Codec> Read for Record<V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let index = UInt::read(buf)?.into();
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self { index, value })
    }
}

impl<V: Codec> EncodeSize for Record<V> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.value.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Codec> arbitrary::Arbitrary<'_> for Record<V>
where
    V: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

/// Implementation of `Cache` storage.
pub struct Cache<E: Storage + Metrics, V: Codec> {
    items_per_blob: u64,
    journal: Journal<E, Record<V>>,
    pending: BTreeSet<u64>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,
    indices: BTreeMap<u64, Location>,
    intervals: RMap,

    items_tracked: Gauge,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics, V: Codec> Cache<E, V> {
    /// Calculate the section for a given index.
    const fn section(&self, index: u64) -> u64 {
        (index / self.items_per_blob) * self.items_per_blob
    }

    /// Initialize a new `Cache` instance.
    ///
    /// The in-memory index for `Cache` is populated during this call
    /// by replaying the journal.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize journal
        let journal = Journal::<E, Record<V>>::init(
            context.with_label("journal"),
            JConfig {
                partition: cfg.partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Initialize keys and run corruption check
        let mut indices = BTreeMap::new();
        let mut intervals = RMap::new();
        {
            debug!("initializing cache");
            let stream = journal.replay(0, 0, cfg.replay_buffer).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;

                // Store index
                indices.insert(data.index, Location { offset, len });

                // Store index in intervals
                intervals.insert(data.index);
            }
            debug!(items = indices.len(), "cache initialized");
        }

        // Initialize metrics
        let items_tracked = Gauge::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register(
            "items_tracked",
            "Number of items tracked",
            items_tracked.clone(),
        );
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());
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

    /// Retrieve an item from the [Cache].
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get index location
        let location = match self.indices.get(&index) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        // Fetch item from disk
        let section = self.section(index);
        let record = self
            .journal
            .get_exact(section, location.offset, location.len)
            .await?;
        Ok(Some(record.value))
    }

    /// Retrieve the next gap in the [Cache].
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// Returns the first index in the [Cache].
    pub fn first(&self) -> Option<u64> {
        self.intervals.iter().next().map(|(&start, _)| start)
    }

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    pub fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(start, max)
    }

    /// Check if an item exists in the [Cache].
    pub fn has(&self, index: u64) -> bool {
        // Update metrics
        self.has.inc();

        // Check if index exists
        self.indices.contains_key(&index)
    }

    /// Prune [Cache] to the provided `min`.
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
        debug!(min, "pruning cache");

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)?;

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
        Ok(())
    }

    /// Store an item in the [Cache].
    ///
    /// If the index already exists, put does nothing and returns.
    pub async fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedTo(oldest_allowed));
        }

        // Check for existing index
        if self.indices.contains_key(&index) {
            return Ok(());
        }

        // Store item in journal
        let record = Record::new(index, value);
        let section = self.section(index);
        let (offset, len) = self.journal.append(section, record).await?;

        // Store index
        self.indices.insert(index, Location { offset, len });

        // Add index to intervals
        self.intervals.insert(index);

        // Add section to pending
        self.pending.insert(section);

        // Update metrics
        let _ = self.items_tracked.try_set(self.indices.len());
        Ok(())
    }

    /// Sync all pending writes.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut syncs = Vec::with_capacity(self.pending.len());
        for section in self.pending.iter() {
            syncs.push(self.journal.sync(*section));
            self.syncs.inc();
        }
        try_join_all(syncs).await?;
        self.pending.clear();
        Ok(())
    }

    /// Stores an item in the [Cache] and syncs it, plus any other pending writes, to disk.
    ///
    /// If the index already exists, the cache is just synced.
    pub async fn put_sync(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.put(index, value).await?;
        self.sync().await
    }

    /// Close the [Cache].
    ///
    /// Any pending writes will be synced prior to closing.
    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }

    /// Remove all persistent data created by this [Cache].
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await.map_err(Error::Journal)
    }
}

impl<E: Storage + Metrics, V: Codec> crate::store::Store for Cache<E, V> {
    type Key = u64;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(*key).await
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
