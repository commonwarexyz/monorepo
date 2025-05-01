use super::{Config, Error, Translator};
use crate::{
    index::Index,
    journal::variable::{Config as JConfig, Journal},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Codec, Config as CodecConfig, EncodeSize, Read, ReadExt, Write,
};
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rangemap::RangeInclusiveSet;
use std::{collections::BTreeMap, marker::PhantomData};
use tracing::{debug, trace};

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Location of a record in `Journal`.
struct Location {
    offset: u32,
    len: u32,
}

/// Record stored in the `Archive`.
struct Record<K: Array, VC: CodecConfig, V: Codec<VC>> {
    index: u64,
    key: K,
    value: V,

    _phantom: PhantomData<VC>,
}

impl<K: Array, VC: CodecConfig, V: Codec<VC>> Record<K, VC, V> {
    /// Create a new `Record`.
    fn new(index: u64, key: K, value: V) -> Self {
        Self {
            index,
            key,
            value,
            _phantom: PhantomData,
        }
    }
}

impl<K: Array, VC: CodecConfig, V: Codec<VC>> Write for Record<K, VC, V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl<K: Array, VC: CodecConfig, V: Codec<VC>> Read<VC> for Record<K, VC, V> {
    fn read_cfg(buf: &mut impl Buf, cfg: &VC) -> Result<Self, commonware_codec::Error> {
        let index = UInt::read(buf)?.into();
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self {
            index,
            key,
            value,
            _phantom: PhantomData,
        })
    }
}

impl<K: Array, VC: CodecConfig, V: Codec<VC>> EncodeSize for Record<K, VC, V> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + K::SIZE + self.value.encode_size()
    }
}

/// Implementation of `Archive` storage.
pub struct Archive<
    T: Translator,
    E: Storage + Metrics,
    K: Array,
    VC: CodecConfig + Copy,
    V: Codec<VC>,
> {
    // The section mask is used to determine which section of the journal to write to.
    section_mask: u64,
    journal: Journal<E, VC, Record<K, VC, V>>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,

    // To efficiently serve `get` and `has` requests, we map a translated representation of each key
    // to its corresponding index. To avoid iterating over this keys map during pruning, we map said
    // indexes to their locations in the journal.
    keys: Index<T, u64>,
    indices: BTreeMap<u64, Location>,
    intervals: RangeInclusiveSet<u64>,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: usize,
    pending: BTreeMap<u64, usize>,

    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, E: Storage + Metrics, K: Array, VC: CodecConfig + Copy, V: Codec<VC>>
    Archive<T, E, K, VC, V>
{
    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying the journal.
    pub async fn init(context: E, cfg: Config<T, VC>) -> Result<Self, Error> {
        // Initialize journal
        let mut journal = Journal::<E, VC, Record<K, VC, V>>::init(
            context.with_label("journal"),
            JConfig {
                partition: cfg.partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
            },
        )
        .await?;

        // Initialize keys and run corruption check
        let mut indices = BTreeMap::new();
        let mut keys = Index::init(context.with_label("index"), cfg.translator.clone());
        let mut intervals = RangeInclusiveSet::new();
        {
            debug!("initializing archive");
            let stream = journal.replay(cfg.replay_concurrency).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;

                // Store index
                let index = data.index;
                indices.insert(index, Location { offset, len });

                // Store index in keys
                keys.insert(&data.key, index);

                // Store index in intervals
                intervals.insert(index..=index);
            }
            debug!(keys = keys.len(), "archive initialized");
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
        items_tracked.set(indices.len() as i64);

        // Return populated archive
        Ok(Self {
            pending_writes: cfg.pending_writes,
            section_mask: cfg.section_mask,
            journal,
            oldest_allowed: None,
            indices,
            intervals,
            keys,
            pending: BTreeMap::new(),
            items_tracked,
            indices_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
        })
    }

    /// Store an item in `Archive`. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    pub async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
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
        let record = Record::new(index, key.clone(), data);
        let section = self.section_mask & index;
        let (offset, len) = self.journal.append(section, record).await?;

        // Store index
        self.indices.insert(index, Location { offset, len });

        // Store interval
        self.intervals.insert(index..=index);

        // Insert and prune any useless keys
        self.keys
            .insert_and_prune(&key, index, |v| *v < oldest_allowed);

        // Update pending writes
        let pending_writes = self.pending.entry(section).or_default();
        *pending_writes += 1;
        if *pending_writes > self.pending_writes {
            self.journal.sync(section).await.map_err(Error::Journal)?;
            trace!(section, mode = "pending", "synced section");
            *pending_writes = 0;
            self.syncs.inc();
        }

        // Update metrics
        self.items_tracked.set(self.indices.len() as i64);
        Ok(())
    }

    /// Retrieve an item from `Archive`.
    pub async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get index location
        let location = match self.indices.get(&index) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        // Fetch item from disk
        let section = self.section_mask & index;
        let record = self
            .journal
            .get_exact(section, location.offset, location.len)
            .await?
            .ok_or(Error::RecordCorrupted)?;
        Ok(Some(record.value))
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

            // Fetch item from disk
            let location = self.indices.get(index).ok_or(Error::RecordCorrupted)?;
            let section = self.section_mask & index;
            let record = self
                .journal
                .get_exact(section, location.offset, location.len)
                .await?
                .ok_or(Error::RecordCorrupted)?;

            // Get key from item
            if record.key.as_ref() == key.as_ref() {
                return Ok(Some(record.value));
            }
            self.unnecessary_reads.inc();
        }

        Ok(None)
    }

    /// Check if an item exists in the `Archive`.
    pub async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
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
        let min = self.section_mask & min;

        // Check if min is less than last pruned
        if let Some(oldest_allowed) = self.oldest_allowed {
            if min <= oldest_allowed {
                // We don't return an error in this case because the caller
                // shouldn't be burdened with converting `min` to some section.
                return Ok(());
            }
        }
        debug!(min, "pruning archive");

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)?;

        // Remove pending writes (no need to call `sync` as we are pruning)
        loop {
            let next = match self.pending.first_key_value() {
                Some((section, _)) if *section < min => *section,
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
            self.intervals.remove(0..=min - 1);
        }

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        self.items_tracked.set(self.indices.len() as i64);
        Ok(())
    }

    /// Forcibly sync all pending writes across all `Journals`.
    pub async fn sync(&mut self) -> Result<(), Error> {
        for (section, count) in self.pending.iter_mut() {
            if *count == 0 {
                continue;
            }
            self.journal.sync(*section).await.map_err(Error::Journal)?;
            trace!(
                section = *section,
                count = *count,
                mode = "force",
                "synced section"
            );
            self.syncs.inc();
            *count = 0;
        }
        Ok(())
    }

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        // Get end of current range (if exists)
        let current = self.intervals.get(&index);
        let current_end = current.map(|range| range.end());

        // Get start of next range (if exists)
        let next = self.intervals.iter().find(|range| range.start() > &index);
        let next_start = next.map(|range| range.start());
        (current_end.copied(), next_start.copied())
    }

    /// Close `Archive` (and underlying `Journal`).
    ///
    /// Any pending writes will be synced by `Journal` prior
    /// to closing.
    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }

    /// Remove all on-disk data created by this `Archive`.
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await.map_err(Error::Journal)
    }
}
