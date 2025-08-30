use super::{Config, Translator};
use crate::{
    archive::{Error, Identifier},
    index::Index,
    journal::variable::{Config as JConfig, Journal},
    rmap::RMap,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, ReadExt, Write};
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;
use futures::{future::try_join_all, pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{BTreeMap, BTreeSet};
use tracing::debug;

/// Location of a record in `Journal`.
struct Location {
    offset: u32,
    len: u32,
}

/// Record stored in the `Archive`.
struct Record<K: Array, V: Codec> {
    index: u64,
    key: K,
    value: V,
}

impl<K: Array, V: Codec> Record<K, V> {
    /// Create a new `Record`.
    fn new(index: u64, key: K, value: V) -> Self {
        Self { index, key, value }
    }
}

impl<K: Array, V: Codec> Write for Record<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl<K: Array, V: Codec> Read for Record<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let index = UInt::read(buf)?.into();
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self { index, key, value })
    }
}

impl<K: Array, V: Codec> EncodeSize for Record<K, V> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + K::SIZE + self.value.encode_size()
    }
}

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, E: Storage + Metrics, K: Array, V: Codec> {
    items_per_section: u64,
    journal: Journal<E, Record<K, V>>,
    pending: BTreeSet<u64>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,

    // To efficiently serve `get` and `has` requests, we map a translated representation of each key
    // to its corresponding index. To avoid iterating over this keys map during pruning, we map said
    // indexes to their locations in the journal.
    keys: Index<T, u64>,
    indices: BTreeMap<u64, Location>,
    intervals: RMap,

    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, E: Storage + Metrics, K: Array, V: Codec> Archive<T, E, K, V> {
    /// Calculate the section for a given index.
    fn section(&self, index: u64) -> u64 {
        (index / self.items_per_section) * self.items_per_section
    }

    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying the journal.
    pub async fn init(context: E, cfg: Config<T, V::Cfg>) -> Result<Self, Error> {
        // Initialize journal
        let journal = Journal::<E, Record<K, V>>::init(
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
        let mut keys = Index::init(context.with_label("index"), cfg.translator.clone());
        let mut intervals = RMap::new();
        {
            debug!("initializing archive");
            let stream = journal.replay(0, 0, cfg.replay_buffer).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;

                // Store index
                indices.insert(data.index, Location { offset, len });

                // Store index in keys
                keys.insert(&data.key, data.index);

                // Store index in intervals
                intervals.insert(data.index);
            }
            debug!(keys = keys.keys(), "archive initialized");
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
            items_per_section: cfg.items_per_section.get(),
            journal,
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
        let location = match self.indices.get(&index) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        // Fetch item from disk
        let section = self.section(index);
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
            let section = self.section(*index);
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
            self.indices_pruned.inc();
        }

        // Remove all keys from interval tree less than min
        if min > 0 {
            self.intervals.remove(0, min - 1);
        }

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        self.items_tracked.set(self.indices.len() as i64);
        Ok(())
    }
}

impl<T: Translator, E: Storage + Metrics, K: Array, V: Codec> crate::archive::Archive
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

        // Store item in journal
        let record = Record::new(index, key.clone(), data);
        let section = self.section(index);
        let (offset, len) = self.journal.append(section, record).await?;

        // Store index
        self.indices.insert(index, Location { offset, len });

        // Store interval
        self.intervals.insert(index);

        // Insert and prune any useless keys
        self.keys
            .insert_and_prune(&key, index, |v| *v < oldest_allowed);

        // Add section to pending
        self.pending.insert(section);

        // Update metrics
        self.items_tracked.set(self.indices.len() as i64);
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
        let mut syncs = Vec::with_capacity(self.pending.len());
        for section in self.pending.iter() {
            syncs.push(self.journal.sync(*section));
            self.syncs.inc();
        }
        try_join_all(syncs).await?;
        self.pending.clear();
        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }

    async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await.map_err(Error::Journal)
    }
}
