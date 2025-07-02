use crate::{
    archive::{minimal::Config, Error, Identifier},
    journal::variable::{self, Journal},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::BloomFilter;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{
    array::{U32, U64},
    Array, BitVec, NZUsize,
};
use futures::{future::try_join_all, join};
use prometheus_client::metrics::counter::Counter;
use std::collections::{BTreeSet, HashMap};
use tracing::debug;

const FALSE_POSITIVE_NUMERATOR: usize = 5;
const FALSE_POSITIVE_DENOMINATOR: usize = 100;

struct JournalRecord<K: Array, V: Codec> {
    key: K,
    value: V,

    next: Option<u32>,
}

impl<K: Array, V: Codec> JournalRecord<K, V> {
    fn new(key: K, value: V, next: Option<u32>) -> Self {
        Self { key, value, next }
    }
}

impl<K: Array, V: Codec> Write for JournalRecord<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next.write(buf);
    }
}

impl<K: Array, V: Codec> Read for JournalRecord<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next = Option::<u32>::read_cfg(buf, &())?;
        Ok(Self { key, value, next })
    }
}

impl<K: Array, V: Codec> EncodeSize for JournalRecord<K, V> {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size() + self.next.encode_size()
    }
}

pub struct MetadataRecord {
    /// The indices currently active in a section.
    active: BitVec,
    /// The bloom filter of keys for the section.
    bloom: BloomFilter,
    /// The cursors for a given section.
    cursors: Vec<Option<u32>>,
    /// The size of the journal for a given section.
    size: u64,
}

impl Write for MetadataRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.active.write(buf);
        self.bloom.write(buf);
        self.cursors.write(buf);
        self.size.write(buf);
    }
}

impl Read for MetadataRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let active = BitVec::read_cfg(buf, &(..=usize::MAX).into())?;
        let bloom = BloomFilter::read_cfg(buf, &((..=usize::MAX).into(), (..=usize::MAX).into()))?;
        let cursors = Vec::<Option<u32>>::read_cfg(buf, &((..=usize::MAX).into(), ()))?;
        let size = u64::read_cfg(buf, &())?;
        Ok(Self {
            active,
            bloom,
            cursors,
            size,
        })
    }
}

impl EncodeSize for MetadataRecord {
    fn encode_size(&self) -> usize {
        self.active.encode_size()
            + self.bloom.encode_size()
            + self.cursors.encode_size()
            + self.size.encode_size()
    }
}

pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    items_per_section: u64,
    cursor_heads: u32,

    metadata: Metadata<E, U64, MetadataRecord>,
    journal: Journal<E, JournalRecord<K, V>>,
    ordinal: Ordinal<E, U32>,

    modified: BTreeSet<u64>,

    // Metrics
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Archive<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let metadata = Metadata::<E, U64, MetadataRecord>::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Initialize journal
        let mut journal = Journal::init(
            context.with_label("journal"),
            variable::Config {
                partition: cfg.journal_partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Collect sections
        let sections = metadata.keys(None).collect::<Vec<_>>();
        let mut section_bits = HashMap::new();
        for section in sections {
            // Get record
            let active = metadata.get(section).unwrap();

            // Get active bits
            let section = section.to_u64();
            section_bits.insert(section, &active.active);

            // Rewind journal
            journal.rewind(section, active.size).await?;
        }

        // Initialize ordinal
        let ordinal = Ordinal::init_align(
            context.with_label("ordinal"),
            ordinal::Config {
                partition: cfg.ordinal_partition,
                items_per_blob: cfg.items_per_section,
                write_buffer: cfg.write_buffer,
                replay_buffer: cfg.replay_buffer,
            },
            Some(section_bits),
        )
        .await?;

        // Initialize metrics
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());

        Ok(Self {
            items_per_section: cfg.items_per_section,
            cursor_heads: cfg.cursor_heads,
            metadata,
            journal,
            ordinal,
            modified: BTreeSet::new(),
            gets,
            has,
            syncs,
        })
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Get section
        let section = index / self.items_per_section;

        // Get ordinal
        let Some(offset) = self.ordinal.get(index).await? else {
            return Ok(None);
        };

        // Get journal entry
        let Some(entry) = self.journal.get(section, offset.to_u32()).await? else {
            return Ok(None);
        };

        // Get value
        Ok(Some(entry.value))
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Get keys
        let keys = self.metadata.keys(None).collect::<Vec<_>>();

        // For each key, check if in bloom filter
        for section in keys {
            let record = self.metadata.get(section).unwrap();
            let section = section.to_u64();
            if !record.bloom.contains(key.as_ref()) {
                continue;
            }

            // Get cursor
            let head = crc32fast::hash(key.as_ref()) % self.cursor_heads;
            let mut cursor = record.cursors[head as usize];

            // Try to find key in journal
            while let Some(this) = cursor {
                let entry = self.journal.get(section, this).await?.unwrap();
                if entry.key == *key {
                    return Ok(Some(entry.value));
                }
                cursor = entry.next;
            }
        }

        // No key found
        Ok(None)
    }

    async fn initialize_section(&mut self, section: u64) {
        // Create active bit vector
        let active = BitVec::zeroes(self.items_per_section as usize);

        // Create bloom filter
        let bloom = BloomFilter::with_capacity(
            NZUsize!(self.items_per_section as usize),
            NZUsize!(FALSE_POSITIVE_NUMERATOR),
            NZUsize!(FALSE_POSITIVE_DENOMINATOR),
        )
        .unwrap();

        // Create cursors
        let cursors = vec![None; self.cursor_heads as usize];

        // Store record
        let record = MetadataRecord {
            active,
            bloom,
            cursors,
            size: 0,
        };
        let record_size = record.encode_size();
        self.metadata.put(section.into(), record);
        debug!(section, size = record_size, "initialized section");
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> crate::archive::Archive
    for Archive<E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Ignore duplicates
        if self.ordinal.has(index) {
            return Ok(());
        }

        // Check if section exists
        let section = index / self.items_per_section;
        self.modified.insert(section);

        // Initialize section if it doesn't exist
        if self.metadata.get(&section.into()).is_none() {
            self.initialize_section(section).await;
        }
        let record = self.metadata.get_mut(&section.into()).unwrap();

        // Get head for key
        let head = crc32fast::hash(key.as_ref()) % self.cursor_heads;
        let cursor = record.cursors[head as usize];

        // Put item in journal
        let entry = JournalRecord::new(key.clone(), data, cursor);
        let (offset, _) = self.journal.append(section, entry).await?;
        record.size = self.journal.size(section).await?;

        // Put cursor in metadata
        record.cursors[head as usize] = Some(offset);

        // Insert key into bloom filter
        record.bloom.insert(key.as_ref());

        // Update active bits
        record.active.set((index % self.items_per_section) as usize);

        // Put section and offset in ordinal
        self.ordinal.put(index, offset.into()).await?;

        Ok(())
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.gets.inc();

        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();

        match identifier {
            Identifier::Index(index) => Ok(self.ordinal.has(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Get sections
        let sections = self.metadata.keys(None).cloned().collect::<Vec<_>>();

        // Remove old sections from metadata
        let min_section = min / self.items_per_section;
        for section in sections {
            if section.to_u64() >= min_section {
                break;
            }
            self.metadata.remove(&section).unwrap();
        }

        // Sync metadata before removing any other data to ensure we can always recover
        self.metadata.sync().await?;

        // Remove journal
        self.journal.prune(min_section).await?;

        // Remove ordinal
        self.ordinal.prune(min).await?;

        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync journal and ordinal
        let mut futures = Vec::new();
        for section in self.modified.iter() {
            futures.push(self.journal.sync(*section));
        }
        let (journal_result, ordinal_result) = join!(try_join_all(futures), self.ordinal.sync());
        journal_result?;
        ordinal_result?;

        // Clear modified sections
        self.modified.clear();

        // Sync metadata once underlying are synced
        self.metadata.sync().await?;

        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.ordinal.next_gap(index)
    }

    async fn close(self) -> Result<(), Error> {
        // Close journal
        self.journal.close().await?;

        // Close ordinal
        self.ordinal.close().await?;

        // Close metadata
        self.metadata.close().await?;

        Ok(())
    }

    async fn destroy(self) -> Result<(), Error> {
        // Destroy journal
        self.journal.destroy().await?;

        // Destroy ordinal
        self.ordinal.destroy().await?;

        // Destroy metadata
        self.metadata.destroy().await?;

        Ok(())
    }
}
