use crate::{
    archive::{immutable::Config, Error, Identifier},
    journal::variable::{self, Journal},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::BloomFilter;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{
    array::{prefixed_u64::U64, U32},
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

    next: Option<(u64, u32)>,
}

impl<K: Array, V: Codec> JournalRecord<K, V> {
    fn new(key: K, value: V, next: Option<(u64, u32)>) -> Self {
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
        let next = Option::<(u64, u32)>::read_cfg(buf, &((), ()))?;
        Ok(Self { key, value, next })
    }
}

impl<K: Array, V: Codec> EncodeSize for JournalRecord<K, V> {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size() + self.next.encode_size()
    }
}

enum MetadataRecord {
    Cursor(u64, u64),
    Indices(Option<BitVec>),
}

impl MetadataRecord {
    fn cursor(&self) -> (u64, u64) {
        match self {
            Self::Cursor(index, size) => (*index, *size),
            _ => panic!("incorrect record"),
        }
    }

    fn indices(&self) -> &Option<BitVec> {
        match self {
            Self::Indices(indices) => indices,
            _ => panic!("incorrect record"),
        }
    }
}

impl Write for MetadataRecord {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Cursor(index, size) => {
                buf.put_u8(0);
                buf.put_u64(*index);
                buf.put_u64(*size);
            }
            Self::Indices(indices) => {
                buf.put_u8(1);
                indices.write(buf);
            }
        }
    }
}

impl Read for MetadataRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(Self::Cursor(buf.get_u64(), buf.get_u64())),
            1 => Ok(Self::Indices(Option::<BitVec>::read_cfg(
                buf,
                &(0..=usize::MAX).into(),
            )?)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for MetadataRecord {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Cursor(_, _) => u64::SIZE + u64::SIZE,
            Self::Indices(indices) => indices.encode_size(),
        }
    }
}

const CURSOR_PREFIX: u8 = 0;
const INDICES_PREFIX: u8 = 1;

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
        let mut metadata = Metadata::<E, U64, MetadataRecord>::init(
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

        // Rewind journal
        let cursor_key = U64::new(CURSOR_PREFIX, 0);
        let cursor = match metadata.get(&cursor_key) {
            Some(cursor) => cursor.cursor(),
            None => {
                metadata.put(cursor_key.clone(), MetadataRecord::Cursor(0, 0));
                metadata.get(&cursor_key).unwrap().cursor()
            }
        };
        journal.rewind(cursor.0, cursor.1).await?;

        // Collect sections
        let sections = metadata.keys(Some(&[INDICES_PREFIX])).collect::<Vec<_>>();
        let mut section_bits = HashMap::new();
        for section in sections {
            // Get record
            let indices = metadata.get(section).unwrap().indices();

            // Get indices
            let section = section.to_u64();
            section_bits.insert(section, indices);
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

        // Update active bits
        record.active.set((index % self.items_per_section) as usize);
        if record.active.ones() == self.items_per_section as usize {
            record.active = None;
        }

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
