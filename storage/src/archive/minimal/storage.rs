use crate::{
    archive::{minimal::Config, Error, Identifier},
    journal::variable::{self, Journal},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::BloomFilter;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{array::U64, Array, BitVec};
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Deref,
};

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
    cursors: Vec<u32>,
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
        let cursors = Vec::<u32>::read_cfg(buf, &((..=usize::MAX).into(), (..=usize::MAX).into()))?;
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

    sections: BTreeSet<u64>,
    metadata: Metadata<E, U64, MetadataRecord>,
    journal: Journal<E, JournalRecord<K, V>>,
    ordinal: Ordinal<E, K>,
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
        let mut section_set = BTreeSet::new();
        let mut section_bits = HashMap::new();
        for section in sections {
            // Get record
            let active = metadata.get(&section).unwrap();

            // Get active bits
            let section = section.to_u64();
            section_bits.insert(section, &active.active);

            // Rewind journal
            journal.rewind(section, active.size).await?;

            // Add section to set
            section_set.insert(section);
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

        Ok(Self {
            items_per_section: cfg.items_per_section,
            cursor_heads: cfg.cursor_heads,
            sections: section_set,
            metadata,
            journal,
            ordinal,
        })
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        let key = self.ordinal.get(index).await?;
        if let Some(key) = key {
            self.get_key(&key).await
        } else {
            Ok(None)
        }
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        unimplemented!()
    }

    async fn initialize_section(&self, section: u64) {
        // Create active bit vector
        let active = BitVec::with_capacity(self.items_per_section as usize);

        // Create size vector
        let size = 0;

        // Create bloom filter
        let bloom = BloomFilter::with_capacity(self.items_per_section as usize);

        // Create cursors
        let cursors = vec![0; self.cursor_heads as usize];

        // Store record
        let record = MetadataRecord {
            active,
            bloom,
            cursors,
            size,
        };
        self.metadata.put(section.into(), record);
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> crate::archive::Archive
    for Archive<E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Check if section exists
        let section = index / self.items_per_section;
        if !self.sections.contains(&section) {
            self.initialize_section(section).await?;
        }

        // Get head for key
        let head = crc32fast::hash(key.as_ref()) % self.cursor_heads;
        let cursor_key = MetadataKey::new(section, METADATA_CURSOR, head);
        let cursor = self
            .metadata
            .get(&cursor_key)
            .expect("cursor should exist")
            .cursor();

        // Put item in journal
        let record = JournalRecord::new(key.clone(), data, cursor);
        let (offset, _) = self.journal.append(section, record).await?;

        // Put cursor in metadata
        self.metadata
            .put(cursor_key, MetadataRecord::Cursor(Some(offset)));

        // Put section and offset in ordinal
        self.ordinal.put(index, (section, offset)).await?;

        unimplemented!()
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        match identifier {
            Identifier::Index(index) => Ok(self.ordinal.has(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    async fn prune(&mut self, min: u64) -> Result<(), Error> {
        unimplemented!()
    }

    async fn sync(&mut self) -> Result<(), Error> {
        unimplemented!()
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.ordinal.next_gap(index)
    }

    async fn close(self) -> Result<(), Error> {
        unimplemented!()
    }

    async fn destroy(self) -> Result<(), Error> {
        unimplemented!()
    }
}
