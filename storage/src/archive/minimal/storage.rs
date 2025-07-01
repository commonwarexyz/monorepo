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
use commonware_utils::{Array, BitVec};
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, HashMap},
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

const METADATA_ACTIVE: u8 = 0;
const METADATA_BLOOM: u8 = 1;
const METADATA_CURSOR: u8 = 2;
const METADATA_SIZE: u8 = 3;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
struct MetadataKey([u8; 12]);

impl MetadataKey {
    fn new(section: u64, purpose: u8, extra: u32) -> Self {
        let mut arr = [0; Self::SIZE];
        arr[0] = purpose;
        arr[1..9].copy_from_slice(&section.to_be_bytes());
        arr[9..].copy_from_slice(&extra.to_be_bytes());

        Self(arr)
    }

    fn section(&self) -> u64 {
        u64::from_be_bytes(self.0[1..9].try_into().unwrap())
    }

    fn purpose(&self) -> u8 {
        self.0[0]
    }

    fn extra(&self) -> u32 {
        u32::from_be_bytes(self.0[9..].try_into().unwrap())
    }

    fn purpose_prefix(purpose: u8) -> [u8; 1] {
        [purpose]
    }

    fn section_prefix(purpose: u8, section: u64) -> [u8; 9] {
        let mut arr = [0; 9];
        arr[0] = purpose;
        arr[1..9].copy_from_slice(&section.to_be_bytes());
        arr
    }
}

impl Write for MetadataKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for MetadataKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self(<[u8; Self::SIZE]>::read(buf)?))
    }
}

impl FixedSize for MetadataKey {
    const SIZE: usize = 12;
}

impl Array for MetadataKey {}

impl AsRef<[u8]> for MetadataKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for MetadataKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MetadataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MetadataKey(section={}, purpose={}, extra={})",
            self.section(),
            self.purpose(),
            self.extra()
        )
    }
}

impl std::fmt::Display for MetadataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MetadataKey(section={}, purpose={}, extra={})",
            self.section(),
            self.purpose(),
            self.extra()
        )
    }
}

enum MetadataRecord {
    /// The indices currently active in a section.
    Active(BitVec),
    /// The bloom filter of keys for the section.
    Bloom(BloomFilter),
    /// The first item in the section for a given key.
    Cursor(u32),
    /// The size of the journal for a given section.
    Size(u64),
}

impl MetadataRecord {
    fn size(&self) -> u64 {
        match self {
            Self::Size(size) => *size,
            _ => panic!("wrong type"),
        }
    }

    fn active(&self) -> &BitVec {
        match self {
            Self::Active(active) => active,
            _ => panic!("wrong type"),
        }
    }
}

impl Write for MetadataRecord {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Active(active) => {
                buf.put_u8(METADATA_ACTIVE);
                active.write(buf)
            }
            Self::Bloom(bloom) => {
                buf.put_u8(METADATA_BLOOM);
                bloom.write(buf)
            }
            Self::Cursor(cursor) => {
                buf.put_u8(METADATA_CURSOR);
                cursor.write(buf)
            }
            Self::Size(size) => {
                buf.put_u8(METADATA_SIZE);
                size.write(buf)
            }
        }
    }
}

impl Read for MetadataRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            METADATA_ACTIVE => Ok(Self::Active(BitVec::read_cfg(
                buf,
                &(..=usize::MAX).into(),
            )?)),
            METADATA_BLOOM => Ok(Self::Bloom(BloomFilter::read_cfg(
                buf,
                &((..=usize::MAX).into(), (..=usize::MAX).into()),
            )?)),
            METADATA_CURSOR => Ok(Self::Cursor(u32::read_cfg(buf, &())?)),
            METADATA_SIZE => Ok(Self::Size(u64::read_cfg(buf, &())?)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for MetadataRecord {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Active(active) => active.encode_size(),
            Self::Bloom(bloom) => bloom.encode_size(),
            Self::Cursor(cursor) => cursor.encode_size(),
            Self::Size(size) => size.encode_size(),
        }
    }
}

pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    items_per_section: u64,
    metadata: Metadata<E, MetadataKey, MetadataRecord>,
    journal: Journal<E, JournalRecord<K, V>>,
    ordinal: Ordinal<E, K>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Archive<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let metadata = Metadata::<E, MetadataKey, MetadataRecord>::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Collect all journal sizes
        let section_prefix = MetadataKey::purpose_prefix(METADATA_SIZE);
        let sections = metadata.keys(Some(&section_prefix));
        let mut section_sizes = BTreeMap::new();
        for section in sections {
            let length = metadata.get(section).unwrap().size();
            section_sizes.insert(section.section(), length);
        }

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

        // Limit journal sizes to committed
        for (section, size) in section_sizes {
            journal.rewind(section, size).await?;
        }

        // Collect all activity
        let active_prefix = MetadataKey::purpose_prefix(METADATA_ACTIVE);
        let sections = metadata.keys(Some(&active_prefix));
        let mut section_bits = HashMap::new();
        for section in sections {
            let active = metadata.get(section).unwrap().active();
            section_bits.insert(section.section(), active);
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
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> crate::archive::Archive
    for Archive<E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Put key in ordinal
        self.ordinal.put(index, key).await?;

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
