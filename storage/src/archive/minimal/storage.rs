use crate::{
    archive::{minimal::Config, Error},
    journal::variable::Journal,
    metadata::{self, Metadata},
    rmap::RMap,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::BloomFilter;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::{Array, BitVec};
use std::{collections::BTreeMap, ops::Deref};

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

pub struct Archive<E: Storage + Metrics, K: Array, V: Codec> {
    section_mask: u64,
    metadata: Journal<E, MetadataRecord>,
    journal: Journal<E, JournalRecord<K, V>>,
    ordinal: BTreeMap<u64, E::Blob>,
    rmap: RMap,
}

impl<E: Storage + Metrics, K: Array, V: Codec> Archive<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let mut metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: &(),
            },
        )
        .await?;

        // Initialize journal
        let journal = Journal::init(
            context.with_label("journal"),
            journal::variable::Config {
                partition: cfg.journal_partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;
    }
}
