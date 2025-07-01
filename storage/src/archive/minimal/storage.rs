use crate::journal::variable::Journal;
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::BloomFilter;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::{Array, BitVec};

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

enum MetadataRecord {
    /// The indices currently active in a section.
    Active(BitVec),
    /// The bloom filter of keys for the section.
    Bloom(BloomFilter),
    /// The first item in the section for a given key.
    Cursor(u32),
}

impl Write for MetadataRecord {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Active(active) => {
                buf.put_u8(0);
                active.write(buf)
            }
            Self::Bloom(bloom) => {
                buf.put_u8(1);
                bloom.write(buf)
            }
            Self::Cursor(cursor) => {
                buf.put_u8(2);
                cursor.write(buf)
            }
        }
    }
}

impl Read for MetadataRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(Self::Active(BitVec::read_cfg(
                buf,
                &(..=usize::MAX).into(),
            )?)),
            1 => Ok(Self::Bloom(BloomFilter::read_cfg(
                buf,
                &((..=usize::MAX).into(), (..=usize::MAX).into()),
            )?)),
            2 => Ok(Self::Cursor(u32::read_cfg(buf, &())?)),
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
        }
    }
}

pub struct Archive<E: Storage + Metrics, K: Array, V: Codec> {
    section_mask: u64,
    journal: Journal<E, JournalRecord<K, V>>,
    metadata: Journal<E, MetadataRecord>,
}
