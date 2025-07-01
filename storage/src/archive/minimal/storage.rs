use crate::journal::variable::Journal;
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt, Write};
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;

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

pub struct Archive<E: Storage + Metrics, K: Array, V: Codec> {
    section_mask: u64,
    journal: Journal<E>,
}
