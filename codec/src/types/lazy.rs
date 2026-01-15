use crate::{Decode, Encode, EncodeSize, Read, Write};
use bytes::{Buf, Bytes};
use core::hash::Hash;
use std::sync::OnceLock;

#[derive(Clone)]
pub struct Lazy<T: Read> {
    bytes: Bytes,
    cfg: Option<T::Cfg>,
    value: OnceLock<Option<T>>,
}

impl<T: Read> Lazy<T> {
    pub fn new(buf: &mut impl Buf, cfg: T::Cfg) -> Self {
        let bytes = buf.copy_to_bytes(buf.remaining());
        Self {
            bytes,
            cfg: Some(cfg),
            value: Default::default(),
        }
    }
}

impl<T: Read> Lazy<T> {
    pub fn get(&self) -> Option<&T> {
        self.value
            .get_or_init(|| {
                T::decode_cfg(
                    self.bytes.clone(),
                    self.cfg
                        .as_ref()
                        .expect("Lazy should have cfg if value is not initialized"),
                )
                .ok()
            })
            .as_ref()
    }
}

impl<T: Read + Encode> From<T> for Lazy<T> {
    fn from(value: T) -> Self {
        Self {
            bytes: value.encode(),
            cfg: None,
            value: Some(value).into(),
        }
    }
}

impl<T: Read + PartialEq> PartialEq for Lazy<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<T: Read + Eq> Eq for Lazy<T> {}

impl<T: Read + PartialOrd> PartialOrd for Lazy<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.get().partial_cmp(&other.get())
    }
}

impl<T: Read + Ord> Ord for Lazy<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl<T: Read + Hash> Hash for Lazy<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.get().hash(state);
    }
}

impl<T: Read> EncodeSize for Lazy<T> {
    fn encode_size(&self) -> usize {
        self.bytes.len()
    }
}

impl<T: Read> Write for Lazy<T> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.bytes.write(buf);
    }
}

impl<T: Read> Read for Lazy<T> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, crate::Error> {
        Ok(Self::new(buf, cfg.clone()))
    }
}

impl<T: Read + core::fmt::Debug> core::fmt::Debug for Lazy<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get().fmt(f)
    }
}
