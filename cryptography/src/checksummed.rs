use crate::Hasher;
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error, FixedSize, Read, Write};
use std::marker::PhantomData;

/// A wrapper around a [Codec] type that has a checksum.
///
/// Automatically creates the checksum when writing and verifies it when reading.
pub struct Checksummed<T: Codec, H: Hasher> {
    pub data: T,
    _hasher: PhantomData<H>,
}

impl<T: Codec, H: Hasher> Checksummed<T, H> {
    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: Codec, H: Hasher> From<T> for Checksummed<T, H> {
    fn from(data: T) -> Self {
        Self {
            data,
            _hasher: PhantomData,
        }
    }
}

impl<T: Codec, H: Hasher> Read for Checksummed<T, H>
where
    H::Digest: Codec<Cfg = ()> + PartialEq,
{
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let data = T::read_cfg(buf, cfg)?;
        let hash = H::Digest::read_cfg(buf, &())?;
        let data_bytes = data.encode();
        let mut hasher = H::new();
        hasher.update(&data_bytes);
        let expected_hash = hasher.finalize();
        if hash != expected_hash {
            return Err(Error::Invalid("Checksummed", "checksum mismatch"));
        }
        Ok(Self {
            data,
            _hasher: PhantomData,
        })
    }
}

impl<T: Codec, H: Hasher> Write for Checksummed<T, H>
where
    H::Digest: Codec<Cfg = ()>,
{
    fn write(&self, buf: &mut impl BufMut) {
        let data = self.data.encode();
        let mut hasher = H::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        hash.write(buf);
        buf.put_slice(&data);
    }
}

impl<T: Codec, H: Hasher> EncodeSize for Checksummed<T, H>
where
    H::Digest: FixedSize,
{
    fn encode_size(&self) -> usize {
        self.data.encode_size() + H::Digest::SIZE
    }
}
