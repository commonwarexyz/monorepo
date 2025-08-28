use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};

/// A mock request for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    pub id: u64,
    pub data: u32,
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u32(self.data);
    }
}

impl Read for Request {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let data = u32::read(buf)?;
        Ok(Self { id, data })
    }
}

impl FixedSize for Request {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Committable for Request {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.id.to_be_bytes())
    }
}

impl Digestible for Request {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.data.to_be_bytes());
        hasher.finalize()
    }
}

/// A mock response for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Response {
    pub id: u64,
    // Use a different size to ensure we don't accidentally parse with `Request`.
    pub result: u64,
}

impl Write for Response {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u64(self.result);
    }
}

impl Read for Response {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let result = u64::read(buf)?;
        Ok(Self { id, result })
    }
}

impl FixedSize for Response {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Committable for Response {
    type Commitment = Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.id.to_be_bytes())
    }
}

impl Digestible for Response {
    type Digest = <Sha256 as Hasher>::Digest;

    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.result.to_be_bytes());
        hasher.finalize()
    }
}
