use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_cryptography::{Committable, Digestible, Hasher, Sha256};
use std::fmt;

/// A mock request for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    pub id: u64,
    pub data: Vec<u8>,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Request(id={}, data_len={})", self.id, self.data.len())
    }
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        8 + 4 + self.data.len()
    }
}

impl Read for Request {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = buf.get_u64();
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return Err(CodecError::UnexpectedEnd);
        }
        let mut data = vec![0u8; len];
        buf.copy_to_slice(&mut data);
        Ok(Self { id, data })
    }
}

impl Committable for Request {
    type Commitment = <Sha256 as Hasher>::Digest;

    fn commitment(&self) -> Self::Commitment {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.finalize()
    }
}

impl Digestible for Request {
    type Digest = <Sha256 as Hasher>::Digest;

    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.data);
        hasher.finalize()
    }
}

/// A mock response for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Response {
    pub id: u64,
    pub result: Vec<u8>,
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Response(id={}, result_len={})",
            self.id,
            self.result.len()
        )
    }
}

impl Write for Response {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u32(self.result.len() as u32);
        buf.put_slice(&self.result);
    }
}

impl EncodeSize for Response {
    fn encode_size(&self) -> usize {
        8 + 4 + self.result.len()
    }
}

impl Read for Response {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = buf.get_u64();
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return Err(CodecError::UnexpectedEnd);
        }
        let mut result = vec![0u8; len];
        buf.copy_to_slice(&mut result);
        Ok(Self { id, result })
    }
}

impl Committable for Response {
    type Commitment = u64;

    fn commitment(&self) -> Self::Commitment {
        self.id
    }
}

impl Digestible for Response {
    type Digest = <Sha256 as Hasher>::Digest;

    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.result);
        hasher.finalize()
    }
}
