use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};

/// A query request sent from originator to handlers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    pub id: u64,
    pub value: u32,
}

impl Write for Query {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u32(self.value);
    }
}

impl Read for Query {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let value = u32::read(buf)?;
        Ok(Self { id, value })
    }
}

impl FixedSize for Query {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Committable for Query {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.id.to_be_bytes())
    }
}

impl Digestible for Query {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.value.to_be_bytes());
        hasher.finalize()
    }
}

/// A query result response sent from handlers to originator.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryResult {
    pub id: u64,
    pub result: u32,
    pub node_id: u64,
}

impl Write for QueryResult {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.id);
        buf.put_u32(self.result);
        buf.put_u64(self.node_id);
    }
}

impl Read for QueryResult {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let result = u32::read(buf)?;
        let node_id = u64::read(buf)?;
        Ok(Self { id, result, node_id })
    }
}

impl FixedSize for QueryResult {
    const SIZE: usize = u64::SIZE + u32::SIZE + u64::SIZE;
}

impl Committable for QueryResult {
    type Commitment = Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.id.to_be_bytes())
    }
}

impl Digestible for QueryResult {
    type Digest = <Sha256 as Hasher>::Digest;

    fn digest(&self) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.result.to_be_bytes());
        hasher.update(&self.node_id.to_be_bytes());
        hasher.finalize()
    }
}
