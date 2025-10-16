use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_cryptography::{Committable, Digest, Digestible, Hasher};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<D: Digest> {
    /// The parent block's digest.
    pub parent: D,

    /// The height of the block in the blockchain.
    pub height: u64,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Pre-computed digest of the block.
    digest: D,
}

impl<D: Digest> Block<D> {
    fn compute_digest<H: Hasher<Digest = D>>(parent: &D, height: u64, timestamp: u64) -> D {
        let mut hasher = H::new();
        hasher.update(parent);
        hasher.update(&height.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    }

    pub fn new<H: Hasher<Digest = D>>(parent: D, height: u64, timestamp: u64) -> Self {
        let digest = Self::compute_digest::<H>(&parent, height, timestamp);
        Self {
            parent,
            height,
            timestamp,
            digest,
        }
    }
}

impl<D: Digest> Write for Block<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        UInt(self.height).write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for Block<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = D::read(reader)?;
        let height = UInt::read(reader)?.into();
        let timestamp = UInt::read(reader)?.into();
        let digest = D::read(reader)?;

        // Pre-compute the digest
        Ok(Self {
            parent,
            height,
            timestamp,
            digest,
        })
    }
}

impl<D: Digest> EncodeSize for Block<D> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + UInt(self.height).encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<D: Digest> Digestible for Block<D> {
    type Digest = D;

    fn digest(&self) -> D {
        self.digest
    }
}

impl<D: Digest> Committable for Block<D> {
    type Commitment = D;

    fn commitment(&self) -> D {
        self.digest
    }
}

impl<D: Digest> crate::Block for Block<D> {
    fn height(&self) -> u64 {
        self.height
    }

    fn parent(&self) -> Self::Commitment {
        self.parent
    }
}
