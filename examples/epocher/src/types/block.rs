use commonware_codec::{varint::UInt, Encode, EncodeSize, Read, ReadExt, Write};
use commonware_consensus::types::Round;
use commonware_cryptography::{
    sha256::{self, Digest as Sha256Digest},
    Committable, Digestible, Hasher,
};

/// Genesis round.
pub const GENESIS_ROUND: Round = Round::new(0, 0);
/// Genesis block.
pub const GENESIS_BLOCK: Block = Block::new(Sha256Digest([0; 32]), 0, 0);

/// Block type.
#[derive(Clone, Debug)]
pub struct Block {
    pub parent: Sha256Digest,
    pub height: u64,
    pub random: u64,
}

impl Block {
    pub const fn new(parent: Sha256Digest, height: u64, random: u64) -> Self {
        Self {
            parent,
            height,
            random,
        }
    }

    pub fn hash(&self) -> Sha256Digest {
        let mut hasher = sha256::Sha256::new();
        let bytes = self.encode();
        hasher.update(&bytes);
        hasher.finalize()
    }
}

impl Write for Block {
    fn write(&self, w: &mut impl bytes::BufMut) {
        self.parent.write(w);
        UInt(self.height).write(w);
        self.random.write(w);
    }
}

impl Read for Block {
    type Cfg = ();
    fn read_cfg(r: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let parent = Sha256Digest::read(r)?;
        let height = UInt::read(r)?.into();
        let random = u64::read(r)?;
        Ok(Self {
            parent,
            height,
            random,
        })
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + UInt(self.height).encode_size() + self.random.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Sha256Digest;
    fn digest(&self) -> Sha256Digest {
        self.hash()
    }
}

impl Committable for Block {
    type Commitment = Sha256Digest;
    fn commitment(&self) -> Sha256Digest {
        self.hash()
    }
}

impl commonware_consensus::Block for Block {
    fn height(&self) -> u64 {
        self.height
    }

    fn parent(&self) -> Sha256Digest {
        self.parent
    }
}
