//! Types for the `commonware-reshare` example application.

use crate::dkg::DealOutcome;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::Block as ConsensusBlock;
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Committable, Digestible, Hasher, Signer,
};

/// A block in the reshare chain.
#[derive(Clone)]
pub struct Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// The parent digest.
    pub parent: H::Digest,

    /// The current height.
    pub height: u64,

    /// An optional outcome of a dealing operation.
    pub deal_outcome: Option<DealOutcome<C, V>>,
}

impl<H, C, V> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new [Block].
    pub const fn new(
        parent: H::Digest,
        height: u64,
        deal_outcome: Option<DealOutcome<C, V>>,
    ) -> Self {
        Self {
            parent,
            height,
            deal_outcome,
        }
    }
}

impl<H, C, V> Write for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        self.deal_outcome.write(buf);
    }
}

impl<H, C, V> EncodeSize for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size() + self.deal_outcome.encode_size()
    }
}

impl<H, C, V> Read for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    // The consensus quorum
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            parent: H::Digest::read(buf)?,
            height: u64::read(buf)?,
            deal_outcome: Option::<DealOutcome<C, V>>::read_cfg(buf, cfg)?,
        })
    }
}

impl<H, C, V> Digestible for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&self.encode())
    }
}

impl<H, C, V> Committable for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Commitment = H::Digest;

    fn commitment(&self) -> H::Digest {
        self.digest()
    }
}

impl<H, C, V> ConsensusBlock for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn parent(&self) -> Self::Commitment {
        self.parent
    }

    fn height(&self) -> u64 {
        self.height
    }
}

/// Returns the genesis block.
pub fn genesis_block<H, C, V>() -> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    Block::new(H::empty(), 0, None)
}
