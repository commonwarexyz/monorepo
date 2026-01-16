//! Types for the `commonware-reshare` example application.
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::types::Context, types::Height, Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    bls12381::{dkg::SignedDealerLog, primitives::variant::Variant},
    Committable, Digest, Digestible, Hasher, Signer,
};
use std::num::NonZeroU32;

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
    pub height: Height,

    /// The consensus context when this block was proposed.
    pub context: Context<H::Digest, C::PublicKey>,

    /// An optional outcome of a dealing operation.
    pub log: Option<SignedDealerLog<V, C>>,
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
        height: Height,
        context: Context<H::Digest, C::PublicKey>,
        log: Option<SignedDealerLog<V, C>>,
    ) -> Self {
        Self {
            parent,
            height,
            context,
            log,
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
        self.context.write(buf);
        self.log.write(buf);
    }
}

impl<H, C, V> EncodeSize for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + self.context.encode_size()
            + self.log.encode_size()
    }
}

impl<H, C, V> Read for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    // The consensus quorum
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            parent: H::Digest::read(buf)?,
            height: Height::read(buf)?,
            context: Context::read(buf)?,
            log: Read::read_cfg(buf, cfg)?,
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

impl<H, C, V> Heightable for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn height(&self) -> Height {
        self.height
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
}

impl<H, C, V> CertifiableBlock for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Context = Context<H::Digest, C::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

/// Returns the genesis block with the given context.
///
/// The genesis block has an empty parent digest and height zero.
pub const fn genesis_block<H, C, V>(context: Context<H::Digest, C::PublicKey>) -> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    Block::new(
        <<H as Hasher>::Digest as Digest>::EMPTY,
        Height::zero(),
        context,
        None,
    )
}
