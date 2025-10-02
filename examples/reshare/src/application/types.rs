//! Types for the `commonware-reshare` example

use crate::dkg::DealOutcome;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::Block as ConsensusBlock;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519, Committable, Digestible, Hasher, PrivateKey, Sha256,
};

pub type H = Sha256;
pub type D = <H as Hasher>::Digest;
pub type B = Block<H, ed25519::PrivateKey, MinSig>;

pub type Identity = <MinSig as Variant>::Public;
pub type Evaluation = Identity;
pub type Signature = <MinSig as Variant>::Signature;

/// A block in the reshare chain.
#[derive(Clone)]
pub struct Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    /// The parent digest.
    pub parent: H::Digest,

    /// The current height.
    pub height: u64,

    /// An optional outcome of a resharing operation.
    pub reshare_outcome: Option<DealOutcome<P, V>>,
}

impl<H, P, V> Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    /// Create a new [Block].
    pub fn new(parent: H::Digest, height: u64, reshare_outcome: Option<DealOutcome<P, V>>) -> Self {
        Self {
            parent,
            height,
            reshare_outcome,
        }
    }
}

impl<H, P, V> Write for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        self.reshare_outcome.write(buf);
    }
}

impl<H, P, V> EncodeSize for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size() + self.reshare_outcome.encode_size()
    }
}

impl<H, P, V> Read for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            parent: H::Digest::read(buf)?,
            height: u64::read(buf)?,
            reshare_outcome: Option::<DealOutcome<P, V>>::read_cfg(buf, cfg)?,
        })
    }
}

impl<H, P, V> Digestible for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&self.parent);
        hasher.update(&self.height.to_le_bytes());
        hasher.finalize()
    }
}

impl<H, P, V> Committable for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    type Commitment = H::Digest;

    fn commitment(&self) -> H::Digest {
        self.digest()
    }
}

impl<H, P, V> ConsensusBlock for Block<H, P, V>
where
    H: Hasher,
    P: PrivateKey,
    V: Variant,
{
    fn parent(&self) -> Self::Commitment {
        self.parent
    }

    fn height(&self) -> u64 {
        self.height
    }
}
