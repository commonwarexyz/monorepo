use crate::threshold_simplex::types::{Finalization, Notarization};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Committable, Digest, Digestible, Hasher,
};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<V: Variant, D: Digest> {
    pub proof: Notarization<V, D>,
    pub block: Block<D>,
}

impl<V: Variant, D: Digest> Notarized<V, D> {
    pub fn new(proof: Notarization<V, D>, block: Block<D>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        self.proof.verify(namespace, identity)
    }
}

impl<V: Variant, D: Digest> Write for Notarized<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for Notarized<V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::<V, D>::read(buf)?;
        let block = Block::<D>::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Notarized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Notarized<V, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<V: Variant, D: Digest> {
    pub proof: Finalization<V, D>,
    pub block: Block<D>,
}

impl<V: Variant, D: Digest> Finalized<V, D> {
    pub fn new(proof: Finalization<V, D>, block: Block<D>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        self.proof.verify(namespace, identity)
    }
}

impl<V: Variant, D: Digest> Write for Finalized<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for Finalized<V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::<V, D>::read(buf)?;
        let block = Block::<D>::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Finalized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Finalized<V, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}
