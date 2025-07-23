use crate::{
    threshold_simplex::types::{Finalization, Notarization},
    Block,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::variant::Variant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<V: Variant, B: Block> {
    pub proof: Notarization<V, B::Commitment>,
    pub block: B,
}

impl<V: Variant, B: Block> Notarized<V, B> {
    pub fn new(proof: Notarization<V, B::Commitment>, block: B) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        self.proof.verify(namespace, identity)
    }
}

impl<V: Variant, B: Block> Write for Notarized<V, B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<V: Variant, B: Block> Read for Notarized<V, B> {
    type Cfg = B::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::<V, B::Commitment>::read(buf)?;
        let block = B::read_cfg(buf, cfg)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.commitment() {
            return Err(Error::Invalid(
                "types::Notarized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<V: Variant, B: Block> EncodeSize for Notarized<V, B> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<V: Variant, B: Block> {
    pub proof: Finalization<V, B::Commitment>,
    pub block: B,
}

impl<V: Variant, B: Block> Finalized<V, B> {
    pub fn new(proof: Finalization<V, B::Commitment>, block: B) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        self.proof.verify(namespace, identity)
    }
}

impl<V: Variant, B: Block> Write for Finalized<V, B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<V: Variant, B: Block> Read for Finalized<V, B> {
    type Cfg = B::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::<V, B::Commitment>::read(buf)?;
        let block = B::read_cfg(buf, cfg)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.commitment() {
            return Err(Error::Invalid(
                "types::Finalized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<V: Variant, B: Block> EncodeSize for Finalized<V, B> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}
