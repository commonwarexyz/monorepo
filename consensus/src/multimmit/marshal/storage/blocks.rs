//! Compact finalized producer-block metadata.

use super::archive::FinalizedArchive;
use crate::{
    Epochable as _,
    multimmit::types::{BlockRef, TransactionBlockHeader},
    types::Epoch,
};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};

/// Metadata needed to authenticate and schedule a producer block without reading its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct BlockMeta<D: Digest> {
    header: TransactionBlockHeader<D>,
    encoded_len: u64,
}

impl<D: Digest> BlockMeta<D> {
    /// Creates metadata for an encoded transaction block.
    pub(in crate::multimmit::marshal) const fn new(
        header: TransactionBlockHeader<D>,
        encoded_len: u64,
    ) -> Self {
        Self {
            header,
            encoded_len,
        }
    }

    /// Returns the authenticated transaction-block header.
    pub(in crate::multimmit::marshal) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the encoded length of the complete transaction block.
    pub(in crate::multimmit::marshal) const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
}

impl<D: Digest> Read for BlockMeta<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            header: TransactionBlockHeader::read(buf)?,
            encoded_len: u64::read(buf)?,
        })
    }
}

impl<D: Digest> Write for BlockMeta<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.header.write(buf);
        self.encoded_len.write(buf);
    }
}

impl<D: Digest> EncodeSize for BlockMeta<D> {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.encoded_len.encode_size()
    }
}

/// Finalized metadata binding a block to the marshal generation that ordered it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct FinalBlockMeta<D: Digest> {
    block: BlockMeta<D>,
    generation: u64,
}

impl<D: Digest> FinalBlockMeta<D> {
    pub(in crate::multimmit::marshal) const fn new(block: BlockMeta<D>, generation: u64) -> Self {
        Self { block, generation }
    }

    pub(in crate::multimmit::marshal) const fn block(&self) -> &BlockMeta<D> {
        &self.block
    }

    pub(in crate::multimmit::marshal) const fn generation(&self) -> u64 {
        self.generation
    }
}

impl<D: Digest> Read for FinalBlockMeta<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            block: BlockMeta::read(buf)?,
            generation: u64::read(buf)?,
        })
    }
}

impl<D: Digest> Write for FinalBlockMeta<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.block.write(buf);
        self.generation.write(buf);
    }
}

impl<D: Digest> EncodeSize for FinalBlockMeta<D> {
    fn encode_size(&self) -> usize {
        self.block.encode_size() + self.generation.encode_size()
    }
}

/// Authenticates compact metadata against its archive key and namespace coordinates.
pub(super) fn validated_reference<H: Hasher>(
    meta: &BlockMeta<H::Digest>,
    digest: H::Digest,
    epoch: Epoch,
    chains: usize,
) -> Option<BlockRef<H::Digest>> {
    let reference = meta.header().block_ref::<H>();
    (reference.digest() == digest
        && (reference.chain().get() as usize) < chains
        && meta.header().epoch() == epoch)
        .then_some(reference)
}

/// Dense finalized output rows. Bodies remain under custody and are addressed by this metadata.
pub(in crate::multimmit::marshal) type FinalBlock<T, E, H> =
    FinalizedArchive<T, E, <H as Hasher>::Digest, FinalBlockMeta<<H as Hasher>::Digest>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::{ChainId, Height};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::Sha256;

    #[test]
    fn metadata_round_trip_authenticates_key_epoch_and_chain() {
        let epoch = Epoch::new(7);
        let header = TransactionBlockHeader::new(
            epoch,
            ChainId::new(1),
            Height::new(3),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        let digest = header.digest::<Sha256>();
        let meta = BlockMeta::new(header.clone(), 512 * 1024);
        let encoded = meta.encode();
        assert_eq!(encoded.len(), meta.encode_size());
        assert_eq!(BlockMeta::decode(encoded).unwrap(), meta);
        assert_eq!(
            validated_reference::<Sha256>(&meta, digest, epoch, 2),
            Some(header.block_ref::<Sha256>())
        );
        assert!(
            validated_reference::<Sha256>(&meta, Sha256::hash(&[b"wrong"]), epoch, 2).is_none()
        );
        assert!(validated_reference::<Sha256>(&meta, digest, Epoch::new(8), 2).is_none());
        assert!(validated_reference::<Sha256>(&meta, digest, epoch, 1).is_none());

        let finalized = FinalBlockMeta::new(meta, 11);
        let encoded = finalized.encode();
        assert_eq!(encoded.len(), finalized.encode_size());
        assert_eq!(FinalBlockMeta::decode(encoded).unwrap(), finalized);
    }
}
