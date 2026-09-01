//! Compact producer-block metadata for pending custody and finalized rows.

use crate::{
    Epochable as _,
    multimmit::types::{BlockRef, TransactionBlockHeader},
    types::Epoch,
};
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};

/// Metadata needed to authenticate and schedule a producer block without reading its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockMeta<D: Digest> {
    header: TransactionBlockHeader<D>,
    encoded_len: u64,
}

impl<D: Digest> BlockMeta<D> {
    /// Creates metadata for an encoded transaction block.
    pub(crate) const fn new(header: TransactionBlockHeader<D>, encoded_len: u64) -> Self {
        Self {
            header,
            encoded_len,
        }
    }

    /// Returns the authenticated transaction-block header.
    pub(crate) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the encoded length of the complete transaction block.
    pub(crate) const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    /// Returns the block reference if the header hashes to `digest` and names a chain below
    /// `chains` in `epoch`.
    pub(crate) fn authenticate<H: Hasher<Digest = D>>(
        &self,
        digest: D,
        epoch: Epoch,
        chains: usize,
    ) -> Option<BlockRef<D>> {
        let reference = self.header.block_ref::<H>();
        (reference.digest() == digest
            && (reference.chain().get() as usize) < chains
            && self.header.epoch() == epoch)
            .then_some(reference)
    }
}

impl<D: Digest> Read for BlockMeta<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
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
pub(crate) struct FinalBlockMeta<D: Digest> {
    block: BlockMeta<D>,
    floor_generation: u64,
}

impl<D: Digest> FinalBlockMeta<D> {
    /// Binds block metadata to the floor generation that committed it.
    pub(crate) const fn new(block: BlockMeta<D>, floor_generation: u64) -> Self {
        Self {
            block,
            floor_generation,
        }
    }

    /// Returns the block metadata.
    pub(crate) const fn block(&self) -> &BlockMeta<D> {
        &self.block
    }

    /// Returns the floor generation that committed the block.
    pub(crate) const fn floor_generation(&self) -> u64 {
        self.floor_generation
    }
}

impl<D: Digest> Read for FinalBlockMeta<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            block: BlockMeta::read(buf)?,
            floor_generation: u64::read(buf)?,
        })
    }
}

impl<D: Digest> Write for FinalBlockMeta<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.block.write(buf);
        self.floor_generation.write(buf);
    }
}

impl<D: Digest> EncodeSize for FinalBlockMeta<D> {
    fn encode_size(&self) -> usize {
        self.block.encode_size() + self.floor_generation.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for BlockMeta<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for FinalBlockMeta<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::ChainId, types::Height};
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
            meta.authenticate::<Sha256>(digest, epoch, 2),
            Some(header.block_ref::<Sha256>())
        );
        assert!(
            meta.authenticate::<Sha256>(Sha256::hash(&[b"wrong"]), epoch, 2)
                .is_none()
        );
        assert!(
            meta.authenticate::<Sha256>(digest, Epoch::new(8), 2)
                .is_none()
        );
        assert!(meta.authenticate::<Sha256>(digest, epoch, 1).is_none());

        let finalized = FinalBlockMeta::new(meta, 11);
        let encoded = finalized.encode();
        assert_eq!(encoded.len(), finalized.encode_size());
        assert_eq!(FinalBlockMeta::decode(encoded).unwrap(), finalized);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<BlockMeta<Sha256Digest>> => 128,
            CodecConformance<FinalBlockMeta<Sha256Digest>> => 128,
        }
    }
}
