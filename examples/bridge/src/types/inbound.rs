use super::block::BlockFormat;
use crate::Scheme;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    Digest,
};

/// Enum representing incoming messages from validators to the indexer.
///
/// Used to interact with the indexer's storage of blocks and finality certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Inbound<D: Digest> {
    /// Request to store a new block in the indexer's storage.
    PutBlock(PutBlock<D>),
    /// Request to retrieve a block from the indexer's storage.
    GetBlock(GetBlock<D>),
    /// Request to store a finality certificate in the indexer's storage.
    PutFinalization(PutFinalization<D>),
    /// Request to retrieve the latest finality certificate from the indexer's storage.
    GetFinalization(GetFinalization),
}

impl<D: Digest> Write for Inbound<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::PutBlock(block) => {
                buf.put_u8(0);
                block.write(buf);
            }
            Self::GetBlock(block) => {
                buf.put_u8(1);
                block.write(buf);
            }
            Self::PutFinalization(finalization) => {
                buf.put_u8(2);
                finalization.write(buf);
            }
            Self::GetFinalization(finalization) => {
                buf.put_u8(3);
                finalization.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for Inbound<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let block = PutBlock::read_cfg(buf, &())?;
                Ok(Self::PutBlock(block))
            }
            1 => {
                let block = GetBlock::<D>::read_cfg(buf, &())?;
                Ok(Self::GetBlock(block))
            }
            2 => {
                let finalization = PutFinalization::read_cfg(buf, &())?;
                Ok(Self::PutFinalization(finalization))
            }
            3 => {
                let finalization = GetFinalization::read_cfg(buf, &())?;
                Ok(Self::GetFinalization(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for Inbound<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::PutBlock(block) => block.encode_size(),
            Self::GetBlock(block) => block.encode_size(),
            Self::PutFinalization(finalization) => finalization.encode_size(),
            Self::GetFinalization(finalization) => finalization.encode_size(),
        }
    }
}

/// Message to store a new block in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutBlock<D: Digest> {
    /// The network identifier for which the block belongs.
    pub network: <MinSig as Variant>::Public,
    /// The block to be stored.
    pub block: BlockFormat<D>,
}

impl<D: Digest> Write for PutBlock<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.block.write(buf);
    }
}

impl<D: Digest> Read for PutBlock<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = <MinSig as Variant>::Public::read(buf)?;
        let block = BlockFormat::<D>::read(buf)?;
        Ok(Self { network, block })
    }
}

impl<D: Digest> EncodeSize for PutBlock<D> {
    fn encode_size(&self) -> usize {
        <MinSig as Variant>::Public::SIZE + self.block.encode_size()
    }
}

/// Message to retrieve a block from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlock<D: Digest> {
    /// The network identifier for which the block belongs.
    pub network: <MinSig as Variant>::Public,
    /// The digest of the block to retrieve.
    pub digest: D,
}

impl<D: Digest> Write for GetBlock<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.digest.write(buf);
    }
}

impl<D: Digest> Read for GetBlock<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = <MinSig as Variant>::Public::read(buf)?;
        let digest = D::read(buf)?;
        Ok(Self { network, digest })
    }
}

impl<D: Digest> FixedSize for GetBlock<D> {
    const SIZE: usize = <MinSig as Variant>::Public::SIZE + D::SIZE;
}

/// Message to store a finality certificate in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutFinalization<D: Digest> {
    /// The network identifier for which the finality certificate belongs.
    pub network: <MinSig as Variant>::Public,
    /// The finality certificate
    pub finalization: Finalization<Scheme, D>,
}

impl<D: Digest> Write for PutFinalization<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.finalization.write(buf);
    }
}

impl<D: Digest> Read for PutFinalization<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = <MinSig as Variant>::Public::read(buf)?;
        let finalization = Finalization::read(buf)?;
        Ok(Self {
            network,
            finalization,
        })
    }
}

impl<D: Digest> EncodeSize for PutFinalization<D> {
    fn encode_size(&self) -> usize {
        self.network.encode_size() + self.finalization.encode_size()
    }
}

/// Message to retrieve the latest finality certificate from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFinalization {
    /// The network identifier for which to retrieve the finality certificate.
    pub network: <MinSig as Variant>::Public,
}

impl Write for GetFinalization {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
    }
}

impl Read for GetFinalization {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = <MinSig as Variant>::Public::read(buf)?;
        Ok(Self { network })
    }
}

impl EncodeSize for GetFinalization {
    fn encode_size(&self) -> usize {
        <MinSig as Variant>::Public::SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_consensus::{
        simplex::{signing_scheme::bls12381_threshold, types::Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::group::{self},
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::{CryptoGroup, Random as _};
    use rand::thread_rng;

    fn new_block() -> BlockFormat<Sha256Digest> {
        BlockFormat::Random(12345678901234567890)
    }

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_group_public() -> <MinSig as Variant>::Public {
        let mut result = <MinSig as Variant>::Public::generator();
        let scalar = group::Scalar::random(&mut thread_rng());
        result *= &scalar;
        result
    }

    fn new_finalization() -> Finalization<Scheme, Sha256Digest> {
        let scalar = group::Scalar::random(&mut thread_rng());
        let mut proposal_signature = <MinSig as Variant>::Signature::generator();
        proposal_signature *= &scalar;
        let mut seed_signature = <MinSig as Variant>::Signature::generator();
        seed_signature *= &scalar;
        Finalization {
            proposal: Proposal {
                round: Round::new(Epoch::new(333), View::new(12345)),
                parent: View::new(54321),
                payload: new_digest(),
            },
            certificate: bls12381_threshold::Signature::<MinSig> {
                vote_signature: proposal_signature,
                seed_signature,
            },
        }
    }

    #[test]
    fn test_inbound_codec() {
        // PutBlock
        let original = Inbound::<Sha256Digest>::PutBlock(PutBlock {
            network: new_group_public(),
            block: new_block(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // GetBlock
        let original = Inbound::<Sha256Digest>::GetBlock(GetBlock {
            network: new_group_public(),
            digest: new_digest(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // PutFinalization
        let original = Inbound::<Sha256Digest>::PutFinalization(PutFinalization {
            network: new_group_public(),
            finalization: new_finalization(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // GetFinalization
        let original = Inbound::<Sha256Digest>::GetFinalization(GetFinalization {
            network: new_group_public(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
