//! Wire protocol messages for the Commonware Bridge example.
//!
//! This module defines the messages used for communication between validators and the indexer
//! in the Commonware Bridge example. The messages are used to store and retrieve blocks and
//! finality certificates, facilitating the exchange of consensus certificates between two networks.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::threshold_simplex::types::Finalization;
use commonware_cryptography::{bls12381::primitives::group, Digest};

/// Enum representing incoming messages from validators to the indexer.
///
/// Used to interact with the indexer's storage of blocks and finality certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Inbound<D: Digest> {
    /// Request to store a new block in the indexer's storage.
    PutBlock(PutBlock),
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
            Inbound::PutBlock(block) => {
                buf.put_u8(0);
                block.write(buf);
            }
            Inbound::GetBlock(block) => {
                buf.put_u8(1);
                block.write(buf);
            }
            Inbound::PutFinalization(finalization) => {
                buf.put_u8(2);
                finalization.write(buf);
            }
            Inbound::GetFinalization(finalization) => {
                buf.put_u8(3);
                finalization.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for Inbound<D> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let block = PutBlock::read_cfg(buf, &())?;
                Ok(Inbound::PutBlock(block))
            }
            1 => {
                let block = GetBlock::<D>::read_cfg(buf, &())?;
                Ok(Inbound::GetBlock(block))
            }
            2 => {
                let finalization = PutFinalization::read_cfg(buf, &())?;
                Ok(Inbound::PutFinalization(finalization))
            }
            3 => {
                let finalization = GetFinalization::read_cfg(buf, &())?;
                Ok(Inbound::GetFinalization(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for Inbound<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Inbound::PutBlock(block) => block.encode_size(),
            Inbound::GetBlock(block) => block.encode_size(),
            Inbound::PutFinalization(finalization) => finalization.encode_size(),
            Inbound::GetFinalization(finalization) => finalization.encode_size(),
        }
    }
}

/// Message to store a new block in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutBlock {
    /// The network identifier for which the block belongs.
    pub network: group::Public,
    /// The block data to be stored.
    pub data: Bytes,
}

impl Write for PutBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.data.write(buf);
    }
}

impl Read for PutBlock {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        let data = Bytes::read_cfg(buf, &..)?;
        Ok(PutBlock { network, data })
    }
}

impl EncodeSize for PutBlock {
    fn encode_size(&self) -> usize {
        group::Public::SIZE + self.data.encode_size()
    }
}

/// Message to retrieve a block from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlock<D: Digest> {
    /// The network identifier for which the block belongs.
    pub network: group::Public,
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
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        let digest = D::read(buf)?;
        Ok(GetBlock { network, digest })
    }
}

impl<D: Digest> FixedSize for GetBlock<D> {
    const SIZE: usize = group::Public::SIZE + D::SIZE;
}

/// Message to store a finality certificate in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutFinalization<D: Digest> {
    /// The network identifier for which the finality certificate belongs.
    pub network: group::Public,
    /// The finality certificate
    pub finalization: Finalization<D>,
}

impl<D: Digest> Write for PutFinalization<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.finalization.write(buf);
    }
}

impl<D: Digest> Read for PutFinalization<D> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        let finalization = Finalization::read(buf)?;
        Ok(PutFinalization {
            network,
            finalization,
        })
    }
}

impl<D: Digest> FixedSize for PutFinalization<D> {
    const SIZE: usize = group::Public::SIZE + Finalization::<D>::SIZE;
}

/// Message to retrieve the latest finality certificate from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFinalization {
    /// The network identifier for which to retrieve the finality certificate.
    pub network: group::Public,
}

impl Write for GetFinalization {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
    }
}

impl Read for GetFinalization {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        Ok(GetFinalization { network })
    }
}

impl EncodeSize for GetFinalization {
    fn encode_size(&self) -> usize {
        group::Public::SIZE
    }
}

/// Enum representing responses from the indexer to validators.
///
/// These responses correspond to the results of the operations requested by `Inbound` messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Outbound<D: Digest> {
    /// Indicates the success or failure of a `Put` operation,
    /// or if a `Get` operation found the requested item.
    Success(bool),
    /// Contains the requested block data in response to a `GetBlock` message.
    Block(Bytes),
    /// Contains the requested finality certificate in response to a `GetFinalization` message.
    Finalization(Finalization<D>),
}

impl<D: Digest> Write for Outbound<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Outbound::Success(success) => {
                buf.put_u8(0);
                success.write(buf);
            }
            Outbound::Block(data) => {
                buf.put_u8(1);
                data.write(buf);
            }
            Outbound::Finalization(data) => {
                buf.put_u8(2);
                data.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for Outbound<D> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let success = bool::read(buf)?;
                Ok(Outbound::Success(success))
            }
            1 => {
                let data = Bytes::read_cfg(buf, &..)?;
                Ok(Outbound::Block(data))
            }
            2 => {
                let finalization = Finalization::read(buf)?;
                Ok(Outbound::Finalization(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for Outbound<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Outbound::Success(success) => success.encode_size(),
            Outbound::Block(data) => data.encode_size(),
            Outbound::Finalization(finalization) => finalization.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_consensus::threshold_simplex::types::Proposal;
    use commonware_cryptography::{
        bls12381::primitives::group::{self, Element, G2},
        sha256::Digest as Sha256Digest,
    };
    use rand::thread_rng;

    fn new_data() -> Bytes {
        Bytes::from("test data")
    }
    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_group_public() -> group::Public {
        let mut result = group::Public::one();
        let scalar = group::Scalar::rand(&mut thread_rng());
        result.mul(&scalar);
        result
    }

    fn new_finalization() -> Finalization<Sha256Digest> {
        let scalar = group::Scalar::rand(&mut thread_rng());
        let mut proposal_signature = G2::one();
        proposal_signature.mul(&scalar);
        let mut seed_signature = G2::one();
        seed_signature.mul(&scalar);
        Finalization {
            proposal: Proposal {
                view: 12345,
                parent: 54321,
                payload: new_digest(),
            },
            proposal_signature,
            seed_signature,
        }
    }

    #[test]
    fn test_inbound_codec() {
        // PutBlock
        let original = Inbound::<Sha256Digest>::PutBlock(PutBlock {
            network: new_group_public(),
            data: new_data(),
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

    #[test]
    fn test_outbound_codec() {
        // Success
        let original = Outbound::<Sha256Digest>::Success(true);
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Block
        let original = Outbound::<Sha256Digest>::Block(new_data());
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Finalization
        let original = Outbound::<Sha256Digest>::Finalization(new_finalization());
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
