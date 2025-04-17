//! Wire protocol messages for the Commonware Bridge example.
//!
//! This module defines the messages used for communication between validators and the indexer
//! in the Commonware Bridge example. The messages are used to store and retrieve blocks and
//! finality certificates, facilitating the exchange of consensus certificates between two networks.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{bls12381::primitives::group, Digest};

/// Enum representing incoming messages from validators to the indexer.
///
/// Used to interact with the indexer's storage of blocks and finality certificates.
pub enum Inbound<D: Digest> {
    /// Request to store a new block in the indexer's storage.
    PutBlock(PutBlock),
    /// Request to retrieve a block from the indexer's storage.
    GetBlock(GetBlock<D>),
    /// Request to store a finality certificate in the indexer's storage.
    PutFinalization(PutFinalization),
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

impl<D: Digest> EncodeSize for GetBlock<D> {
    fn encode_size(&self) -> usize {
        group::Public::SIZE + self.digest.encode_size()
    }
}

/// Message to store a finality certificate in the indexer's storage.
pub struct PutFinalization {
    /// The network identifier for which the finality certificate belongs.
    pub network: group::Public,
    /// The finality certificate data to be stored.
    pub data: Bytes,
}

impl Write for PutFinalization {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.data.write(buf);
    }
}

impl Read for PutFinalization {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        let data = Bytes::read_cfg(buf, &..)?;
        Ok(PutFinalization { network, data })
    }
}

impl EncodeSize for PutFinalization {
    fn encode_size(&self) -> usize {
        group::Public::SIZE + self.data.encode_size()
    }
}

/// Message to retrieve the latest finality certificate from the indexer's storage.
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
pub enum Outbound {
    /// Indicates the success or failure of a `Put` operation,
    /// or if a `Get` operation found the requested item.
    Success(bool),
    /// Contains the requested block data in response to a `GetBlock` message.
    Block(Bytes),
    /// Contains the requested finality certificate in response to a `GetFinalization` message.
    Finalization(Bytes),
}

impl Write for Outbound {
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

impl Read for Outbound {
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
                let data = Bytes::read_cfg(buf, &..)?;
                Ok(Outbound::Finalization(data))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Outbound {
    fn encode_size(&self) -> usize {
        1 + match self {
            Outbound::Success(success) => success.encode_size(),
            Outbound::Block(data) => data.encode_size(),
            Outbound::Finalization(data) => data.encode_size(),
        }
    }
}
