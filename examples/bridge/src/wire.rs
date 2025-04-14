use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::group;
use commonware_utils::Array;

pub enum Inbound<D: Array> {
    PutBlock(PutBlock),
    GetBlock(GetBlock<D>),
    PutFinalization(PutFinalization),
    GetFinalization(GetFinalization),
}

impl<D: Array> Write for Inbound<D> {
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

impl<D: Array> Read for Inbound<D> {
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

impl<D: Array> EncodeSize for Inbound<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Inbound::PutBlock(block) => block.encode_size(),
            Inbound::GetBlock(block) => block.encode_size(),
            Inbound::PutFinalization(finalization) => finalization.encode_size(),
            Inbound::GetFinalization(finalization) => finalization.encode_size(),
        }
    }
}

pub struct PutBlock {
    pub network: group::Public,
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

pub struct GetBlock<D: Array> {
    pub network: group::Public,
    pub digest: D,
}

impl<D: Array> Write for GetBlock<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.network.write(buf);
        self.digest.write(buf);
    }
}

impl<D: Array> Read for GetBlock<D> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let network = group::Public::read(buf)?;
        let digest = D::read(buf)?;
        Ok(GetBlock { network, digest })
    }
}

impl<D: Array> EncodeSize for GetBlock<D> {
    fn encode_size(&self) -> usize {
        group::Public::SIZE + self.digest.encode_size()
    }
}

pub struct PutFinalization {
    pub network: group::Public,
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

pub struct GetFinalization {
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

pub enum Outbound {
    Success(bool), // if PUT (success), if GET (success is false if not found)
    Block(Bytes),
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
            Outbound::Success(_) => bool::SIZE,
            Outbound::Block(data) => data.encode_size(),
            Outbound::Finalization(data) => data.encode_size(),
        }
    }
}
