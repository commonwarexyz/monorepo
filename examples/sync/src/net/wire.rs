use crate::net::{ErrorResponse, RequestId};
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::Digest;
use commonware_storage::{adb::sync::Target, mmr::Proof};
use std::num::NonZeroU64;

/// Maximum number of digests in a proof.
pub const MAX_DIGESTS: usize = 10_000;

/// Request for data from the server.
#[derive(Debug)]
pub struct GetDataRequest {
    pub request_id: RequestId,
    pub size: u64,
    pub start_loc: u64,
    pub max_data: NonZeroU64,
}

/// Response with data and proof.
#[derive(Debug)]
pub struct GetDataResponse<Data, D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub proof: Proof<D>,
    pub data: Vec<Data>,
}

/// Request for sync target from server.
#[derive(Debug)]
pub struct GetSyncTargetRequest {
    pub request_id: RequestId,
}

/// Response with sync target.
#[derive(Debug)]
pub struct GetSyncTargetResponse<D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub target: Target<D>,
}

/// Messages that can be sent over the wire.
#[derive(Debug)]
pub enum Message<Data, D>
where
    D: Digest,
{
    GetDataRequest(GetDataRequest),
    GetDataResponse(GetDataResponse<Data, D>),
    GetSyncTargetRequest(GetSyncTargetRequest),
    GetSyncTargetResponse(GetSyncTargetResponse<D>),
    Error(ErrorResponse),
}

impl<Data, D> Message<Data, D>
where
    D: Digest,
{
    pub fn request_id(&self) -> RequestId {
        match self {
            Message::GetDataRequest(r) => r.request_id,
            Message::GetDataResponse(r) => r.request_id,
            Message::GetSyncTargetRequest(r) => r.request_id,
            Message::GetSyncTargetResponse(r) => r.request_id,
            Message::Error(e) => e.request_id,
        }
    }
}

impl<Data, D> super::Message for Message<Data, D>
where
    Data: Encode + DecodeExt<()> + Send + Sync + 'static,
    D: Digest,
{
    fn request_id(&self) -> RequestId {
        self.request_id()
    }
}

impl<Data, D> Write for Message<Data, D>
where
    Data: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Message::GetDataRequest(req) => {
                0u8.write(buf);
                req.write(buf);
            }
            Message::GetDataResponse(resp) => {
                1u8.write(buf);
                resp.write(buf);
            }
            Message::GetSyncTargetRequest(req) => {
                2u8.write(buf);
                req.write(buf);
            }
            Message::GetSyncTargetResponse(resp) => {
                3u8.write(buf);
                resp.write(buf);
            }
            Message::Error(err) => {
                4u8.write(buf);
                err.write(buf);
            }
        }
    }
}

impl<Data, D> EncodeSize for Message<Data, D>
where
    Data: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Message::GetDataRequest(req) => req.encode_size(),
            Message::GetDataResponse(resp) => resp.encode_size(),
            Message::GetSyncTargetRequest(req) => req.encode_size(),
            Message::GetSyncTargetResponse(resp) => resp.encode_size(),
            Message::Error(err) => err.encode_size(),
        }
    }
}

impl<Data, D> Read for Message<Data, D>
where
    Data: Read<Cfg = ()>,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Message::GetDataRequest(GetDataRequest::read(buf)?)),
            1 => Ok(Message::GetDataResponse(GetDataResponse::read(buf)?)),
            2 => Ok(Message::GetSyncTargetRequest(GetSyncTargetRequest::read(
                buf,
            )?)),
            3 => Ok(Message::GetSyncTargetResponse(GetSyncTargetResponse::read(
                buf,
            )?)),
            4 => Ok(Message::Error(ErrorResponse::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

impl Write for GetDataRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.size.write(buf);
        self.start_loc.write(buf);
        self.max_data.get().write(buf);
    }
}

impl EncodeSize for GetDataRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.size.encode_size()
            + self.start_loc.encode_size()
            + self.max_data.get().encode_size()
    }
}

impl Read for GetDataRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let size = u64::read(buf)?;
        let start_loc = u64::read(buf)?;
        let max_data_raw = u64::read(buf)?;
        let max_data = NonZeroU64::new(max_data_raw)
            .ok_or_else(|| CodecError::Invalid("GetDataRequest", "max_data cannot be zero"))?;
        Ok(Self {
            request_id,
            size,
            start_loc,
            max_data,
        })
    }
}

impl GetDataRequest {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.start_loc >= self.size {
            return Err(crate::Error::InvalidRequest(format!(
                "start_loc >= size ({}) >= ({})",
                self.start_loc, self.size
            )));
        }
        if self.max_data.get() == 0 {
            return Err(crate::Error::InvalidRequest(
                "max_data cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl<Data, D> Write for GetDataResponse<Data, D>
where
    Data: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.proof.write(buf);
        self.data.write(buf);
    }
}

impl<Data, D> EncodeSize for GetDataResponse<Data, D>
where
    Data: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.proof.encode_size() + self.data.encode_size()
    }
}

impl<Data, D> Read for GetDataResponse<Data, D>
where
    Data: Read<Cfg = ()>,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let proof = Proof::<D>::read_cfg(buf, &MAX_DIGESTS)?;
        let data = {
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<Data>::read_cfg(buf, &(range_cfg, ()))?
        };
        Ok(Self {
            request_id,
            proof,
            data,
        })
    }
}

impl Write for GetSyncTargetRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
    }
}

impl EncodeSize for GetSyncTargetRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
    }
}

impl Read for GetSyncTargetRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        Ok(Self { request_id })
    }
}

impl<D> Write for GetSyncTargetResponse<D>
where
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.target.write(buf);
    }
}

impl<D> EncodeSize for GetSyncTargetResponse<D>
where
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.target.encode_size()
    }
}

impl<D> Read for GetSyncTargetResponse<D>
where
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let target = Target::<D>::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}
