use crate::net::{ErrorResponse, RequestId};
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::Digest;
use commonware_storage::{adb::sync::Target, mmr::verification::Proof};
use std::num::NonZeroU64;

/// Maximum number of digests in a proof.
pub const MAX_DIGESTS: usize = 10_000;

/// Request for operations from the server.
#[derive(Debug)]
pub struct GetOperationsRequest {
    pub request_id: RequestId,
    pub size: u64,
    pub start_loc: u64,
    pub max_ops: NonZeroU64,
}

/// Response with operations and proof.
#[derive(Debug)]
pub struct GetOperationsResponse<Op, D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub proof: Proof<D>,
    pub operations: Vec<Op>,
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
pub enum Message<Op, D>
where
    D: Digest,
{
    GetOperationsRequest(GetOperationsRequest),
    GetOperationsResponse(GetOperationsResponse<Op, D>),
    GetSyncTargetRequest(GetSyncTargetRequest),
    GetSyncTargetResponse(GetSyncTargetResponse<D>),
    Error(ErrorResponse),
}

impl<Op, D> Message<Op, D>
where
    D: Digest,
{
    pub fn request_id(&self) -> RequestId {
        match self {
            Message::GetOperationsRequest(r) => r.request_id,
            Message::GetOperationsResponse(r) => r.request_id,
            Message::GetSyncTargetRequest(r) => r.request_id,
            Message::GetSyncTargetResponse(r) => r.request_id,
            Message::Error(e) => e.request_id,
        }
    }
}

impl<Op, D> super::Message for Message<Op, D>
where
    Op: Encode + DecodeExt<()> + Send + Sync + 'static,
    D: Digest,
{
    fn request_id(&self) -> RequestId {
        self.request_id()
    }
}

impl<Op, D> Write for Message<Op, D>
where
    Op: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Message::GetOperationsRequest(req) => {
                0u8.write(buf);
                req.write(buf);
            }
            Message::GetOperationsResponse(resp) => {
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

impl<Op, D> EncodeSize for Message<Op, D>
where
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Message::GetOperationsRequest(req) => req.encode_size(),
            Message::GetOperationsResponse(resp) => resp.encode_size(),
            Message::GetSyncTargetRequest(req) => req.encode_size(),
            Message::GetSyncTargetResponse(resp) => resp.encode_size(),
            Message::Error(err) => err.encode_size(),
        }
    }
}

impl<Op, D> Read for Message<Op, D>
where
    Op: Read<Cfg = ()>,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Message::GetOperationsRequest(GetOperationsRequest::read(
                buf,
            )?)),
            1 => Ok(Message::GetOperationsResponse(GetOperationsResponse::read(
                buf,
            )?)),
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

impl Write for GetOperationsRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.size.write(buf);
        self.start_loc.write(buf);
        self.max_ops.get().write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.size.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.get().encode_size()
    }
}

impl Read for GetOperationsRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let size = u64::read(buf)?;
        let start_loc = u64::read(buf)?;
        let max_ops_raw = u64::read(buf)?;
        let max_ops = NonZeroU64::new(max_ops_raw)
            .ok_or_else(|| CodecError::Invalid("GetOperationsRequest", "max_ops cannot be zero"))?;
        Ok(Self {
            request_id,
            size,
            start_loc,
            max_ops,
        })
    }
}

impl GetOperationsRequest {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.start_loc >= self.size {
            return Err(crate::Error::InvalidRequest(format!(
                "start_loc >= size ({}) >= ({})",
                self.start_loc, self.size
            )));
        }
        if self.max_ops.get() == 0 {
            return Err(crate::Error::InvalidRequest(
                "max_ops cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl<Op, D> Write for GetOperationsResponse<Op, D>
where
    Op: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.proof.write(buf);
        self.operations.write(buf);
    }
}

impl<Op, D> EncodeSize for GetOperationsResponse<Op, D>
where
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.proof.encode_size() + self.operations.encode_size()
    }
}

impl<Op, D> Read for GetOperationsResponse<Op, D>
where
    Op: Read<Cfg = ()>,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let proof = Proof::<D>::read_cfg(buf, &MAX_DIGESTS)?;
        let operations = {
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<Op>::read_cfg(buf, &(range_cfg, ()))?
        };
        Ok(Self {
            request_id,
            proof,
            operations,
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
