use crate::net::{ErrorResponse, RequestId};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, IsUnit, Read, ReadExt as _, Write,
};
use commonware_cryptography::Digest;
use commonware_runtime::{Buf, BufMut};
use commonware_storage::{
    mmr,
    qmdb::sync::{self, CompactTarget, Target},
};

/// Maximum number of operations decoded per response.
pub const MAX_OPS: usize = 10_000;

/// Request for operations from the server.
#[derive(Debug)]
pub struct GetOperationsRequest {
    pub request_id: RequestId,
    pub request: sync::Request<mmr::Family>,
}

/// Response with operations and proof.
#[derive(Debug)]
pub struct GetOperationsResponse<Op, D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub response: sync::Response<mmr::Family, Op, D>,
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
    pub target: Target<mmr::Family, D>,
}

/// Request for the server's current compact sync target.
#[derive(Debug)]
pub struct GetCompactTargetRequest {
    pub request_id: RequestId,
}

/// Response with compact-sync target.
#[derive(Debug)]
pub struct GetCompactTargetResponse<D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub target: CompactTarget<mmr::Family, D>,
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
    GetCompactTargetRequest(GetCompactTargetRequest),
    GetCompactTargetResponse(GetCompactTargetResponse<D>),
    Error(ErrorResponse),
}

impl<Op, D> Message<Op, D>
where
    D: Digest,
{
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::GetOperationsRequest(r) => r.request_id,
            Self::GetOperationsResponse(r) => r.request_id,
            Self::GetSyncTargetRequest(r) => r.request_id,
            Self::GetSyncTargetResponse(r) => r.request_id,
            Self::GetCompactTargetRequest(r) => r.request_id,
            Self::GetCompactTargetResponse(r) => r.request_id,
            Self::Error(e) => e.request_id,
        }
    }
}

impl<Op, D> super::Message for Message<Op, D>
where
    Op: Encode + Read + Send + Sync + 'static,
    Op::Cfg: IsUnit,
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
            Self::GetOperationsRequest(req) => {
                0u8.write(buf);
                req.write(buf);
            }
            Self::GetOperationsResponse(resp) => {
                1u8.write(buf);
                resp.write(buf);
            }
            Self::GetSyncTargetRequest(req) => {
                2u8.write(buf);
                req.write(buf);
            }
            Self::GetSyncTargetResponse(resp) => {
                3u8.write(buf);
                resp.write(buf);
            }
            Self::GetCompactTargetRequest(req) => {
                4u8.write(buf);
                req.write(buf);
            }
            Self::GetCompactTargetResponse(resp) => {
                5u8.write(buf);
                resp.write(buf);
            }
            Self::Error(err) => {
                6u8.write(buf);
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
            Self::GetOperationsRequest(req) => req.encode_size(),
            Self::GetOperationsResponse(resp) => resp.encode_size(),
            Self::GetSyncTargetRequest(req) => req.encode_size(),
            Self::GetSyncTargetResponse(resp) => resp.encode_size(),
            Self::GetCompactTargetRequest(req) => req.encode_size(),
            Self::GetCompactTargetResponse(resp) => resp.encode_size(),
            Self::Error(err) => err.encode_size(),
        }
    }
}

impl<Op, D> Read for Message<Op, D>
where
    Op: Read,
    Op::Cfg: IsUnit,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::GetOperationsRequest(GetOperationsRequest::read(buf)?)),
            1 => Ok(Self::GetOperationsResponse(GetOperationsResponse::read(
                buf,
            )?)),
            2 => Ok(Self::GetSyncTargetRequest(GetSyncTargetRequest::read(buf)?)),
            3 => Ok(Self::GetSyncTargetResponse(GetSyncTargetResponse::read(
                buf,
            )?)),
            4 => Ok(Self::GetCompactTargetRequest(
                GetCompactTargetRequest::read(buf)?,
            )),
            5 => Ok(Self::GetCompactTargetResponse(
                GetCompactTargetResponse::read(buf)?,
            )),
            6 => Ok(Self::Error(ErrorResponse::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

impl Write for GetOperationsRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.request.write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.request.encode_size()
    }
}

impl Read for GetOperationsRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            request_id: RequestId::read_cfg(buf, &())?,
            request: sync::Request::read(buf)?,
        })
    }
}

impl<Op, D> Write for GetOperationsResponse<Op, D>
where
    Op: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.response.write(buf);
    }
}

impl<Op, D> EncodeSize for GetOperationsResponse<Op, D>
where
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.response.encode_size()
    }
}

impl<Op, D> Read for GetOperationsResponse<Op, D>
where
    Op: Read,
    Op::Cfg: IsUnit,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            request_id: RequestId::read_cfg(buf, &())?,
            response: sync::Response::read_cfg(buf, &(MAX_OPS, Op::Cfg::default()))?,
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
        let target = Target::<mmr::Family, D>::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}

impl Write for GetCompactTargetRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
    }
}

impl EncodeSize for GetCompactTargetRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
    }
}

impl Read for GetCompactTargetRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        Ok(Self { request_id })
    }
}

impl<D> Write for GetCompactTargetResponse<D>
where
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.target.write(buf);
    }
}

impl<D> EncodeSize for GetCompactTargetResponse<D>
where
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.target.encode_size()
    }
}

impl<D> Read for GetCompactTargetResponse<D>
where
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let target = CompactTarget::<mmr::Family, D>::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}
