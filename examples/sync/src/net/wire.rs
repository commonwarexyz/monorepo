use crate::net::{ErrorResponse, RequestId};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, IsUnit, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::Digest;
use commonware_runtime::{Buf, BufMut};
use commonware_storage::{
    mmr::{self, Location, Proof},
    qmdb::sync::{compact, compact::State, Target},
};
use std::num::NonZeroU64;

/// Maximum number of digests in a proof.
pub const MAX_DIGESTS: usize = 10_000;

/// Maximum number of pinned nodes (one per MMR peak, bounded by max tree height).
pub const MAX_PINNED_NODES: usize = 64;

/// Request for operations from the server.
#[derive(Debug)]
pub struct GetOperationsRequest {
    pub request_id: RequestId,
    pub op_count: Location,
    pub start_loc: Location,
    pub max_ops: NonZeroU64,
    pub include_pinned_nodes: bool,
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
    pub pinned_nodes: Option<Vec<D>>,
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

/// Request for compact authenticated state.
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
    pub target: compact::Target<mmr::Family, D>,
}

/// Request for compact authenticated state.
#[derive(Debug)]
pub struct GetCompactStateRequest<D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub target: compact::Target<mmr::Family, D>,
}

/// Response with compact authenticated state.
#[derive(Debug)]
pub struct GetCompactStateResponse<Op, D>
where
    D: Digest,
{
    pub request_id: RequestId,
    pub state: State<mmr::Family, Op, D>,
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
    GetCompactStateRequest(GetCompactStateRequest<D>),
    GetCompactStateResponse(GetCompactStateResponse<Op, D>),
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
            Self::GetCompactStateRequest(r) => r.request_id,
            Self::GetCompactStateResponse(r) => r.request_id,
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
            Self::GetCompactStateRequest(req) => {
                6u8.write(buf);
                req.write(buf);
            }
            Self::GetCompactStateResponse(resp) => {
                7u8.write(buf);
                resp.write(buf);
            }
            Self::Error(err) => {
                8u8.write(buf);
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
            Self::GetCompactStateRequest(req) => req.encode_size(),
            Self::GetCompactStateResponse(resp) => resp.encode_size(),
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
            6 => Ok(Self::GetCompactStateRequest(GetCompactStateRequest::read(
                buf,
            )?)),
            7 => Ok(Self::GetCompactStateResponse(
                GetCompactStateResponse::read(buf)?,
            )),
            8 => Ok(Self::Error(ErrorResponse::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

impl Write for GetOperationsRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.get().write(buf);
        (self.include_pinned_nodes as u8).write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.get().encode_size()
            + 1u8.encode_size()
    }
}

impl Read for GetOperationsRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let op_count = Location::read(buf)?;
        let start_loc = Location::read(buf)?;
        let max_ops = u64::read(buf)?;
        let Some(max_ops) = NonZeroU64::new(max_ops) else {
            return Err(CodecError::Invalid(
                "GetOperationsRequest",
                "max_ops cannot be zero",
            ));
        };
        let include_pinned_nodes = u8::read(buf)? != 0;
        Ok(Self {
            request_id,
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        })
    }
}

impl GetOperationsRequest {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.start_loc >= self.op_count {
            return Err(crate::Error::InvalidRequest(format!(
                "start_loc >= size ({}) >= ({})",
                self.start_loc, self.op_count
            )));
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
        match &self.pinned_nodes {
            Some(nodes) => {
                1u8.write(buf);
                nodes.write(buf);
            }
            None => {
                0u8.write(buf);
            }
        }
    }
}

impl<Op, D> EncodeSize for GetOperationsResponse<Op, D>
where
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.proof.encode_size()
            + self.operations.encode_size()
            + 1u8.encode_size()
            + self
                .pinned_nodes
                .as_ref()
                .map_or(0, |nodes| nodes.encode_size())
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
        let request_id = RequestId::read_cfg(buf, &())?;
        let proof = Proof::<D>::read_cfg(buf, &MAX_DIGESTS)?;
        let operations = {
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<Op>::read_cfg(buf, &(range_cfg, Op::Cfg::default()))?
        };
        let has_pinned_nodes = u8::read(buf)? != 0;
        let pinned_nodes = if has_pinned_nodes {
            let range_cfg = RangeCfg::from(0..=MAX_PINNED_NODES);
            Some(Vec::<D>::read_cfg(buf, &(range_cfg, ()))?)
        } else {
            None
        };
        Ok(Self {
            request_id,
            proof,
            operations,
            pinned_nodes,
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

impl<D> Write for GetCompactStateRequest<D>
where
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.target.write(buf);
    }
}

impl<D> EncodeSize for GetCompactStateRequest<D>
where
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.target.encode_size()
    }
}

impl<D> Read for GetCompactStateRequest<D>
where
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let target = compact::Target::<mmr::Family, D>::read_cfg(buf, &())?;
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
        let target = compact::Target::<mmr::Family, D>::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}

impl<Op, D> Write for GetCompactStateResponse<Op, D>
where
    Op: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.state.leaf_count.write(buf);
        self.state.pinned_nodes.write(buf);
        self.state.last_commit_op.write(buf);
        self.state.last_commit_proof.write(buf);
    }
}

impl<Op, D> EncodeSize for GetCompactStateResponse<Op, D>
where
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.state.leaf_count.encode_size()
            + self.state.pinned_nodes.encode_size()
            + self.state.last_commit_op.encode_size()
            + self.state.last_commit_proof.encode_size()
    }
}

impl<Op, D> Read for GetCompactStateResponse<Op, D>
where
    Op: Read,
    Op::Cfg: IsUnit,
    D: Digest,
{
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let leaf_count = Location::read(buf)?;
        let range_cfg = RangeCfg::from(0..=MAX_PINNED_NODES);
        let pinned_nodes = Vec::<D>::read_cfg(buf, &(range_cfg, ()))?;
        let last_commit_op = Op::read_cfg(buf, &Op::Cfg::default())?;
        let last_commit_proof = Proof::<D>::read_cfg(buf, &MAX_DIGESTS)?;
        Ok(Self {
            request_id,
            state: State {
                leaf_count,
                pinned_nodes,
                last_commit_op,
                last_commit_proof,
            },
        })
    }
}
