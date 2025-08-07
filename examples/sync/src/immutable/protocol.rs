//! Network protocol for Immutable example. Mirrors the Any protocol but with Variable ops.

use crate::immutable::Operation;
use crate::net::{self as net, RequestId, WireMessage};
use bytes::{Buf, BufMut};
use commonware_codec::DecodeExt;
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write};
use commonware_cryptography::sha256::Digest;
use commonware_storage::{adb::sync::Target, mmr::verification::Proof};
use std::num::NonZeroU64;

// Local max proof elements for immutable wire (kept consistent with Any example)
const MAX_DIGESTS: usize = 10_000;

#[derive(Debug, Clone)]
pub enum Message {
    GetOperationsRequest(GetOperationsRequest),
    GetOperationsResponse(GetOperationsResponse),
    GetSyncTargetRequest(GetSyncTargetRequest),
    GetSyncTargetResponse(GetSyncTargetResponse),
    Error(net::ErrorResponse),
}

impl Message {
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

#[derive(Debug, Clone)]
pub struct GetOperationsRequest {
    pub request_id: RequestId,
    pub size: u64,
    pub start_loc: u64,
    pub max_ops: NonZeroU64,
}

#[derive(Debug, Clone)]
pub struct GetOperationsResponse {
    pub request_id: RequestId,
    pub proof: Proof<Digest>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone)]
pub struct GetSyncTargetRequest {
    pub request_id: RequestId,
}

#[derive(Debug, Clone)]
pub struct GetSyncTargetResponse {
    pub request_id: RequestId,
    pub target: Target<Digest>,
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Message::GetOperationsRequest(r) => {
                0u8.write(buf);
                r.write(buf)
            }
            Message::GetOperationsResponse(r) => {
                1u8.write(buf);
                r.write(buf)
            }
            Message::GetSyncTargetRequest(r) => {
                2u8.write(buf);
                r.write(buf)
            }
            Message::GetSyncTargetResponse(r) => {
                3u8.write(buf);
                r.write(buf)
            }
            Message::Error(e) => {
                4u8.write(buf);
                e.write(buf)
            }
        }
    }
}
impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Message::GetOperationsRequest(r) => r.encode_size(),
            Message::GetOperationsResponse(r) => r.encode_size(),
            Message::GetSyncTargetRequest(r) => r.encode_size(),
            Message::GetSyncTargetResponse(r) => r.encode_size(),
            Message::Error(e) => e.encode_size(),
        }
    }
}
impl Read for Message {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
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
            4 => Ok(Message::Error(net::ErrorResponse::read(buf)?)),
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

impl Write for GetOperationsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.proof.write(buf);
        self.operations.write(buf);
    }
}
impl EncodeSize for GetOperationsResponse {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.proof.encode_size() + self.operations.encode_size()
    }
}
impl Read for GetOperationsResponse {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        // Proof uses usize cfg for max digests
        let proof = Proof::read_cfg(buf, &MAX_DIGESTS)?;
        let operations = {
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<Operation>::read_cfg(buf, &(range_cfg, ()))?
        };
        Ok(Self {
            request_id,
            proof,
            operations,
        })
    }
}

impl WireMessage for Message {
    fn request_id(&self) -> RequestId {
        match self {
            Message::GetOperationsRequest(req) => req.request_id,
            Message::GetOperationsResponse(resp) => resp.request_id,
            Message::GetSyncTargetRequest(req) => req.request_id,
            Message::GetSyncTargetResponse(resp) => resp.request_id,
            Message::Error(err) => err.request_id,
        }
    }

    fn decode_from(bytes: &[u8]) -> Result<Self, commonware_codec::Error> {
        Self::decode(bytes)
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

impl Write for GetSyncTargetResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.target.write(buf);
    }
}
impl EncodeSize for GetSyncTargetResponse {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size() + self.target.encode_size()
    }
}
impl Read for GetSyncTargetResponse {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let target = Target::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}
