//! Network protocol definitions for syncing a [commonware_storage::adb::any::fixed::Any] database.
//!
//! This module defines the network protocol used for syncing a
//! [commonware_storage::adb::any::fixed::Any] database to a server's database state. It includes
//! message types, error handling, and validation logic for safe network communication.
//!
//! The protocol supports:
//! - Getting server metadata (database size, root digest, operation bounds)
//! - Fetching operations with cryptographic proofs
//! - Getting target updates for dynamic sync
//! - Error handling

use crate::Operation;
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, ReadRangeExt as _, Write,
};
use commonware_cryptography::sha256::Digest;
use commonware_storage::{adb::any::sync::SyncTarget, mmr::verification::Proof};
use std::{
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of digests in a proof.
const MAX_DIGESTS: usize = 10_000;

/// Unique identifier for correlating requests with responses.
pub type RequestId = u64;

/// A requester that generates monotonically increasing request IDs.
#[derive(Debug)]
pub struct Requester {
    counter: AtomicU64,
}

impl Default for Requester {
    fn default() -> Self {
        Self::new()
    }
}

impl Requester {
    pub fn new() -> Self {
        Requester {
            counter: AtomicU64::new(1),
        }
    }

    pub fn next(&self) -> RequestId {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Network protocol messages for syncing a [commonware_storage::adb::any::fixed::Any] database.
#[derive(Debug, Clone)]
pub enum Message {
    /// Request operations from the server.
    GetOperationsRequest(GetOperationsRequest),
    /// Response with operations and proof.
    GetOperationsResponse(GetOperationsResponse),
    /// Request sync target from server.
    GetSyncTargetRequest(GetSyncTargetRequest),
    /// Response with sync target.
    GetSyncTargetResponse(GetSyncTargetResponse),
    /// Error response.
    /// Note that, in this example, the server sends an error response to the client in the event
    /// of an invalid request or internal error. In a real-world application, this may be inadvisable.
    /// A server may want to simply ignore the client's faulty request and close the connection
    /// to the client. Similarly, a client may not care about the reason for the server's error.
    Error(ErrorResponse),
}

impl Message {
    pub fn request_id(&self) -> RequestId {
        match self {
            Message::GetOperationsRequest(req) => req.request_id,
            Message::GetOperationsResponse(resp) => resp.request_id,
            Message::GetSyncTargetRequest(req) => req.request_id,
            Message::GetSyncTargetResponse(resp) => resp.request_id,
            Message::Error(err) => err.request_id,
        }
    }
}

/// Request for operations from the server.
#[derive(Debug, Clone)]
pub struct GetOperationsRequest {
    /// Unique identifier for this request.
    pub request_id: RequestId,
    /// Size of the database at the root we are syncing to.
    pub size: u64,
    /// Starting location for the operations.
    pub start_loc: u64,
    /// Maximum number of operations to return.
    pub max_ops: NonZeroU64,
}

/// Response with operations and proof.
#[derive(Debug, Clone)]
pub struct GetOperationsResponse {
    /// Unique identifier matching the original request.
    pub request_id: RequestId,
    /// Serialized proof that the operations were in the database.
    pub proof: Proof<Digest>,
    /// Serialized operations in the requested range.
    pub operations: Vec<Operation>,
}

/// Request for sync target from server.
#[derive(Debug, Clone)]
pub struct GetSyncTargetRequest {
    /// Unique identifier for this request.
    pub request_id: RequestId,
}

/// Response with sync target.
#[derive(Debug, Clone)]
pub struct GetSyncTargetResponse {
    /// Unique identifier matching the original request.
    pub request_id: RequestId,
    /// Sync target information.
    pub target: SyncTarget<Digest>,
}

/// Error response.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Unique identifier matching the original request.
    pub request_id: RequestId,
    /// Error code.
    pub error_code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Error codes for protocol errors.
#[derive(Debug, Clone)]
pub enum ErrorCode {
    /// Invalid request parameters.
    InvalidRequest,
    /// Database error occurred.
    DatabaseError,
    /// Network error occurred.
    NetworkError,
    /// Request timeout.
    Timeout,
    /// Internal server error.
    InternalError,
}

impl Write for Message {
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

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        // 1 byte for the discriminant
        1 + match self {
            Message::GetOperationsRequest(req) => req.encode_size(),
            Message::GetOperationsResponse(resp) => resp.encode_size(),
            Message::GetSyncTargetRequest(req) => req.encode_size(),
            Message::GetSyncTargetResponse(resp) => resp.encode_size(),
            Message::Error(err) => err.encode_size(),
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let discriminant = u8::read(buf)?;
        match discriminant {
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
            _ => Err(CodecError::InvalidEnum(discriminant)),
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
        let target = SyncTarget::read_cfg(buf, &())?;
        Ok(Self { request_id, target })
    }
}

impl Write for ErrorResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.error_code.write(buf);
        self.message.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for ErrorResponse {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.error_code.encode_size()
            + self.message.as_bytes().to_vec().encode_size()
    }
}

impl Read for ErrorResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let error_code = ErrorCode::read(buf)?;
        // Read string as Vec<u8> and convert to String
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| CodecError::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
            request_id,
            error_code,
            message,
        })
    }
}

impl Write for ErrorCode {
    fn write(&self, buf: &mut impl BufMut) {
        let discriminant = match self {
            ErrorCode::InvalidRequest => 0u8,
            ErrorCode::DatabaseError => 1u8,
            ErrorCode::NetworkError => 2u8,
            ErrorCode::Timeout => 3u8,
            ErrorCode::InternalError => 4u8,
        };
        discriminant.write(buf);
    }
}

impl EncodeSize for ErrorCode {
    fn encode_size(&self) -> usize {
        size_of::<u8>()
    }
}

impl Read for ErrorCode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let discriminant = u8::read(buf)?;
        match discriminant {
            0 => Ok(ErrorCode::InvalidRequest),
            1 => Ok(ErrorCode::DatabaseError),
            2 => Ok(ErrorCode::NetworkError),
            3 => Ok(ErrorCode::Timeout),
            4 => Ok(ErrorCode::InternalError),
            _ => Err(CodecError::InvalidEnum(discriminant)),
        }
    }
}

impl GetOperationsRequest {
    /// Validate the request parameters.
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn test_request_id_generation() {
        let requester = Requester::new();
        let id1 = requester.next();
        let id2 = requester.next();
        let id3 = requester.next();

        // Request IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);

        // Should be consecutive since we're using a single Requester
        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1);
    }

    #[test]
    fn test_error_code_roundtrip_serialization() {
        use commonware_codec::{DecodeExt, Encode};

        let test_cases = vec![
            ErrorCode::InvalidRequest,
            ErrorCode::DatabaseError,
            ErrorCode::NetworkError,
            ErrorCode::Timeout,
            ErrorCode::InternalError,
        ];

        for error_code in test_cases {
            // Serialize
            let encoded = error_code.encode().to_vec();

            // Deserialize
            let decoded = ErrorCode::decode(&encoded[..]).expect("Failed to decode ErrorCode");

            // Verify they match
            match (&error_code, &decoded) {
                (ErrorCode::InvalidRequest, ErrorCode::InvalidRequest) => {}
                (ErrorCode::DatabaseError, ErrorCode::DatabaseError) => {}
                (ErrorCode::NetworkError, ErrorCode::NetworkError) => {}
                (ErrorCode::Timeout, ErrorCode::Timeout) => {}
                (ErrorCode::InternalError, ErrorCode::InternalError) => {}
                _ => panic!("ErrorCode roundtrip failed: {error_code:?} != {decoded:?}"),
            }
        }
    }

    #[test]
    fn test_get_operations_request_validation() {
        // Valid request
        let requester = Requester::new();
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 10,
            max_ops: NZU64!(50),
        };
        assert!(request.validate().is_ok());

        // Invalid start_loc
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 100,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));

        // start_loc beyond size
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 150,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));
    }
}
