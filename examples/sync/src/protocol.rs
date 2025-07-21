//! Network protocol definitions for syncing a [commonware_storage::adb::any::Any] database.
//!
//! This module defines the network protocol used for syncing a [commonware_storage::adb::any::Any]
//! database to a server's database state. It includes message types, error handling, and validation
//! logic for safe network communication.
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
use std::num::NonZeroU64;
use thiserror::Error;

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of digests in a proof.
const MAX_DIGESTS: usize = 10_000;

/// Network protocol messages for syncing a [commonware_storage::adb::any::Any] database.
#[derive(Debug, Clone)]
pub enum Message {
    /// Request operations from the server.
    GetOperationsRequest(GetOperationsRequest),
    /// Response with operations and proof.
    GetOperationsResponse(GetOperationsResponse),
    /// Request sync target from server.
    GetSyncTargetRequest,
    /// Response with sync target.
    GetSyncTargetResponse(SyncTarget<Digest>),
    /// Error response.
    /// Note that, in this example, the server sends an error response to the client in the event
    /// of an invalid request or internal error. In a real-world application, this may be inadvisable.
    /// A server may want to simply ignore the client's faulty request and close the connection
    /// to the client. Similarly, a client may not care about the reason for the server's error.
    Error(ErrorResponse),
}

/// Request for operations from the server.
#[derive(Debug, Clone)]
pub struct GetOperationsRequest {
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
    /// Serialized proof that the operations were in the database.
    pub proof: Proof<Digest>,
    /// Serialized operations in the requested range.
    pub operations: Vec<Operation>,
}

/// Error response.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
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

/// Errors that can occur during protocol operations.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("Database error: {0}")]
    DatabaseError(#[from] commonware_storage::adb::Error),

    #[error("Network error: {0}")]
    NetworkError(String),
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
            Message::GetSyncTargetRequest => {
                2u8.write(buf);
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
            Message::GetSyncTargetRequest => 0,
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
            2 => Ok(Message::GetSyncTargetRequest),
            3 => Ok(Message::GetSyncTargetResponse(SyncTarget::read(buf)?)),
            4 => Ok(Message::Error(ErrorResponse::read(buf)?)),
            _ => Err(CodecError::InvalidEnum(discriminant)),
        }
    }
}

impl Write for GetOperationsRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.size.write(buf);
        self.start_loc.write(buf);
        self.max_ops.get().write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.size.encode_size() + self.start_loc.encode_size() + self.max_ops.get().encode_size()
    }
}

impl Read for GetOperationsRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let size = u64::read(buf)?;
        let start_loc = u64::read(buf)?;
        let max_ops_raw = u64::read(buf)?;
        let max_ops = NonZeroU64::new(max_ops_raw)
            .ok_or_else(|| CodecError::Invalid("GetOperationsRequest", "max_ops cannot be zero"))?;
        Ok(Self {
            size,
            start_loc,
            max_ops,
        })
    }
}

impl Write for GetOperationsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
    }
}

impl EncodeSize for GetOperationsResponse {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.operations.encode_size()
    }
}

impl Read for GetOperationsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let proof = Proof::read_cfg(buf, &MAX_DIGESTS)?;
        let operations = {
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<Operation>::read_cfg(buf, &(range_cfg, ()))?
        };
        Ok(Self { proof, operations })
    }
}

impl Write for ErrorResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.error_code.write(buf);
        self.message.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for ErrorResponse {
    fn encode_size(&self) -> usize {
        self.error_code.encode_size() + self.message.as_bytes().to_vec().encode_size()
    }
}

impl Read for ErrorResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let error_code = ErrorCode::read(buf)?;
        // Read string as Vec<u8> and convert to String
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| CodecError::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
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

impl From<ProtocolError> for ErrorResponse {
    fn from(error: ProtocolError) -> Self {
        let (error_code, message) = match error {
            ProtocolError::InvalidRequest { message } => (ErrorCode::InvalidRequest, message),
            ProtocolError::DatabaseError(e) => (ErrorCode::DatabaseError, e.to_string()),
            ProtocolError::NetworkError(e) => (ErrorCode::NetworkError, e),
        };
        ErrorResponse {
            error_code,
            message,
        }
    }
}

impl GetOperationsRequest {
    /// Validate the request parameters.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.start_loc >= self.size {
            return Err(ProtocolError::InvalidRequest {
                message: format!("start_loc >= size ({}) >= ({})", self.start_loc, self.size),
            });
        }

        if self.max_ops.get() == 0 {
            return Err(ProtocolError::InvalidRequest {
                message: "max_ops cannot be zero".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn test_get_operations_request_validation() {
        // Valid request
        let request = GetOperationsRequest {
            size: 100,
            start_loc: 10,
            max_ops: NZU64!(50),
        };
        assert!(request.validate().is_ok());

        // Invalid start_loc
        let request = GetOperationsRequest {
            size: 100,
            start_loc: 100,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidRequest { .. })
        ));

        // start_loc beyond size
        let request = GetOperationsRequest {
            size: 100,
            start_loc: 150,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidRequest { .. })
        ));
    }
}
