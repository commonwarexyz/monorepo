//! Network protocol definitions for ADB sync.
//!
//! This module defines the network protocol used for ADB synchronization between
//! clients and servers. It includes message types, error handling, and validation
//! logic for safe network communication.
//!
//! The protocol supports:
//! - Getting server metadata (database size, target hash, operation bounds)
//! - Fetching operations with cryptographic proofs
//! - Comprehensive error handling

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt as _, Write};
use commonware_cryptography::sha256::Digest;
use std::num::NonZeroU64;
use thiserror::Error;

/// Protocol version identifier.
pub const PROTOCOL_VERSION: u8 = 0;

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Network protocol messages for ADB sync.
#[derive(Debug, Clone)]
pub enum Message {
    /// Request operations from the server.
    GetOperationsRequest(GetOperationsRequest),
    /// Response with operations and proof.
    GetOperationsResponse(GetOperationsResponse),
    /// Request server metadata (target hash, bounds, etc.).
    GetServerMetadataRequest(GetServerMetadataRequest),
    /// Response with server metadata.
    GetServerMetadataResponse(GetServerMetadataResponse),
    /// Error response.
    Error(ErrorResponse),
}

/// Request for operations from the server.
#[derive(Debug, Clone)]
pub struct GetOperationsRequest {
    /// Protocol version.
    pub version: u8,
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
    /// Protocol version.
    pub version: u8,
    /// Serialized proof that the operations were in the database.
    pub proof_bytes: Vec<u8>,
    /// Serialized operations in the requested range.
    pub operations_bytes: Vec<u8>,
}

/// Request for server metadata.
#[derive(Debug, Clone)]
pub struct GetServerMetadataRequest {
    /// Protocol version.
    pub version: u8,
}

/// Response with server metadata.
#[derive(Debug, Clone)]
pub struct GetServerMetadataResponse {
    /// Protocol version.
    pub version: u8,
    /// Target hash of the database.
    pub target_hash: Digest,
    /// Oldest retained operation location.
    pub oldest_retained_loc: u64,
    /// Latest operation location.
    pub latest_op_loc: u64,
}

/// Error response.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Protocol version.
    pub version: u8,
    /// Error code.
    pub error_code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Error codes for protocol errors.
#[derive(Debug, Clone)]
pub enum ErrorCode {
    /// Unsupported protocol version.
    UnsupportedVersion,
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
    #[error("Unsupported protocol version: {version}")]
    UnsupportedVersion { version: u8 },

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
            Message::GetServerMetadataRequest(req) => {
                2u8.write(buf);
                req.write(buf);
            }
            Message::GetServerMetadataResponse(resp) => {
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
            Message::GetServerMetadataRequest(req) => req.encode_size(),
            Message::GetServerMetadataResponse(resp) => resp.encode_size(),
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
            2 => Ok(Message::GetServerMetadataRequest(
                GetServerMetadataRequest::read(buf)?,
            )),
            3 => Ok(Message::GetServerMetadataResponse(
                GetServerMetadataResponse::read(buf)?,
            )),
            4 => Ok(Message::Error(ErrorResponse::read(buf)?)),
            _ => Err(CodecError::InvalidEnum(discriminant)),
        }
    }
}

impl Write for GetOperationsRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.size.write(buf);
        self.start_loc.write(buf);
        self.max_ops.get().write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.size.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.get().encode_size()
    }
}

impl Read for GetOperationsRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let size = u64::read(buf)?;
        let start_loc = u64::read(buf)?;
        let max_ops_raw = u64::read(buf)?;
        let max_ops = NonZeroU64::new(max_ops_raw)
            .ok_or_else(|| CodecError::Invalid("GetOperationsRequest", "max_ops cannot be zero"))?;
        Ok(Self {
            version,
            size,
            start_loc,
            max_ops,
        })
    }
}

impl Write for GetOperationsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.proof_bytes.write(buf);
        self.operations_bytes.write(buf);
    }
}

impl EncodeSize for GetOperationsResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.proof_bytes.encode_size()
            + self.operations_bytes.encode_size()
    }
}

impl Read for GetOperationsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        use commonware_codec::ReadRangeExt;
        let version = u8::read(buf)?;
        let proof_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let operations_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        Ok(Self {
            version,
            proof_bytes,
            operations_bytes,
        })
    }
}

impl Write for GetServerMetadataRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
    }
}

impl EncodeSize for GetServerMetadataRequest {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
    }
}

impl Read for GetServerMetadataRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            version: u8::read(buf)?,
        })
    }
}

impl Write for GetServerMetadataResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.target_hash.write(buf);
        self.oldest_retained_loc.write(buf);
        self.latest_op_loc.write(buf);
    }
}

impl EncodeSize for GetServerMetadataResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.target_hash.encode_size()
            + self.oldest_retained_loc.encode_size()
            + self.latest_op_loc.encode_size()
    }
}

impl Read for GetServerMetadataResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let target_hash = Digest::read(buf)?;
        let oldest_retained_loc = u64::read(buf)?;
        let latest_op_loc = u64::read(buf)?;
        Ok(Self {
            version,
            target_hash,
            oldest_retained_loc,
            latest_op_loc,
        })
    }
}

impl Write for ErrorResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.error_code.write(buf);
        self.message.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for ErrorResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.error_code.encode_size()
            + self.message.as_bytes().to_vec().encode_size()
    }
}

impl Read for ErrorResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let error_code = ErrorCode::read(buf)?;
        // Read string as Vec<u8> and convert to String
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| CodecError::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
            version,
            error_code,
            message,
        })
    }
}

impl Write for ErrorCode {
    fn write(&self, buf: &mut impl BufMut) {
        let discriminant = match self {
            ErrorCode::UnsupportedVersion => 0u8,
            ErrorCode::InvalidRequest => 1u8,
            ErrorCode::DatabaseError => 2u8,
            ErrorCode::NetworkError => 3u8,
            ErrorCode::Timeout => 4u8,
            ErrorCode::InternalError => 5u8,
        };
        discriminant.write(buf);
    }
}

impl EncodeSize for ErrorCode {
    fn encode_size(&self) -> usize {
        1 // u8 discriminant
    }
}

impl Read for ErrorCode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let discriminant = u8::read(buf)?;
        match discriminant {
            0 => Ok(ErrorCode::UnsupportedVersion),
            1 => Ok(ErrorCode::InvalidRequest),
            2 => Ok(ErrorCode::DatabaseError),
            3 => Ok(ErrorCode::NetworkError),
            4 => Ok(ErrorCode::Timeout),
            5 => Ok(ErrorCode::InternalError),
            _ => Err(CodecError::InvalidEnum(discriminant)),
        }
    }
}

impl From<ProtocolError> for ErrorResponse {
    fn from(error: ProtocolError) -> Self {
        let (error_code, message) = match error {
            ProtocolError::UnsupportedVersion { version } => (
                ErrorCode::UnsupportedVersion,
                format!("Unsupported version: {version}"),
            ),
            ProtocolError::InvalidRequest { message } => (ErrorCode::InvalidRequest, message),
            ProtocolError::DatabaseError(e) => (ErrorCode::DatabaseError, e.to_string()),
            ProtocolError::NetworkError(e) => (ErrorCode::NetworkError, e),
        };

        ErrorResponse {
            version: PROTOCOL_VERSION,
            error_code,
            message,
        }
    }
}

impl GetOperationsRequest {
    /// Validate the request parameters.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                version: self.version,
            });
        }

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

impl GetServerMetadataRequest {
    /// Validate the request parameters.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                version: self.version,
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
            version: PROTOCOL_VERSION,
            size: 100,
            start_loc: 10,
            max_ops: NZU64!(50),
        };
        assert!(request.validate().is_ok());

        // Invalid version
        let request = GetOperationsRequest {
            version: 99,
            size: 100,
            start_loc: 10,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        // Invalid start_loc
        let request = GetOperationsRequest {
            version: PROTOCOL_VERSION,
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
            version: PROTOCOL_VERSION,
            size: 100,
            start_loc: 150,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn test_get_server_metadata_request_validation() {
        // Valid request
        let request = GetServerMetadataRequest {
            version: PROTOCOL_VERSION,
        };
        assert!(request.validate().is_ok());

        // Invalid version
        let request = GetServerMetadataRequest {
            version: PROTOCOL_VERSION.wrapping_sub(1),
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }
}
