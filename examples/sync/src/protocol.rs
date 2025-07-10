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
use commonware_runtime::{Sink, Stream};
use std::num::NonZeroU64;
use thiserror::Error;

/// Protocol version identifier.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

// ========== Message Framing Functions ==========

/// Read a length-prefixed message from a stream.
///
/// This function reads a 4-byte big-endian length prefix followed by the message data.
/// The message length is validated to prevent DoS attacks.
pub async fn read_message<S: Stream>(stream: &mut S) -> Result<Vec<u8>, MessageFramingError> {
    // Read the 4-byte length prefix
    let length_buf = vec![0u8; 4];
    let length_data = stream
        .recv(length_buf)
        .await
        .map_err(|e| MessageFramingError::ReadFailed(e.to_string()))?;

    if length_data.len() != 4 {
        return Err(MessageFramingError::InvalidLengthPrefix);
    }

    // Convert bytes to u32 (network byte order)
    let message_length = u32::from_be_bytes([
        length_data.as_ref()[0],
        length_data.as_ref()[1],
        length_data.as_ref()[2],
        length_data.as_ref()[3],
    ]) as usize;

    // Validate message length (prevent DoS)
    if message_length == 0 || message_length > MAX_MESSAGE_SIZE {
        return Err(MessageFramingError::InvalidMessageLength(message_length));
    }

    // Read the actual message
    let message_buf = vec![0u8; message_length];
    let message_data = stream
        .recv(message_buf)
        .await
        .map_err(|e| MessageFramingError::ReadFailed(e.to_string()))?;

    if message_data.len() != message_length {
        return Err(MessageFramingError::MessageLengthMismatch {
            expected: message_length,
            actual: message_data.len(),
        });
    }

    Ok(message_data.as_ref().to_vec())
}

/// Send a length-prefixed message to a sink.
///
/// This function sends a 4-byte big-endian length prefix followed by the message data.
pub async fn send_message<S: Sink>(
    sink: &mut S,
    message: &[u8],
) -> Result<(), MessageFramingError> {
    // Validate message length
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(MessageFramingError::MessageTooLarge(message.len()));
    }

    // Send 4-byte length prefix
    let length = message.len() as u32;
    let length_bytes = length.to_be_bytes();
    sink.send(length_bytes.to_vec())
        .await
        .map_err(|e| MessageFramingError::WriteFailed(e.to_string()))?;

    // Send the actual message
    sink.send(message.to_vec())
        .await
        .map_err(|e| MessageFramingError::WriteFailed(e.to_string()))?;

    Ok(())
}

/// Errors that can occur during message framing operations.
#[derive(Debug, Error)]
pub enum MessageFramingError {
    #[error("Failed to read from stream: {0}")]
    ReadFailed(String),

    #[error("Failed to write to sink: {0}")]
    WriteFailed(String),

    #[error("Invalid length prefix")]
    InvalidLengthPrefix,

    #[error("Invalid message length: {0} (max: {MAX_MESSAGE_SIZE})")]
    InvalidMessageLength(usize),

    #[error("Message too large: {0} bytes (max: {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(usize),

    #[error("Message length mismatch: expected {expected}, got {actual}")]
    MessageLengthMismatch { expected: usize, actual: usize },
}

// ========== Protocol Types ==========

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
    /// Request ID for matching request/response.
    pub request_id: u64,
}

/// Response with operations and proof.
#[derive(Debug, Clone)]
pub struct GetOperationsResponse {
    /// Protocol version.
    pub version: u8,
    /// Request ID that this response corresponds to.
    pub request_id: u64,
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
    /// Request ID for matching request/response.
    pub request_id: u64,
}

/// Response with server metadata.
#[derive(Debug, Clone)]
pub struct GetServerMetadataResponse {
    /// Protocol version.
    pub version: u8,
    /// Request ID that this response corresponds to.
    pub request_id: u64,
    /// Target hash of the database (hex string).
    pub target_hash: String,
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
    /// Request ID that this error corresponds to (if applicable).
    pub request_id: Option<u64>,
    /// Error code.
    pub error_code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

// ========== Error Types ==========

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
        self.request_id.write(buf);
    }
}

impl EncodeSize for GetOperationsRequest {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.size.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.get().encode_size()
            + self.request_id.encode_size()
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
        let request_id = u64::read(buf)?;
        Ok(Self {
            version,
            size,
            start_loc,
            max_ops,
            request_id,
        })
    }
}

impl Write for GetOperationsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.request_id.write(buf);
        self.proof_bytes.write(buf);
        self.operations_bytes.write(buf);
    }
}

impl EncodeSize for GetOperationsResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.request_id.encode_size()
            + self.proof_bytes.encode_size()
            + self.operations_bytes.encode_size()
    }
}

impl Read for GetOperationsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        use commonware_codec::ReadRangeExt;
        let version = u8::read(buf)?;
        let request_id = u64::read(buf)?;
        let proof_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let operations_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        Ok(Self {
            version,
            request_id,
            proof_bytes,
            operations_bytes,
        })
    }
}

impl Write for GetServerMetadataRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.request_id.write(buf);
    }
}

impl EncodeSize for GetServerMetadataRequest {
    fn encode_size(&self) -> usize {
        self.version.encode_size() + self.request_id.encode_size()
    }
}

impl Read for GetServerMetadataRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let request_id = u64::read(buf)?;
        Ok(Self {
            version,
            request_id,
        })
    }
}

impl Write for GetServerMetadataResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.request_id.write(buf);
        let target_hash_bytes = self.target_hash.as_bytes();
        target_hash_bytes.to_vec().write(buf);
        self.oldest_retained_loc.write(buf);
        self.latest_op_loc.write(buf);
    }
}

impl EncodeSize for GetServerMetadataResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.request_id.encode_size()
            + self.target_hash.as_bytes().to_vec().encode_size()
            + self.oldest_retained_loc.encode_size()
            + self.latest_op_loc.encode_size()
    }
}

impl Read for GetServerMetadataResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let request_id = u64::read(buf)?;
        // Read string as Vec<u8> and convert to String
        // Target hash should be exactly 64 characters (SHA256 hex)
        let target_hash_bytes = Vec::<u8>::read_range(buf, 0..=64)?;
        let target_hash = String::from_utf8(target_hash_bytes).map_err(|_| {
            CodecError::Invalid("GetServerMetadataResponse", "invalid UTF-8 in target_hash")
        })?;
        let oldest_retained_loc = u64::read(buf)?;
        let latest_op_loc = u64::read(buf)?;
        Ok(Self {
            version,
            request_id,
            target_hash,
            oldest_retained_loc,
            latest_op_loc,
        })
    }
}

impl Write for ErrorResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.request_id.write(buf);
        self.error_code.write(buf);
        self.message.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for ErrorResponse {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.request_id.encode_size()
            + self.error_code.encode_size()
            + self.message.as_bytes().to_vec().encode_size()
    }
}

impl Read for ErrorResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let request_id = Option::<u64>::read(buf)?;
        let error_code = ErrorCode::read(buf)?;
        // Read string as Vec<u8> and convert to String
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| CodecError::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
            version,
            request_id,
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
            request_id: None,
            error_code,
            message,
        }
    }
}

impl GetOperationsRequest {
    /// Create a new [GetOperationsRequest].
    pub fn new(size: u64, start_loc: u64, max_ops: NonZeroU64, request_id: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            size,
            start_loc,
            max_ops,
            request_id,
        }
    }

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

impl GetOperationsResponse {
    /// Create a new [GetOperationsResponse].
    pub fn new(request_id: u64, proof_bytes: Vec<u8>, operations_bytes: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            proof_bytes,
            operations_bytes,
        }
    }
}

impl GetServerMetadataRequest {
    /// Create a new [GetServerMetadataRequest].
    pub fn new(request_id: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
        }
    }

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

impl GetServerMetadataResponse {
    /// Create a new [GetServerMetadataResponse].
    pub fn new(
        request_id: u64,
        target_hash: String,
        oldest_retained_loc: u64,
        latest_op_loc: u64,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            target_hash,
            oldest_retained_loc,
            latest_op_loc,
        }
    }
}

impl ErrorResponse {
    /// Create a new [ErrorResponse].
    pub fn new(request_id: Option<u64>, error_code: ErrorCode, message: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            error_code,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn test_get_operations_request_validation() {
        // Valid request
        let request = GetOperationsRequest::new(100, 10, NZU64!(50), 1);
        assert!(request.validate().is_ok());

        // Invalid version
        let mut request = GetOperationsRequest::new(100, 10, NZU64!(50), 1);
        request.version = 99;
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        // Invalid start_loc
        let request = GetOperationsRequest::new(100, 100, NZU64!(50), 1);
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidRequest { .. })
        ));

        // start_loc beyond size
        let request = GetOperationsRequest::new(100, 150, NZU64!(50), 1);
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn test_get_server_metadata_request_validation() {
        // Valid request
        let request = GetServerMetadataRequest::new(1);
        assert!(request.validate().is_ok());

        // Invalid version
        let mut request = GetServerMetadataRequest::new(1);
        request.version = 99;
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }
}
