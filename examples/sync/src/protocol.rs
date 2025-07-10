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

use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;
use thiserror::Error;

/// Protocol version identifier.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size in bytes (1MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Network protocol messages for ADB sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

// ========== Request/Response Types ==========

/// Request for operations from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetServerMetadataRequest {
    /// Protocol version.
    pub version: u8,
    /// Request ID for matching request/response.
    pub request_id: u64,
}

/// Response with server metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetServerMetadataResponse {
    /// Protocol version.
    pub version: u8,
    /// Request ID that this response corresponds to.
    pub request_id: u64,
    /// Current database size (operation count).
    pub database_size: u64,
    /// Target hash of the database (hex string).
    pub target_hash: String,
    /// Oldest retained operation location.
    pub oldest_retained_loc: u64,
    /// Latest operation location.
    pub latest_op_loc: u64,
}

/// Error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Server overloaded.
    Overloaded,
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

    #[error("Serialization error: {0}")]
    SerializationError(#[from] commonware_codec::Error),

    #[error("Request timeout")]
    Timeout,

    #[error("Server overloaded")]
    Overloaded,

    #[error("Internal error: {0}")]
    InternalError(String),
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
            ProtocolError::SerializationError(e) => (
                ErrorCode::InternalError,
                format!("Serialization error: {e}"),
            ),
            ProtocolError::Timeout => (ErrorCode::Timeout, "Request timeout".to_string()),
            ProtocolError::Overloaded => (ErrorCode::Overloaded, "Server overloaded".to_string()),
            ProtocolError::InternalError(e) => (ErrorCode::InternalError, e),
        };

        ErrorResponse {
            version: PROTOCOL_VERSION,
            request_id: None,
            error_code,
            message,
        }
    }
}

// ========== Implementation Methods ==========

impl GetOperationsRequest {
    /// Create a new GetOperationsRequest.
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
    /// Create a new GetOperationsResponse.
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
    /// Create a new GetServerMetadataRequest.
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
    /// Create a new GetServerMetadataResponse.
    pub fn new(
        request_id: u64,
        database_size: u64,
        target_hash: String,
        oldest_retained_loc: u64,
        latest_op_loc: u64,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            database_size,
            target_hash,
            oldest_retained_loc,
            latest_op_loc,
        }
    }
}

impl ErrorResponse {
    /// Create a new ErrorResponse.
    pub fn new(request_id: Option<u64>, error_code: ErrorCode, message: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            error_code,
            message,
        }
    }
}

// ========== Tests ==========

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

    #[test]
    fn test_message_serialization() {
        let request = GetOperationsRequest::new(100, 10, NZU64!(50), 1);
        let message = Message::GetOperationsRequest(request);

        // Test basic message construction
        if let Message::GetOperationsRequest(req) = message {
            assert_eq!(req.size, 100);
            assert_eq!(req.start_loc, 10);
            assert_eq!(req.max_ops.get(), 50);
            assert_eq!(req.request_id, 1);
        } else {
            panic!("Message type mismatch");
        }
    }

    #[test]
    fn test_error_response_from_protocol_error() {
        let error = ProtocolError::UnsupportedVersion { version: 99 };
        let response: ErrorResponse = error.into();

        assert_eq!(response.version, PROTOCOL_VERSION);
        assert!(matches!(response.error_code, ErrorCode::UnsupportedVersion));
        assert!(response.message.contains("99"));
    }

    #[test]
    fn test_server_metadata_response_creation() {
        let response = GetServerMetadataResponse::new(1, 100, "abcdef".to_string(), 0, 99);

        assert_eq!(response.request_id, 1);
        assert_eq!(response.database_size, 100);
        assert_eq!(response.target_hash, "abcdef");
        assert_eq!(response.oldest_retained_loc, 0);
        assert_eq!(response.latest_op_loc, 99);
    }
}
