//! Error types for the sync example.

use crate::net::ErrorCode;
use thiserror::Error;

/// Errors that can occur in the sync example.
#[derive(Debug, Error)]
pub enum Error {
    /// Stream error during communication
    #[error("stream error")]
    Network(#[from] commonware_stream::Error),

    /// Received unexpected response type for a request
    #[error("unexpected response type for request {request_id}")]
    UnexpectedResponse { request_id: u64 },

    /// Server returned an error response
    #[error("server error (code: {code:?}): {message}")]
    Server { code: ErrorCode, message: String },

    /// Invalid request parameters
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Database operation failed
    #[error("database operation failed")]
    Database(#[from] commonware_storage::adb::Error),

    /// Request channel to I/O task closed unexpectedly
    #[error("request channel closed - I/O task may have terminated")]
    RequestChannelClosed,

    /// Response channel closed before receiving response
    #[error("response channel closed for request {request_id}")]
    ResponseChannelClosed { request_id: u64 },

    /// Target update channel error
    #[error("target update channel error: {reason}")]
    TargetUpdateChannel { reason: String },

    /// Configuration error
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl Error {
    /// Convert this error to a protocol error code for transmission over the network.
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            Error::InvalidRequest(_) => ErrorCode::InvalidRequest,
            Error::Database(_) => ErrorCode::DatabaseError,
            Error::Network(_) => ErrorCode::NetworkError,
            Error::RequestChannelClosed | Error::ResponseChannelClosed { .. } => {
                ErrorCode::InternalError
            }
            _ => ErrorCode::InternalError,
        }
    }
}
