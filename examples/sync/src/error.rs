//! Error types for the sync example.

use commonware_storage::adb::any::sync::Error as SyncError;
use std::net::SocketAddr;
use thiserror::Error;

/// Errors that can occur in the sync example.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to establish connection to server
    #[error("Failed to connect to server at {addr}: {source}")]
    ConnectionFailed {
        addr: SocketAddr,
        #[source]
        source: commonware_runtime::Error,
    },

    /// Network runtime error
    #[error("Runtime network error")]
    RuntimeNetwork(#[from] commonware_runtime::Error),

    /// Stream error during communication
    #[error("Stream error")]
    Stream(#[from] commonware_stream::Error),

    /// Failed to encode message for transmission
    #[error("Failed to encode message")]
    Encode(#[from] commonware_codec::Error),

    /// Failed to decode received message
    #[error("Failed to decode message")]
    Decode(#[source] commonware_codec::Error),

    /// Received unexpected response type for a request
    #[error("Unexpected response type for request {request_id}")]
    UnexpectedResponse { request_id: u64 },

    /// Server returned an error response
    #[error("Server error (code: {code:?}): {message}")]
    ServerError {
        code: crate::ErrorCode,
        message: String,
    },

    /// Invalid request parameters
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Database operation failed
    #[error("Database operation failed")]
    Database(#[from] commonware_storage::adb::Error),

    /// Request channel to I/O task closed unexpectedly
    #[error("Request channel closed - I/O task may have terminated")]
    RequestChannelClosed,

    /// Response channel closed before receiving response
    #[error("Response channel closed for request {request_id}")]
    ResponseChannelClosed { request_id: u64 },

    /// Target update channel error
    #[error("Target update channel error: {reason}")]
    TargetUpdateChannel { reason: String },

    /// Configuration error
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Sync operation failed
    #[error("Sync failed")]
    Sync(#[from] SyncError),
}

impl Error {
    /// Convert this error to a protocol error code for transmission over the network.
    pub fn to_error_code(&self) -> crate::ErrorCode {
        match self {
            Error::InvalidRequest(_) => crate::ErrorCode::InvalidRequest,
            Error::Database(_) => crate::ErrorCode::DatabaseError,
            Error::RuntimeNetwork(_) | Error::Stream(_) | Error::ConnectionFailed { .. } => {
                crate::ErrorCode::NetworkError
            }
            Error::RequestChannelClosed | Error::ResponseChannelClosed { .. } => {
                crate::ErrorCode::InternalError
            }
            _ => crate::ErrorCode::InternalError,
        }
    }
}

// Convert our error type to sync error for trait compatibility
impl From<Error> for SyncError {
    fn from(err: Error) -> Self {
        SyncError::Resolver(Box::new(err))
    }
}
