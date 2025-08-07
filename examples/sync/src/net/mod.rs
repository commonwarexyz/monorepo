use std::mem::size_of;

use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Unique identifier for correlating requests with responses.
pub type RequestId = u64;

/// A requester that generates monotonically increasing request IDs.
#[derive(Debug, Clone)]
pub struct Requester {
    counter: Arc<AtomicU64>,
}

impl Default for Requester {
    fn default() -> Self {
        Self::new()
    }
}

impl Requester {
    pub fn new() -> Self {
        Requester {
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next(&self) -> RequestId {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
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

/// Error response shared by Any/Immutable protocols.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Unique identifier matching the original request.
    pub request_id: RequestId,
    /// Error code.
    pub error_code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
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

/// Trait that both Message enums (Any/Immutable) implement so shared networking can be reused.
pub trait WireMessage: Encode + Clone + Sized {
    fn request_id(&self) -> RequestId;
    fn decode_from(bytes: &[u8]) -> Result<Self, commonware_codec::Error>;
}

pub mod client;
