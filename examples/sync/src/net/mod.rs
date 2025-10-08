use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use std::mem::size_of;

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

pub mod request_id;
pub use request_id::RequestId;
pub mod io;
pub mod resolver;
pub mod wire;
pub use resolver::Resolver;

/// A message that can be sent over the wire.
pub(super) trait Message: Encode + DecodeExt<()> + Sized + Send + Sync + 'static {
    fn request_id(&self) -> RequestId;
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

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let discriminant = u8::read(buf)?;
        match discriminant {
            0 => Ok(ErrorCode::InvalidRequest),
            1 => Ok(ErrorCode::DatabaseError),
            2 => Ok(ErrorCode::NetworkError),
            3 => Ok(ErrorCode::Timeout),
            4 => Ok(ErrorCode::InternalError),
            _ => Err(Error::InvalidEnum(discriminant)),
        }
    }
}

/// Error from the server.
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

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let error_code = ErrorCode::read(buf)?;
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| Error::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
            request_id,
            error_code,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::net::{request_id::Generator, wire::GetOperationsRequest, ErrorCode};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_storage::mmr::Location;
    use commonware_utils::NZU64;

    #[test]
    fn test_error_code_roundtrip_serialization() {
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
        let requester = Generator::new();
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100).unwrap(),
            start_loc: Location::new(10).unwrap(),
            max_ops: NZU64!(50),
        };
        assert!(request.validate().is_ok());

        // Invalid start_loc
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100).unwrap(),
            start_loc: Location::new(100).unwrap(),
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));

        // start_loc beyond size
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100).unwrap(),
            start_loc: Location::new(150).unwrap(),
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));
    }
}
