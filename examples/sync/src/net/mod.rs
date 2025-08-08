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
pub trait WireMessage: Encode + Clone + Sized + Send + Sync + 'static {
    fn request_id(&self) -> RequestId;
    fn decode_from(bytes: &[u8]) -> Result<Self, commonware_codec::Error>;
}

pub mod client;
pub mod wire;

use commonware_cryptography::Digest;
use commonware_storage::adb::sync::Target;
use std::num::NonZeroU64;

/// Network resolver that works directly with generic wire messages.
#[derive(Clone)]
pub struct Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Read<Cfg = ()> + Write + EncodeSize + Encode + Clone + Send + Sync + 'static,
    D: Digest,
{
    client: client::Client<E, wire::Message<Op, D>>,
}

impl<E, Op, D> Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Clone + Send + Sync + 'static + ReadExt<Cfg = ()> + Write + EncodeSize,
    D: Digest,
{
    pub fn new(context: E, server_addr: std::net::SocketAddr) -> Self {
        let client = client::Client::<E, wire::Message<Op, D>>::new(context, server_addr);
        Self { client }
    }

    pub async fn get_sync_target(&self) -> Result<Target<D>, crate::Error> {
        let request =
            wire::Message::GetSyncTargetRequest(wire::GetSyncTargetRequest { request_id: 0 });
        let response = self.client.send(request).await?;
        match response {
            wire::Message::GetSyncTargetResponse(r) => Ok(r.target),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            other => Err(crate::Error::UnexpectedResponse {
                request_id: other.request_id(),
            }),
        }
    }
}

impl<E, Op, D> commonware_storage::adb::sync::resolver::Resolver for Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Clone + Send + Sync + 'static + ReadExt<Cfg = ()> + Write + EncodeSize,
    D: Digest,
{
    type Digest = D;
    type Op = Op;
    type Error = crate::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<
        commonware_storage::adb::sync::resolver::FetchResult<Self::Op, Self::Digest>,
        Self::Error,
    > {
        let request = wire::Message::GetOperationsRequest(wire::GetOperationsRequest {
            request_id: 0,
            size,
            start_loc,
            max_ops,
        });
        let response = self.client.send(request).await?;
        let (proof, operations) = match response {
            wire::Message::GetOperationsResponse(r) => (r.proof, r.operations),
            wire::Message::Error(err) => {
                return Err(crate::Error::Server {
                    code: err.error_code,
                    message: err.message,
                })
            }
            other => {
                return Err(crate::Error::UnexpectedResponse {
                    request_id: other.request_id(),
                })
            }
        };
        let (tx, _rx) = futures::channel::oneshot::channel();
        Ok(commonware_storage::adb::sync::resolver::FetchResult {
            proof,
            operations,
            success_tx: tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::net::{wire::GetOperationsRequest, ErrorCode, Requester};
    use commonware_codec::{DecodeExt as _, Encode as _};
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
