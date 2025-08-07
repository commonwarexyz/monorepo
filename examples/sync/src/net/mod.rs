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

use commonware_cryptography::Digest as CryptoDigest;
use commonware_storage::adb::sync::Target;
use commonware_storage::mmr::verification::Proof;
use std::num::NonZeroU64;

/// Protocol adapter that abstracts over Any/Immutable wire message enums so a single resolver can be used.
pub trait Protocol: Clone + Send + 'static {
    type Digest: CryptoDigest;
    type Op: Clone + Send + 'static;
    type Message: WireMessage + Clone + Send + Sync + 'static;

    fn make_get_target(request_id: RequestId) -> Self::Message;
    fn parse_get_target_response(msg: Self::Message) -> Result<Target<Self::Digest>, crate::Error>;

    fn make_get_ops(
        request_id: RequestId,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Self::Message;
    fn parse_get_ops_response(
        msg: Self::Message,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Op>), crate::Error>;
}

/// Generic network resolver that works with any protocol implementing [Protocol].
#[derive(Clone)]
pub struct GenericResolver<E, P>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    P: Protocol,
{
    client: client::NetworkClient<E, P::Message>,
}

impl<E, P> GenericResolver<E, P>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    P: Protocol,
{
    pub fn new(context: E, server_addr: std::net::SocketAddr) -> Self {
        let client = client::NetworkClient::<E, P::Message>::new(context, server_addr);
        Self { client }
    }

    pub async fn get_sync_target(&self) -> Result<Target<P::Digest>, crate::Error> {
        let request_id = 0u64;
        let request = P::make_get_target(request_id);
        let response = self.client.send(request).await?;
        P::parse_get_target_response(response)
    }
}

impl<E, P> commonware_storage::adb::sync::resolver::Resolver for GenericResolver<E, P>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    P: Protocol,
{
    type Digest = P::Digest;
    type Op = P::Op;
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
        let request_id = 0u64;
        let request = P::make_get_ops(request_id, size, start_loc, max_ops);
        let response = self.client.send(request).await?;
        let (proof, operations) = P::parse_get_ops_response(response)?;
        let (tx, _rx) = futures::channel::oneshot::channel();
        Ok(commonware_storage::adb::sync::resolver::FetchResult {
            proof,
            operations,
            success_tx: tx,
        })
    }
}
