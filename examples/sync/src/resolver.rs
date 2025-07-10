//! Provides a [Resolver] implementation that communicates with a remote server
//! to fetch operations and proofs.

use crate::{
    GetOperationsRequest, GetServerMetadataRequest, GetServerMetadataResponse, Message,
    MAX_MESSAGE_SIZE,
};
use commonware_codec::{DecodeExt, Encode, Read};
use commonware_runtime::RwLock;
use commonware_storage::{
    adb::any::sync::{
        resolver::{GetOperationsResult, Resolver},
        Error as SyncError,
    },
    mmr::verification::Proof,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{
    net::SocketAddr,
    num::NonZeroU64,
    sync::{atomic::AtomicU64, Arc},
};
use thiserror::Error;
use tracing::{error, info};

const MAX_DIGESTS: usize = 10_000;

/// Connection state for persistent networking.
struct Connection<E>
where
    E: commonware_runtime::Network,
{
    sink: commonware_runtime::SinkOf<E>,
    stream: commonware_runtime::StreamOf<E>,
}

/// Network resolver that fetches operations from a remote server.
pub struct NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
{
    /// Runtime context for networking.
    context: E,
    /// Server address.
    server_addr: SocketAddr,
    /// Persistent connection (wrapped in mutex for async access).
    connection: Arc<RwLock<Option<Connection<E>>>>,
    /// Request ID counter.
    request_id_counter: AtomicU64,
}

impl<E> NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
{
    /// Returns a new [NetworkResolver] that communicates with the server at `server_addr`.
    pub fn new(server_addr: SocketAddr, context: E) -> Self {
        Self {
            server_addr,
            connection: Arc::new(RwLock::new(None)),
            context,
            request_id_counter: AtomicU64::new(0),
        }
    }

    /// Connect to the server if not already connected.
    async fn get_connection(&self) -> Result<(), ResolverError> {
        let mut connection_guard = self.connection.write().await;

        // Check if we already have a connection
        if connection_guard.is_some() {
            return Ok(());
        }

        // Create new connection
        info!(server_addr = %self.server_addr, "Establishing connection");
        let (sink, stream) = self
            .context
            .dial(self.server_addr)
            .await
            .map_err(|e| ResolverError::ConnectionError(format!("Failed to connect: {e}")))?;

        *connection_guard = Some(Connection { sink, stream });
        info!(server_addr = %self.server_addr, "Connected");

        Ok(())
    }

    /// Generate a unique request ID.
    fn generate_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Send a request and receive a response using the persistent connection.
    async fn send_request(&self, request: Message) -> Result<Message, ResolverError> {
        // Ensure we have a connection
        self.get_connection().await?;

        let mut connection_guard = self.connection.write().await;
        let connection = connection_guard
            .as_mut()
            .ok_or_else(|| ResolverError::ConnectionError("No connection available".to_string()))?;

        // Serialize and send the request
        let request_data = request.encode().to_vec();

        send_frame(&mut connection.sink, &request_data, MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| ResolverError::ConnectionError(e.to_string()))?;

        // Read the response
        let response_data = recv_frame(&mut connection.stream, MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| ResolverError::ConnectionError(e.to_string()))?;

        // Deserialize the response
        let response = Message::decode(&response_data[..])
            .map_err(|e| ResolverError::DeserializationError(e.to_string()))?;

        Ok(response)
    }

    /// Get server metadata (target hash and bounds)
    pub async fn get_server_metadata(&self) -> Result<GetServerMetadataResponse, ResolverError> {
        let request_id = self.generate_request_id();
        let request = GetServerMetadataRequest::new(request_id);

        match self
            .send_request(Message::GetServerMetadataRequest(request))
            .await?
        {
            Message::GetServerMetadataResponse(response) => {
                info!("Received server metadata");
                Ok(response)
            }
            Message::Error(err) => {
                error!(error = %err.message, "❌ Server error");
                Err(ResolverError::ServerError(err.message))
            }
            _ => {
                error!("❌ Unexpected response type");
                Err(ResolverError::UnexpectedResponse)
            }
        }
    }
}

impl<E, H, K, V> Resolver<H, K, V> for NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
    H: commonware_cryptography::Hasher,
    K: Array,
    V: Array,
{
    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<H, K, V>, SyncError> {
        let request_id = self.generate_request_id();
        let request = GetOperationsRequest::new(size, start_loc, max_ops, request_id);

        info!(
            max_ops = max_ops.get(),
            start_loc, "Requesting operations from server"
        );

        let response = self
            .send_request(Message::GetOperationsRequest(request))
            .await?;

        let response = match response {
            Message::GetOperationsResponse(response) => response,
            Message::Error(err) => {
                error!(error = %err.message, "❌ Server error");
                return Err(SyncError::Resolver(Box::new(err)));
            }
            _ => {
                error!("❌ Unexpected response type");
                return Err(SyncError::Resolver(Box::new("Unexpected response type")));
            }
        };

        // Deserialize the proof
        let proof = {
            let mut buf = &response.proof_bytes[..];
            Proof::read_cfg(&mut buf, &MAX_DIGESTS).map_err(|e| SyncError::Resolver(Box::new(e)))?
        };

        // Deserialize the operations
        let operations = {
            let mut buf = &response.operations_bytes[..];
            use commonware_codec::RangeCfg;
            let range_cfg = RangeCfg::from(0..=MAX_DIGESTS);
            Vec::<commonware_storage::adb::operation::Operation<K, V>>::read_cfg(
                &mut buf,
                &(range_cfg, ()),
            )
            .map_err(|e| SyncError::Resolver(Box::new(e)))?
        };

        info!(
            operations_len = operations.len(),
            proof_len = proof.digests.len(),
            "Received operations and proof"
        );

        // Create a oneshot channel for proof verification feedback.
        // We don't use the feedback, but this is required by the Resolver trait.
        let (success_tx, _success_rx) = oneshot::channel();
        Ok(GetOperationsResult {
            proof,
            operations,
            success_tx,
        })
    }
}

/// Errors that can occur during network resolution.
#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Unexpected response")]
    UnexpectedResponse,
}

impl From<ResolverError> for SyncError {
    fn from(err: ResolverError) -> Self {
        SyncError::Resolver(Box::new(err))
    }
}
