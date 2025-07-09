//! Network-based resolver implementation for ADB sync.
//!
//! This module provides a network resolver that implements the ADB sync Resolver trait
//! for fetching operations from a remote server. It maintains a persistent connection,
//! handles message serialization, and verifies proofs.

use crate::{GetOperationsRequest, GetServerMetadataRequest, GetServerMetadataResponse, Message};
use commonware_codec::Read;
use commonware_runtime::{Sink, Stream};
use commonware_storage::adb::any::sync::{
    resolver::{GetOperationsResult, Resolver},
    Error as SyncError,
};
use commonware_storage::mmr::verification::Proof;
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{net::SocketAddr, num::NonZeroU64, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// Maximum response size to prevent memory exhaustion.
const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024; // 100MB

/// Connection state for persistent networking.
struct Connection<E>
where
    E: commonware_runtime::Network,
{
    sink: commonware_runtime::SinkOf<E>,
    stream: commonware_runtime::StreamOf<E>,
}

/// Network resolver that fetches operations from a remote server using persistent connections.
pub struct NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
{
    /// Server address.
    server_addr: SocketAddr,
    /// Persistent connection (wrapped in mutex for async access).
    connection: Arc<Mutex<Option<Connection<E>>>>,
    /// Runtime context for networking.
    context: E,
    /// Request ID counter.
    request_id_counter: std::sync::atomic::AtomicU64,
}

impl<E> NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
{
    /// Create a new network resolver.
    pub fn new(server_addr: SocketAddr, context: E) -> Self {
        Self {
            server_addr,
            connection: Arc::new(Mutex::new(None)),
            context,
            request_id_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get or create a persistent connection to the server.
    async fn get_connection(&self) -> Result<(), ResolverError> {
        let mut connection_guard = self.connection.lock().await;

        // Check if we already have a connection
        if connection_guard.is_some() {
            return Ok(());
        }

        // Create new connection
        info!(server_addr = %self.server_addr, "🔗 Establishing connection");
        let (sink, stream) = self
            .context
            .dial(self.server_addr)
            .await
            .map_err(|e| ResolverError::ConnectionError(format!("Failed to connect: {}", e)))?;

        *connection_guard = Some(Connection { sink, stream });
        info!(server_addr = %self.server_addr, "✅ Connected");

        Ok(())
    }

    /// Generate a unique request ID.
    fn generate_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Read a length-prefixed message from the stream.
    async fn read_message<S: Stream>(stream: &mut S) -> Result<Vec<u8>, ResolverError> {
        // Read the 4-byte length prefix
        let length_buf = vec![0u8; 4];
        let length_data = stream
            .recv(length_buf)
            .await
            .map_err(|e| ResolverError::ConnectionError(format!("Failed to read length: {}", e)))?;

        if length_data.len() != 4 {
            return Err(ResolverError::ConnectionError(
                "Invalid length prefix".to_string(),
            ));
        }

        // Convert bytes to u32 (network byte order)
        let message_length = u32::from_be_bytes([
            length_data.as_ref()[0],
            length_data.as_ref()[1],
            length_data.as_ref()[2],
            length_data.as_ref()[3],
        ]) as usize;

        // Validate message length
        if message_length == 0 || message_length > MAX_RESPONSE_SIZE {
            return Err(ResolverError::ConnectionError(format!(
                "Invalid message length: {}",
                message_length
            )));
        }

        // Read the actual message
        let message_buf = vec![0u8; message_length];
        let message_data = stream.recv(message_buf).await.map_err(|e| {
            ResolverError::ConnectionError(format!("Failed to read message: {}", e))
        })?;

        if message_data.len() != message_length {
            return Err(ResolverError::ConnectionError(
                "Message length mismatch".to_string(),
            ));
        }

        Ok(message_data.as_ref().to_vec())
    }

    /// Send a length-prefixed message to the sink.
    async fn send_message<S: Sink>(sink: &mut S, message: &[u8]) -> Result<(), ResolverError> {
        // Send 4-byte length prefix
        let length = message.len() as u32;
        let length_bytes = length.to_be_bytes();
        sink.send(length_bytes.to_vec())
            .await
            .map_err(|e| ResolverError::ConnectionError(format!("Failed to send length: {}", e)))?;

        // Send the actual message
        sink.send(message.to_vec()).await.map_err(|e| {
            ResolverError::ConnectionError(format!("Failed to send message: {}", e))
        })?;

        Ok(())
    }

    /// Send a request and receive a response using the persistent connection.
    async fn send_request(&self, request: Message) -> Result<Message, ResolverError> {
        // Ensure we have a connection
        self.get_connection().await?;

        let mut connection_guard = self.connection.lock().await;
        let connection = connection_guard
            .as_mut()
            .ok_or_else(|| ResolverError::ConnectionError("No connection available".to_string()))?;

        // Serialize and send the request
        let request_data = serde_json::to_vec(&request)
            .map_err(|e| ResolverError::SerializationError(e.to_string()))?;

        Self::send_message(&mut connection.sink, &request_data).await?;

        // Read the response
        let response_data = Self::read_message(&mut connection.stream).await?;

        // Deserialize the response
        let response = serde_json::from_slice(&response_data)
            .map_err(|e| ResolverError::DeserializationError(e.to_string()))?;

        Ok(response)
    }

    /// Get server metadata.
    pub async fn get_server_metadata(&self) -> Result<GetServerMetadataResponse, ResolverError> {
        let request_id = self.generate_request_id();
        let request = GetServerMetadataRequest::new(request_id);

        debug!(request_id, "📡 Sending metadata request");

        match self
            .send_request(Message::GetServerMetadataRequest(request))
            .await?
        {
            Message::GetServerMetadataResponse(response) => {
                info!("✅ Received server metadata");
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
            start_loc, "📦 Requesting operations from server"
        );

        let response = self
            .send_request(Message::GetOperationsRequest(request))
            .await?;

        let response = match response {
            Message::GetOperationsResponse(response) => response,
            Message::Error(err) => {
                error!(error = %err.message, "❌ Server error");
                return Err(SyncError::Adb(
                    commonware_storage::adb::Error::JournalError(
                        commonware_storage::journal::Error::Runtime(
                            commonware_runtime::Error::ConnectionFailed,
                        ),
                    ),
                ));
            }
            _ => {
                error!("❌ Unexpected response type");
                return Err(SyncError::Adb(
                    commonware_storage::adb::Error::JournalError(
                        commonware_storage::journal::Error::Runtime(
                            commonware_runtime::Error::ConnectionFailed,
                        ),
                    ),
                ));
            }
        };

        // Deserialize the proof using read_cfg
        let proof = {
            let mut buf = &response.proof_bytes[..];
            let max_digests = 10000; // Allow up to 10,000 digests
            Proof::read_cfg(&mut buf, &max_digests).map_err(|e| {
                SyncError::Adb(commonware_storage::adb::Error::JournalError(
                    commonware_storage::journal::Error::Codec(e),
                ))
            })?
        };

        // Deserialize the operations using read_cfg
        let operations = {
            let mut buf = &response.operations_bytes[..];
            use commonware_codec::RangeCfg;
            let range_cfg = RangeCfg::from(0..=10000); // Allow up to 10,000 operations
            Vec::<commonware_storage::adb::operation::Operation<K, V>>::read_cfg(
                &mut buf,
                &(range_cfg, ()),
            )
            .map_err(|e| {
                SyncError::Adb(commonware_storage::adb::Error::JournalError(
                    commonware_storage::journal::Error::Codec(e),
                ))
            })?
        };

        info!(
            operations_len = operations.len(),
            "✅ Received operations with proof"
        );

        // Create a oneshot channel for proof verification feedback
        let (success_tx, _success_rx) = oneshot::channel();

        Ok(GetOperationsResult {
            proof,
            operations,
            success_tx,
        })
    }
}

impl<E> Clone for NetworkResolver<E>
where
    E: commonware_runtime::Network + Clone,
{
    fn clone(&self) -> Self {
        Self {
            server_addr: self.server_addr,
            connection: self.connection.clone(),
            context: self.context.clone(),
            request_id_counter: std::sync::atomic::AtomicU64::new(0),
        }
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
    fn from(_err: ResolverError) -> Self {
        SyncError::Adb(commonware_storage::adb::Error::JournalError(
            commonware_storage::journal::Error::Runtime(
                commonware_runtime::Error::ConnectionFailed,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_error_display() {
        let err = ResolverError::ConnectionError("test error".to_string());
        assert_eq!(err.to_string(), "Connection error: test error");
    }
}
