//! Provides a [Resolver] implementation that communicates with a remote server
//! to fetch operations and proofs.

use crate::{GetOperationsRequest, GetSyncTargetRequest, Message, RequestId, MAX_MESSAGE_SIZE};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::sha256::Digest;
use commonware_macros::select;
use commonware_storage::adb::any::sync::{
    resolver::{GetOperationsResult, Resolver as ResolverTrait},
    Error as SyncError, SyncTarget,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, num::NonZeroU64};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Connection state for persistent networking.
struct Connection<E>
where
    E: commonware_runtime::Network,
{
    sink: commonware_runtime::SinkOf<E>,
    stream: commonware_runtime::StreamOf<E>,
}

/// Network resolver that fetches operations from a remote server.
#[derive(Clone)]
pub struct Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    request_sender: mpsc::Sender<IoRequest>,
    _phantom: PhantomData<E>,
}

/// Request data sent to the I/O task.
struct IoRequest {
    request_id: RequestId,
    message: Message,
    response_sender: oneshot::Sender<Result<Message, ResolverError>>,
}

/// I/O task that manages connection and request/response correlation.
struct IoTask<E>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
{
    server_addr: SocketAddr,
    request_receiver: mpsc::Receiver<IoRequest>,
    connection: Option<Connection<E>>,
    pending_requests: HashMap<RequestId, oneshot::Sender<Result<Message, ResolverError>>>,
    context: E,
}

impl<E> IoTask<E>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
{
    async fn run(mut self) {
        info!(server_addr = %self.server_addr, "I/O task starting");

        loop {
            // Ensure we have a valid connection before proceeding
            if self.connection.is_none() {
                if let Err(e) = self.establish_connection().await {
                    error!(error = %e, "failed to establish connection, retrying in 1s...");
                    // Add a small delay before retrying to avoid tight loop on persistent failures
                    self.context.sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }

            // Take ownership of connection to avoid borrow conflicts
            let mut connection = self.connection.take().unwrap();
            let mut keep_connection = true;

            select! {
                // Wait for request to send
                request_opt = self.request_receiver.next() => {
                    match request_opt {
                        Some(IoRequest { request_id, message, response_sender }) => {
                            // Store pending request for correlation
                            self.pending_requests.insert(request_id, response_sender);

                            // Send request directly (non-blocking to caller)
                            let data = message.encode().to_vec();
                            if let Err(e) = send_frame(&mut connection.sink, &data, MAX_MESSAGE_SIZE).await {
                                error!(error = %e, "failed to send request");
                                // Remove from pending and notify sender
                                if let Some(sender) = self.pending_requests.remove(&request_id) {
                                    let _ = sender.send(Err(ResolverError::ConnectionError(e.to_string())));
                                }
                                keep_connection = false;
                            } else {
                                debug!(request_id = request_id.value(), "request sent, awaiting response");
                            }
                        },
                        None => break, // Channel closed, exit task
                    }
                },

                // Wait for response
                response_result = recv_frame(&mut connection.stream, MAX_MESSAGE_SIZE) => {
                    match response_result {
                        Ok(response_data) => {
                            // Give response to waiting receiver oneshot
                            match Message::decode(&response_data[..]) {
                                Ok(message) => {
                                    let request_id = message.request_id();
                                    if let Some(response_sender) = self.pending_requests.remove(&request_id) {
                                        debug!(request_id = request_id.value(), "correlating response with request");
                                        let _ = response_sender.send(Ok(message));
                                    } else {
                                        warn!(request_id = request_id.value(), "received response for unknown request ID");
                                    }
                                },
                                Err(e) => {
                                    error!(error = %e, "failed to decode response");
                                    keep_connection = false;
                                }
                            }
                        },
                        Err(e) => {
                            error!(error = %e, "connection error, will reconnect");
                            keep_connection = false;
                        }
                    }
                }
            }

            // Restore connection if it's still good
            if keep_connection {
                self.connection = Some(connection);
            }
        }

        info!("I/O task shutting down");
        self.fail_all_pending_requests(ResolverError::ConnectionError(
            "I/O task shutting down".to_string(),
        ));
    }

    async fn establish_connection(&mut self) -> Result<(), ResolverError> {
        info!(server_addr = %self.server_addr, "establishing connection");

        let (sink, stream) = self
            .context
            .dial(self.server_addr)
            .await
            .map_err(|e| ResolverError::ConnectionError(e.to_string()))?;

        self.connection = Some(Connection { sink, stream });
        info!(server_addr = %self.server_addr, "connection established");
        Ok(())
    }

    fn fail_all_pending_requests(&mut self, error: ResolverError) {
        for (request_id, response_sender) in self.pending_requests.drain() {
            debug!(request_id = request_id.value(), "failing pending request");
            let _ = response_sender.send(Err(error.clone()));
        }
    }
}

impl<E> Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    pub fn new(context: E, server_addr: SocketAddr) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(64);

        let context_for_io_task = context.clone();

        let io_task = IoTask {
            server_addr,
            request_receiver,
            connection: None,
            pending_requests: HashMap::new(),
            context: context_for_io_task,
        };

        let _handle = context.spawn(move |_| async move {
            io_task.run().await;
        });

        Self {
            request_sender,
            _phantom: PhantomData,
        }
    }

    pub async fn get_sync_target(&self) -> Result<SyncTarget<Digest>, ResolverError> {
        let request = GetSyncTargetRequest {
            request_id: RequestId::new(),
        };

        let response = self
            .send_request(Message::GetSyncTargetRequest(request))
            .await?;

        match response {
            Message::GetSyncTargetResponse(response) => Ok(response.target),
            Message::Error(err) => {
                error!(error = %err.message, "server error");
                Err(ResolverError::ServerError(err.message))
            }
            _ => {
                error!("unexpected response type");
                Err(ResolverError::UnexpectedResponse)
            }
        }
    }

    async fn send_request(&self, message: Message) -> Result<Message, ResolverError> {
        // Extract the request_id from the message itself - don't create a new one!
        let request_id = message.request_id();
        let (response_sender, response_receiver) = oneshot::channel();

        let request = IoRequest {
            request_id,
            message,
            response_sender,
        };

        self.request_sender
            .clone()
            .send(request)
            .await
            .map_err(|_| ResolverError::ConnectionError("I/O task unavailable".to_string()))?;

        response_receiver
            .await
            .map_err(|_| ResolverError::ConnectionError("I/O task dropped response".to_string()))?
    }
}

impl<E> ResolverTrait for Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    type Digest = Digest;
    type Key = crate::Key;
    type Value = crate::Value;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, SyncError> {
        let request = GetOperationsRequest {
            request_id: RequestId::new(),
            size,
            start_loc,
            max_ops,
        };

        let response = self
            .send_request(Message::GetOperationsRequest(request))
            .await
            .map_err(|e| SyncError::Resolver(Box::new(e)))?;

        match response {
            Message::GetOperationsResponse(response) => {
                let (success_tx, _success_rx) = oneshot::channel();
                Ok(GetOperationsResult {
                    operations: response.operations,
                    proof: response.proof,
                    success_tx,
                })
            }
            Message::Error(err) => Err(SyncError::Resolver(Box::new(ResolverError::ServerError(
                err.message,
            )))),
            _ => Err(SyncError::Resolver(Box::new(
                ResolverError::UnexpectedResponse,
            ))),
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum ResolverError {
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("server error: {0}")]
    ServerError(String),
    #[error("unexpected response")]
    UnexpectedResponse,
}
