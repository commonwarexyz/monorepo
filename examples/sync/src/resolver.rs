//! Provides a [Resolver] implementation that communicates with a remote server
//! to fetch operations and proofs.

use crate::{
    error::Error, GetOperationsRequest, GetSyncTargetRequest, Message, RequestId, MAX_MESSAGE_SIZE,
};
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
use tracing::{debug, error, info, warn};

const REQUEST_BUFFER_SIZE: usize = 64;

/// Request data sent to the I/O task.
struct IoRequest {
    message: Message,
    response_sender: oneshot::Sender<Result<Message, Error>>,
}

/// I/O task that manages connection and request/response correlation.
struct IoTask<E>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
{
    context: E,
    server_addr: SocketAddr,
    request_receiver: mpsc::Receiver<IoRequest>,
    pending_requests: HashMap<RequestId, oneshot::Sender<Result<Message, Error>>>,
}

impl<E> IoTask<E>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
{
    async fn run(mut self) {
        info!(server_addr = %self.server_addr, "I/O task starting");

        // Establish connection once - if this fails, we're done
        let (mut sink, mut stream) = match self.context.dial(self.server_addr).await {
            Ok((sink, stream)) => {
                info!(server_addr = %self.server_addr, "connection established");
                (sink, stream)
            }
            Err(e) => {
                error!(error = %e, "failed to establish connection, exiting");
                // Notify all pending requests that the connection failed
                for (_, response_sender) in self.pending_requests {
                    let _ = response_sender.send(Err(Error::RequestChannelClosed));
                }
                return;
            }
        };

        loop {
            select! {
                // Wait for request to send
                outgoing = self.request_receiver.next() => {
                    match outgoing {
                        Some(IoRequest { message, response_sender }) => {
                            let request_id = message.request_id();
                            // Store pending request for correlation
                            self.pending_requests.insert(request_id, response_sender);

                            let data = message.encode().to_vec();
                            if let Err(e) = send_frame(&mut sink, &data, MAX_MESSAGE_SIZE).await {
                                error!(error = %e, "failed to send request, exiting");
                                // Notify the pending request of the error
                                if let Some(response_sender) = self.pending_requests.remove(&request_id) {
                                    let _ = response_sender.send(Err(Error::Stream(e)));
                                }
                                return;
                            } else {
                                debug!(request_id = request_id.value(), "request sent, awaiting response");
                            }
                        },
                        None => {
                            info!("request channel closed, exiting");
                            return;
                        }
                    }
                },

                // Wait for response
                incoming = recv_frame(&mut stream, MAX_MESSAGE_SIZE) => {
                    match incoming {
                        Ok(response_data) => {
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
                                    warn!(error = %e, "failed to decode response");
                                    // Can't correlate with a specific request without decoding
                                }
                            }
                        },
                        Err(e) => {
                            error!(error = %e, "connection error, exiting");
                            // Notify all pending requests that the I/O task is shutting down
                            for (_request_id, response_sender) in self.pending_requests.drain() {
                                let _ = response_sender.send(Err(Error::RequestChannelClosed));
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
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

impl<E> Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    pub fn new(context: E, server_addr: SocketAddr) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(REQUEST_BUFFER_SIZE);

        let io_task = IoTask {
            server_addr,
            request_receiver,
            pending_requests: HashMap::new(),
            context: context.clone(),
        };

        let _handle = context.spawn(move |_| async move {
            io_task.run().await;
        });

        Self {
            request_sender,
            _phantom: PhantomData,
        }
    }

    pub async fn get_sync_target(&self) -> Result<SyncTarget<Digest>, Error> {
        let request = GetSyncTargetRequest {
            request_id: RequestId::new(),
        };

        let request_id = request.request_id.value();

        let response = self
            .send_request(Message::GetSyncTargetRequest(request))
            .await?;

        match response {
            Message::GetSyncTargetResponse(response) => Ok(response.target),
            Message::Error(err) => {
                error!(error = %err.message, "server error");
                Err(Error::ServerError {
                    code: err.error_code,
                    message: err.message,
                })
            }
            _ => {
                error!("unexpected response type");
                Err(Error::UnexpectedResponse { request_id })
            }
        }
    }

    async fn send_request(&self, message: Message) -> Result<Message, Error> {
        let (response_sender, response_receiver) = oneshot::channel();

        let request_id = message.request_id();
        let request = IoRequest {
            message,
            response_sender,
        };

        self.request_sender
            .clone()
            .send(request)
            .await
            .map_err(|_| Error::RequestChannelClosed)?;

        response_receiver
            .await
            .map_err(|_| Error::ResponseChannelClosed {
                request_id: request_id.value(),
            })?
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

        let request_id = request.request_id.value();

        let response = self
            .send_request(Message::GetOperationsRequest(request))
            .await?;

        match response {
            Message::GetOperationsResponse(response) => {
                let (success_tx, _success_rx) = oneshot::channel();
                Ok(GetOperationsResult {
                    operations: response.operations,
                    proof: response.proof,
                    success_tx,
                })
            }
            Message::Error(err) => Err(SyncError::from(Error::ServerError {
                code: err.error_code,
                message: err.message,
            })),
            _ => Err(SyncError::from(Error::UnexpectedResponse { request_id })),
        }
    }
}
