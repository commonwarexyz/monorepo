use std::{collections::HashMap, net::SocketAddr};

use commonware_macros::select;
use commonware_stream::utils::codec::{recv_frame, send_frame};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};

use crate::net::{RequestId, WireMessage, MAX_MESSAGE_SIZE};
use crate::Error;

const REQUEST_BUFFER_SIZE: usize = 64;

/// Request data sent to the I/O task.
pub struct IoRequest<M: WireMessage> {
    pub message: M,
    pub response_sender: oneshot::Sender<Result<M, Error>>,
}

/// Generic I/O task for a wire message enum `M`.
pub struct IoTask<E, M>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
    M: WireMessage + Send + 'static,
{
    pub context: E,
    pub server_addr: SocketAddr,
    pub request_receiver: mpsc::Receiver<IoRequest<M>>,
    pub pending_requests: HashMap<RequestId, oneshot::Sender<Result<M, Error>>>,
}

impl<E, M> IoTask<E, M>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
    M: WireMessage + Send + 'static,
{
    pub async fn run(mut self) {
        let (mut sink, mut stream) = match self.context.dial(self.server_addr).await {
            Ok((sink, stream)) => (sink, stream),
            Err(_e) => {
                // Connection failed; notify waiters generically
                for (_, response_sender) in self.pending_requests.drain() {
                    let _ = response_sender.send(Err(Error::RequestChannelClosed));
                }
                return;
            }
        };

        loop {
            select! {
                outgoing = self.request_receiver.next() => {
                    match outgoing {
                        Some(IoRequest { message, response_sender }) => {
                            let request_id = message.request_id();
                            self.pending_requests.insert(request_id, response_sender);
                            let data = message.encode().to_vec();
                            if let Err(e) = send_frame(&mut sink, &data, MAX_MESSAGE_SIZE).await {
                                if let Some(sender) = self.pending_requests.remove(&request_id) {
                                    let _ = sender.send(Err(Error::Network(e)));
                                }
                                return;
                            }
                        },
                        None => return,
                    }
                },
                incoming = recv_frame(&mut stream, MAX_MESSAGE_SIZE) => {
                    match incoming {
                        Ok(response_data) => {
                            match M::decode_from(&response_data[..]) {
                                Ok(message) => {
                                    let request_id = message.request_id();
                                    if let Some(sender) = self.pending_requests.remove(&request_id) {
                                        let _ = sender.send(Ok(message));
                                    }
                                },
                                Err(_) => { /* ignore */ }
                            }
                        },
                        Err(_e) => {
                            for (_, sender) in self.pending_requests.drain() {
                                let _ = sender.send(Err(Error::RequestChannelClosed));
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Minimal generic network resolver facade over IoTask for a specific message type.
#[derive(Clone)]
pub struct Client<E, M>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    M: WireMessage,
{
    request_sender: mpsc::Sender<IoRequest<M>>,
    _phantom: std::marker::PhantomData<(E, M)>,
}

impl<E, M> Client<E, M>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    M: WireMessage + Send + 'static,
{
    pub fn new(context: E, server_addr: SocketAddr) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(REQUEST_BUFFER_SIZE);
        let task = IoTask::<E, M> {
            context: context.clone(),
            server_addr,
            request_receiver,
            pending_requests: HashMap::new(),
        };
        let _handle = context.spawn(move |_| async move {
            task.run().await;
        });
        Self {
            request_sender,
            _phantom: Default::default(),
        }
    }

    pub async fn send(&self, message: M) -> Result<M, Error> {
        let (tx, rx) = oneshot::channel();
        self.request_sender
            .clone()
            .send(IoRequest {
                message,
                response_sender: tx,
            })
            .await
            .map_err(|_| Error::RequestChannelClosed)?;
        rx.await
            .map_err(|_| Error::ResponseChannelClosed { request_id: 0 })?
    }
}
