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

/// A request and callback for a response.
pub struct Request<M: WireMessage> {
    pub message: M,
    pub response_tx: oneshot::Sender<Result<M, Error>>,
}

/// Sends requests and handles responses.
pub struct Requester<E, M>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
    M: WireMessage + Send + 'static,
{
    pub context: E,
    pub server_addr: SocketAddr,
    /// Source of messages to send.
    pub request_rx: mpsc::Receiver<Request<M>>,
    /// Map of request IDs to response senders.
    pub pending_requests: HashMap<RequestId, oneshot::Sender<Result<M, Error>>>,
}

impl<E, M> Requester<E, M>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
    M: WireMessage + Send + 'static,
{
    /// Start sending and receiving messages.
    pub async fn run(mut self) {
        let (mut sink, mut stream) = match self.context.dial(self.server_addr).await {
            Ok((sink, stream)) => (sink, stream),
            Err(_) => {
                for (_, response_tx) in self.pending_requests.drain() {
                    let _ = response_tx.send(Err(Error::RequestChannelClosed)); // TODO: Replace dummy error RequestChannelClosed with real error
                }
                return;
            }
        };

        loop {
            select! {
                outgoing = self.request_rx.next() => {
                    match outgoing {
                        Some(Request { message, response_tx }) => {
                            let request_id = message.request_id();
                            self.pending_requests.insert(request_id, response_tx);
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
    request_sender: mpsc::Sender<Request<M>>,
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
        let task = Requester::<E, M> {
            context: context.clone(),
            server_addr,
            request_rx: request_receiver,
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
            .send(Request {
                message,
                response_tx: tx,
            })
            .await
            .map_err(|_| Error::RequestChannelClosed)?;
        rx.await
            .map_err(|_| Error::ResponseChannelClosed { request_id: 0 })?
    }
}
