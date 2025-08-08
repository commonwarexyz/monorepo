use std::{collections::HashMap, net::SocketAddr};

use crate::net::{request_id::RequestId, WireMessage, MAX_MESSAGE_SIZE};
use crate::Error;
use commonware_macros::select;
use commonware_stream::utils::codec::{recv_frame, send_frame};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};

const REQUEST_BUFFER_SIZE: usize = 64;

/// A request and callback for a response.
pub struct Request<M: WireMessage> {
    pub request: M,
    pub response_tx: oneshot::Sender<Result<M, Error>>,
}

/// Generic I/O task for a wire message enum `M`.
pub struct IoTask<E, M>
where
    E: commonware_runtime::Network + commonware_runtime::Spawner + commonware_runtime::Clock,
    M: WireMessage + Send + 'static,
{
    pub context: E,
    pub server_addr: SocketAddr,
    // Source of requests to send.
    pub request_rx: mpsc::Receiver<Request<M>>,
    // Map of request IDs to response senders.
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
                for (_, response_tx) in self.pending_requests.drain() {
                    let _ = response_tx.send(Err(Error::RequestChannelClosed));
                    // TODO: Replace dummy error RequestChannelClosed with real error
                }
                return;
            }
        };

        loop {
            select! {
                outgoing = self.request_rx.next() => {
                    match outgoing {
                        Some(Request { request, response_tx }) => {
                            let request_id = request.request_id();
                            self.pending_requests.insert(request_id, response_tx);
                            let data = request.encode().to_vec();
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
                                let _ = sender.send(Err(Error::RequestChannelClosed)); // TODO: Replace dummy error RequestChannelClosed with real error
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Starts the I/O task and returns a sender for requests and a handle to the task.
/// The I/O task is responsible for sending and receiving messages over the network.
/// The I/O task uses a oneshot channel to send responses back to the caller.
pub fn start_io<E, M>(
    context: E,
    server_addr: SocketAddr,
) -> (mpsc::Sender<Request<M>>, commonware_runtime::Handle<()>)
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    M: WireMessage + Send + 'static,
{
    let (request_tx, request_rx) = mpsc::channel(REQUEST_BUFFER_SIZE);
    let task = IoTask::<E, M> {
        context: context.clone(),
        server_addr,
        request_rx,
        pending_requests: HashMap::new(),
    };
    let handle = context.spawn(move |_| task.run());
    (request_tx, handle)
}
