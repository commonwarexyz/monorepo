use std::{collections::HashMap, net::SocketAddr};

use crate::net::{request_id::RequestId, WireMessage, MAX_MESSAGE_SIZE};
use crate::Error;
use commonware_macros::select;
use commonware_runtime::{Sink, Stream};
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

/// Run the I/O loop for a wire message enum `M`.
async fn run<Si, St, M>(
    mut sink: Si,
    mut stream: St,
    mut request_rx: mpsc::Receiver<Request<M>>,
    mut pending_requests: HashMap<RequestId, oneshot::Sender<Result<M, Error>>>,
) where
    Si: Sink,
    St: Stream,
    M: WireMessage + Send + 'static,
{
    loop {
        select! {
            outgoing = request_rx.next() => {
                match outgoing {
                    Some(Request { request, response_tx }) => {
                        let request_id = request.request_id();
                        pending_requests.insert(request_id, response_tx);
                        let data = request.encode().to_vec();
                        if let Err(e) = send_frame(&mut sink, &data, MAX_MESSAGE_SIZE).await {
                            if let Some(sender) = pending_requests.remove(&request_id) {
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
                                if let Some(sender) = pending_requests.remove(&request_id) {
                                    let _ = sender.send(Ok(message));
                                }
                            },
                            Err(_) => { /* ignore */ }
                        }
                    },
                    Err(_e) => {
                        for (_, sender) in pending_requests.drain() {
                            let _ = sender.send(Err(Error::RequestChannelClosed));
                        }
                        return;
                    }
                }
            }
        }
    }
}

/// Starts the I/O task and returns a sender for requests and a handle to the task.
/// The I/O task is responsible for sending and receiving messages over the network.
/// The I/O task uses a oneshot channel to send responses back to the caller.
pub async fn start_io<E, M>(
    context: E,
    server_addr: SocketAddr,
) -> Result<(mpsc::Sender<Request<M>>, commonware_runtime::Handle<()>), commonware_runtime::Error>
where
    E: commonware_runtime::Spawner + commonware_runtime::Network,
    M: WireMessage + Send + 'static,
{
    let (sink, stream) = context.dial(server_addr).await?;
    let (request_tx, request_rx) = mpsc::channel(REQUEST_BUFFER_SIZE);
    let handle = context.spawn(move |_| run(sink, stream, request_rx, HashMap::new()));
    Ok((request_tx, handle))
}
