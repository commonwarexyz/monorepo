use crate::{
    net::{request_id::RequestId, Message, MAX_MESSAGE_SIZE},
    Error,
};
use commonware_macros::select;
use commonware_runtime::{Handle, Sink, Spawner, Stream};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::collections::HashMap;

const REQUEST_BUFFER_SIZE: usize = 64;

/// A request and callback for a response.
pub(super) struct Request<M: Message> {
    pub(super) request: M,
    pub(super) response_tx: oneshot::Sender<Result<M, Error>>,
}

/// Run the I/O loop which:
/// - Receives requests from the request channel and sends them to the sink.
/// - Receives responses from the stream and forwards them to their callback channel.
async fn run_loop<Si, St, M>(
    mut sink: Si,
    mut stream: St,
    mut request_rx: mpsc::Receiver<Request<M>>,
    mut pending_requests: HashMap<RequestId, oneshot::Sender<Result<M, Error>>>,
) where
    Si: Sink,
    St: Stream,
    M: Message,
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
                        match M::decode(&response_data[..]) {
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
pub(super) fn run<E, Si, St, M>(
    context: E,
    sink: Si,
    stream: St,
) -> Result<(mpsc::Sender<Request<M>>, Handle<()>), commonware_runtime::Error>
where
    E: Spawner,
    Si: Sink,
    St: Stream,
    M: Message,
{
    let (request_tx, request_rx) = mpsc::channel(REQUEST_BUFFER_SIZE);
    let handle = context.spawn(move |_| run_loop(sink, stream, request_rx, HashMap::new()));
    Ok((request_tx, handle))
}
