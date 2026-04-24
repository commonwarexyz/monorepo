use crate::{
    net::{request_id::RequestId, Message, MAX_MESSAGE_SIZE},
    Error,
};
use commonware_macros::select_loop;
use commonware_runtime::{Handle, IoBufs, Sink, Spawner, Stream};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_utils::channel::{mpsc, oneshot};
use std::collections::HashMap;
use tracing::debug;

const REQUEST_BUFFER_SIZE: usize = 64;
const RECV_BUFFER_SIZE: usize = 64;

/// A request and callback for a response.
pub(super) struct Request<M: Message> {
    pub(super) request: M,
    pub(super) response_tx: oneshot::Sender<Result<M, Error>>,
}

/// Dedicated recv task: reads frames from the stream and forwards them on a
/// channel. Runs in its own task so that `recv_frame` is never cancelled by
/// `select!` (cancelling a partially-read frame corrupts the stream).
async fn recv_loop<St: Stream>(mut stream: St, tx: mpsc::Sender<IoBufs>) {
    loop {
        match recv_frame(&mut stream, MAX_MESSAGE_SIZE).await {
            Ok(data) => {
                if tx.send(data).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Run the I/O loop which:
/// - Receives requests from the request channel and sends them to the sink.
/// - Receives responses (via channel from the recv task) and forwards them to
///   their callback channel.
///
/// Both select branches (`request_rx.recv()` and `response_rx.recv()`) are
/// cancellation-safe, unlike `recv_frame`.
async fn run_loop<E, Si, St, M>(
    context: E,
    mut sink: Si,
    stream: St,
    mut request_rx: mpsc::Receiver<Request<M>>,
    mut pending_requests: HashMap<RequestId, oneshot::Sender<Result<M, Error>>>,
) where
    E: Spawner + Clone,
    Si: Sink,
    St: Stream,
    M: Message,
{
    let (response_tx, mut response_rx) = mpsc::channel(RECV_BUFFER_SIZE);

    // Spawn dedicated recv task so recv_frame is never cancelled.
    let recv_handle = context
        .clone()
        .spawn(move |_| recv_loop(stream, response_tx));

    select_loop! {
        context,
        on_stopped => {
            debug!("context shutdown, terminating I/O task");
            recv_handle.abort();
        },
        Some(Request {
            request,
            response_tx,
        }) = request_rx.recv() else {
            recv_handle.abort();
            return;
        } => {
            let request_id = request.request_id();
            pending_requests.insert(request_id, response_tx);
            let data = request.encode();
            if let Err(e) = send_frame(&mut sink, data, MAX_MESSAGE_SIZE).await {
                if let Some(sender) = pending_requests.remove(&request_id) {
                    let _ = sender.send(Err(Error::Network(e)));
                }
                recv_handle.abort();
                return;
            }
        },
        Some(response_data) = response_rx.recv() else {
            for (_, sender) in pending_requests.drain() {
                let _ = sender.send(Err(Error::RequestChannelClosed));
            }
            return;
        } => {
            match M::decode(response_data.coalesce()) {
                Ok(message) => {
                    let request_id = message.request_id();
                    if let Some(sender) = pending_requests.remove(&request_id) {
                        let _ = sender.send(Ok(message));
                    }
                }
                Err(_) => { /* ignore */ }
            }
        },
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
    let handle =
        context.spawn(move |context| run_loop(context, sink, stream, request_rx, HashMap::new()));
    Ok((request_tx, handle))
}
