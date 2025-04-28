//! Utilities to serve metrics over HTTP.

use crate::{Error, Listener, Metrics, Network, Sink, Spawner, Stream};
use httparse::{Request, Status};
use std::net::SocketAddr;
use tracing::{debug, error};

const MAX_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = MAX_HEADERS * 1024;

/// Read and discard the HTTP request.
///
/// If we reply before we have consumed everything the client already
/// placed on the wire, then close our half of the socket, the kernel will send
/// an abortive close (RST) instead of the graceful FIN.
///
/// Prometheus interprets the resulting `ECONNRESET` as “connection reset by
/// peer”. Draining up to the header terminator `CRLF CRLF` ensures the socket
/// is quiescent before we write.
async fn discard_request<St: Stream>(stream: &mut St) -> Result<(), Error> {
    let mut buf = Vec::<u8>::with_capacity(MAX_HEADER_BYTES);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = Request::new(&mut headers);
        match request.parse(&buf) {
            Ok(Status::Complete(header_length)) => {
                // Once we have a complete header, we can check for the
                // Content-Length header to determine how much more data we need
                // to read.
                let content_length = request
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| core::str::from_utf8(h.value).ok())
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);

                // Drain the rest of the request.
                let needed = header_length + content_length;
                if buf.len() < needed {
                    let mut extra = vec![0u8; needed - buf.len()];
                    stream.recv(&mut extra).await?;
                }
                return Ok(());
            }
            Ok(Status::Partial) => {
                // If we have a partial header, we need to read more data.
                let mut byte = [0u8; 1];
                stream.recv(&mut byte).await?;
                buf.push(byte[0]);
            }
            Err(_) => return Err(Error::ReadFailed),
        }
    }
}

/// Maintains a single connection by sending back metrics whenever a request is received.
/// Ignores any data sent by the client.
async fn serve_connection<C, Si, St>(context: &C, mut sink: Si, mut stream: St)
where
    C: Metrics,
    Si: Sink,
    St: Stream,
{
    loop {
        // Read and discard the request
        if let Err(e) = discard_request(&mut stream).await {
            error!(error = ?e, "Failed to read request headers");
            return;
        }

        // Encode metrics from the provided context
        let body = context.encode();
        let response = format!(
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/plain; version=0.0.4\r\n",
                "Content-Length: {}\r\n\r\n",
                "{}"
            ),
            body.len(),
            body
        );

        // Send the response
        if let Err(e) = sink.send(response.as_bytes()).await {
            error!(error = ?e, "Failed to send metrics response");
            return;
        }
    }
}

/// Serve metrics over HTTP (on all methods and paths) for the given address.
pub async fn serve<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    C: Metrics + Spawner + Network<L, Si, St>,
>(
    context: C,
    address: SocketAddr,
) {
    let mut listener = context
        .bind(address)
        .await
        .expect("Could not bind to metrics address");
    while let Ok((peer, sink, stream)) = listener.accept().await {
        debug!(?peer, "serving metrics");
        context
            .with_label("connection")
            .spawn(move |context| async move {
                serve_connection(&context, sink, stream).await;
            });
    }
}
