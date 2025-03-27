//! Utilities to serve metrics over HTTP.

use crate::{Listener, Metrics, Network, Sink, Spawner, Stream};
use std::net::SocketAddr;
use tracing::{debug, error};

/// Handles a single connection by sending back the current metrics.
/// Ignores any data sent by the client.
async fn encode<C, Si>(context: &C, mut sink: Si)
where
    C: Metrics,
    Si: Sink,
{
    // Encode metrics from the provided context
    let body = context.encode();

    // Format a minimal HTTP 200 OK response
    // Uses standard Prometheus content type and advises client to close
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );

    // Send the response
    if let Err(e) = sink.send(response.as_bytes()).await {
        error!(error = ?e, "Failed to send metrics response");
    }
}

/// Serve metrics over HTTP (on all methods and paths) for the given address.
pub async fn serve<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    C: Metrics + Network<L, Si, St> + Spawner,
>(
    context: C,
    address: SocketAddr,
) {
    let mut listener = context
        .bind(address)
        .await
        .expect("Could not bind to metrics address");
    while let Ok((peer, sink, _)) = listener.accept().await {
        debug!(?peer, "serving metrics");
        encode(&context, sink).await;
    }
}
