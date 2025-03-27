use crate::{Error, Listener, Metrics, Network, Sink, Spawner, Stream};
use std::net::SocketAddr;

// Define static HTTP response strings
const NOT_FOUND_RESPONSE: &str =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_REQUEST_RESPONSE: &str =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Reads a single line from the stream, handling CRLF line endings.
/// Returns the line as a `String` or an `Error` if reading fails.
async fn read_line<St: Stream>(stream: &mut St) -> Result<String, Error> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0];
        stream.recv(&mut byte).await?;
        if byte[0] == b'\n' && line.last() == Some(&b'\r') {
            line.pop(); // Remove trailing \r
            break;
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&line).to_string())
}

/// Reads the request line from the stream and consumes the headers.
/// Returns `Ok(Some(line))` if a valid request line is found, `Ok(None)` if the first line is empty (malformed request),
/// or `Err` if there's a read error.
async fn read_request_line<St: Stream>(stream: &mut St) -> Result<Option<String>, Error> {
    let first_line = read_line(stream).await?;
    if first_line.is_empty() {
        return Ok(None); // No request line, malformed request
    }
    // Consume headers until an empty line is found
    loop {
        let line = read_line(stream).await?;
        if line.is_empty() {
            break;
        }
    }
    Ok(Some(first_line))
}

/// Handles a single connection, processing the request and sending the appropriate response.
async fn handle_connection<T, Si, St>(context: T, mut sink: Si, mut stream: St)
where
    T: Metrics,
    Si: Sink,
    St: Stream,
{
    let response = match read_request_line(&mut stream).await {
        // Valid request line that starts with "GET /metrics "
        Ok(Some(line)) if line.starts_with("GET /metrics ") => {
            let body = context.encode(); // Get metrics data
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
        }
        // Valid request line, but not a metrics request
        Ok(Some(_)) => NOT_FOUND_RESPONSE.to_string(),
        // No request line (malformed request)
        Ok(None) => BAD_REQUEST_RESPONSE.to_string(),
        // Read error, drop the connection
        Err(_) => return,
    };
    // Send the response, ignoring any send errors
    sink.send(response.as_bytes()).await.ok();
}

/// Serve metrics over HTTP on the given address.
pub async fn serve<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    C: Metrics + Network<L, Si, St> + Spawner,
>(
    context: C,
    addr: SocketAddr,
) {
    let mut listener = context
        .bind(addr)
        .await
        .expect("Could not bind to metrics address");
    while let Ok((_, sink, stream)) = listener.accept().await {
        context
            .with_label("connection")
            .spawn(move |context| async move {
                handle_connection(context, sink, stream).await;
            });
    }
}
