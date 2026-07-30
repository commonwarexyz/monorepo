use crate::EmbeddedAssets;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const MAX_REQUEST_SIZE: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn serve(listener: TcpListener) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = serve_connection(stream).await;
        });
    }
}

async fn serve_connection(mut stream: TcpStream) -> io::Result<()> {
    let Some(path) = read_path(&mut stream).await? else {
        return write_response(&mut stream, "400 Bad Request", "text/plain", b"bad request").await;
    };
    let Some(asset) = EmbeddedAssets::get(&path) else {
        return write_response(&mut stream, "404 Not Found", "text/plain", b"not found").await;
    };

    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nCache-Control: {}\r\nConnection: close\r\n\r\n",
        asset.body.len(),
        asset.content_type,
        asset.cache_control,
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(asset.body).await
}

async fn read_path(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        if request.len() >= MAX_REQUEST_SIZE {
            return Ok(None);
        }
        let read = timeout(REQUEST_TIMEOUT, stream.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;
        if read == 0 {
            return Ok(None);
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let Some(first_line) = request.split(|byte| *byte == b'\n').next() else {
        return Ok(None);
    };
    let Ok(first_line) = std::str::from_utf8(first_line) else {
        return Ok(None);
    };
    let first_line = first_line.trim_end_matches('\r');
    let mut parts = first_line.split_whitespace();
    if parts.next() != Some("GET") {
        return Ok(None);
    }
    let Some(path) = parts.next() else {
        return Ok(None);
    };
    let Some(version) = parts.next() else {
        return Ok(None);
    };
    if !path.starts_with('/') || !version.starts_with("HTTP/") {
        return Ok(None);
    }
    Ok(Some(path.to_string()))
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await
}

pub(crate) fn public_url(host: std::net::IpAddr, address: SocketAddr, pair: &str) -> String {
    format!("http://{host}:{}/#pair={pair}", address.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn keeps_pairing_secret_out_of_http_request_target() {
        let url = public_url(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            SocketAddr::from(([0, 0, 0, 0], 39184)),
            "secret",
        );
        assert_eq!(url, "http://192.168.1.42:39184/#pair=secret");
    }
}
