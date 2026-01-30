use crate::{network::proxy::ProxyConfig, Error, IoBufMut, IoBufs};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tracing::warn;

/// Implementation of [crate::Sink] for the [tokio] runtime.
pub struct Sink {
    write_timeout: Duration,
    sink: OwnedWriteHalf,
}

impl crate::Sink for Sink {
    async fn send(&mut self, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        // Time out if we take too long to write
        timeout(self.write_timeout, self.sink.write_all_buf(&mut buf.into()))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::SendFailed)?;
        Ok(())
    }
}

/// Implementation of [crate::Stream] for the [tokio] runtime.
///
/// Uses a [`BufReader`] to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    read_timeout: Duration,
    stream: BufReader<OwnedReadHalf>,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, len: u64) -> Result<IoBufs, Error> {
        let len = len as usize;
        let read_fut = async {
            let mut buf = IoBufMut::zeroed(len);
            self.stream
                .read_exact(buf.as_mut())
                .await
                .map_err(|_| Error::RecvFailed)?;
            Ok(IoBufs::from(buf.freeze()))
        };

        // Time out if we take too long to read
        timeout(self.read_timeout, read_fut)
            .await
            .map_err(|_| Error::Timeout)?
    }

    fn peek(&self, max_len: u64) -> &[u8] {
        let max_len = max_len as usize;
        let buffered = self.stream.buffer();
        let len = std::cmp::min(buffered.len(), max_len);
        &buffered[..len]
    }
}

/// Implementation of [crate::Listener] using the [tokio] runtime.
pub struct Listener {
    cfg: Config,
    listener: TcpListener,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        // Accept a new TCP stream
        let (stream, tcp_addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Split the stream
        let (read_half, write_half) = stream.into_split();
        let mut buf_reader = BufReader::with_capacity(self.cfg.read_buffer_size, read_half);

        // Parse PROXY header if configured and connection is from trusted proxy
        let client_addr = if let Some(ref proxy_cfg) = self.cfg.proxy {
            if proxy_cfg.is_trusted(tcp_addr.ip()) {
                crate::network::proxy::parse(&mut buf_reader).await?
            } else {
                tcp_addr
            }
        } else {
            tcp_addr
        };

        Ok((
            client_addr,
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink: write_half,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: buf_reader,
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// Configuration for the tokio [Network] implementation of the [crate::Network] trait.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether or not to disable Nagle's algorithm.
    ///
    /// The algorithm combines a series of small network packets into a single packet
    /// before sending to reduce overhead of sending multiple small packets which might not
    /// be efficient on slow, congested networks. However, to do so the algorithm introduces
    /// a slight delay as it waits to accumulate more data. Latency-sensitive networks should
    /// consider disabling it to send the packets as soon as possible to reduce latency.
    ///
    /// Note: Make sure that your compile target has and allows this configuration otherwise
    /// panics or unexpected behaviours are possible.
    tcp_nodelay: Option<bool>,
    /// Read timeout for connections, after which the connection will be closed
    read_timeout: Duration,
    /// Write timeout for connections, after which the connection will be closed
    write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    read_buffer_size: usize,
    /// Optional PROXY protocol configuration.
    ///
    /// When set, connections from trusted proxy IPs will have PROXY headers
    /// parsed to obtain the real client address.
    proxy: Option<ProxyConfig>,
}

#[cfg_attr(feature = "iouring-network", allow(dead_code))]
impl Config {
    // Setters
    /// See [Config]
    pub const fn with_tcp_nodelay(mut self, tcp_nodelay: Option<bool>) -> Self {
        self.tcp_nodelay = tcp_nodelay;
        self
    }
    /// See [Config]
    pub const fn with_read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }
    /// See [Config]
    pub const fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }
    /// See [Config]
    pub const fn with_read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.read_buffer_size = read_buffer_size;
        self
    }
    /// Enable PROXY protocol support.
    /// Only connections from trusted proxies will have headers parsed.
    pub fn with_proxy(mut self, config: ProxyConfig) -> Self {
        self.proxy = Some(config);
        self
    }

    // Getters
    /// See [Config]
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.tcp_nodelay
    }
    /// See [Config]
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
    /// See [Config]
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
    /// See [Config]
    pub const fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }
    /// See [Config]
    pub const fn proxy(&self) -> Option<&ProxyConfig> {
        self.proxy.as_ref()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            read_buffer_size: 64 * 1024, // 64 KB
            proxy: None,
        }
    }
}

#[derive(Clone, Debug)]
/// [crate::Network] implementation that uses the [tokio] runtime.
pub struct Network {
    cfg: Config,
}

impl From<Config> for Network {
    fn from(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::from(Config::default())
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| Listener {
                cfg: self.cfg.clone(),
                listener,
            })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        // Create a new TCP stream
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let (stream, sink) = stream.into_split();
        Ok((
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: BufReader::with_capacity(self.cfg.read_buffer_size, stream),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        network::{proxy::ProxyConfig, tests, tokio as TokioNetwork},
        Listener as _, Network as _, Sink as _, Stream as _,
    };
    use commonware_macros::test_group;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            TokioNetwork::Network::from(
                TokioNetwork::Config::default()
                    .with_read_timeout(Duration::from_secs(15))
                    .with_write_timeout(Duration::from_secs(15)),
            )
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            TokioNetwork::Network::from(
                TokioNetwork::Config::default()
                    .with_read_timeout(Duration::from_secs(15))
                    .with_write_timeout(Duration::from_secs(15)),
            )
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        // Use a long read timeout to ensure we're not just waiting for timeout
        let read_timeout = Duration::from_secs(30);
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(read_timeout)
                .with_write_timeout(Duration::from_secs(5)),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read a small message (much smaller than the 64KB buffer)
            let start = Instant::now();
            let received = stream.recv(10).await.unwrap();
            let elapsed = start.elapsed();

            (received, elapsed)
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.clone()).await.unwrap();

        // Wait for the reader to complete
        let (received, elapsed) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.coalesce(), msg.as_slice());

        // Verify it completed quickly (well under the read timeout)
        // Should complete in milliseconds, not seconds
        assert!(elapsed < read_timeout);
    }

    #[tokio::test]
    async fn test_read_timeout_with_partial_data() {
        // Use a short read timeout to make the test fast
        let read_timeout = Duration::from_millis(100);
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(read_timeout)
                .with_write_timeout(Duration::from_secs(5)),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Try to read 100 bytes, but only 5 will be sent
            let start = Instant::now();
            let result = stream.recv(100).await;
            let elapsed = start.elapsed();

            (result, elapsed)
        });

        // Connect and send only partial data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (result, elapsed) = reader.await.unwrap();
        assert!(matches!(result, Err(crate::Error::Timeout)));

        // Verify the timeout occurred around the expected time
        assert!(elapsed >= read_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < read_timeout * 2);
    }

    #[tokio::test]
    async fn test_unbuffered_mode() {
        // Set read_buffer_size to 0 to disable buffering
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_buffer_size(0)
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5)),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // In unbuffered mode, peek should always return empty
            assert!(stream.peek(100).is_empty());

            // Read messages without buffering
            let buf1 = stream.recv(5).await.unwrap();

            // Even after recv, peek should be empty in unbuffered mode
            assert!(stream.peek(100).is_empty());

            let buf2 = stream.recv(5).await.unwrap();
            assert!(stream.peek(100).is_empty());

            (buf1, buf2)
        });

        // Connect and send two messages
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
        sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (buf1, buf2) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
    }

    #[tokio::test]
    async fn test_peek_with_buffered_data() {
        // Use default buffer size to enable buffering
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5)),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Initially peek should be empty (no data received yet)
            assert!(stream.peek(100).is_empty());

            // Receive partial data - this should buffer more than requested
            let first = stream.recv(5).await.unwrap();
            assert_eq!(first.coalesce(), b"hello");

            // Peek should show remaining buffered data
            let peeked = stream.peek(100);
            assert!(!peeked.is_empty());
            assert_eq!(peeked, b" world");

            // Peek again should return the same (non-consuming)
            assert_eq!(stream.peek(100), b" world");

            // Peek with max_len should truncate
            assert_eq!(stream.peek(3), b" wo");

            // Receive the rest
            let rest = stream.recv(6).await.unwrap();
            assert_eq!(rest.coalesce(), b" world");

            // Peek should be empty after consuming all buffered data
            assert!(stream.peek(100).is_empty());
        });

        // Connect and send data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"hello world").await.unwrap();

        reader.await.unwrap();
    }

    // PROXY protocol integration tests

    #[tokio::test]
    async fn test_proxy_v1_trusted_source() {
        let proxy_config = ProxyConfig::new()
            .with_trusted_proxy_cidr("127.0.0.0/8")
            .unwrap();

        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5))
                .with_proxy(proxy_config),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client_addr, _sink, mut stream) = listener.accept().await.unwrap();
            // Should get the proxied address, not 127.0.0.1
            assert_eq!(client_addr.ip().to_string(), "192.168.1.100");
            assert_eq!(client_addr.port(), 56789);

            // Data after PROXY header should be readable
            let data = stream.recv(5).await.unwrap();
            assert_eq!(data.coalesce(), b"hello");
        });

        // Connect and send PROXY header followed by data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nhello")
            .await
            .unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_untrusted_source_no_parsing() {
        // Only trust 10.0.0.0/8, not 127.0.0.0/8
        let proxy_config = ProxyConfig::new()
            .with_trusted_proxy_cidr("10.0.0.0/8")
            .unwrap();

        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5))
                .with_proxy(proxy_config),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client_addr, _sink, mut stream) = listener.accept().await.unwrap();
            // Should get the TCP address (127.0.0.1) since source is not trusted
            assert!(client_addr.ip().is_loopback());

            // PROXY header is NOT parsed, so it appears as data
            let data = stream.recv(6).await.unwrap();
            assert_eq!(data.coalesce(), b"PROXY ");
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nhello")
            .await
            .unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_no_config_no_parsing() {
        // No proxy config at all
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5)),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client_addr, _sink, mut stream) = listener.accept().await.unwrap();
            // Should get the TCP address
            assert!(client_addr.ip().is_loopback());

            // PROXY header appears as data
            let data = stream.recv(6).await.unwrap();
            assert_eq!(data.coalesce(), b"PROXY ");
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\nhello")
            .await
            .unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_v2_trusted_source() {
        let proxy_config = ProxyConfig::new()
            .with_trusted_proxy_cidr("127.0.0.0/8")
            .unwrap();

        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5))
                .with_proxy(proxy_config),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client_addr, _sink, mut stream) = listener.accept().await.unwrap();
            // Should get the proxied address from v2 header
            assert_eq!(client_addr.ip().to_string(), "192.168.1.100");
            assert_eq!(client_addr.port(), 56789);

            // Data after PROXY header should be readable
            let data = stream.recv(5).await.unwrap();
            assert_eq!(data.coalesce(), b"hello");
        });

        // Build v2 binary header
        const V2_SIG: [u8; 12] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        let mut header = Vec::new();
        header.extend_from_slice(&V2_SIG);
        header.push(0x21); // version 2, PROXY command
        header.push(0x11); // AF_INET, TCP
        header.extend_from_slice(&12u16.to_be_bytes()); // address length
        header.extend_from_slice(&[192, 168, 1, 100]); // src ip
        header.extend_from_slice(&[10, 0, 0, 1]); // dst ip
        header.extend_from_slice(&56789u16.to_be_bytes()); // src port
        header.extend_from_slice(&443u16.to_be_bytes()); // dst port
        header.extend_from_slice(b"hello");

        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(header).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_invalid_header_from_trusted_rejected() {
        let proxy_config = ProxyConfig::new()
            .with_trusted_proxy_cidr("127.0.0.0/8")
            .unwrap();

        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5))
                .with_proxy(proxy_config),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Accept should fail because PROXY header is invalid
            let result = listener.accept().await;
            assert!(result.is_err());
        });

        // Connect and send invalid data (not a PROXY header)
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"GET / HTTP/1.1\r\n").await.unwrap();

        server.await.unwrap();
    }
}
