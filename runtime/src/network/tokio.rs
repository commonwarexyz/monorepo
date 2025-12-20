use crate::Error;
use commonware_utils::StableBuf;
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
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
        // Time out if we take too long to write
        timeout(self.write_timeout, self.sink.write_all(msg.into().as_ref()))
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
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        if buf.is_empty() {
            return Ok(buf);
        }

        // Time out if we take too long to read
        timeout(self.read_timeout, self.stream.read_exact(buf.as_mut()))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;

        Ok(buf)
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
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let (read_half, sink) = stream.into_split();
        Ok((
            addr,
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: BufReader::with_capacity(self.cfg.read_buffer_size, read_half),
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            read_buffer_size: 64 * 1024, // 64 KB
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
        let (read_half, sink) = stream.into_split();
        Ok((
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: BufReader::with_capacity(self.cfg.read_buffer_size, read_half),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        network::{tests, tokio as TokioNetwork},
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
            let buf = stream.recv(vec![0u8; 10]).await.unwrap();
            let elapsed = start.elapsed();

            (buf, elapsed)
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.clone()).await.unwrap();

        // Wait for the reader to complete
        let (received, elapsed) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.as_ref(), &msg[..]);

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
            let result = stream.recv(vec![0u8; 100]).await;
            let elapsed = start.elapsed();

            (result, elapsed)
        });

        // Connect and send only partial data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(vec![1u8, 2, 3, 4, 5]).await.unwrap();

        // Wait for the reader to complete
        let (result, elapsed) = reader.await.unwrap();
        assert!(matches!(result, Err(crate::Error::Timeout)));

        // Verify the timeout occurred around the expected time
        assert!(elapsed >= read_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < read_timeout + Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_timeout_discards_partial_read() {
        use tokio::sync::oneshot;

        let read_timeout = Duration::from_millis(50);
        let network = TokioNetwork::Network::from(
            TokioNetwork::Config::default()
                .with_read_timeout(read_timeout)
                .with_write_timeout(Duration::from_secs(5)),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Channel to coordinate between sender and receiver
        let (first_msg_sent_tx, first_msg_sent_rx) = oneshot::channel::<()>();
        let (timeout_occurred_tx, timeout_occurred_rx) = oneshot::channel::<()>();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Wait for first message to be sent
            first_msg_sent_rx.await.unwrap();

            // Give time for the data to arrive and be buffered
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Try to read 100 bytes, but only 5 were sent - this will timeout.
            // The 5 bytes that were partially read are discarded.
            let result = stream.recv(vec![0u8; 100]).await;
            assert!(result.is_err()); // Should timeout

            // Signal that timeout occurred
            timeout_occurred_tx.send(()).unwrap();

            // Read the second message - the first message's bytes are gone
            let result = stream.recv(vec![0u8; 5]).await;

            (stream, result)
        });

        // Connect and send first message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let first_msg = vec![b'A'; 5];
        sink.send(first_msg.clone()).await.unwrap();
        first_msg_sent_tx.send(()).unwrap();

        // Wait for the timeout to occur
        timeout_occurred_rx.await.unwrap();

        // Send second message
        let second_msg = vec![b'B'; 5];
        sink.send(second_msg.clone()).await.unwrap();

        // Get results
        let (_stream, result) = reader.await.unwrap();
        let received = result.expect("second read should succeed");

        // The first message was discarded due to timeout - we get the second.
        // This is correct: after a timeout, the stream is in an undefined state
        // and should be closed. Continuing to read is undefined behavior.
        assert_eq!(received.as_ref(), &second_msg[..], "Should have lost data");
        assert_ne!(
            received.as_ref(),
            &first_msg[..],
            "Should not have received the first message"
        );
    }
}
