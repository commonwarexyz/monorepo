use crate::Error;
use commonware_utils::StableBuf;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
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
/// This stream uses an internal read buffer to reduce syscall overhead.
/// Multiple small reads can be satisfied from the buffer without
/// additional network operations.
pub struct Stream {
    read_timeout: Duration,
    stream: OwnedReadHalf,
    /// Internal buffer for batching reads.
    buffer: Vec<u8>,
    /// Start position of valid data in the buffer.
    buffer_pos: usize,
    /// Amount of valid data in the buffer (from buffer_pos).
    buffer_len: usize,
}

impl Stream {
    /// Reads data from the network into the internal buffer.
    /// Returns the number of bytes read, or an error.
    async fn fill_buffer(&mut self) -> Result<usize, Error> {
        // Compact buffer: move remaining data to the front
        if self.buffer_pos > 0 {
            self.buffer
                .copy_within(self.buffer_pos..self.buffer_pos + self.buffer_len, 0);
            self.buffer_pos = 0;
        }

        // Read into the remaining space in the buffer
        let read_start = self.buffer_len;
        let bytes_read = timeout(
            self.read_timeout,
            self.stream.read(&mut self.buffer[read_start..]),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::RecvFailed)?;

        if bytes_read == 0 {
            return Err(Error::RecvFailed); // EOF
        }

        self.buffer_len += bytes_read;
        Ok(bytes_read)
    }

    /// Returns the number of buffered bytes available.
    #[inline]
    const fn buffered(&self) -> usize {
        self.buffer_len
    }

    /// Copies bytes from the internal buffer to the output.
    /// Returns the number of bytes copied.
    #[inline]
    fn copy_from_buffer(&mut self, output: &mut [u8]) -> usize {
        let to_copy = output.len().min(self.buffer_len);
        output[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;
        self.buffer_len -= to_copy;
        to_copy
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let needed = buf.len();
        if needed == 0 {
            return Ok(buf);
        }

        let mut filled = 0;

        // First, drain any buffered data
        if self.buffered() > 0 {
            filled = self.copy_from_buffer(&mut buf.as_mut()[..needed]);
            if filled == needed {
                return Ok(buf);
            }
        }

        // Need more data. If the remaining request is large (>= buffer capacity),
        // read directly into the output buffer to avoid extra copies.
        let remaining = needed - filled;
        if remaining >= self.buffer.len() {
            // Read directly into output buffer
            timeout(
                self.read_timeout,
                self.stream.read_exact(&mut buf.as_mut()[filled..]),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;
            return Ok(buf);
        }

        // For smaller remaining requests, fill the buffer and copy out
        while filled < needed {
            self.fill_buffer().await?;
            filled += self.copy_from_buffer(&mut buf.as_mut()[filled..needed]);
        }

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
        let (read_half, write_half) = stream.into_split();
        Ok((
            addr,
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink: write_half,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: read_half,
                buffer: vec![0u8; self.cfg.read_buffer_size],
                buffer_pos: 0,
                buffer_len: 0,
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

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
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
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
        let (read_half, write_half) = stream.into_split();
        Ok((
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink: write_half,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: read_half,
                buffer: vec![0u8; self.cfg.read_buffer_size],
                buffer_pos: 0,
                buffer_len: 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::network::{tests, tokio as TokioNetwork};
    use commonware_macros::test_group;
    use std::time::Duration;

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
}
