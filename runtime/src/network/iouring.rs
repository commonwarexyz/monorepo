//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Network operations are sent via a [futures::channel::mpsc] channel to a dedicated io_uring event
//! loop running in a separate thread. Operation results are returned via a [futures::channel::oneshot]
//! channel. This implementation uses two separate io_uring instances: one for send operations and
//! one for receive operations.
//!
//! ## Memory Safety
//!
//! We pass to the kernel, via io_uring, a pointer to the buffer being read from/written into.
//! Therefore, we ensure that the memory location is valid for the duration of the operation.
//! That is, it doesn't move or go out of scope until the operation completes.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-network` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.

use crate::iouring::{self, should_retry};
use commonware_utils::StableBuf;
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _,
};
use io_uring::types::Fd;
use prometheus_client::registry::Registry;
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    pub read_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
            iouring_config: iouring::Config::default(),
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
        }
    }
}

#[derive(Clone, Debug)]
/// [crate::Network] implementation that uses io_uring to do async I/O.
pub struct Network {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
}

impl Network {
    /// Returns a new [Network] instance.
    /// This function creates two io_uring instances, one for sending and one for receiving.
    /// This function spawns two threads to run the io_uring event loops.
    /// The threads run until the work submission channel is closed or an error occurs.
    /// The caller should take special care to ensure the io_uring `size` given in `cfg` is
    /// large enough, given the number of connections that will be maintained.
    /// Each ongoing send/recv to/from each connection will consume a slot in the io_uring.
    /// The io_uring `size` should be a multiple of the number of expected connections.
    pub(crate) fn start(mut cfg: Config, registry: &mut Registry) -> Result<Self, crate::Error> {
        // Create an io_uring instance to handle send operations.
        let (send_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        std::thread::spawn({
            let cfg = cfg.clone();
            let registry = registry.sub_registry_with_prefix("iouring_sender");
            let metrics = Arc::new(iouring::Metrics::new(registry));
            move || block_on(iouring::run(cfg.iouring_config, metrics, rx))
        });

        // Create an io_uring instance to handle receive operations.
        let (recv_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);
        let registry = registry.sub_registry_with_prefix("iouring_receiver");
        let metrics = Arc::new(iouring::Metrics::new(registry));
        std::thread::spawn(|| block_on(iouring::run(cfg.iouring_config, metrics, rx)));

        Ok(Self {
            tcp_nodelay: cfg.tcp_nodelay,
            send_submitter,
            recv_submitter,
            read_buffer_size: cfg.read_buffer_size,
        })
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        let listener = TcpListener::bind(socket)
            .await
            .map_err(|_| crate::Error::BindFailed)?;
        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            inner: listener,
            send_submitter: self.send_submitter.clone(),
            recv_submitter: self.recv_submitter.clone(),
            read_buffer_size: self.read_buffer_size,
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));
        Ok((
            Sink::new(fd.clone(), self.send_submitter.clone()),
            Stream::new(fd, self.recv_submitter.clone(), self.read_buffer_size),
        ))
    }
}

/// Implementation of [crate::Listener] for an io-uring [Network].
pub struct Listener {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    inner: TcpListener,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let stream = stream
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));

        Ok((
            remote_addr,
            Sink::new(fd.clone(), self.send_submitter.clone()),
            Stream::new(fd, self.recv_submitter.clone(), self.read_buffer_size),
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
    }
}

/// Implementation of [crate::Sink] for an io-uring [Network].
pub struct Sink {
    fd: Arc<OwnedFd>,
    /// Used to submit send operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
}

impl Sink {
    fn new(fd: Arc<OwnedFd>, submitter: mpsc::Sender<iouring::Op>) -> Self {
        Self { fd, submitter }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), crate::Error> {
        let mut msg = msg.into();
        let mut bytes_sent = 0;
        let msg_len = msg.len();

        while bytes_sent < msg_len {
            // Figure out how much is left to send and where to send from.
            //
            // SAFETY: `msg` is a `StableBuf` guaranteeing the memory won't move.
            // `bytes_sent` is always < `msg_len` due to the loop condition, so
            // `add(bytes_sent)` stays within bounds and `msg_len - bytes_sent`
            // correctly represents the remaining valid bytes.
            let remaining = unsafe {
                std::slice::from_raw_parts(
                    msg.as_mut_ptr().add(bytes_sent) as *const u8,
                    msg_len - bytes_sent,
                )
            };

            // Create the io_uring send operation
            let op = io_uring::opcode::Send::new(
                self.as_raw_fd(),
                remaining.as_ptr(),
                remaining.len() as u32,
            )
            .build();

            // Submit the operation to the io_uring event loop
            let (tx, rx) = oneshot::channel();
            self.submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffer: Some(msg),
                })
                .await
                .map_err(|_| crate::Error::SendFailed)?;

            // Wait for the operation to complete
            let (result, got_msg) = rx.await.map_err(|_| crate::Error::SendFailed)?;
            msg = got_msg.unwrap();
            if should_retry(result) {
                continue;
            }

            // Non-positive result indicates an error or EOF.
            if result <= 0 {
                return Err(crate::Error::SendFailed);
            }

            // Mark bytes as sent.
            bytes_sent += result as usize;
        }
        Ok(())
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
    /// Internal read buffer.
    buffer: Vec<u8>,
    /// Current read position in the buffer.
    buffer_pos: usize,
    /// Number of valid bytes in the buffer.
    buffer_len: usize,
}

impl Stream {
    fn new(fd: Arc<OwnedFd>, submitter: mpsc::Sender<iouring::Op>, buffer_capacity: usize) -> Self {
        Self {
            fd,
            submitter,
            buffer: vec![0u8; buffer_capacity],
            buffer_pos: 0,
            buffer_len: 0,
        }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }

    /// Submits a recv operation to io_uring.
    ///
    /// # Arguments
    /// * `buffer` - Buffer for ownership tracking (kept alive during io_uring op)
    /// * `offset` - Offset into buffer to write received data
    /// * `len` - Maximum bytes to receive
    ///
    /// # Returns
    /// The buffer and either bytes received or an error.
    async fn submit_recv(
        &mut self,
        mut buffer: StableBuf,
        offset: usize,
        len: usize,
    ) -> (StableBuf, Result<usize, crate::Error>) {
        loop {
            // SAFETY: offset + len <= buffer.len() as guaranteed by callers.
            let ptr = unsafe { buffer.as_mut_ptr().add(offset) };
            let op = io_uring::opcode::Recv::new(self.as_raw_fd(), ptr, len as u32).build();

            let (tx, rx) = oneshot::channel();
            if self
                .submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffer: Some(buffer),
                })
                .await
                .is_err()
            {
                // Channel closed - io_uring thread died, buffer is lost
                return (StableBuf::default(), Err(crate::Error::RecvFailed));
            }

            let Ok((result, buf)) = rx.await else {
                // Channel closed - io_uring thread died, buffer is lost
                return (StableBuf::default(), Err(crate::Error::RecvFailed));
            };
            buffer = buf.unwrap();

            if should_retry(result) {
                continue;
            }

            if result <= 0 {
                let err = if result == -libc::ETIMEDOUT {
                    crate::Error::Timeout
                } else {
                    crate::Error::RecvFailed
                };
                return (buffer, Err(err));
            }

            return (buffer, Ok(result as usize));
        }
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self) -> Result<usize, crate::Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer: StableBuf = std::mem::take(&mut self.buffer).into();
        let len = buffer.len();

        // If the buffer is lost due to a channel error, we don't restore it.
        // Channel errors mean the io_uring thread died, so the stream is unusable anyway.
        let (buffer, result) = self.submit_recv(buffer, 0, len).await;
        self.buffer = buffer.into();
        self.buffer_len = result?;
        Ok(self.buffer_len)
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, crate::Error> {
        let mut buf = buf.into();
        let mut bytes_received = 0;
        let buf_len = buf.len();

        while bytes_received < buf_len {
            // First drain any buffered data
            let buffered = self.buffer_len - self.buffer_pos;
            if buffered > 0 {
                let to_copy = std::cmp::min(buffered, buf_len - bytes_received);
                buf.as_mut()[bytes_received..bytes_received + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                bytes_received += to_copy;
                continue;
            }

            let remaining = buf_len - bytes_received;

            // Buffer is empty, read from socket
            // For large reads or unbuffered mode, read directly into caller's buffer
            let buffer_capacity = self.buffer.capacity();
            if buffer_capacity == 0 || remaining >= buffer_capacity {
                let (returned_buf, result) = self.submit_recv(buf, bytes_received, remaining).await;
                buf = returned_buf;
                bytes_received += result?;
            } else {
                // Fill internal buffer, then loop will copy
                self.fill_buffer().await?;
            }
        }

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iouring,
        network::{
            iouring::{Config, Network},
            tests,
        },
    };
    use commonware_macros::test_group;
    use prometheus_client::registry::Registry;
    use std::time::Duration;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        size: 256,
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};

        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read a small message (much smaller than the 64KB buffer)
            let buf = stream.recv(vec![0u8; 10]).await.unwrap();
            buf
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.clone()).await.unwrap();

        // Wait for the reader to complete
        let received = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.as_ref(), &msg[..]);
    }

    #[tokio::test]
    async fn test_read_timeout_with_partial_data() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use std::time::Instant;

        // Use a short timeout to make the test fast
        let op_timeout = Duration::from_millis(100);
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    op_timeout: Some(op_timeout),
                    force_poll: Duration::from_millis(10),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

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
        assert!(elapsed >= op_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < op_timeout * 3);
    }

    #[tokio::test]
    async fn test_unbuffered_mode() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};

        // Set read_buffer_size to 0 to disable buffering
        let network = Network::start(
            Config {
                read_buffer_size: 0,
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read messages without buffering
            let buf1 = stream.recv(vec![0u8; 5]).await.unwrap();
            let buf2 = stream.recv(vec![0u8; 5]).await.unwrap();
            (buf1, buf2)
        });

        // Connect and send two messages
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(vec![1u8, 2, 3, 4, 5]).await.unwrap();
        sink.send(vec![6u8, 7, 8, 9, 10]).await.unwrap();

        // Wait for the reader to complete
        let (buf1, buf2) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(buf1.as_ref(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.as_ref(), &[6u8, 7, 8, 9, 10]);
    }
}
