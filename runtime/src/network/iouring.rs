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
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

#[derive(Clone, Debug, Default)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
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
            Sink {
                fd: fd.clone(),
                submitter: self.send_submitter.clone(),
            },
            Stream {
                fd,
                submitter: self.recv_submitter.clone(),
            },
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
            Sink {
                fd: fd.clone(),
                submitter: self.send_submitter.clone(),
            },
            Stream {
                fd,
                submitter: self.recv_submitter.clone(),
            },
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
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

const MAX_IOV: usize = 16;

/// Converts a slice of byte slices to a slice of [`libc::iovec`]s on the stack.
///
/// If the number of buffers exceeds [MAX_IOV], an error is returned.
#[inline(always)]
fn io_vecs(bufs: &[&[u8]]) -> Result<[MaybeUninit<libc::iovec>; MAX_IOV], crate::Error> {
    if bufs.len() > MAX_IOV {
        return Err(crate::Error::SendFailed);
    }

    let mut io_vecs: [MaybeUninit<libc::iovec>; MAX_IOV] = [MaybeUninit::uninit(); MAX_IOV];

    for (i, buf) in bufs.iter().enumerate() {
        io_vecs[i].write(libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        });
    }

    Ok(io_vecs)
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: &[&[u8]]) -> Result<(), crate::Error> {
        // Convert the buffers to io_vec s, required for Linux ABI compatibility.
        let iovecs = io_vecs(bufs)?;

        // Create the io_uring writev operation
        let op = io_uring::opcode::Writev::new(
            self.as_raw_fd(),
            iovecs.as_ptr() as *const libc::iovec,
            bufs.len() as u32,
        )
        .build();

        // Submit the operation to the io_uring event loop
        let (tx, rx) = oneshot::channel();
        self.submitter
            .send(crate::iouring::Op {
                work: op,
                sender: tx,
                buffer: None, // Caller keeps buffers alive via borrows
            })
            .await
            .map_err(|_| crate::Error::SendFailed)?;

        // Wait for the operation to complete
        let (result, _) = rx.await.map_err(|_| crate::Error::SendFailed)?;

        // Non-positive result indicates an error or EOF.
        // Note: We don't retry EAGAIN here since writev on a socket should
        // complete fully or fail.
        if result <= 0 {
            return Err(crate::Error::SendFailed);
        }

        Ok(())
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
}

impl Stream {
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, crate::Error> {
        let mut bytes_received = 0;
        let mut buf = buf.into();
        let buf_len = buf.len();
        while bytes_received < buf_len {
            // Figure out how much is left to read and where to read into.
            //
            // SAFETY: `buf` is a `StableBuf` guaranteeing the memory won't move.
            // `bytes_received` is always < `buf_len` due to the loop condition, so
            // `add(bytes_received)` stays within bounds and `buf_len - bytes_received`
            // correctly represents the remaining valid bytes.
            let remaining = unsafe {
                std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().add(bytes_received),
                    buf_len - bytes_received,
                )
            };

            // Create the io_uring recv operation
            let op = io_uring::opcode::Recv::new(
                self.as_raw_fd(),
                remaining.as_mut_ptr(),
                remaining.len() as u32,
            )
            .build();

            // Submit the operation to the io_uring event loop
            let (tx, rx) = oneshot::channel();
            self.submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffer: Some(buf),
                })
                .await
                .map_err(|_| crate::Error::RecvFailed)?;

            // Wait for the operation to complete
            let (result, got_buf) = rx.await.map_err(|_| crate::Error::RecvFailed)?;
            buf = got_buf.unwrap();
            if should_retry(result) {
                continue;
            }

            // Non-positive result indicates an error or EOF.
            if result <= 0 {
                return Err(crate::Error::RecvFailed);
            }
            bytes_received += result as usize;
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
}
