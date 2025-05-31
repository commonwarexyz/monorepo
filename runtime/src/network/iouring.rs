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

#[derive(Clone, Debug)]
/// [crate::Network] implementation that uses io_uring to do async I/O.
pub struct Network {
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
    pub(crate) fn start(
        cfg: iouring::Config,
        registry: &mut Registry,
    ) -> Result<Self, crate::Error> {
        // Create an io_uring instance to handle send operations.
        let (send_submitter, rx) = mpsc::channel(cfg.size as usize);
        std::thread::spawn({
            let cfg = cfg.clone();
            let registry = registry.sub_registry_with_prefix("iouring_sender");
            let metrics = Arc::new(iouring::Metrics::new(registry));
            move || block_on(iouring::run(cfg, metrics, rx))
        });

        // Create an io_uring instance to handle receive operations.
        let (recv_submitter, rx) = mpsc::channel(cfg.size as usize);
        let registry = registry.sub_registry_with_prefix("iouring_receiver");
        let metrics = Arc::new(iouring::Metrics::new(registry));
        std::thread::spawn(|| block_on(iouring::run(cfg, metrics, rx)));

        Ok(Self {
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

impl crate::Sink for Sink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), crate::Error> {
        let mut msg = msg.into();
        let mut bytes_sent = 0;
        let msg_len = msg.len();

        while bytes_sent < msg_len {
            // Figure out how much is left to read and where to read into
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
            // Figure out how much is left to read and where to read into
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
        iouring::Config,
        network::{iouring::Network, tests},
    };
    use prometheus_client::registry::Registry;
    use std::time::Duration;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            Network::start(Config::default(), &mut Registry::default())
                .expect("Failed to start io_uring")
        })
        .await;
    }

    #[tokio::test]
    #[ignore]
    async fn stress_test_trait() {
        tests::stress_test_network_trait(|| {
            Network::start(
                Config {
                    size: 256,
                    force_poll: Some(Duration::from_millis(100)),
                    ..Default::default()
                },
                &mut Registry::default(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }
}
