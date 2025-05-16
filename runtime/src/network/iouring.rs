use crate::iouring;
use commonware_utils::{StableBuf, StableBufMut};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _,
};
use io_uring::{squeue::Entry as SqueueEntry, types::Fd};
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
/// [crate::Network] implementation that uses io_uring to do async I/O.
pub struct Network {
    /// Sends send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
    /// Sends recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Network {
    /// Returns a new [Network] instance.
    /// This function creates two io_uring instances, one for sending and one for receiving.
    /// This function spawns two threads to run the io_uring event loops.
    /// The threads run until the work submission channel is closed or an error occurs.
    pub(crate) fn start(cfg: iouring::Config) -> Result<Self, crate::Error> {
        // Create an io_uring instance to handle send operations.
        let (send_submitter, rx) = mpsc::channel(cfg.size as usize);
        let cfg_clone = cfg.clone();
        std::thread::spawn(move || block_on(iouring::run(cfg_clone, rx)));

        // Create an io_uring instance to handle receive operations.
        let (recv_submitter, rx) = mpsc::channel(cfg.size as usize);
        std::thread::spawn(|| block_on(iouring::run(cfg, rx)));

        Ok(Self {
            send_submitter: send_submitter.clone(),
            recv_submitter: recv_submitter.clone(),
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
    send_submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
    recv_submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
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
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Sink {
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Sink for Sink {
    async fn send<B: StableBuf>(&mut self, msg: B) -> Result<(), crate::Error> {
        let mut bytes_sent = 0;
        let msg = msg.as_ref();
        while bytes_sent < msg.len() {
            let remaining = &msg[bytes_sent..];

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
                .send((op, tx))
                .await
                .map_err(|_| crate::Error::SendFailed)?;

            // Wait for the operation to complete
            let result = rx.await.map_err(|_| crate::Error::SendFailed)?;

            // Negative result indicates an error
            let result: usize = result.try_into().map_err(|_| crate::Error::SendFailed)?;
            bytes_sent += result;
        }
        Ok(())
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
pub struct Stream {
    fd: Arc<OwnedFd>,
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Stream {
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Stream for Stream {
    async fn recv<B: StableBufMut>(&mut self, mut buf: B) -> Result<B, crate::Error> {
        let mut bytes_received = 0;
        let buf_len = buf.len();
        let buf_ref = buf.deref_mut();
        while bytes_received < buf_len {
            let remaining = &mut buf_ref[bytes_received..];

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
                .send((op, tx))
                .await
                .map_err(|_| crate::Error::RecvFailed)?;

            // Wait for the operation to complete
            let result = rx.await.map_err(|_| crate::Error::RecvFailed)?;
            if result <= 0 {
                // Non-positive result indicates an error or EOF.
                return Err(crate::Error::RecvFailed);
            }
            bytes_received += result as usize;
        }
        Ok(buf)
    }
}
