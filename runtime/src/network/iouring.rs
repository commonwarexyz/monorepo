use futures::{
    channel::{mpsc, oneshot},
    SinkExt as _,
};
use io_uring::{squeue::Entry as SqueueEntry, types::Fd, IoUring};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsFd, AsRawFd, OwnedFd},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct IoUringConfig {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub iopoll: bool,
    /// If true, use single issuer mode.
    pub single_issuer: bool,
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            size: 128,
            iopoll: false,
            single_issuer: true,
        }
    }
}

fn new_ring(cfg: &IoUringConfig) -> Result<IoUring, std::io::Error> {
    let mut builder = &mut IoUring::builder();
    if cfg.iopoll {
        builder = builder.setup_iopoll();
    }
    if cfg.single_issuer {
        builder = builder.setup_single_issuer();
    }
    builder.build(cfg.size)
}

#[derive(Clone, Debug)]
pub(crate) struct Network {
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        let listener = TcpListener::bind(socket).map_err(|_| crate::Error::BindFailed)?;
        Ok(Listener {
            inner: listener,
            submitter: self.submitter.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        let stream = TcpStream::connect(socket).map_err(|_| crate::Error::ConnectionFailed)?;
        let fd = Arc::new(OwnedFd::from(stream));

        Ok((
            Sink {
                fd: fd.clone(),
                submitter: self.submitter.clone(),
            },
            Stream {
                fd,
                submitter: self.submitter.clone(),
            },
        ))
    }
}

pub(crate) struct Listener {
    inner: TcpListener,
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));

        Ok((
            remote_addr,
            Sink {
                fd: fd.clone(),
                submitter: self.submitter.clone(),
            },
            Stream {
                fd,
                submitter: self.submitter.clone(),
            },
        ))
    }
}

pub(crate) struct Sink {
    fd: Arc<OwnedFd>,
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Sink {
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), crate::Error> {
        let mut bytes_sent = 0;

        while bytes_sent < msg.len() {
            let remaining = &msg[bytes_sent..];

            let op =
                io_uring::opcode::Send::new(self.as_raw_fd(), remaining.as_ptr(), msg.len() as u32)
                    .build();

            let (tx, rx) = oneshot::channel();

            self.submitter
                .send((op, tx))
                .await
                .map_err(|_| crate::Error::SendFailed)?;
            let result = rx.await.map_err(|_| crate::Error::SendFailed)?;
            if result <= 0 {
                return Err(crate::Error::SendFailed);
            }
            bytes_sent += result as usize;
        }
        Ok(())
    }
}

pub(crate) struct Stream {
    fd: Arc<OwnedFd>,
    submitter: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Stream {
    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), crate::Error> {
        let mut bytes_received = 0;

        while bytes_received < buf.len() {
            let remaining = &mut buf[bytes_received..];

            let op = io_uring::opcode::Recv::new(
                self.as_raw_fd(),
                remaining.as_mut_ptr(),
                buf.len() as u32,
            )
            .build();

            let (tx, rx) = oneshot::channel();

            self.submitter
                .send((op, tx))
                .await
                .map_err(|_| crate::Error::RecvFailed)?;
            let result = rx.await.map_err(|_| crate::Error::RecvFailed)?;
            if result <= 0 {
                return Err(crate::Error::RecvFailed);
            }
            bytes_received += result as usize;
        }
        Ok(())
    }
}
