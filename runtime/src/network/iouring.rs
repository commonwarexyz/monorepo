use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _, StreamExt as _,
};
use io_uring::{squeue::Entry as SqueueEntry, types::Fd, IoUring};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, OwnedFd},
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

impl Network {
    pub(crate) fn start(cfg: IoUringConfig) -> Result<Self, crate::Error> {
        let (tx, rx) = mpsc::channel(128);

        std::thread::spawn(|| block_on(run_network(cfg, rx)));

        Ok(Self {
            submitter: tx.clone(),
        })
    }
}

/// Background task that polls for completed work and notifies waiters on completion.
/// The user data field of all operations received on `receiver` will be ignored.
async fn run_network(
    cfg: IoUringConfig,
    mut receiver: mpsc::Receiver<(SqueueEntry, oneshot::Sender<i32>)>,
) {
    let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to.
    let mut waiters: std::collections::HashMap<_, oneshot::Sender<i32>> =
        std::collections::HashMap::with_capacity(cfg.size as usize);

    loop {
        // Try to get a completion
        if let Some(cqe) = ring.completion().next() {
            let work_id = cqe.user_data();
            let result = cqe.result();
            let sender = waiters.remove(&work_id).expect("work is missing");
            // Notify with the result of this operation
            let _ = sender.send(result);
            continue;
        }

        // Try to fill the submission queue with incoming work.
        // Stop if we are at the max number of processing work.
        while waiters.len() < cfg.size as usize {
            // Wait for more work
            let (mut work, sender) = if waiters.is_empty() {
                // Block until there is something to do
                match receiver.next().await {
                    Some(work) => work,
                    None => return,
                }
            } else {
                // Handle incoming work
                match receiver.try_next() {
                    // Got work without blocking
                    Ok(Some(work_item)) => work_item,
                    // Channel closed, shut down
                    Ok(None) => return,
                    // No new work available, wait for a completion
                    Err(_) => break,
                }
            };

            // Assign a unique id
            let work_id = next_work_id;
            work = work.user_data(work_id);
            // Use wrapping add in case we overflow
            next_work_id = next_work_id.wrapping_add(1);

            // We'll send the result of this operation to `sender`.
            waiters.insert(work_id, sender);

            // Submit the operation to the ring
            unsafe {
                ring.submission()
                    .push(&work)
                    .expect("unable to push to queue");
            }
        }

        // Wait for at least 1 item to be in the completion queue.
        // Note that we block until anything is in the completion queue,
        // even if it's there before this call. That is, a completion
        // that arrived before this call will be counted and cause this
        // call to return. Note that waiters.len() > 0 here.
        ring.submit_and_wait(1).expect("unable to submit to ring");
    }
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

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
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
