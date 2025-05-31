use commonware_utils::StableBuf;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{
    cqueue::Entry as CqueueEntry,
    opcode::{LinkTimeout, Timeout},
    squeue::Entry as SqueueEntry,
    types::Timespec,
    IoUring,
};
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use std::{collections::HashMap, sync::Arc, time::Duration};

/// Reserved ID for a CQE that indicates an operation timed out.
const TIMEOUT_WORK_ID: u64 = u64::MAX;
/// Reserved ID for a CQE that indicates the event loop timed out
/// while waiting for in-flight operations to complete
/// during shutdown.
const SHUTDOWN_TIMEOUT_WORK_ID: u64 = u64::MAX - 1;
/// Reserved ID for a CQE that indicates the event loop should
/// wake up to check for new work.
const POLL_WORK_ID: u64 = u64::MAX - 2;

#[derive(Debug)]
/// Tracks io_uring metrics.
pub struct Metrics {
    /// Number of operations submitted to the io_uring whose CQEs haven't
    /// yet been processed. Note this metric doesn't include timeouts,
    /// which are generated internally by the io_uring event loop.
    /// It's only updated before `submit_and_wait` is called, so it may
    /// temporarily vary from the actual number of pending operations.
    pending_operations: Gauge,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            pending_operations: Gauge::default(),
        };
        registry.register(
            "pending_operations",
            "Number of operations submitted to the io_uring whose CQEs haven't yet been processed",
            metrics.pending_operations.clone(),
        );
        metrics
    }
}

#[derive(Clone, Debug)]
/// Configuration for an io_uring instance.
/// See `man io_uring`.
pub struct Config {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub io_poll: bool,
    /// If true, use single issuer mode.
    /// Warning: when enabled, user must guarantee that the same thread
    /// that creates the io_uring instance is the only thread that submits
    /// work to it. Since the `run` event loop is a future that may move
    /// between threads, this means in practice that `single_issuer` should
    /// only be used in a single-threaded context.
    /// See IORING_SETUP_SINGLE_ISSUER in <https://man7.org/linux/man-pages/man2/io_uring_setup.2.html>.
    pub single_issuer: bool,
    /// In the io_uring event loop (`run`), wait at most this long for a new
    /// completion before checking for new work to submit to the io_ring.
    ///
    /// If None, wait indefinitely. In this case, caller must ensure that operations
    /// submitted to the io_uring complete so that they don't block the event loop
    /// and cause a deadlock.
    ///
    /// To illustrate the possibility of deadlock when this field is None,
    /// consider a common network pattern.
    /// In one task, a client sends a message to the server and recvs a response.
    /// In another task, the server recvs a message from the client and sends a response.
    /// If the client submits its recv operation to the io_uring, and the
    /// io_uring event loop begins to await its completion (i.e. it parks in
    /// `submit_and_wait`) before the server submits its recv operation, there is a
    /// deadlock. The client's recv can't complete until the server sends its message,
    /// but the server can't send its message until the io_uring event loop wakes up
    /// to process the completion of the client's recv operation.
    /// Note that in this example, the server and client are both using the same
    /// io_uring instance. If they aren't, this situation can't occur.
    pub force_poll: Option<Duration>,
    /// If None, operations submitted to the io_uring will not time out.
    /// In this case, the caller should be careful to ensure that the
    /// operations submitted to the io_uring will eventually complete.
    /// If Some, each submitted operation will time out after this duration.
    /// If an operation times out, its result will be -[libc::ETIMEDOUT].
    pub op_timeout: Option<Duration>,
    /// The maximum time the io_uring event loop will wait for in-flight operations
    /// to complete before abandoning them during shutdown.
    /// If None, the event loop will wait indefinitely for in-flight operations
    /// to complete before shutting down. In this case, the caller should be careful
    /// to ensure that the operations submitted to the io_uring will eventually complete.
    pub shutdown_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            io_poll: false,
            single_issuer: false,
            force_poll: None,
            op_timeout: None,
            shutdown_timeout: None,
        }
    }
}

fn new_ring(cfg: &Config) -> Result<IoUring, std::io::Error> {
    let mut builder = &mut IoUring::builder();
    if cfg.io_poll {
        builder = builder.setup_iopoll();
    }
    if cfg.single_issuer {
        builder = builder.setup_single_issuer();
    }
    builder.build(cfg.size)
}

/// An operation submitted to the io_uring event loop which will be processed
/// asynchronously by the event loop in `run`.
pub struct Op {
    /// The submission queue entry to be submitted to the ring.
    /// Its user data field will be overwritten. Users shouldn't rely on it.
    pub work: SqueueEntry,
    /// Sends the result of the operation and `buffer`.
    pub sender: oneshot::Sender<(i32, Option<StableBuf>)>,
    /// The buffer used for the operation, if any.
    /// E.g. For read, this is the buffer being read into.
    /// If None, the operation doesn't use a buffer (e.g. a sync operation).
    /// We hold the buffer here so it's guaranteed to live until the operation
    /// completes, preventing write-after-free issues.
    pub buffer: Option<StableBuf>,
}

// Returns false iff we received a shutdown timeout
// and we should stop processing completions.
#[allow(clippy::type_complexity)]
fn handle_cqe(
    waiters: &mut HashMap<u64, (oneshot::Sender<(i32, Option<StableBuf>)>, Option<StableBuf>)>,
    cqe: CqueueEntry,
    cfg: &Config,
) {
    let work_id = cqe.user_data();
    match work_id {
        TIMEOUT_WORK_ID => {
            assert!(
                cfg.op_timeout.is_some(),
                "received TIMEOUT_WORK_ID with op_timeout disabled"
            );
        }
        POLL_WORK_ID => {
            assert!(
                cfg.force_poll.is_some(),
                "received POLL_WORK_ID without force_poll enabled"
            );
        }
        SHUTDOWN_TIMEOUT_WORK_ID => {
            unreachable!("received SHUTDOWN_TIMEOUT_WORK_ID, should be handled in drain");
        }
        _ => {
            let result = cqe.result();
            let result = if result == -libc::ECANCELED && cfg.op_timeout.is_some() {
                // This operation timed out
                -libc::ETIMEDOUT
            } else {
                result
            };

            let (result_sender, buffer) = waiters.remove(&work_id).expect("missing sender");
            let _ = result_sender.send((result, buffer));
        }
    }
}

/// Creates a new io_uring instance that listens for incoming work on `receiver`.
/// This function will block until `receiver` is closed or an error occurs.
/// It should be run in a separate task.
pub(crate) async fn run(cfg: Config, metrics: Arc<Metrics>, mut receiver: mpsc::Receiver<Op>) {
    let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to
    // and the buffer used for the operation.
    #[allow(clippy::type_complexity)]
    let mut waiters: std::collections::HashMap<
        _,
        (oneshot::Sender<(i32, Option<StableBuf>)>, Option<StableBuf>),
    > = std::collections::HashMap::with_capacity(cfg.size as usize);

    loop {
        // Try to get a completion
        while let Some(cqe) = ring.completion().next() {
            handle_cqe(&mut waiters, cqe, &cfg);
        }

        // Try to fill the submission queue with incoming work.
        // Stop if we are at the max number of processing work.
        while waiters.len() < cfg.size as usize {
            // Wait for more work
            let op = if waiters.is_empty() {
                // Block until there is something to do
                match receiver.next().await {
                    // Got work
                    Some(work) => work,
                    // Channel closed, shut down
                    None => {
                        drain(&mut ring, &mut waiters, &cfg).await;
                        return;
                    }
                }
            } else {
                // Handle incoming work
                match receiver.try_next() {
                    // Got work without blocking
                    Ok(Some(work_item)) => work_item,
                    // Channel closed, shut down
                    Ok(None) => {
                        drain(&mut ring, &mut waiters, &cfg).await;
                        return;
                    }
                    // No new work available, wait for a completion
                    Err(_) => break,
                }
            };
            let Op {
                mut work,
                sender,
                buffer,
            } = op;

            // Assign a unique id
            let work_id = next_work_id;
            next_work_id += 1;
            if next_work_id == POLL_WORK_ID {
                // Wrap back to 0
                next_work_id = 0;
            }
            work = work.user_data(work_id);

            // We'll send the result of this operation to `sender`.
            waiters.insert(work_id, (sender, buffer));

            // Submit the operation to the ring, with timeout if configured
            if let Some(timeout) = &cfg.op_timeout {
                // Link the operation to the (following) timeout
                work = work.flags(io_uring::squeue::Flags::IO_LINK);

                // Create the timeout
                let timeout = Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos());
                let timeout = LinkTimeout::new(&timeout)
                    .build()
                    .user_data(TIMEOUT_WORK_ID);

                // Submit the op and timeout
                unsafe {
                    let mut sq = ring.submission();
                    sq.push(&work).expect("unable to push to queue");
                    sq.push(&timeout).expect("unable to push timeout to queue");
                }
            } else {
                // No timeout, submit the operation normally
                unsafe {
                    ring.submission()
                        .push(&work)
                        .expect("unable to push to queue");
                }
            }
        }

        if let Some(freq) = cfg.force_poll {
            // Submit a timeout operation to wake us up to check for new work.
            let timeout = io_uring::types::Timespec::new()
                .sec(freq.as_secs())
                .nsec(freq.subsec_nanos());
            let timeout = Timeout::new(&timeout).build().user_data(POLL_WORK_ID);
            unsafe {
                ring.submission()
                    .push(&timeout)
                    .expect("unable to push to queue");
            }
        }

        // Wait for at least 1 item to be in the completion queue.
        // Note that we block until anything is in the completion queue,
        // even if it's there before this call. That is, a completion
        // that arrived before this call will be counted and cause this
        // call to return. Note that waiters.len() > 0 here.
        metrics.pending_operations.set(waiters.len() as _);
        ring.submit_and_wait(1).expect("unable to submit to ring");
    }
}

/// Process `ring` completions until all pending operations are complete or
/// until `timeout` fires. If `timeout` is None, wait indefinitely.
#[allow(clippy::type_complexity)]
async fn drain(
    ring: &mut IoUring,
    waiters: &mut HashMap<u64, (oneshot::Sender<(i32, Option<StableBuf>)>, Option<StableBuf>)>,
    cfg: &Config,
) {
    if let Some(timeout) = cfg.shutdown_timeout {
        // Create a timeout that will fire if we can't clear all the inflight operations.
        let timeout = Timespec::new()
            .sec(timeout.as_secs())
            .nsec(timeout.subsec_nanos());
        let timeout = Timeout::new(&timeout)
            .build()
            .user_data(SHUTDOWN_TIMEOUT_WORK_ID);
        unsafe {
            ring.submission()
                .push(&timeout)
                .expect("unable to push to queue");
        }
    }

    while !waiters.is_empty() {
        ring.submit_and_wait(1).expect("unable to submit to ring");
        while let Some(cqe) = ring.completion().next() {
            if cqe.user_data() == SHUTDOWN_TIMEOUT_WORK_ID {
                // We timed out waiting for the shutdown to complete.
                // Abandon all remaining operations.
                assert!(cfg.shutdown_timeout.is_some());
                return;
            }
            handle_cqe(waiters, cqe, cfg);
        }
    }
}

/// Returns whether some result should be retried due to a transient error.
///
/// Errors considered transient:
/// * EAGAIN: There is no data ready. Try again later.
/// * EWOULDBLOCK: Operation would block.
pub fn should_retry(return_value: i32) -> bool {
    return_value == -libc::EAGAIN || return_value == -libc::EWOULDBLOCK
}

#[cfg(test)]
mod tests {
    use crate::iouring::{Config, Op};
    use futures::{
        channel::{
            mpsc::channel,
            oneshot::{self, Canceled},
        },
        SinkExt as _,
    };
    use io_uring::{
        opcode,
        types::{Fd, Timespec},
    };
    use prometheus_client::registry::Registry;
    use std::time::Duration;
    use std::{
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::Arc,
    };

    async fn recv_then_send(cfg: Config, should_succeed: bool) {
        // Create a new io_uring instance
        let (mut submitter, receiver) = channel(0);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics.clone(), receiver));

        let (left_pipe, right_pipe) = UnixStream::pair().unwrap();

        // Submit a read
        let msg = b"hello".to_vec();
        let mut buf = vec![0; msg.len()];
        let recv =
            opcode::Recv::new(Fd(left_pipe.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (recv_tx, recv_rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work: recv,
                sender: recv_tx,
                buffer: Some(buf.into()),
            })
            .await
            .expect("failed to send work");

        while metrics.pending_operations.get() == 0 {
            // Wait for the read to be submitted
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Submit a write that satisfies the read.
        let write =
            opcode::Write::new(Fd(right_pipe.as_raw_fd()), msg.as_ptr(), msg.len() as _).build();
        let (write_tx, write_rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work: write,
                sender: write_tx,
                buffer: Some(msg.into()),
            })
            .await
            .expect("failed to send work");

        // Wait for the read and write operations to complete.
        if should_succeed {
            let (result, _) = recv_rx.await.expect("failed to receive result");
            assert!(result > 0, "recv failed: {}", result);
            let (result, _) = write_rx.await.expect("failed to receive result");
            assert!(result > 0, "write failed: {}", result);
        } else {
            let _ = recv_rx.await;
            let _ = write_rx.await;
        }
        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_force_poll_enabled() {
        // When force_poll is set, the event loop should wake up
        // periodically to check for new work.
        let cfg = Config {
            force_poll: Some(Duration::from_millis(10)),
            ..Default::default()
        };
        recv_then_send(cfg, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_force_poll_disabled() {
        // When force_poll is None, the event loop should block on recv
        // and never wake up to check for new work, meaning it never sees the
        // write operation which satisfies the read. This means it
        // should hit the timeout and never complete.
        let cfg = Config {
            force_poll: None,
            ..Default::default()
        };
        // recv_then_send should block indefinitely.
        // Set a timeout and make sure it doesn't complete.
        let timeout = tokio::time::timeout(Duration::from_secs(2), recv_then_send(cfg, false));
        assert!(
            timeout.await.is_err(),
            "recv_then_send completed unexpectedly"
        );
    }

    #[tokio::test]
    async fn test_timeout() {
        // Create an io_uring instance
        let cfg = super::Config {
            op_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit a work item that will time out (because we don't write to the pipe)
        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let mut buf = vec![0; 8];
        let work =
            opcode::Recv::new(Fd(pipe_left.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work,
                sender: tx,
                buffer: Some(buf.into()),
            })
            .await
            .expect("failed to send work");
        // Wait for the timeout
        let (result, _) = rx.await.expect("failed to receive result");
        assert_eq!(result, -libc::ETIMEDOUT);
        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout() {
        // Create an io_uring instance with shutdown timeout disabled
        let cfg = super::Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit an operation that will complete after shutdown
        let timeout = Timespec::new().sec(3);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffer: None,
            })
            .await
            .unwrap();

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // Wait for the operation `timeout` to fire.
        let (result, _) = rx.await.unwrap();
        assert_eq!(result, -libc::ETIME);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout() {
        // Create an io_uring instance with shutdown timeout enabled
        let cfg = super::Config {
            shutdown_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit an operation that will complete long after shutdown starts
        let timeout = Timespec::new().sec(5_000);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffer: None,
            })
            .await
            .unwrap();

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // The event loop should shut down before the `timeout` fires,
        // dropping `tx` and causing `rx` to return Canceled.
        let err = rx.await.unwrap_err();
        assert!(matches!(err, Canceled { .. }));
        handle.await.unwrap();
    }
}
