use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{
    opcode::{LinkTimeout, Timeout},
    squeue::Entry as SqueueEntry,
    types::Timespec,
    IoUring,
};
use std::time::Duration;

/// Reserved ID for a CQE that indicates an operation timed out.
const TIMEOUT_WORK_ID: u64 = u64::MAX;
/// Reserved ID for a CQE that indicates the event loop should
/// wake up to check for new work.
const POLL_WORK_ID: u64 = u64::MAX - 1;

#[derive(Clone, Debug)]
/// Configuration for an io_uring instance.
/// See `man io_uring`.
pub struct Config {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub io_poll: bool,
    /// If true, use single issuer mode.
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            io_poll: false,
            single_issuer: true,
            force_poll: None,
            op_timeout: None,
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

/// Creates a new io_uring instance that listens for incoming work on `receiver`.
///
/// Each incoming work is `(work, sender)`, where:
/// * `work` is the submission queue entry to be submitted to the ring.
///   Its user data field will be overwritten. Users shouldn't rely on it.
/// * `sender` is where we send the return value of the work.
///
/// This function will block until `receiver` is closed or an error occurs.
/// It should be run in a separate task.
pub(crate) async fn run(
    cfg: Config,
    mut receiver: mpsc::Receiver<(SqueueEntry, oneshot::Sender<i32>)>,
) {
    let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to.
    let mut waiters: std::collections::HashMap<_, oneshot::Sender<i32>> =
        std::collections::HashMap::with_capacity(cfg.size as usize);

    loop {
        // Try to get a completion
        while let Some(cqe) = ring.completion().next() {
            let work_id = cqe.user_data();
            match work_id {
                POLL_WORK_ID => {
                    // This CQE means we woke up to check for new work.
                    // Assert that new work polling is enabled.
                    assert!(cfg.force_poll.is_some());
                }
                TIMEOUT_WORK_ID => {
                    // An operation timed out. The timed out operation will be
                    // reported to the submitter when its CQE is processed.
                    assert!(cfg.op_timeout.is_some());
                }
                _ => {
                    // Report this operation's result to the submitter.
                    let result = cqe.result();
                    let result = if result == -libc::ECANCELED && cfg.op_timeout.is_some() {
                        // This operation timed out
                        -libc::ETIMEDOUT
                    } else {
                        result
                    };

                    let result_sender = waiters.remove(&work_id).expect("result sender not found");
                    result_sender.send(result).expect("failed to send result");
                }
            }
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
            next_work_id += 1;
            if next_work_id == POLL_WORK_ID {
                // Wrap back to 0
                next_work_id = 0;
            }
            work = work.user_data(work_id);

            // We'll send the result of this operation to `sender`.
            waiters.insert(work_id, sender);

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
        ring.submit_and_wait(1).expect("unable to submit to ring");
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
    use crate::iouring::Config;
    use futures::{
        channel::{mpsc::channel, oneshot},
        SinkExt as _,
    };
    use io_uring::{opcode, types::Fd};
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    use std::time::Duration;

    async fn recv_then_send(cfg: Config) {
        // Create a new io_uring instance
        let (mut submitter, receiver) = channel(0);
        let handle = tokio::spawn(super::run(cfg, receiver));

        let (left_pipe, right_pipe) = UnixStream::pair().unwrap();

        // Submit a read
        let msg = b"hello";
        let mut buf = vec![0; msg.len()];
        let recv =
            opcode::Recv::new(Fd(left_pipe.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (recv_tx, recv_rx) = oneshot::channel();
        submitter
            .send((recv, recv_tx))
            .await
            .expect("failed to send work");

        // Submit a write that satisfies the read.
        // Note that since the channel capacity is 0, we can only successfully send
        // the write after the event loop has reached receiver.await(), which implies
        // the event loop is parked in submit_and_wait when the send below is called.
        let write =
            opcode::Write::new(Fd(right_pipe.as_raw_fd()), msg.as_ptr(), msg.len() as _).build();
        let (write_tx, write_rx) = oneshot::channel();
        submitter
            .send((write, write_tx))
            .await
            .expect("failed to send work");

        // Wait for the read and write operations to complete.
        let result = recv_rx.await.expect("failed to receive result");
        assert!(result > 0, "recv failed: {}", result);
        let result = write_rx.await.expect("failed to receive result");
        assert!(result > 0, "write failed: {}", result);
        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_force_poll() {
        // When force_poll is set, the event loop should wake up
        // periodically to check for new work.
        let cfg = Config {
            force_poll: Some(Duration::from_millis(10)),
            ..Default::default()
        };
        recv_then_send(cfg).await;

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
        let timeout = tokio::time::timeout(Duration::from_secs(2), recv_then_send(cfg));
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
        let handle = tokio::spawn(super::run(cfg, receiver));

        // Submit a work item that will time out (because we don't write to the pipe)
        let (pipe, _pipe_other_side) = UnixStream::pair().unwrap();
        let mut buf = vec![0; 1024];
        let work =
            opcode::Recv::new(Fd(pipe.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send((work, tx))
            .await
            .expect("failed to send work");
        // Wait for the timeout
        let result = rx.await.expect("failed to receive result");
        assert_eq!(result, -libc::ETIMEDOUT);
        drop(submitter);
        handle.await.unwrap();
    }
}
