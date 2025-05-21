use std::time::Duration;

use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{opcode, squeue::Entry as SqueueEntry, IoUring};

const TIMEOUT_WORK_ID: u64 = u64::MAX;

#[derive(Clone, Debug)]
/// Configuration for an io_uring instance.
/// See `man io_uring`.
pub struct Config {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub iopoll: bool,
    /// If true, use single issuer mode.
    pub single_issuer: bool,
    /// In the io_uring event loop, wait at most this long for a new completion
    /// before checking for new work.
    /// If None, wait indefinitely. In this case, caller must ensure that
    /// operations submitted to the ring complete in a timely manner.
    /// Otherwise, an operation that takes a long time may block the
    /// event loop while waiting for its completion.
    pub poll_new_work_freq: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            iopoll: false,
            single_issuer: true,
            poll_new_work_freq: Some(Duration::from_secs(1)),
        }
    }
}

fn new_ring(cfg: &Config) -> Result<IoUring, std::io::Error> {
    let mut builder = &mut IoUring::builder();
    if cfg.iopoll {
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
        if let Some(cqe) = ring.completion().next() {
            let work_id = cqe.user_data();
            let result = cqe.result();
            if work_id == TIMEOUT_WORK_ID {
                // Ignore timeout. It woke us up to check for new work.
                // We don't need to do anything here.
                continue;
            }
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

        if let Some(freq) = cfg.poll_new_work_freq {
            let timeout = io_uring::types::Timespec::new()
                .sec(freq.as_secs())
                .nsec(freq.subsec_nanos());
            let op = opcode::Timeout::new(&timeout)
                .build()
                .user_data(TIMEOUT_WORK_ID);
            // Submit the timeout operation to the ring
            unsafe {
                ring.submission()
                    .push(&op)
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
    use std::{
        os::{fd::AsRawFd, unix::net::UnixStream},
        time::Duration,
    };

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
    async fn test_poll_new_work_freq() {
        // When poll_new_work_freq is set, the event loop should wake up
        // periodically to check for new work.
        let cfg = Config {
            poll_new_work_freq: Some(Duration::from_millis(10)),
            ..Default::default()
        };
        recv_then_send(cfg).await;

        // When poll_new_work_freq is None, the event loop should block on recv
        // and never wake up to check for new work, meaning it never sees the
        // write operation which satisfies the read. This means it
        // should hit the timeout and never complete.
        let cfg = Config {
            poll_new_work_freq: None,
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
}
