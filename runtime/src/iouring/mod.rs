use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{opcode::LinkTimeout, squeue::Entry as SqueueEntry, types::Timespec, IoUring};
use std::time::Duration;

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
            iopoll: false,
            single_issuer: true,
            op_timeout: Some(Duration::from_secs(10)),
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

            if let Some(sender) = waiters.remove(&work_id) {
                if result == -libc::ECANCELED && cfg.op_timeout.is_some() {
                    // Send a timeout error code to the caller
                    let _ = sender.send(-libc::ETIMEDOUT);
                } else {
                    // Send the actual result
                    let _ = sender.send(result);
                }
            } else {
                // This is a timeout. Make sure timeouts are enabled.
                debug_assert!(cfg.op_timeout.is_some());
                debug_assert_eq!(work_id, TIMEOUT_WORK_ID);
            }
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
            next_work_id += 1;
            if next_work_id == TIMEOUT_WORK_ID {
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
    use futures::{
        channel::{mpsc::channel, oneshot},
        SinkExt as _,
    };
    use io_uring::{opcode, types::Fd};
    use std::os::{fd::AsRawFd, unix::net::UnixStream};

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
