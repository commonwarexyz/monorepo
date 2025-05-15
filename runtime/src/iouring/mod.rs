use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{squeue::Entry as SqueueEntry, IoUring};

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            iopoll: false,
            single_issuer: true,
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
