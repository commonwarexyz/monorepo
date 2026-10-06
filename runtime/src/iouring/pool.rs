//! The pool of workers that poll ordinary tasks: its shared scheduling state
//! and its threads.
//!
//! [`Table`] is created before any worker starts. It holds every pool
//! worker's mailbox, the pool-wide inject queue, the idle set, and the
//! shutdown barrier. Every task's header reaches it through a weak
//! reference, so a wake from any thread can find the task's pool.
//!
//! A runnable woken on a worker of its own pool joins that worker's ready
//! queue, and a new task stays on a pool worker with nothing else queued or no
//! other worker. Every other push goes to the inject queue: wakes and spawns
//! from outside the pool or on a closing worker, and spawns that leave a busy
//! worker. Workers take a share of the queue whenever their own runs dry and
//! every [`INJECT_INTERVAL`] takes, so a busy worker cannot keep a burst
//! waiting one interval per runnable.
//!
//! A push into the inject queue wakes one parked worker. A worker publishes
//! itself in the idle set before its last look at the queue, so either the
//! pusher finds its bit or the worker finds the push:
//!
//! ```text
//! push                     parking worker i
//!   queue the runnable       set idle bit i
//!   fence(SeqCst)            fence(SeqCst)
//!   claim an idle bit ---+-> recheck the inject queue
//!                        |
//!   wake its worker <----+   arm the wake source, block
//! ```
//!
//! A wake that arrives before the worker arms its wait is latched by the
//! worker's wake source, so the wait returns at once.
//!
//! Shutdown closes the task set before the inject queue, so a runnable the
//! closed queue refuses belongs to a task the set still retains. Every pool
//! worker then drains the set, and no worker closes its mailbox or its ring
//! until all of them have drained it and finished their last poll, since a
//! task polled on one worker can hold registrations on another, whose mailbox
//! forwards their results.

use super::{
    mailbox::Mailbox,
    runtime::{Panic, Role, Shared, Worker},
    task::{Ready, Runnable},
};
use crate::utils::{self, Panicker};
use commonware_utils::channel::oneshot;
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    mem,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Arc, mpsc},
    thread::JoinHandle,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Condvar, Mutex, MutexGuard,
            atomic::{AtomicU64, AtomicUsize, Ordering, fence},
        };
    } else {
        use commonware_utils::sync::{Condvar, Mutex, MutexGuard};
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
    }
}

/// Takes between two looks at the inject queue while a worker has work of its
/// own, tokio's default `global_queue_interval`.
pub const INJECT_INTERVAL: u32 = 31;

/// Most runnables one take moves from the inject queue, as tokio caps it at
/// half its local queue.
const INJECT_BATCH: usize = 128;

/// Most workers in one pool, one bit each in the idle set.
pub const MAX_WORKERS: usize = 64;

/// Runnables waiting for any worker of the pool.
struct Inject {
    /// Whether pushes are still accepted.
    open: bool,
    /// Runnables in arrival order.
    runnables: VecDeque<Runnable>,
}

/// Progress of the pool's shutdown.
struct Closing {
    /// Whether the task set and the inject queue have closed.
    closed: bool,
    /// Pool workers that may still poll a task or clear one from the set.
    active: usize,
}

/// Scheduling state shared by every pool worker and by task wakers.
pub struct Table {
    /// Every pool worker's mailbox, indexed by worker.
    mailboxes: Box<[Arc<Mailbox>]>,
    /// One bit per worker that is parked or about to park.
    idle: CachePadded<AtomicU64>,
    /// Inject queue length, mirrored outside the lock.
    inject_len: CachePadded<AtomicUsize>,
    /// Runnables waiting for any worker of the pool.
    inject: CachePadded<Mutex<Inject>>,
    /// Shutdown progress, which workers wait on through `progress`.
    closing: Mutex<Closing>,
    /// Signalled when the pool closes and when the last active worker finishes.
    progress: Condvar,
}

impl Table {
    /// The state for a pool whose workers own `mailboxes`, in worker order.
    pub fn new(mailboxes: Vec<Arc<Mailbox>>) -> Self {
        assert!(
            (1..=MAX_WORKERS).contains(&mailboxes.len()),
            "an io_uring pool has 1 to {MAX_WORKERS} workers"
        );
        Self {
            mailboxes: mailboxes.into(),
            idle: CachePadded::new(AtomicU64::new(0)),
            inject_len: CachePadded::new(AtomicUsize::new(0)),
            inject: CachePadded::new(Mutex::new(Inject {
                open: true,
                runnables: VecDeque::new(),
            })),
            closing: Mutex::new(Closing {
                closed: false,
                active: 0,
            }),
            progress: Condvar::new(),
        }
    }

    /// Workers in the pool.
    pub fn workers(&self) -> usize {
        self.mailboxes.len()
    }

    /// Mailbox of worker `index`.
    pub fn mailbox(&self, index: u32) -> &Arc<Mailbox> {
        &self.mailboxes[index as usize]
    }

    /// Lock the inject queue.
    fn inject(&self) -> MutexGuard<'_, Inject> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let inject = self.inject.lock().unwrap();
            } else {
                let inject = self.inject.lock();
            }
        }
        inject
    }

    /// Lock the shutdown progress.
    fn closing(&self) -> MutexGuard<'_, Closing> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let closing = self.closing.lock().unwrap();
            } else {
                let closing = self.closing.lock();
            }
        }
        closing
    }

    /// Wait on `progress` with `closing` held.
    fn wait<'a>(&self, closing: MutexGuard<'a, Closing>) -> MutexGuard<'a, Closing> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                self.progress.wait(closing).unwrap()
            } else {
                let mut closing = closing;
                self.progress.wait(&mut closing);
                closing
            }
        }
    }

    /// Queue `runnable` for any worker and wake a parked one, or return it
    /// once the queue has closed.
    pub fn push(&self, runnable: Runnable) -> Result<(), Runnable> {
        {
            let mut inject = self.inject();
            if !inject.open {
                return Err(runnable);
            }
            inject.runnables.push_back(runnable);
            self.inject_len
                .store(inject.runnables.len(), Ordering::Release);
        }

        // Pairs with the fence in `park_begin`: either the load in `notify`
        // sees the parking worker's bit, or that worker's recheck sees the
        // push.
        fence(Ordering::SeqCst);
        self.notify();
        Ok(())
    }

    /// Whether the inject queue holds runnables.
    pub fn has_inject(&self) -> bool {
        self.inject_len.load(Ordering::Acquire) != 0
    }

    /// Take the oldest runnable from the inject queue.
    #[cfg(test)]
    #[must_use]
    pub fn pop(&self) -> Option<Runnable> {
        if !self.has_inject() {
            return None;
        }
        let mut inject = self.inject();
        let runnable = inject.runnables.pop_front();
        self.inject_len
            .store(inject.runnables.len(), Ordering::Release);
        runnable
    }

    /// Take a share of the inject queue, as tokio does: one runnable more
    /// than an even split between the workers, at most [`INJECT_BATCH`].
    /// Returns the oldest and queues the rest in `ready`.
    #[must_use]
    pub fn take(&self, ready: &mut Ready) -> Option<Runnable> {
        if !self.has_inject() {
            return None;
        }
        let mut inject = self.inject();
        let len = inject.runnables.len();
        let count = (len / self.workers() + 1).min(INJECT_BATCH).min(len);
        let mut taken = inject.runnables.drain(..count);
        let first = taken.next();
        for runnable in taken {
            ready.push(runnable);
        }
        self.inject_len
            .store(inject.runnables.len(), Ordering::Release);
        first
    }

    /// Wake one parked worker, if any.
    fn notify(&self) {
        let mut idle = self.idle.load(Ordering::SeqCst);
        while idle != 0 {
            let index = idle.trailing_zeros();
            match self.idle.compare_exchange_weak(
                idle,
                idle & !(1 << index),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.mailboxes[index as usize].waker.wake();
                    return;
                }
                Err(actual) => idle = actual,
            }
        }
    }

    /// Publish that worker `index` is about to park. The caller then looks
    /// at the inject queue once more before it blocks.
    pub fn park_begin(&self, index: u32) {
        self.idle.fetch_or(1 << index, Ordering::SeqCst);

        // Pairs with the fence in `push`.
        fence(Ordering::SeqCst);
    }

    /// Withdraw worker `index` from the idle set once it runs again.
    pub fn park_end(&self, index: u32) {
        self.idle.fetch_and(!(1 << index), Ordering::SeqCst);
    }

    /// Whether worker `index` is published in the idle set.
    #[cfg(test)]
    pub fn is_idle(&self, index: u32) -> bool {
        self.idle.load(Ordering::SeqCst) & (1 << index) != 0
    }

    /// Count one more pool worker that shutdown waits for.
    pub fn enter(&self) {
        self.closing().active += 1;
    }

    /// Close the inject queue, discarding its runnables, and release the
    /// workers waiting for the pool to close. The caller has closed the task
    /// set, which retains every discarded runnable's task.
    pub fn close(&self) {
        let runnables = {
            let mut inject = self.inject();
            inject.open = false;
            self.inject_len.store(0, Ordering::Release);
            mem::take(&mut inject.runnables)
        };

        // Releasing references runs no user code.
        for runnable in runnables {
            runnable.discard();
        }

        self.closing().closed = true;
        self.progress.notify_all();
    }

    /// Block until the pool has closed. Every pool worker waits here before it
    /// drains the task set, which holds back one that stopped early after a
    /// failure.
    pub fn wait_closed(&self) {
        let mut closing = self.closing();
        while !closing.closed {
            closing = self.wait(closing);
        }
    }

    /// Record that the calling worker polls and clears no more tasks, then
    /// block until every other pool worker has done the same.
    pub fn finish(&self) {
        let mut closing = self.closing();
        closing.active -= 1;
        if closing.active == 0 {
            self.progress.notify_all();
            return;
        }
        while closing.active != 0 {
            closing = self.wait(closing);
        }
    }
}

/// A pool worker's thread.
struct Thread {
    /// Ends the worker's root, which starts its shutdown.
    stop: Option<oneshot::Sender<()>>,
    /// Joined once the worker has cleaned up.
    handle: JoinHandle<()>,
}

/// The pool workers after worker zero, each on its own thread.
#[derive(Default)]
pub struct Pool {
    /// Threads in worker order, starting at worker one.
    threads: Vec<Thread>,
}

impl Pool {
    /// Start every worker after worker zero, waiting for each to create its
    /// ring before starting the next. Every failure of a started worker is
    /// sent to `failures`, which interrupts the root while it runs. The runner
    /// collects a later one after joining the pool.
    ///
    /// Panics with the first startup failure, after which the caller stops
    /// the workers already started.
    pub fn start(&mut self, shared: &Arc<Shared>, failures: &Panicker) {
        let count = shared.pool.workers();
        self.threads.reserve(count - 1);

        for index in 1..count {
            #[cfg(test)]
            let _fault = super::runtime::tests::before_pool_worker(shared, index);
            let (stop, stopped) = oneshot::channel();
            let (ready, started) = mpsc::channel();
            let shared = shared.clone();
            let failures = failures.clone();
            let handle = utils::thread::spawn(shared.cfg.thread_stack_size(), move || {
                run(shared, index as u32, ready, stopped, failures)
            });
            self.threads.push(Thread {
                stop: Some(stop),
                handle,
            });
            match started.recv().expect("pool worker exited during startup") {
                Ok(()) => {}
                Err(panic) => resume_unwind(panic),
            }
        }
    }

    /// Ask every worker to shut down, without waiting for any.
    pub fn stop(&mut self) {
        for thread in &mut self.threads {
            if let Some(stop) = thread.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    /// Join every worker, resuming the first thread that panicked.
    pub fn join(&mut self) {
        let mut first: Option<Panic> = None;
        for thread in self.threads.drain(..) {
            if let Err(panic) = thread.handle.join() {
                if first.is_none() {
                    first = Some(panic);
                } else {
                    mem::forget(panic);
                }
            }
        }
        if let Some(panic) = first {
            resume_unwind(panic);
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // A backstop for partial startup and for an unwind that skips the
        // runner's own stop and join.
        self.stop();
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| self.join())) {
            mem::forget(panic);
        }
    }
}

/// Run pool worker `index` on its own thread until `stopped` resolves. Reports
/// readiness, or the startup failure, through `ready`.
///
/// Once started, the worker sends every failure to `failures`. A failure
/// that ends it early goes before cleanup, since cleanup waits for the runner
/// to close the pool, and only the interrupted root makes it do so.
fn run(
    shared: Arc<Shared>,
    index: u32,
    ready: mpsc::Sender<Result<(), Panic>>,
    stopped: oneshot::Receiver<()>,
    failures: Panicker,
) {
    // Readiness is sent only once the worker exists with its ring and TLS.
    // The sender is kept until then so a startup failure can be returned.
    let mut ready = Some(ready);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (mut worker, _) = Worker::run(
            shared,
            Role::Pool(index),
            || {
                let _ = ready.take().unwrap().send(Ok(()));
                async move {
                    let _ = stopped.await;
                }
            },
            None,
            false,
        )?;
        if let Some(panic) = worker.take_panic() {
            failures.notify(panic);
        }
        worker.cleanup();
        Ok::<_, Panic>(worker.take_panic())
    }));
    let panic = match result {
        Ok(Ok(None)) => return,
        Ok(Ok(Some(panic))) | Ok(Err(panic)) | Err(panic) => panic,
    };

    // A worker that never started must keep the root from running.
    match ready {
        Some(ready) => {
            if let Err(error) = ready.send(Err(panic)) {
                mem::forget(error);
            }
        }
        None => failures.notify(panic),
    }
}
