//! Runtime threads on io_uring.
//!
//! A runtime thread is a worker with a thread and io_uring ring of its own, like the worker of a
//! blocking task, whose root future is a [ThreadRoot]: a small executor for the thread's
//! residents. The pool, its run queues and work stealing are not involved. Residents are polled
//! on the thread's worker, so their I/O and sleeps register on its ring.
//!
//! Each turn of the root admits at most [BATCH] queued jobs, in order, then polls at most [BATCH]
//! ready residents, and wakes itself if work remains. Each resident owns one waker for its whole
//! life, carrying a `queued` flag, so a burst of wakes queues it once. Waking the root is
//! coalesced with one `notified` flag, so a burst sends at most one root wake.
//!
//! ```text
//! resident wake                        host turn
//! -------------                        ---------
//! queued: false -> true?               store the root waker, notified := false
//!   push id onto the ready list        closing? close and return
//!   notified: false -> true?           admit <= 64 jobs (each marked queued, pushed)
//!     wake the root                    take <= 64 ready ids, then for each:
//!                                        queued := false, poll, reinsert or retire
//!                                      work left? wake the root
//! ```
//!
//! The thread body runs on every exit path, while it still holds its [ActiveWorker]: it
//! disposes of every queued job if the worker never started, publishes every failure through
//! the runner's thread panicker, and only then releases its node and its reservation.

use super::{ActiveWorker, Panic, Panics, Role, Shared, Worker};
use crate::{
    Cpus, Thread, ThreadError,
    iouring::slab::{Id, Slab},
    telemetry::metrics::task::ThreadLabel,
    threads::{
        Owner, ThreadInner, ThreadRuntime,
        admission::{Job, Resident, ResidentCount, ThreadBackend, Turn, Work},
        validate,
    },
    utils::{self, Aborter, abort::AbortHandle, supervision::Tree},
};
use std::{
    collections::VecDeque,
    future::Future,
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

// Loom models the wake path, so loom builds swap in its primitives.
cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Mutex, MutexGuard, atomic::{AtomicBool, Ordering}};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::sync::atomic::{AtomicBool, Ordering};
    }
}

/// Maximum jobs admitted, and maximum residents polled, per turn.
const BATCH: usize = 64;

/// Backend state of an io_uring runtime thread.
pub(super) struct IouringThread {
    /// The thread's ready list and root wake.
    wake: Arc<WakeState>,
}

impl ThreadBackend for IouringThread {
    fn wake(&self) {
        self.wake.notify();
    }
}

impl IouringThread {
    /// Number of resident ids on the ready list.
    #[cfg(test)]
    pub(super) fn ready_len(&self) -> usize {
        self.wake.lock().ids.len()
    }

    /// Number of root wakes the thread's residents and admission have sent.
    #[cfg(test)]
    pub(super) fn root_wakes(&self) -> usize {
        self.wake.root_wakes.load(Ordering::SeqCst)
    }
}

/// The ready list of a thread's residents and the wake of its root, shared with every
/// resident's waker.
pub(super) struct WakeState {
    /// Ids of residents to poll, each queued at most once until it is polled.
    ready: Mutex<Ready>,
    /// Set by the first wake after the host cleared it, so a burst wakes the root once.
    notified: AtomicBool,
    /// The worker's root waker, stored by the root's first poll.
    root: Mutex<Option<Waker>>,
    /// Root wakes sent.
    #[cfg(test)]
    root_wakes: std::sync::atomic::AtomicUsize,
}

/// The ready list and whether the thread closed it.
struct Ready {
    /// Ids of residents to poll.
    ids: Vec<Id>,
    /// Set once the thread closes. Later wakes do nothing.
    closed: bool,
}

impl WakeState {
    /// An empty, open ready list without a root waker.
    pub(super) fn new() -> Self {
        Self {
            ready: Mutex::new(Ready {
                ids: Vec::new(),
                closed: false,
            }),
            notified: AtomicBool::new(false),
            root: Mutex::new(None),
            #[cfg(test)]
            root_wakes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Lock the ready list.
    fn lock(&self) -> MutexGuard<'_, Ready> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let ready = self.ready.lock().unwrap();
            } else {
                let ready = self.ready.lock();
            }
        }
        ready
    }

    /// Lock the root waker.
    fn root(&self) -> MutexGuard<'_, Option<Waker>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let root = self.root.lock().unwrap();
            } else {
                let root = self.root.lock();
            }
        }
        root
    }

    /// Queue `id` for a poll, then wake the root, unless the thread closed.
    pub(super) fn push(&self, id: Id) {
        {
            let mut ready = self.lock();
            if ready.closed {
                return;
            }
            ready.ids.push(id);
        }
        self.notify();
    }

    /// Wake the root, unless a wake since the host's last turn already did.
    pub(super) fn notify(&self) {
        if self.notified.swap(true, Ordering::SeqCst) {
            return;
        }

        // Wake outside the lock: waking runs no user code, but keeps lock order trivial.
        let root = self.root().clone();
        if let Some(root) = root {
            #[cfg(test)]
            self.root_wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            root.wake();
        }
    }

    /// Start a host turn: record the root waker, then clear `notified`, so a wake from here on
    /// wakes the root again.
    pub(super) fn begin_turn(&self, waker: &Waker) {
        {
            let mut root = self.root();
            if !root.as_ref().is_some_and(|root| root.will_wake(waker)) {
                *root = Some(waker.clone());
            }
        }
        self.notified.store(false, Ordering::SeqCst);
    }

    /// Move up to `max` queued ids, oldest first, into `batch`. Returns whether more remain.
    pub(super) fn take(&self, max: usize, batch: &mut Vec<Id>) -> bool {
        let mut ready = self.lock();
        let count = max.min(ready.ids.len());
        batch.extend(ready.ids.drain(..count));
        !ready.ids.is_empty()
    }

    /// Close the ready list, so later wakes do nothing.
    pub(super) fn close(&self) {
        let mut ready = self.lock();
        ready.closed = true;
        ready.ids.clear();
    }
}

/// The waker of one resident, stable for its whole life.
struct ResidentWaker {
    /// The resident's slot.
    id: Id,
    /// Whether the resident's id is on the ready list or about to be polled.
    queued: AtomicBool,
    /// The thread's ready list.
    wake: Arc<WakeState>,
}

impl Wake for ResidentWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::SeqCst) {
            self.wake.push(self.id);
        }
    }
}

impl ThreadRuntime for Shared {
    fn create_thread(
        self: Arc<Self>,
        node: Arc<Tree>,
        name: &str,
        cpus: Option<Cpus>,
    ) -> Result<Thread, ThreadError> {
        if let Some(cpus) = &cpus {
            validate(cpus, self.affinity.base())?;
        }

        // The reservation keeps shutdown waiting until the thread published its failures.
        let Some(active) = self.workers.reserve() else {
            return Err(ThreadError::Closed);
        };
        let residents = self
            .metrics
            .thread_residents
            .get_or_create(&ThreadLabel::new(name.to_string()))
            .clone();
        let id = self
            .threads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pinned = cpus.is_some();
        let wake = Arc::new(WakeState::new());
        let inner = ThreadInner::new(
            self.runner,
            id,
            name.to_string(),
            cpus,
            &node,
            residents,
            Box::new(IouringThread { wake }),
        );
        if node
            .try_register(Aborter::thread(Arc::downgrade(&inner)))
            .is_err()
        {
            return Err(ThreadError::Closed);
        }
        if pinned {
            self.affinity.arm();
        }

        let stack_size = self.cfg.thread_stack_size;
        let launch = ThreadLaunch {
            shared: self,
            inner: inner.clone(),
            node,
            active,
        };
        match utils::thread::try_spawn(stack_size, Some(utils::thread::name(name)), move || {
            launch.run()
        }) {
            Ok(_) => Ok(Thread::new(inner)),
            Err(error) => {
                // The refused closure already released Shared, the node and the reservation.
                inner.finish_close();
                Err(ThreadError::Spawn(Arc::new(error)))
            }
        }
    }
}

/// What a thread's native thread owns. Fields drop in order, so Shared and the node are
/// released before the reservation.
struct ThreadLaunch {
    /// Runtime services, retained until the worker's cleanup finishes.
    shared: Arc<Shared>,
    /// The thread's shared state.
    inner: Arc<ThreadInner>,
    /// The node the thread occupies, held until its close completes.
    node: Arc<Tree>,
    /// Keeps the runner's shutdown waiting, released last.
    active: ActiveWorker,
}

impl ThreadLaunch {
    /// Run the thread, then publish its failures, on every exit path, before releasing the
    /// node and the reservation.
    fn run(self) {
        let Self {
            shared,
            inner,
            node,
            active,
        } = self;
        let failures = catch_unwind(AssertUnwindSafe(|| run_thread(&shared, &inner)))
            .unwrap_or_else(|panic| {
                dispose_unstarted(&inner);
                vec![panic]
            });
        for failure in failures {
            shared.thread_panicker.notify(failure);
        }
        inner.finish_close();
        drop(shared);
        drop(inner);
        drop(node);
        drop(active);
    }
}

/// Pin the thread, then run its worker with a [ThreadRoot] as the root, and clean the worker
/// up. Returns every failure to publish: a startup failure (of the pin or the ring), or the
/// worker's retained failure.
fn run_thread(shared: &Arc<Shared>, inner: &Arc<ThreadInner>) -> Vec<Panic> {
    // Apply the pin before the ring exists. A failure is a startup failure.
    if let Err(error) = shared.affinity.enter(inner.cpus()) {
        let panic = catch_unwind(AssertUnwindSafe(|| {
            panic!("failed to pin runtime thread to its CPUs: {error}")
        }))
        .expect_err("a startup error must panic");
        dispose_unstarted(inner);
        return vec![panic];
    }

    let wake = inner
        .backend::<IouringThread>()
        .expect("an io_uring thread has io_uring backend state")
        .wake
        .clone();
    let build = || {
        let owner = Owner::new(
            Thread::new(inner.clone()),
            shared.thread_panicker.clone(),
            false,
        );
        ThreadRoot::new(inner.clone(), wake, owner)
    };
    match Worker::run(shared.clone(), Role::Dedicated, build, None) {
        // The ring never came up, so no root was built to dispose of the queued jobs.
        Err(panic) => {
            dispose_unstarted(inner);
            vec![panic]
        }
        Ok((mut worker, output)) => {
            // Drive and callback failures are retained in the worker, which reports them here.
            worker.cleanup();
            worker.result(output).err().into_iter().collect()
        }
    }
}

/// Close admission and drop every queued job of a thread whose root never ran, each contained.
fn dispose_unstarted(inner: &ThreadInner) {
    if let Some(backend) = inner.backend::<IouringThread>() {
        backend.wake.close();
    }
    for job in inner.detach() {
        Panics::contain(move || drop(job));
    }
}

/// The root future of a runtime thread's worker: an executor for the thread's residents.
pub(super) struct ThreadRoot {
    /// The thread's shared state.
    inner: Arc<ThreadInner>,
    /// The thread's ready list and root wake.
    wake: Arc<WakeState>,
    /// The thread's owner state, handed to every [crate::Local] on it.
    owner: Rc<Owner>,
    /// Residents, each taken out of its slot while it is polled.
    residents: Slab<Option<ResidentEntry>>,
    /// Jobs detached from the ingress that have not been admitted.
    batch: VecDeque<Job>,
    /// Ready ids taken for this turn.
    ready: Vec<Id>,
    /// Set once the thread closed.
    closed: bool,
}

/// A resident of a runtime thread on io_uring. Fields drop in order, the future first.
struct ResidentEntry {
    /// The task wrapper.
    future: Resident,
    /// The resident's stable waker.
    waker: Waker,
    /// The waker's state.
    flag: Arc<ResidentWaker>,
    /// Aborts the resident's task when the thread closes.
    abort: AbortHandle,
    /// Counts the resident until it retires.
    _count: Option<ResidentCount>,
}

impl ThreadRoot {
    /// The root of the thread behind `inner`.
    fn new(inner: Arc<ThreadInner>, wake: Arc<WakeState>, owner: Rc<Owner>) -> Self {
        Self {
            inner,
            wake,
            owner,
            residents: Slab::with_capacity(0),
            batch: VecDeque::new(),
            ready: Vec::new(),
            closed: false,
        }
    }

    /// Admit `job` as a resident queued for its first poll, running its factory now, or drop
    /// a factory whose task was aborted or whose thread is closing.
    fn admit(&mut self, job: Job) {
        let Job { work, abort, count } = job;
        let future = match work {
            Work::Placed(future) => future as Resident,
            Work::Factory(factory) => {
                if abort.is_aborted() || !self.inner.is_open() {
                    Panics::contain(move || drop(factory));
                    self.owner.reap();
                    return;
                }
                match factory.run(&self.owner) {
                    Some(future) => future,
                    None => return,
                }
            }
        };
        let wake = self.wake.clone();
        let id = self.residents.insert_with(|id| {
            let flag = Arc::new(ResidentWaker {
                id,
                queued: AtomicBool::new(true),
                wake,
            });
            Some(ResidentEntry {
                future,
                waker: Waker::from(flag.clone()),
                flag,
                abort,
                _count: count,
            })
        });
        self.wake.push(id);
    }

    /// Poll the resident `id` once, unless it retired, then reinsert or retire it.
    fn poll_resident(&mut self, id: Id) {
        let Some(mut entry) = self.residents.get_mut(id).and_then(Option::take) else {
            return;
        };

        // A wake from here on, including one during the poll, queues the next poll.
        entry.flag.queued.store(false, Ordering::SeqCst);
        let mut cx = Context::from_waker(&entry.waker);

        // User poll panics are caught inside the task wrapper, so a panic here is a disposal
        // panic, which io_uring contains.
        match Panics::contain(|| entry.future.as_mut().poll(&mut cx)) {
            Some(Poll::Pending) => {
                if let Some(slot) = self.residents.get_mut(id) {
                    *slot = Some(entry);
                }
            }
            _ => {
                self.residents.remove(id);
                entry.flag.queued.store(true, Ordering::SeqCst);
                Panics::contain(move || drop(entry));
            }
        }
    }

    /// Close the thread: close admission if it is still open, abort every resident, then drop
    /// every resident, queued job, parked factory and result slot, each contained.
    fn close(&mut self) {
        if mem::replace(&mut self.closed, true) {
            return;
        }
        let detached = self.inner.detach();
        self.batch.extend(detached);
        self.wake.close();

        let ids: Vec<Id> = (0..self.residents.slots())
            .filter_map(|index| self.residents.id_at(index))
            .collect();
        for &id in &ids {
            if let Some(Some(entry)) = self.residents.get(id) {
                entry.abort.abort();
            }
        }
        for id in ids {
            if let Some(entry) = self.residents.remove(id).flatten() {
                Panics::contain(move || drop(entry));
            }
        }
        while let Some(job) = self.batch.pop_front() {
            Panics::contain(move || drop(job));
        }
        self.owner.close();
    }
}

impl Future for ThreadRoot {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(());
        }
        this.wake.begin_turn(cx.waker());

        // The aborter may have closed admission before the root registered its waker, so
        // every turn checks admission first.
        let turn = this.inner.take_batch(BATCH, &mut this.batch);
        if turn == Turn::Closing {
            this.close();
            return Poll::Ready(());
        }
        while let Some(job) = this.batch.pop_front() {
            this.admit(job);
        }

        // Poll a bounded batch of ready residents, without holding any lock while they run.
        let mut ready = mem::take(&mut this.ready);
        let more = this.wake.take(BATCH, &mut ready);
        for id in ready.drain(..) {
            this.poll_resident(id);
        }
        this.ready = ready;

        if turn == Turn::More || more {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for ThreadRoot {
    fn drop(&mut self) {
        // The worker drops an unfinished root after a retained failure, when admission may
        // still be open.
        self.close();
    }
}
