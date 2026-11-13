//! Runtime threads on Tokio.
//!
//! A runtime thread is a native thread running a `LocalSet` inside the owning runtime's
//! `block_on`, so factories and resident polls see the owning runtime and each resident gets
//! Tokio's per-task cooperative budget. A control future admits queued jobs into the `LocalSet`,
//! at most [BATCH] per poll, and returns once the thread starts closing. The thread body then
//! disposes of everything, in order, on every exit path, and only then releases the thread's
//! node and its tracker guard.
//!
//! ```text
//! thread body
//!   +-- apply the pin, or the armed reset
//!   +-- block_on(local_set.run_until(control))      control: admit <= 64 jobs per poll
//!   |                                                         return once closing
//!   +-- close admission, detach the ingress
//!   +-- runtime entered:
//!   |     abort residents, drop the LocalSet (each resident disposes of itself),
//!   |     drop detached jobs, parked factories and result slots
//!   +-- publish failures, mark closed
//!   +-- release the node, then the tracker guard
//! ```
//!
//! Residents are aborted only through the runtime's own [AbortHandle]s, and each resident
//! wrapper disposes of its future in its own panic boundary, because Tokio swallows panics
//! raised while it drops a task's future.

use super::{Executor, TaskGuard};
use crate::{
    Cpus, Thread, ThreadError,
    telemetry::metrics::task::ThreadLabel,
    threads::{
        Owner, ThreadInner, ThreadRuntime,
        admission::{FactoryJob, Job, Resident, ResidentCount, ThreadBackend, Turn, Work},
        affinity::AffinityState,
        validate,
    },
    utils::{self, Aborter, Panicker, abort::AbortHandle, supervision::Tree},
};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::{Pin, pin},
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::{runtime::Handle as RuntimeHandle, sync::Notify, task::LocalSet};

/// Maximum jobs the control future admits per poll.
const BATCH: usize = 64;

/// Backend state of a Tokio runtime thread.
pub(super) struct TokioThread {
    /// Wakes the control future. It stores at most one permit, which coalesces bursts.
    notify: Notify,
}

impl ThreadBackend for TokioThread {
    fn wake(&self) {
        self.notify.notify_one();
    }
}

impl ThreadRuntime for Executor {
    fn create_thread(
        self: Arc<Self>,
        node: Arc<Tree>,
        name: &str,
        cpus: Option<Cpus>,
    ) -> Result<Thread, ThreadError> {
        if let Some(cpus) = &cpus {
            validate(cpus, self.affinity.base())?;
        }

        // The thread counts as a task until its disposal finishes and its failures are
        // published.
        let Some(tracker) = self.tasks.admit() else {
            return Err(ThreadError::Closed);
        };
        let residents = self
            .metrics
            .thread_residents
            .get_or_create(&ThreadLabel::new(name.to_string()))
            .clone();
        let id = self.threads.fetch_add(1, Ordering::Relaxed);
        let pinned = cpus.is_some();
        let inner = ThreadInner::new(
            self.runner,
            id,
            name.to_string(),
            cpus,
            &node,
            residents,
            Box::new(TokioThread {
                notify: Notify::new(),
            }),
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

        let body = Body {
            runtime: self.runtime.clone(),
            panicker: self.panicker.clone(),
            affinity: self.affinity.clone(),
            inner: inner.clone(),
            node,
            tracker,
        };
        match utils::thread::try_spawn(
            self.thread_stack_size,
            Some(utils::thread::name(name)),
            move || body.run(),
        ) {
            Ok(_) => Ok(Thread::new(inner)),
            Err(error) => {
                // The refused closure already released the node and the tracker guard.
                inner.finish_close();
                Err(ThreadError::Spawn(Arc::new(error)))
            }
        }
    }
}

/// What a thread's native thread owns. Fields drop in order, so a refused thread releases its
/// node before its tracker guard.
struct Body {
    /// Runtime whose `block_on` runs the thread's `LocalSet`.
    runtime: RuntimeHandle,
    /// Reports the thread's task and host failures.
    panicker: Panicker,
    /// The runner's base set and reset.
    affinity: Arc<AffinityState>,
    /// The thread's shared state.
    inner: Arc<ThreadInner>,
    /// The node the thread occupies, held until its close completes.
    node: Arc<Tree>,
    /// Keeps the runner's shutdown waiting, released last.
    tracker: TaskGuard,
}

impl Body {
    /// Run the thread, then close it, on every exit path. A panic of the host itself is caught
    /// while the tracker guard is still held, and published before the guard is released.
    fn run(self) {
        let Self {
            runtime,
            panicker,
            affinity,
            inner,
            node,
            tracker,
        } = self;
        let failures = catch_unwind(AssertUnwindSafe(|| {
            host(&runtime, &panicker, &affinity, &inner)
        }))
        .unwrap_or_else(|panic| {
            // The host failed outside its own boundaries, so close what it may have left.
            let mut failures = vec![panic];
            let _enter = runtime.enter();
            for job in inner.detach() {
                if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(job))) {
                    failures.push(panic);
                }
            }
            failures
        });
        for failure in failures {
            panicker.notify(failure);
        }
        inner.finish_close();
        drop(inner);
        drop(node);
        drop(tracker);
    }
}

/// Run the thread's host until it closes, then dispose of every resident, queued job, parked
/// factory and result slot, each in its own panic boundary. Returns the host's own failures:
/// a startup failure or a panic of the control future.
fn host(
    runtime: &RuntimeHandle,
    panicker: &Panicker,
    affinity: &AffinityState,
    inner: &Arc<ThreadInner>,
) -> Vec<Box<dyn Any + Send>> {
    let mut failures = Vec::new();

    // Apply the pin before anything else. A failure is a late startup failure.
    let started = affinity.enter(inner.cpus()).map_err(|error| {
        catch_unwind(AssertUnwindSafe(|| {
            panic!("failed to pin runtime thread to its CPUs: {error}")
        }))
        .expect_err("a startup error must panic")
    });

    // The owner half lives on this thread, in this frame.
    let owner = Owner::new(Thread::new(inner.clone()), panicker.clone(), true);
    let host = Rc::new(Host {
        inner: inner.clone(),
        owner,
        panicker: panicker.clone(),
        residents: RefCell::new(BTreeMap::new()),
        next: Cell::new(0),
        batch: RefCell::new(VecDeque::new()),
    });
    let local_set = LocalSet::new();
    match started {
        Ok(()) => {
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
                runtime.block_on(local_set.run_until(control(&host, &local_set)))
            })) {
                failures.push(panic);
            }
        }
        Err(panic) => failures.push(panic),
    }

    // Close admission and keep the detached jobs in thread-owned state.
    host.batch.borrow_mut().extend(inner.detach());

    // Dispose of everything with the owning runtime entered, residents first.
    {
        let _enter = runtime.enter();
        host.abort_residents();
        if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(local_set))) {
            failures.push(panic);
        }
        loop {
            let job = host.batch.borrow_mut().pop_front();
            let Some(job) = job else {
                break;
            };
            host.dispose(job);
        }
        host.owner.close();
    }
    failures
}

/// Admit at most [BATCH] queued jobs per poll into the `LocalSet`, and return once the thread is
/// closing, after aborting its residents.
async fn control(host: &Rc<Host>, local_set: &LocalSet) {
    let notify = &host
        .inner
        .backend::<TokioThread>()
        .expect("a Tokio thread has Tokio backend state")
        .notify;
    let mut notified = pin!(notify.notified());
    poll_fn(|cx| {
        #[cfg(test)]
        tests::before_control(&host.inner);

        let turn = host.inner.take_batch(BATCH, &mut host.batch.borrow_mut());
        if turn == Turn::Closing {
            // Residents retire as the thread body disposes of them. Nothing would wake this
            // future when the last one does, so return now.
            host.abort_residents();
            return Poll::Ready(());
        }
        loop {
            let job = host.batch.borrow_mut().pop_front();
            let Some(job) = job else {
                break;
            };
            host.admit(job, local_set);
        }

        // Let the LocalSet tick residents between batches, and treat a notification as a hint
        // to look at the ingress again, never as a count.
        if turn == Turn::More {
            cx.waker().wake_by_ref();
        } else if notified.as_mut().poll(cx).is_ready() {
            notified.set(notify.notified());
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}

/// The owner half of a Tokio runtime thread, on its native thread.
struct Host {
    /// The thread's shared state.
    inner: Arc<ThreadInner>,
    /// The thread's owner state, handed to every [crate::Local] on it.
    owner: Rc<Owner>,
    /// Reports task and disposal panics.
    panicker: Panicker,
    /// Abort handles of residents that have not retired, by resident id.
    residents: RefCell<BTreeMap<u64, AbortHandle>>,
    /// Id of the next resident.
    next: Cell<u64>,
    /// Jobs detached from the ingress that have not been admitted.
    batch: RefCell<VecDeque<Job>>,
}

impl Host {
    /// Drop `value` in its own panic boundary, reporting a panic.
    fn dispose<V>(&self, value: V) {
        if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(value))) {
            self.panicker.notify(panic);
        }
    }

    /// Abort every resident that has not retired.
    fn abort_residents(&self) {
        let residents: Vec<_> = self.residents.borrow().values().cloned().collect();
        for resident in residents {
            resident.abort();
        }
    }

    /// Spawn `job` into the `LocalSet`, or drop a factory whose task was already aborted.
    fn admit(self: &Rc<Self>, job: Job, local_set: &LocalSet) {
        let Job { work, abort, count } = job;
        let state = match work {
            Work::Factory(factory) if abort.is_aborted() => {
                self.dispose(factory);
                self.owner.reap();
                return;
            }
            Work::Factory(factory) => State::Factory(factory),
            Work::Placed(future) => State::Future(future),
        };
        let id = self.next.get();
        self.next.set(id + 1);
        self.residents.borrow_mut().insert(id, abort.clone());
        let resident = ResidentTask {
            host: self.clone(),
            id,
            state: Some(state),
            abort,
            _count: count,
        };
        drop(local_set.spawn_local(resident));

        #[cfg(test)]
        tests::after_admit();
    }
}

/// What a resident holds.
enum State {
    /// A factory that has not run.
    Factory(Box<dyn FactoryJob>),
    /// The task wrapper.
    Future(Resident),
}

/// A resident of a Tokio runtime thread: a `LocalSet` task that runs its factory on its first
/// poll and polls its task wrapper, and owns their disposal.
struct ResidentTask {
    /// The thread's owner half.
    host: Rc<Host>,
    /// Id in the host's resident registry.
    id: u64,
    /// The factory or future, until the resident disposes of it.
    state: Option<State>,
    /// Aborts the resident's task.
    abort: AbortHandle,
    /// Counts the resident until it retires.
    _count: Option<ResidentCount>,
}

impl Future for ResidentTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if matches!(this.state, Some(State::Factory(_))) {
            let Some(State::Factory(job)) = this.state.take() else {
                unreachable!("checked above");
            };

            // Cancellation can arrive after admission and before this first poll.
            if this.abort.is_aborted() || !this.host.inner.is_open() {
                this.host.dispose(job);
                this.host.owner.reap();
                return Poll::Ready(());
            }
            match job.run(&this.host.owner) {
                Some(future) => this.state = Some(State::Future(future)),
                None => return Poll::Ready(()),
            }
        }
        let Some(State::Future(future)) = &mut this.state else {
            return Poll::Ready(());
        };

        // User poll panics are caught inside the task wrapper, so a panic here is a disposal
        // panic, which Tokio would otherwise swallow.
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(())) => {
                let state = this.state.take();
                this.host.dispose(state);
                Poll::Ready(())
            }
            Err(panic) => {
                this.host.panicker.notify(panic);
                let state = this.state.take();
                this.host.dispose(state);
                Poll::Ready(())
            }
        }
    }
}

impl Drop for ResidentTask {
    fn drop(&mut self) {
        // Tokio drops a task's future inside its own panic boundary, so dispose of the factory
        // or future here, in one that reports.
        if let Some(state) = self.state.take() {
            let unrun = matches!(state, State::Factory(_));
            self.host.dispose(state);
            if unrun {
                self.host.owner.reap();
            }
        }
        self.host.residents.borrow_mut().remove(&self.id);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use crate::threads::{ThreadInner, admission::State};
    use commonware_utils::sync::Mutex;
    use std::sync::Arc;

    /// When an injected host failure fires.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum HostFailure {
        /// On the control future's next poll.
        Now,
        /// On the first poll that finds the thread closing.
        WhenClosing,
    }

    /// The next injected host failure. nextest runs every test in its own process, so one slot
    /// serves the process.
    static HOST_FAILURE: Mutex<Option<HostFailure>> = Mutex::new(None);

    /// A callback run after the control future moved a job into the `LocalSet`.
    type AdmitHook = Arc<dyn Fn() + Send + Sync>;

    /// The callback run after every admission into a `LocalSet`.
    static AFTER_ADMIT: Mutex<Option<AdmitHook>> = Mutex::new(None);

    /// Make the next control future that reaches `failure` panic.
    pub(crate) fn inject_host_failure(failure: HostFailure) {
        *HOST_FAILURE.lock() = Some(failure);
    }

    /// Install (or with `None`, remove) the callback run after every admission.
    pub(crate) fn set_after_admit(hook: Option<AdmitHook>) {
        let previous = std::mem::replace(&mut *AFTER_ADMIT.lock(), hook);
        drop(previous);
    }

    /// Panic if an injected host failure is due.
    pub(super) fn before_control(inner: &ThreadInner) {
        let due = {
            let mut failure = HOST_FAILURE.lock();
            let due = match *failure {
                Some(HostFailure::Now) => true,
                Some(HostFailure::WhenClosing) => inner.state() != State::Open,
                None => false,
            };
            if due {
                *failure = None;
            }
            due
        };
        if due {
            panic!("injected host failure");
        }
    }

    /// Run the installed admission callback, outside the slot's lock.
    pub(super) fn after_admit() {
        let hook = AFTER_ADMIT.lock().clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}
