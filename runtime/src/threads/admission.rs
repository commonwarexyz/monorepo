//! Admission of work to runtime threads.
//!
//! Each [`Thread`](super::Thread) has one admission lock guarding its state (open, closing or
//! closed) together with its ingress of queued jobs. A submission checks the state and enqueues
//! in one critical section, and a closer sets the closing state under the same lock before it
//! detaches the ingress, so no job is queued behind a close. Nothing runs user code or drops a
//! job under the lock. A rejected job returns to its submitter, and a closer disposes of the
//! detached ingress after unlocking.
//!
//! A job that runs its factory on the thread carries a [`Ticket`] with the task's prepared
//! parts, which close the task's supervision node and resolve its handle if the job is dropped
//! unrun.

use super::{Cpus, Local, local::Owner};
use crate::{
    Handle,
    telemetry::metrics::raw::Gauge,
    utils::{Prepared, supervision::Tree},
};
use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};
#[cfg(not(target_arch = "wasm32"))]
use {crate::utils::abort::AbortHandle, std::collections::VecDeque};

// Loom models the admission lock with the wake path of io_uring threads, so loom builds swap in
// its mutex.
cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Mutex, MutexGuard};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
    }
}

/// Source of runner instance ids, shared by every backend so a [`Thread`](super::Thread) of one
/// runner never matches another, and never reused.
static RUNNER_IDS: AtomicU64 = AtomicU64::new(1);

/// Returns a runner instance id no other runner in this process has.
pub(crate) fn next_runner_id() -> u64 {
    RUNNER_IDS.fetch_add(1, Ordering::Relaxed)
}

/// Backend state of a runtime thread, reached by each backend through [`Any`] on its own paths.
pub(crate) trait ThreadBackend: Any + Send + Sync {
    /// Wake the thread's host so it observes a change of the admission state or the ingress.
    /// Runs no user code.
    fn wake(&self);
}

/// Admission state of a runtime thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// Submissions are admitted.
    Open,
    /// Submissions are rejected and the host is disposing of the thread's work.
    Closing,
    /// The thread's close completed.
    Closed,
}

/// The state and queued jobs guarded by a thread's admission lock.
pub(crate) struct Admission {
    /// Whether submissions are admitted.
    state: State,
    /// Jobs queued for the host, in submission order.
    #[cfg(not(target_arch = "wasm32"))]
    ingress: VecDeque<Job>,
}

/// The shared state of a runtime thread, behind every [`Thread`](super::Thread) handle.
///
/// It holds no context and no runtime services, only ids, the admission lock and the backend
/// state, so a handle kept anywhere keeps nothing of its runner alive.
pub(crate) struct ThreadInner {
    /// Instance id of the runner that created the thread.
    runner: u64,
    /// Id of the thread within its runner.
    id: u64,
    /// Label of the context that created the thread.
    name: String,
    /// CPUs requested with [`ThreadBuilder::pin`](super::ThreadBuilder::pin).
    cpus: Option<Cpus>,
    /// Admission state and ingress.
    admission: Mutex<Admission>,
    /// The supervision node the thread occupies, used only by a root guard to abort it.
    node: Weak<Tree>,
    /// The thread's series of the residents gauge.
    residents: Gauge,
    /// Backend state.
    backend: Box<dyn ThreadBackend>,
}

impl ThreadInner {
    /// Creates the open state of a thread occupying `node`.
    pub(crate) fn new(
        runner: u64,
        id: u64,
        name: String,
        cpus: Option<Cpus>,
        node: &Arc<Tree>,
        residents: Gauge,
        backend: Box<dyn ThreadBackend>,
    ) -> Arc<Self> {
        Arc::new(Self {
            runner,
            id,
            name,
            cpus,
            admission: Mutex::new(Admission {
                state: State::Open,
                #[cfg(not(target_arch = "wasm32"))]
                ingress: VecDeque::new(),
            }),
            node: Arc::downgrade(node),
            residents,
            backend,
        })
    }

    /// Lock the admission state.
    fn lock(&self) -> MutexGuard<'_, Admission> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let admission = self.admission.lock().unwrap();
            } else {
                let admission = self.admission.lock();
            }
        }
        admission
    }

    /// Instance id of the runner that created the thread.
    pub(crate) const fn runner(&self) -> u64 {
        self.runner
    }

    /// Id of the thread within its runner.
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    /// Label of the context that created the thread.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// CPUs requested for the thread.
    pub(crate) const fn cpus(&self) -> Option<&Cpus> {
        self.cpus.as_ref()
    }

    /// The backend state, if it is a `B`, which it is only for threads of `B`'s backend.
    pub(crate) fn backend<B: ThreadBackend>(&self) -> Option<&B> {
        let backend: &dyn Any = &*self.backend;
        backend.downcast_ref()
    }

    /// The node the thread occupies, while it exists.
    pub(crate) fn node(&self) -> Option<Arc<Tree>> {
        self.node.upgrade()
    }

    /// Counts one more resident until the returned guard drops.
    pub(crate) fn count_resident(&self) -> ResidentCount {
        ResidentCount::new(&self.residents)
    }

    /// The current admission state.
    pub(crate) fn state(&self) -> State {
        self.lock().state
    }

    /// Whether submissions are admitted.
    pub(crate) fn is_open(&self) -> bool {
        self.state() == State::Open
    }

    /// Move admission from open to closing, then wake the host if this call closed it.
    ///
    /// Runs no user code, so the thread's aborter and root guard call it directly.
    pub(crate) fn begin_close(&self) {
        let closed = {
            let mut admission = self.lock();
            let open = admission.state == State::Open;
            if open {
                admission.state = State::Closing;
            }
            open
        };
        if closed {
            self.backend.wake();
        }
    }

    /// Mark the thread's close complete.
    pub(crate) fn finish_close(&self) {
        self.lock().state = State::Closed;
    }

    /// Run `register` in the critical section that admits a submission, if the thread is open.
    ///
    /// `register` must take only leaf locks and run no user code.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn admit<R>(&self, register: impl FnOnce() -> R) -> Option<R> {
        let admission = self.lock();
        if admission.state != State::Open {
            return None;
        }

        #[cfg(test)]
        tests::before_enqueue();

        let registered = register();
        drop(admission);
        Some(registered)
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Queue `job` for the host and wake it, or return `job` if the thread is not open. The
    /// caller drops a rejected job after this returns, outside the lock.
    pub(crate) fn submit(&self, mut job: Job) -> Result<(), Job> {
        {
            let mut admission = self.lock();
            if admission.state != State::Open {
                return Err(job);
            }

            #[cfg(test)]
            tests::before_enqueue();

            job.count = Some(self.count_resident());
            admission.ingress.push_back(job);
        }
        self.backend.wake();
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Move up to `max` queued jobs, oldest first, into `batch`, unless the thread is closing.
    pub(crate) fn take_batch(&self, max: usize, batch: &mut VecDeque<Job>) -> Turn {
        let mut admission = self.lock();
        if admission.state != State::Open {
            return Turn::Closing;
        }
        let count = max.min(admission.ingress.len());
        batch.extend(admission.ingress.drain(..count));
        if admission.ingress.is_empty() {
            Turn::Drained
        } else {
            Turn::More
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Move admission to closing, if it is open, and detach every queued job for disposal
    /// outside the lock.
    pub(crate) fn detach(&self) -> VecDeque<Job> {
        let mut admission = self.lock();
        if admission.state == State::Open {
            admission.state = State::Closing;
        }
        std::mem::take(&mut admission.ingress)
    }

    /// Number of queued jobs.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn queued(&self) -> usize {
        self.lock().ingress.len()
    }
}

/// What a host found when it took a batch of jobs.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Turn {
    /// The thread is closing, and no job was taken.
    Closing,
    /// The ingress is empty after the batch.
    Drained,
    /// Jobs remain queued after the batch.
    More,
}

/// Counts one resident of a thread in its residents gauge until dropped.
pub(crate) struct ResidentCount(Gauge);

impl ResidentCount {
    /// Increments `gauge` and returns the guard that decrements it.
    fn new(gauge: &Gauge) -> Self {
        gauge.inc();
        Self(gauge.clone())
    }
}

impl Drop for ResidentCount {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Work queued in a thread's ingress.
///
/// Fields drop in order: the work (a factory before its ticket), then the abort handle, then the
/// resident count.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Job {
    /// The queued work.
    pub(crate) work: Work,
    /// Aborts the job's task, so a host can skip a factory whose task was aborted.
    pub(crate) abort: AbortHandle,
    /// Counts the job as a resident once admitted.
    pub(crate) count: Option<ResidentCount>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Job {
    /// A placed spawn's task wrapper, built on the caller.
    pub(crate) fn placed(
        wrapper: Pin<Box<dyn Future<Output = ()> + Send>>,
        abort: AbortHandle,
    ) -> Self {
        Self {
            work: Work::Placed(wrapper),
            abort,
            count: None,
        }
    }

    /// A factory that builds its task's future on the thread.
    pub(crate) fn factory(factory: Box<dyn FactoryJob>, abort: AbortHandle) -> Self {
        Self {
            work: Work::Factory(factory),
            abort,
            count: None,
        }
    }
}

/// The work of a [`Job`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum Work {
    /// A `Send` task wrapper whose factory already ran on the caller.
    Placed(Pin<Box<dyn Future<Output = ()> + Send>>),
    /// A factory to run on the thread.
    Factory(Box<dyn FactoryJob>),
}

/// A task's resident future: its task wrapper, which need not be `Send`.
pub(crate) type Resident = Pin<Box<dyn Future<Output = ()>>>;

/// A factory queued toward a thread, with the ticket of its task.
pub(crate) trait FactoryJob: Send + 'static {
    /// Run the factory on the thread with `owner`, and wrap the future it returns as the
    /// task. A factory panic is reported through the owner's panicker, resolves the handle with
    /// [`crate::Error::Exited`] and returns `None`.
    fn run(self: Box<Self>, owner: &Rc<Owner>) -> Option<Resident>;
}

/// A [`FactoryJob`] built by [`crate::Spawner::spawn_on`].
///
/// Fields drop in order, so a job dropped unrun drops its factory, then its context, then its
/// ticket.
pub(crate) struct SpawnJob<C, F, T>
where
    T: Send + 'static,
{
    /// The user's factory, with its captures.
    factory: F,
    /// The context handed to the factory, placed on the thread.
    context: C,
    /// The task's prepared parts.
    ticket: Ticket<T>,
}

impl<C, F, T> SpawnJob<C, F, T>
where
    T: Send + 'static,
{
    /// A job running `factory` with `context` as the task `ticket` belongs to.
    pub(crate) const fn new(factory: F, context: C, ticket: Ticket<T>) -> Self {
        Self {
            factory,
            context,
            ticket,
        }
    }
}

impl<C, F, Fut, T> FactoryJob for SpawnJob<C, F, T>
where
    C: Send + 'static,
    F: FnOnce(Local<C>) -> Fut + Send + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    fn run(self: Box<Self>, owner: &Rc<Owner>) -> Option<Resident> {
        let Self {
            factory,
            context,
            ticket,
        } = *self;
        let local = Local::new(context, owner.clone());
        match catch_unwind(AssertUnwindSafe(move || factory(local))) {
            Ok(future) => Some(Box::pin(Handle::wrap(
                ticket.take(),
                future,
                owner.panicker().clone(),
            ))),
            Err(panic) => {
                owner.panicker().notify(panic);
                ticket.exit();
                None
            }
        }
    }
}

/// A task's prepared parts while its factory waits to run on a thread.
///
/// It replaces [`crate::utils::FactoryGuard`] for factories that run on the thread. When the
/// task wrapper takes over, the ticket is consumed. Dropped unconsumed, it aborts the task's
/// node, finishes its metric and drops its result sink, in that order, so the handle resolves
/// [`crate::Error::Closed`].
pub(crate) struct Ticket<T>(Option<Prepared<T>>)
where
    T: Send + 'static;

impl<T> Ticket<T>
where
    T: Send + 'static,
{
    /// Hold `prepared` until the factory runs.
    pub(crate) const fn new(prepared: Prepared<T>) -> Self {
        Self(Some(prepared))
    }

    /// Hand the parts to the task wrapper.
    fn take(mut self) -> Prepared<T> {
        self.0.take().expect("ticket consumed twice")
    }

    /// Resolve the task's handle with [`crate::Error::Exited`] after its factory panicked, then
    /// close its node.
    fn exit(mut self) {
        if let Some(prepared) = self.0.take() {
            prepared.exit();
        }
    }
}

impl<T> Drop for Ticket<T>
where
    T: Send + 'static,
{
    fn drop(&mut self) {
        if let Some(prepared) = self.0.take() {
            prepared.close();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use commonware_utils::sync::Mutex;
    use std::sync::Arc;

    /// A callback run between an admission check and the enqueue or registration it guards.
    type AdmissionHook = Arc<dyn Fn() + Send + Sync>;

    /// The callback run by every admission. nextest runs every test in its own process, so one
    /// slot serves the process.
    static BEFORE_ENQUEUE: Mutex<Option<AdmissionHook>> = Mutex::new(None);

    /// Install (or with `None`, remove) the callback run by every admission.
    pub(crate) fn set_before_enqueue(hook: Option<AdmissionHook>) {
        let previous = std::mem::replace(&mut *BEFORE_ENQUEUE.lock(), hook);
        drop(previous);
    }

    /// Run the installed callback, outside the slot's lock.
    pub(super) fn before_enqueue() {
        let hook = BEFORE_ENQUEUE.lock().clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}
