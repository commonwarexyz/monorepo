//! Runtime threads on Tokio.
//!
//! A runtime thread is a native thread running a `LocalSet` inside the owning runtime's
//! `block_on`, so factories and resident polls see the owning runtime and each resident gets
//! Tokio's per-task cooperative budget. A control future admits queued jobs into the `LocalSet`,
//! at most [BATCH] per poll, and returns once the thread starts closing. On every exit path, the
//! thread body then disposes of the residents, the `LocalSet`, the factories that never ran,
//! the detached jobs, the parked factories and the result slots, in that order and with the
//! runtime entered, and only then releases the thread's node and its tracker guard.
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

    fn available(&self) -> Option<Cpus> {
        if self.tasks.is_closed() {
            return None;
        }
        self.affinity.base().cloned()
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
        drop(panicker);
        drop(affinity);
        drop(runtime);
        drop(inner);
        drop(node);
        drop(tracker);
    }
}

/// Run the thread's host until it closes, then dispose of every resident, queued job, parked
/// factory and result slot, each in its own panic boundary. Returns the host's own failures:
/// a startup failure, or a panic of the control future or of dropping the `LocalSet`.
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
        residents: RefCell::new(BTreeMap::new()),
        next: Cell::new(0),
        batch: RefCell::new(VecDeque::new()),
        deferred: RefCell::new(Vec::new()),
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
        let deferred = host.deferred.take();
        for factory in deferred {
            host.owner.dispose(factory);
        }
        loop {
            let job = host.batch.borrow_mut().pop_front();
            let Some(job) = job else {
                break;
            };
            host.owner.dispose(job);
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
        let turn = host.inner.take_batch(BATCH, &mut host.batch.borrow_mut());
        if turn == Turn::Closing {
            #[cfg(test)]
            tests::on_closing();

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
    inner: Arc<ThreadInner>,
    /// The thread's owner state, handed to every [crate::Local] on it.
    owner: Rc<Owner>,
    /// Abort handles of residents that have not retired, by resident id.
    residents: RefCell<BTreeMap<u64, AbortHandle>>,
    /// Id of the next resident.
    next: Cell<u64>,
    /// Jobs detached from the ingress that have not been admitted.
    batch: RefCell<VecDeque<Job>>,
    /// Factories of admitted residents that never ran because the thread closed, kept so the
    /// close drops them after every resident future.
    deferred: RefCell<Vec<FactoryJob>>,
}

impl Host {
    /// Abort every resident that has not retired.
    fn abort_residents(&self) {
        let residents: Vec<_> = self.residents.borrow().values().cloned().collect();
        for resident in residents {
            resident.abort();
        }
    }

    /// Keep the unrun `factory` of a resident for the close if the thread is closing, or drop it
    /// now, after its task was aborted on an open thread.
    fn discard(&self, factory: FactoryJob) {
        if self.inner.is_open() {
            self.owner.dispose(factory);
            self.owner.reap();
        } else {
            self.deferred.borrow_mut().push(factory);
        }
    }

    /// Spawn `job` into the `LocalSet`, or drop a factory whose task was already aborted.
    fn admit(self: &Rc<Self>, job: Job, local_set: &LocalSet) {
        let Job { work, abort, count } = job;
        let state = match work {
            Work::Factory(factory) if abort.is_aborted() => {
                self.discard(factory);
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
    Factory(FactoryJob),
    /// The task wrapper.
    Future(Resident),
}

/// A resident of a Tokio runtime thread: a `LocalSet` task that runs its factory on its first
/// poll and polls its task wrapper. It disposes of its future, and of a factory that never ran
/// while the thread is open. On a closing thread it hands such a factory to the host, which
/// drops it after every resident future.
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
                this.host.discard(job);
                return Poll::Ready(());
            }
            match job(&this.host.owner) {
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
                this.host.owner.dispose(state);
                Poll::Ready(())
            }
            Err(panic) => {
                this.host.owner.panicker().notify(panic);
                let state = this.state.take();
                this.host.owner.dispose(state);
                Poll::Ready(())
            }
        }
    }
}

impl Drop for ResidentTask {
    fn drop(&mut self) {
        // Tokio drops a task's future inside its own panic boundary, so dispose of the factory
        // or future here, in one that reports.
        match self.state.take() {
            Some(State::Factory(factory)) => self.host.discard(factory),
            Some(state) => self.host.owner.dispose(state),
            None => {}
        }
        self.host.residents.borrow_mut().remove(&self.id);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{Config, Context, Runner};
    use crate::{
        Error, Runner as _, Spawner as _, Supervisor as _,
        threads::testing::{bounded, capturing, closed, flag, is_set, on_drop},
        utils::extract_panic_message,
    };
    use commonware_utils::{
        channel::oneshot::{self, error::TryRecvError},
        sync::Mutex,
    };
    use futures::future::{pending, ready};
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::task::LocalSet;

    /// Whether the next control future that finds its thread closing panics. nextest runs every
    /// test in its own process, so one flag serves the process.
    static HOST_FAILURE: AtomicBool = AtomicBool::new(false);

    /// A callback run after the control future moved a job into the `LocalSet`.
    type AdmitHook = Arc<dyn Fn() + Send + Sync>;

    /// The callback run after every admission into a `LocalSet`.
    static AFTER_ADMIT: Mutex<Option<AdmitHook>> = Mutex::new(None);

    /// Make the next control future that finds its thread closing panic.
    pub(crate) fn inject_host_failure() {
        HOST_FAILURE.store(true, Ordering::SeqCst);
    }

    /// Whether an injected host failure has not fired yet.
    pub(crate) fn host_failure_pending() -> bool {
        HOST_FAILURE.load(Ordering::SeqCst)
    }

    /// Install (or with `None`, remove) the callback run after every admission.
    pub(crate) fn set_after_admit(hook: Option<AdmitHook>) {
        let previous = std::mem::replace(&mut *AFTER_ADMIT.lock(), hook);
        drop(previous);
    }

    /// Panic if a host failure is injected. The control future calls this where it finds its
    /// thread closing, so a close that races a poll cannot slip past the injection.
    pub(super) fn on_closing() {
        if HOST_FAILURE.swap(false, Ordering::SeqCst) {
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

    /// Start a runner with the given panic policy, returning its output or the panic it
    /// failed with.
    fn start<F, Fut>(catch: bool, f: F) -> std::thread::Result<Fut::Output>
    where
        F: FnOnce(Context) -> Fut,
        Fut: Future,
    {
        let cfg = Config::new().with_catch_panics(catch);
        let storage_directory = cfg.storage_directory().clone();
        let result = catch_unwind(AssertUnwindSafe(|| Runner::new(cfg).start(f)));
        let _ = std::fs::remove_dir_all(storage_directory);
        result
    }

    /// `spawn_local` routes by its owner, not by the executor current on the OS thread. A task
    /// spawned from inside a nested `LocalSet` survives that set, runs on the owning thread,
    /// and is aborted when the thread closes. The caller enters a foreign runtime before
    /// spawning, and the factory's timer fires after that runtime shuts down.
    #[test]
    fn test_thread_spawn_local_ignores_ambient_local_set() {
        bounded(|| {
            start(false, |context| async move {
                let creator = context.child("ambient");
                let node = creator.tree.clone();
                let thread = creator.thread().build().unwrap();

                // The spawning resident outlives the check, so only the close can abort the
                // task it spawns.
                let (alive_tx, alive_rx) = oneshot::channel::<()>();
                let (checked_tx, checked_rx) = oneshot::channel();
                let spawner = context
                    .child("spawner")
                    .spawn_on(&thread, move |local| async move {
                        let (started_tx, started_rx) = oneshot::channel();
                        let nested = LocalSet::new();
                        let mut handle = None;
                        let foreign = tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build()
                            .unwrap();
                        let inline = Rc::new(Cell::new(false));
                        nested
                            .run_until(async {
                                let _guard = foreign.enter();
                                handle = Some(local.child("inner").spawn_local({
                                    let inline = inline.clone();
                                    move |_| {
                                        inline.set(true);
                                        let timer = tokio::time::sleep(Duration::from_millis(10));
                                        async move {
                                            let _alive = alive_tx;
                                            timer.await;
                                            started_tx.send(std::thread::current().id()).unwrap();
                                            pending::<()>().await;
                                        }
                                    }
                                }));
                                assert!(!inline.get(), "local factory must be deferred");
                            })
                            .await;

                        // Dropping the nested set would drop a task it owned.
                        drop(nested);
                        foreign.shutdown_background();
                        let started = started_rx.await.expect("task dropped with the nested set");
                        assert_eq!(
                            started,
                            std::thread::current().id(),
                            "local task runs on its owner"
                        );
                        drop(handle);
                        checked_tx.send(()).unwrap();
                        pending::<()>().await;
                    });
                checked_rx.await.unwrap();

                // Closing the thread aborts the detached task.
                node.abort();
                assert!(alive_rx.await.is_err());
                assert!(matches!(spawner.await, Err(Error::Closed)));
            })
        })
        .unwrap();
    }

    /// A `spawn_local` job aborted after the control future moved it into the `LocalSet` and
    /// before its first poll never runs its factory. Its capture drops and its parked factory
    /// is reaped in the same turn, with the thread still open. A `spawn_on` factory admitted as
    /// its thread starts closing, before its first poll, never runs either. The close disposes
    /// of it on the thread and reports the panic of its capture, which fails the runner only
    /// under `catch_panics(false)`.
    #[test]
    fn test_thread_cancel_after_admission() {
        thread_local! {
            /// The handle the admission callback aborts, on the thread.
            static VICTIM: RefCell<Option<crate::LocalHandle<()>>> = const { RefCell::new(None) };
        }

        bounded(|| {
            start(false, |context| async move {
                context
                    .child("cancel")
                    .thread()
                    .spawn(|local| async move {
                        // Abort the stashed handle right after its job enters the LocalSet.
                        let aborted = Arc::new(AtomicBool::new(false));
                        set_after_admit(Some(Arc::new({
                            let aborted = aborted.clone();
                            move || {
                                VICTIM.with(|victim| {
                                    if let Some(handle) = victim.borrow().as_ref() {
                                        handle.abort();
                                        aborted.store(true, Ordering::SeqCst);
                                    }
                                });
                            }
                        })));

                        let ran = Rc::new(Cell::new(false));
                        let (capture, captured) = oneshot::channel::<()>();
                        let handle = local.child("victim").spawn_local({
                            let ran = ran.clone();
                            move |_| {
                                ran.set(true);
                                drop(capture);
                                ready(())
                            }
                        });
                        VICTIM.with(|victim| *victim.borrow_mut() = Some(handle));

                        // The resident resolves once it disposed of its job. Poll the handle in
                        // place, so the callback finds it.
                        let result = std::future::poll_fn(|cx| {
                            VICTIM.with(|victim| {
                                let mut victim = victim.borrow_mut();
                                std::pin::Pin::new(victim.as_mut().unwrap()).poll(cx)
                            })
                        })
                        .await;
                        set_after_admit(None);
                        assert!(matches!(result, Err(Error::Closed)));
                        VICTIM.with(|victim| victim.borrow_mut().take());
                        assert!(aborted.load(Ordering::SeqCst));
                        assert!(!ran.get());
                        let mut captured = captured;
                        assert!(matches!(captured.try_recv(), Err(TryRecvError::Closed)));
                        assert_eq!(local.owner().parked(), 0);
                        assert!(local.home().inner().is_open());
                    })
                    .unwrap()
                    .await
                    .unwrap();
            })
        })
        .unwrap();

        for catch in [false, true] {
            let (home, dropped) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
            let result = bounded({
                let (home, dropped) = (home.clone(), dropped.clone());
                move || {
                    start(catch, move |context| async move {
                        let creator = context.child("deferred");
                        let node = creator.tree.clone();
                        let thread = creator.thread().build().unwrap();
                        let observe = context.child("home");
                        let observe =
                            observe.spawn_on(&thread, |_| ready(std::thread::current().id()));
                        *home.lock() = Some(observe.await.unwrap());

                        // Close the thread right after the control future admits the factory.
                        set_after_admit(Some(Arc::new(move || node.abort())));
                        let capture = on_drop(move || {
                            *dropped.lock() = Some(std::thread::current().id());
                            panic!("deferred capture");
                        });
                        let ran = flag();
                        let victim = context.child("victim");
                        let victim = victim.spawn_on(&thread, capturing(capture, &ran));
                        let victim = closed(victim).await;
                        assert!(victim, "the deferred factory's task stayed open");
                        assert!(!is_set(&ran), "the deferred factory ran");
                    })
                }
            });
            set_after_admit(None);
            let dropped = *dropped.lock();
            let home = *home.lock();
            assert!(dropped.is_some(), "the deferred capture was not dropped");
            assert_eq!(dropped, home, "the capture was dropped off its thread");
            match result {
                Ok(()) => assert!(catch, "the disposal panic did not fail the runner"),
                Err(panic) => {
                    assert!(!catch, "a caught disposal panic failed the runner");
                    assert_eq!(extract_panic_message(&*panic), "deferred capture");
                }
            }
        }
    }

    /// A host failure raised when the thread starts closing, after the runner's root returned,
    /// is published before the thread releases its tracker guard, so it fails the runner.
    #[test]
    fn test_thread_host_failure_during_shutdown_fails_runner() {
        let result = bounded(|| {
            start(false, |context| async move {
                let thread = context.child("closing").thread().build().unwrap();
                context
                    .child("ready")
                    .spawn_on(&thread, |_| ready(()))
                    .await
                    .unwrap();
                drop(
                    context
                        .child("resident")
                        .spawn_on(&thread, |_| pending::<()>()),
                );

                // The thread closes when the runner aborts the root's tree.
                inject_host_failure();
            })
        });
        let panic = result.expect_err("the host failure did not fail the runner");
        assert_eq!(extract_panic_message(&*panic), "injected host failure");
    }
}
