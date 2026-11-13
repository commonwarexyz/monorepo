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
    use super::{
        super::{Config, Context, Runner},
        BATCH,
    };
    use crate::{
        Error, Metrics as _, Runner as _, Spawner as _, Supervisor as _, ThreadError,
        threads::{Local, admission::State},
        utils::extract_panic_message,
    };
    use commonware_utils::{
        channel::oneshot::{self, error::TryRecvError},
        sync::Mutex,
    };
    use futures::future::{pending, ready};
    use rstest::rstest;
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::ThreadId,
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

    // Tests of Tokio runtime threads and of their accounting after a failed OS-thread spawn.

    /// Run `body` on a helper thread, failing if it does not finish in time, so a test that
    /// breaks by deadlock fails instead of hanging.
    fn within<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(catch_unwind(AssertUnwindSafe(body)));
        });
        match done_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(value)) => value,
            Ok(Err(panic)) => resume_unwind(panic),
            Err(_) => panic!("the runner did not return"),
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

    /// Context of a new task placed on `local`'s thread, spawned with `spawn_on`.
    fn sibling(local: &Local<Context>, label: &'static str) -> Context {
        local.child(label).into_inner()
    }

    /// Counts the errors logged on the thread it is installed on.
    struct CountErrors(Arc<AtomicUsize>);

    impl tracing::Subscriber for CountErrors {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::ERROR
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, _: &tracing::Event<'_>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Records the thread it is dropped on, then panics.
    struct Exploding(Arc<Mutex<Vec<ThreadId>>>);

    impl Drop for Exploding {
        fn drop(&mut self) {
            self.0.lock().push(std::thread::current().id());
            panic!("disposal panic");
        }
    }

    /// Records its label when dropped.
    struct Record(&'static str, Arc<Mutex<Vec<&'static str>>>);

    impl Drop for Record {
        fn drop(&mut self) {
            self.1.lock().push(self.0);
        }
    }

    /// The value of the residents gauge of threads labeled `name`, if it is registered.
    fn residents(context: &Context, name: &str) -> Option<i64> {
        let series = format!("thread_residents{{name=\"{name}\"}} ");
        context.encode().lines().find_map(|line| {
            let (_, value) = line.split_once(&series)?;
            value.trim().parse().ok()
        })
    }

    /// A `spawn_local` factory runs on the thread in the owning runtime, never inside the
    /// caller's poll. The caller holds a foreign runtime's enter guard while it spawns, and the
    /// factory creates a timer before returning its future. The timer fires after the foreign
    /// runtime is shut down, so it was bound to the owning runtime.
    #[test]
    fn test_thread_spawn_local_binds_owning_runtime() {
        let value = within(|| {
            start(false, |context| async move {
                context
                    .child("binding")
                    .thread()
                    .spawn(|local| async move {
                        let foreign = tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build()
                            .unwrap();
                        let handle = {
                            let _guard = foreign.enter();
                            local.child("timer").spawn_local(|_| {
                                let sleep = tokio::time::sleep(Duration::from_millis(10));
                                async move {
                                    sleep.await;
                                    7
                                }
                            })
                        };
                        foreign.shutdown_background();
                        handle.await.unwrap()
                    })
                    .unwrap()
                    .await
                    .unwrap()
            })
        })
        .unwrap();
        assert_eq!(value, 7);
    }

    /// `spawn_local` routes by its owner, not by the executor current on the OS thread. A task
    /// spawned from inside a nested `LocalSet` survives that set, runs on the owning thread,
    /// and is aborted when the thread closes.
    #[test]
    fn test_thread_spawn_local_ignores_ambient_local_set() {
        within(|| {
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
                        nested
                            .run_until(async {
                                handle =
                                    Some(local.child("inner").spawn_local(move |_| async move {
                                        let _alive = alive_tx;
                                        started_tx.send(std::thread::current().id()).unwrap();
                                        pending::<()>().await;
                                    }));
                            })
                            .await;

                        // Dropping the nested set would drop a task it owned.
                        drop(nested);
                        let started = started_rx.await.expect("task dropped with the nested set");
                        assert_eq!(started, std::thread::current().id());
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

    /// Jobs queued before the thread's next turn all start, even when they exceed two
    /// admission batches and nothing else is submitted afterwards.
    #[test]
    fn test_thread_prequeued_ingress_all_start() {
        const JOBS: usize = 3 * BATCH;
        let total = within(|| {
            start(false, |context| async move {
                context
                    .child("prequeued")
                    .thread()
                    .spawn(|local| async move {
                        // Queue every job in one poll of the root, so the host cannot take a
                        // turn in between.
                        let handles: Vec<_> = (0..JOBS)
                            .map(|i| {
                                sibling(&local, "job").spawn_on(local.home(), move |_| ready(i))
                            })
                            .collect();
                        assert_eq!(local.home().inner().queued(), JOBS);

                        let mut total = 0;
                        for handle in handles {
                            total += handle.await.unwrap();
                        }
                        total
                    })
                    .unwrap()
                    .await
                    .unwrap()
            })
        })
        .unwrap();
        assert_eq!(total, (0..JOBS).sum::<usize>());
    }

    /// Residents already on a thread keep getting polled while another OS thread keeps its
    /// ingress non-empty.
    #[test]
    fn test_thread_busy_producer_keeps_residents_polled() {
        /// Turns the resident must take while jobs are queued.
        const TURNS: usize = 100;
        within(|| {
            start(false, |context| async move {
                let thread = context.child("busy").thread().build().unwrap();
                let resident = context
                    .child("resident")
                    .spawn_on(&thread, |local| async move {
                        let mut contended = 0;
                        while contended < TURNS {
                            if local.home().inner().queued() > 0 {
                                contended += 1;
                            }
                            tokio::task::yield_now().await;
                        }
                    });

                // Keep the ingress non-empty, and bounded, until the resident finishes.
                let stop = Arc::new(AtomicBool::new(false));
                let producer = std::thread::spawn({
                    let context = context.child("producer");
                    let thread = thread.clone();
                    let stop = stop.clone();
                    move || {
                        while !stop.load(Ordering::SeqCst) {
                            if thread.inner().queued() >= 16 * BATCH {
                                std::thread::yield_now();
                                continue;
                            }
                            for _ in 0..BATCH {
                                drop(context.child("job").spawn_on(&thread, |_| ready(())));
                            }
                        }
                    }
                });
                resident.await.unwrap();
                stop.store(true, Ordering::SeqCst);
                producer.join().unwrap();
            })
        })
        .unwrap();
    }

    /// How a teardown test closes its thread.
    #[derive(Clone, Copy, Debug)]
    enum Close {
        /// The thread's node is aborted.
        Normal,
        /// The host panics.
        HostFailure,
    }

    /// Residents whose destructors panic are disposed of on the thread during teardown, polled
    /// or not, on a normal close and after a host failure. Each panic is reported through
    /// `Panicker::notify`, every handle resolves `Closed`, the residents gauge settles to zero,
    /// and the runner fails with the panic only under `catch_panics(false)`.
    #[rstest]
    fn test_thread_teardown_disposal(
        #[values(Close::Normal, Close::HostFailure)] close: Close,
        #[values(false, true)] catch: bool,
    ) {
        /// Residents polled before the close.
        const POLLED: usize = 2;
        /// Residents in the `LocalSet` whose factories have not run when the close starts.
        const UNPOLLED: usize = 4;

        let drops = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(AtomicUsize::new(0));
        let home = Arc::new(Mutex::new(None));
        let ran = Arc::new(AtomicBool::new(false));
        let result = within({
            let (drops, errors, home, ran) =
                (drops.clone(), errors.clone(), home.clone(), ran.clone());
            move || {
                start(catch, move |context| async move {
                    let creator = context.child("teardown");
                    let node = creator.tree.clone();
                    let thread = creator.thread().build().unwrap();

                    // Count the errors logged on the thread, and record which thread it is.
                    context
                        .child("observe")
                        .spawn_on(&thread, move |_| {
                            std::mem::forget(tracing::subscriber::set_default(CountErrors(errors)));
                            *home.lock() = Some(std::thread::current().id());
                            ready(())
                        })
                        .await
                        .unwrap();

                    // Polled residents hold a value that panics when dropped.
                    let mut handles = Vec::new();
                    for _ in 0..POLLED {
                        let (started_tx, started_rx) = oneshot::channel();
                        let drops = drops.clone();
                        handles.push(context.child("polled").spawn_on(
                            &thread,
                            move |_| async move {
                                let _value = Exploding(drops);
                                started_tx.send(()).unwrap();
                                pending::<()>().await;
                            },
                        ));
                        started_rx.await.unwrap();
                    }

                    // Close the thread as soon as the control future has moved every unpolled
                    // resident into the LocalSet (the submitter is admitted first).
                    let admitted = AtomicUsize::new(0);
                    set_after_admit(Some(Arc::new(move || {
                        if admitted.fetch_add(1, Ordering::SeqCst) + 1 == UNPOLLED + 1 {
                            match close {
                                Close::Normal => node.abort(),
                                Close::HostFailure => panic!("injected host failure"),
                            }
                        }
                    })));

                    // Queue the unpolled residents within one poll of a resident, so the host
                    // admits them all in its next turn. Their factories hold the values, and
                    // their contexts come from the root, so the submitter ending does not
                    // abort them.
                    let contexts: Vec<_> =
                        (0..UNPOLLED).map(|_| context.child("unpolled")).collect();
                    let unpolled = context
                        .child("submitter")
                        .spawn_on(&thread, move |local| {
                            let handles: Vec<_> = contexts
                                .into_iter()
                                .map(|context| {
                                    let value = Exploding(drops.clone());
                                    let ran = ran.clone();
                                    context.spawn_on(local.home(), move |_| {
                                        ran.store(true, Ordering::SeqCst);
                                        drop(value);
                                        ready(())
                                    })
                                })
                                .collect();
                            ready(handles)
                        })
                        .await
                        .unwrap();
                    handles.extend(unpolled);
                    for handle in handles {
                        assert!(matches!(handle.await, Err(Error::Closed)));
                    }

                    // The bookkeeping completes.
                    while residents(&context, "teardown") != Some(0) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
            }
        });

        // Each destructor ran once, on the thread, and no unpolled factory ran.
        let home = home.lock().expect("thread observed");
        let drops = drops.lock();
        assert_eq!(drops.len(), POLLED + UNPOLLED);
        assert!(drops.iter().all(|thread| *thread == home));
        assert!(!ran.load(Ordering::SeqCst));

        // Each panic, and the host failure, reached Panicker::notify, which logs it.
        let failures = match close {
            Close::Normal => POLLED + UNPOLLED,
            Close::HostFailure => POLLED + UNPOLLED + 1,
        };
        assert_eq!(errors.load(Ordering::SeqCst), failures);
        if catch {
            result.expect("caught disposal panics failed the runner");
        } else {
            let panic = result.expect_err("a disposal panic did not fail the runner");
            assert_eq!(extract_panic_message(&*panic), "disposal panic");
        }
    }

    /// A `spawn_local` job aborted after the control future moved it into the `LocalSet` and
    /// before its first poll never runs its factory. Its capture drops and its parked factory
    /// is reaped in the same turn, with the thread still open.
    #[test]
    fn test_thread_cancel_after_admission() {
        thread_local! {
            /// The handle the admission callback aborts, on the thread.
            static VICTIM: RefCell<Option<crate::LocalHandle<()>>> = const { RefCell::new(None) };
        }

        within(|| {
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
    }

    /// A close drops the thread's pending residents before its queued jobs, on a normal close
    /// and after a host failure. Afterwards the thread holds no job.
    #[rstest]
    fn test_thread_close_drops_residents_before_jobs(#[values(false, true)] host_failure: bool) {
        let order = Arc::new(Mutex::new(Vec::new()));
        let thread = within({
            let order = order.clone();
            move || {
                start(true, move |context| async move {
                    if host_failure {
                        inject_host_failure();
                    }
                    let (home_tx, home_rx) = oneshot::channel();
                    let (queue_tx, queue_rx) = oneshot::channel::<()>();
                    let root = context
                        .child("order")
                        .thread()
                        .spawn({
                            let order = order.clone();
                            move |local| async move {
                                home_tx.send(local.home().clone()).unwrap();
                                queue_rx.await.unwrap();

                                // Queue a job and return in the same poll, so the thread
                                // closes with it queued.
                                let job = Record("job", order);
                                let job =
                                    sibling(&local, "job").spawn_on(local.home(), move |_| {
                                        drop(job);
                                        ready(())
                                    });
                                (job, local.home().clone())
                            }
                        })
                        .unwrap();
                    let thread = home_rx.await.unwrap();

                    // The resident is supervised outside the thread, so only the close can
                    // drop it.
                    let (started_tx, started_rx) = oneshot::channel();
                    let resident = Record("resident", order);
                    let resident =
                        context
                            .child("resident")
                            .spawn_on(&thread, move |_| async move {
                                let _resident = resident;
                                started_tx.send(()).unwrap();
                                pending::<()>().await;
                            });
                    started_rx.await.unwrap();
                    queue_tx.send(()).unwrap();

                    let (job, home) = root.await.unwrap();
                    assert_eq!(home, thread);
                    assert!(matches!(job.await, Err(Error::Closed)));
                    assert!(matches!(resident.await, Err(Error::Closed)));
                    thread
                })
            }
        })
        .unwrap();
        assert_eq!(*order.lock(), ["resident", "job"]);
        assert_eq!(thread.inner().queued(), 0);
        assert_eq!(thread.inner().state(), State::Closed);
    }

    /// A host failure raised when the thread starts closing, after the runner's root returned,
    /// is published before the thread releases its tracker guard, so it fails the runner.
    #[test]
    fn test_thread_host_failure_during_shutdown_fails_runner() {
        let result = within(|| {
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

    /// Closing a thread whose residents all wait on futures that never wake does not hang,
    /// even with a `Thread` held past the run and a `Local` leaked on the thread.
    #[test]
    fn test_thread_close_with_pending_residents_does_not_hang() {
        let thread = within(|| {
            start(false, |context| async move {
                let thread = context.child("idle").thread().build().unwrap();
                let mut started = Vec::new();
                for _ in 0..4 {
                    let (started_tx, started_rx) = oneshot::channel();
                    drop(context.child("resident").spawn_on(&thread, move |local| {
                        drop(local.child("local").spawn_local(|_| pending::<()>()));
                        std::mem::forget(local.child("leaked"));
                        async move {
                            started_tx.send(()).unwrap();
                            pending::<()>().await;
                        }
                    }));
                    started.push(started_rx);
                }
                drop(
                    context
                        .child("placed")
                        .on(&thread)
                        .spawn(|_| pending::<()>()),
                );
                for started_rx in started {
                    started_rx.await.unwrap();
                }
                thread
            })
        })
        .unwrap();
        assert_eq!(thread.inner().state(), State::Closed);
    }

    /// When the OS refuses a runtime thread, every finisher rolls back its tracker guard at
    /// once, so the runner's shutdown cannot wait on it, and a later thread still works.
    #[test]
    fn test_thread_spawn_failure_releases_tracker() {
        within(|| {
            start(false, |context| async move {
                let tasks = context.executor.tasks.clone();
                let active = move || tasks.state.lock().active;
                let before = active();

                // The finishers run on this thread, where the failures are armed.
                crate::utils::thread::tests::fail_spawns(3);
                let built = context.child("built").thread().build();
                assert!(matches!(built, Err(ThreadError::Spawn(_))));
                assert_eq!(active(), before);
                let attached = context.child("attached").thread().attach();
                assert!(matches!(attached, Err(ThreadError::Spawn(_))));
                assert_eq!(active(), before);
                let spawned = context.child("spawned").thread().spawn(|_| ready(()));
                assert!(matches!(spawned, Err(ThreadError::Spawn(_))));
                assert_eq!(active(), before);

                let value = context
                    .child("later")
                    .thread()
                    .spawn(|_| ready(1))
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(value, 1);
            })
        })
        .unwrap();
    }
}
