//! Tests of closing runtime threads, their root barrier and their panics, on every runner.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{
    Blob as _, Clock, Cpus, Error, Handle, Local, Metrics, Name, Runner, Spawner, Storage as _,
    Supervisor, Thread, ThreadBuilder, ThreadError, WriteOptions, deterministic,
    mocks::{
        DelayedSyncContext, MutationFaultContext, MutationFaults, PendingSyncs, RecordingContext,
    },
    reschedule,
    signal::Signal,
    threads::{
        admission::{State, tests::set_before_enqueue},
        testing::{DropFlag, bounded, executions, flag, recording, residents, settle},
    },
    tokio,
    utils::extract_panic_message,
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, future::pending};
use rstest::rstest;
use std::{
    cell::Cell,
    future::{Future, Ready, poll_fn, ready},
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

/// The runners a test can run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Deterministic,
    Tokio,
    #[cfg(target_os = "linux")]
    Iouring,
}

/// Call `$run(runner, args..)` with a runner of `$backend` that catches panics if `$catch`.
macro_rules! on_backend {
    ($backend:expr, $catch:expr, $run:ident($($arg:expr),* $(,)?)) => {
        match $backend {
            Backend::Deterministic => $run(
                deterministic::Runner::new(
                    deterministic::Config::default().with_catch_panics($catch),
                )
                $(, $arg)*
            ),
            Backend::Tokio => $run(
                tokio::Runner::new(tokio::Config::default().with_catch_panics($catch))
                $(, $arg)*
            ),
            #[cfg(target_os = "linux")]
            Backend::Iouring => $run(
                iouring::Runner::new(iouring::Config::default().with_catch_panics($catch))
                $(, $arg)*
            ),
        }
    };
}

/// A thread of a runner that already returned, which every later runner rejects.
fn stale_thread() -> Thread {
    deterministic::Runner::default()
        .start(|context| async move { context.child("stale").thread().build().expect("thread") })
}

/// A thread whose root already returned. Its root handle resolved, so it admits nothing.
async fn closed_thread<C: Spawner>(context: &C) -> Thread {
    context
        .child("closed")
        .thread()
        .spawn(|local| ready(local.home().clone()))
        .expect("thread")
        .await
        .expect("root")
}

/// A context whose lineage was already aborted. A placed spawn toward a thread of another runner
/// is rejected synchronously and aborts the node of the context it consumed.
fn aborted_context<C: Spawner>(context: &C, stale: &Thread) -> C {
    let lineage = context.child("lineage");
    let aborted = lineage.child("aborted");
    drop(lineage.on(stale).spawn(|_| async {}));
    aborted
}

/// Assert the root barrier for a thread whose root handle already resolved. A `spawn_on` and a
/// placed spawn toward it, whose futures would complete at once, are closed when they return,
/// and neither factory runs.
fn assert_barrier<C: Spawner>(context: &C, thread: &Thread) {
    let ran = flag();
    let on = context.child("late").spawn_on(thread, recording(&ran));
    let placed = context.child("late").on(thread).spawn(recording(&ran));
    assert!(matches!(on.now_or_never(), Some(Err(Error::Closed))));
    assert!(matches!(placed.now_or_never(), Some(Err(Error::Closed))));
    assert!(
        !ran.load(Ordering::SeqCst),
        "a factory ran after the root barrier"
    );
}

/// What a [Recorder] saw, and where it sends the next `spawn_on`.
#[derive(Default)]
struct Recording {
    /// The last thread `spawn_on` was called with.
    thread: Option<Thread>,
    /// Where the next `spawn_on` goes instead.
    redirect: Option<Thread>,
}

/// Shared view of a [Recorder]'s recording.
#[derive(Clone)]
struct Recorded(Arc<Mutex<Recording>>);

impl Recorded {
    /// The last thread `spawn_on` was called with.
    fn thread(&self) -> Thread {
        self.0.lock().thread.clone().expect("no spawn_on recorded")
    }

    /// Send the next `spawn_on` toward `thread` instead.
    fn redirect(&self, thread: Thread) {
        self.0.lock().redirect = Some(thread);
    }
}

/// A wrapper context whose `spawn_on` records the thread it receives. Since
/// [ThreadBuilder::spawn] calls `spawn_on` on the context it was built from, this gets the
/// thread of a root even when the root never runs.
#[derive(Clone)]
struct Recorder<E> {
    inner: E,
    recorded: Recorded,
}

impl<E> Recorder<E> {
    /// Wrap `inner`.
    fn new(inner: E) -> (Self, Recorded) {
        let recorded = Recorded(Arc::new(Mutex::new(Recording::default())));
        (
            Self {
                inner,
                recorded: recorded.clone(),
            },
            recorded,
        )
    }
}

impl<E: Supervisor> Supervisor for Recorder<E> {
    fn name(&self) -> Name {
        self.inner.name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            recorded: self.recorded.clone(),
        }
    }

    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            recorded: self.recorded,
        }
    }
}

impl<E: Spawner> Spawner for Recorder<E> {
    fn shared(mut self) -> Self {
        self.inner = self.inner.shared();
        self
    }

    fn blocking(mut self) -> Self {
        self.inner = self.inner.blocking();
        self
    }

    fn on(mut self, thread: &Thread) -> Self {
        self.inner = self.inner.on(thread);
        self
    }

    fn placed(mut self) -> Self {
        self.inner = self.inner.placed();
        self
    }

    fn thread(self) -> ThreadBuilder<Self> {
        let recorded = self.recorded;
        self.inner
            .thread()
            .map(move |inner| Self { inner, recorded })
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let recorded = self.recorded;
        self.inner.spawn(move |inner| f(Self { inner, recorded }))
    }

    fn spawn_on<F, Fut, T>(self, thread: &Thread, f: F) -> Handle<T>
    where
        F: FnOnce(Local<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let redirect = {
            let mut recording = self.recorded.0.lock();
            recording.thread = Some(thread.clone());
            recording.redirect.take()
        };
        let target = redirect.unwrap_or_else(|| thread.clone());
        let recorded = self.recorded;
        self.inner.spawn_on(&target, move |local| {
            f(local.map(|inner| Self { inner, recorded }))
        })
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }

    fn stopped(&self) -> Signal {
        self.inner.stopped()
    }
}

/// Once a root's handle resolves, spawns toward its thread are closed at once and never run
/// their factories: after the root completes, after it is aborted at once, and after it is
/// dropped unrun (forced by redirecting it toward a thread of an earlier runner). An aborted
/// root resolves `Closed`, and on deterministic the abort comes before its factory can run.
fn root_exit_closes<R: Runner>(runner: R, stale: Thread, backend: Backend)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        // Native threads may close concurrently with the caller, so repeat to expose a race.
        for _ in 0..16 {
            let (root, recorded) = Recorder::new(context.child("done"));
            let handle = root.thread().spawn(|_| async { 7 }).expect("thread");
            assert!(matches!(handle.await, Ok(7)));
            assert_barrier(&context, &recorded.thread());

            let (root, recorded) = Recorder::new(context.child("aborted"));
            let ran = flag();
            let factory = ran.clone();
            let handle = root
                .thread()
                .spawn(move |_| {
                    factory.store(true, Ordering::SeqCst);
                    pending::<()>()
                })
                .expect("thread");
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(
                backend != Backend::Deterministic || !ran.load(Ordering::SeqCst),
                "the root aborted before its first turn ran"
            );
            assert_barrier(&context, &recorded.thread());

            let (root, recorded) = Recorder::new(context.child("unrun"));
            recorded.redirect(stale.clone());
            let ran = flag();
            let handle = root.thread().spawn(recording(&ran)).expect("thread");
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(!ran.load(Ordering::SeqCst), "the redirected root ran");
            assert_barrier(&context, &recorded.thread());
        }
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_root_exit_closes(#[case] backend: Backend) {
    let stale = stale_thread();
    bounded(move || on_backend!(backend, false, root_exit_closes(stale, backend)));
}

/// A `spawn_on` or `spawn_local` aborted before the thread's next turn never runs its factory,
/// aborts the consumed context's node (so a child wired from it is aborted), and leaves no
/// parked `spawn_local` factory once the turn that skipped it ended.
fn skipped_factory_aborts_node<R: Runner>(runner: R)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let ran = flag();
        let factory = ran.clone();
        let root = context
            .child("skip")
            .thread()
            .spawn(move |local| async move {
                let home = local.home().clone();

                // Everything below happens in this poll, before the host can take a turn.
                let consumed = (*local).child("on");
                let wired_on = consumed.child("wired").shared().spawn(|_| pending::<()>());
                let on = consumed.spawn_on(&home, recording(&factory));
                on.abort();
                let consumed = local.child("local");
                let wired_local = (*consumed)
                    .child("wired")
                    .shared()
                    .spawn(|_| pending::<()>());
                let spawned = consumed.spawn_local(recording(&factory));
                spawned.abort();

                // The thread stays open while these resolve, so only the skipped jobs can
                // close them.
                let on = on.await;
                let spawned = spawned.await;
                let wired_on = wired_on.await;
                let wired_local = wired_local.await;
                let parked = local.owner().parked();
                (
                    matches!(on, Err(Error::Closed)),
                    matches!(spawned, Err(Error::Closed)),
                    matches!(wired_on, Err(Error::Closed)),
                    matches!(wired_local, Err(Error::Closed)),
                    parked,
                )
            })
            .expect("thread");
        let (on, spawned, wired_on, wired_local, parked) = root.await.expect("root");
        assert!(on, "the aborted spawn_on did not resolve Closed");
        assert!(spawned, "the aborted spawn_local did not resolve Closed");
        assert!(wired_on, "a child of the spawn_on context survived");
        assert!(wired_local, "a child of the spawn_local context survived");
        assert_eq!(parked, 0, "the skipped spawn_local left its factory parked");
        assert!(!ran.load(Ordering::SeqCst), "a skipped factory ran");
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_skipped_factory_aborts_node(#[case] backend: Backend) {
    on_backend!(backend, false, skipped_factory_aborts_node());
}

/// The labels of dropped [Record]s and [Reenter]s, in drop order.
type Order = Arc<Mutex<Vec<&'static str>>>;

/// Records its label in an [Order] when dropped, unless disarmed first.
struct Record {
    /// The label to record.
    label: &'static str,
    /// Where to record it, unless disarmed.
    order: Option<Order>,
}

impl Record {
    /// A record of `label` into `order`.
    fn new(label: &'static str, order: &Order) -> Self {
        Self {
            label,
            order: Some(order.clone()),
        }
    }

    /// Drop without recording.
    fn disarm(mut self) {
        self.order = None;
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        if let Some(order) = self.order.take() {
            order.lock().push(self.label);
        }
    }
}

/// A job's capture that records "job" when dropped, then spawns onto its thread with a
/// `spawn_on` and a placed spawn, whose handles it keeps.
struct Reenter<C: Spawner> {
    /// The context the spawns consume.
    context: Option<C>,
    /// The thread the spawns target.
    thread: Thread,
    /// Set if a factory of those spawns ran.
    ran: Arc<AtomicBool>,
    /// Where the drop is recorded.
    order: Order,
    /// Receives the spawns' handles.
    handles: Arc<Mutex<Vec<Handle<()>>>>,
}

impl<C: Spawner> Drop for Reenter<C> {
    fn drop(&mut self) {
        self.order.lock().push("job");
        let context = self.context.take().expect("dropped once");
        let on = context
            .child("on")
            .spawn_on(&self.thread, recording(&self.ran));
        let placed = context
            .child("placed")
            .on(&self.thread)
            .spawn(recording(&self.ran));
        self.handles.lock().extend([on, placed]);
    }
}

/// Wait until `thread` finished closing with nothing queued and no resident counted.
async fn assert_drained<C: Clock + Metrics>(context: &C, thread: &Thread) {
    let inner = thread.inner();
    settle(context, || inner.state() == State::Closed).await;
    assert_eq!(inner.queued(), 0, "a job stayed queued on a closed thread");
    settle(context, || residents(context, thread.name()) == Some(0)).await;
}

/// A root queues a job and returns in the same poll, so its thread closes with the job queued
/// and a resident pending. The close drops the resident before the job, whose factory never
/// runs. The job's handle and a child wired from its context resolve `Closed`, spawns its
/// capture makes toward the closing thread while dropped resolve `Closed` without running, and
/// the thread ends drained. With `host_failure`, the Tokio host panics as the thread starts
/// closing. Returns the drop order.
fn close_order<R: Runner>(runner: R, host_failure: bool) -> Vec<&'static str>
where
    R::Context: Spawner + Clock + Metrics,
{
    let order = Order::default();
    let recorded = order.clone();
    runner.start(|context| async move {
        if host_failure {
            crate::tokio::inject_host_failure();
        }
        let ran = flag();
        let handles = Arc::new(Mutex::new(Vec::new()));
        let (home, homed) = oneshot::channel();
        let (queue, queued) = oneshot::channel::<()>();

        // The job's context is not below the root, so only the dropped job can close its node.
        let consumed = context.child("job");
        let wired = consumed.child("wired").shared().spawn(|_| pending::<()>());
        let capture = (
            context.child("reenter"),
            ran.clone(),
            order.clone(),
            handles.clone(),
        );
        let root = context
            .child("order")
            .thread()
            .spawn(move |local| async move {
                home.send(local.home().clone()).expect("home");
                queued.await.expect("queue");

                // Queue a job and return in the same poll, so the thread closes with it queued.
                let home = local.home().clone();
                let (reenter, ran, order, handles) = capture;
                let capture = Reenter {
                    context: Some(reenter),
                    thread: home.clone(),
                    ran: ran.clone(),
                    order,
                    handles,
                };
                let job = consumed.spawn_on(&home, move |_| {
                    let _capture = capture;
                    ran.store(true, Ordering::SeqCst);
                    ready(())
                });
                (job, residents(&*local, home.name()), home)
            })
            .expect("thread");
        let thread = homed.await.expect("home");

        // The resident is supervised outside the thread, so only the close can drop it.
        let (started, start) = oneshot::channel();
        let record = Record::new("resident", &order);
        let resident = context
            .child("resident")
            .spawn_on(&thread, move |_| async move {
                let _record = record;
                started.send(()).expect("started");
                pending::<()>().await;
            });
        start.await.expect("started");
        queue.send(()).expect("queue");

        let (job, counted, home) = root.await.expect("root");
        assert_eq!(home, thread, "two handles of one thread are not equal");
        assert_eq!(
            counted,
            Some(3),
            "the root, the resident and the job are residents"
        );
        assert!(
            matches!(job.await, Err(Error::Closed)),
            "the job did not close"
        );
        assert!(
            matches!(resident.await, Err(Error::Closed)),
            "the resident did not close"
        );
        assert!(
            matches!(wired.await, Err(Error::Closed)),
            "a child of the job's context survived"
        );
        settle(&context, || handles.lock().len() == 2).await;
        for handle in handles.lock().drain(..) {
            assert!(
                matches!(handle.now_or_never(), Some(Err(Error::Closed))),
                "a spawn made while the close dropped the job did not close"
            );
        }
        assert!(
            !ran.load(Ordering::SeqCst),
            "a factory ran during the close"
        );
        assert_drained(&context, &thread).await;
    });
    recorded.lock().clone()
}

#[rstest]
#[case::deterministic(Backend::Deterministic, false)]
#[case::tokio(Backend::Tokio, false)]
#[case::tokio_host_failure(Backend::Tokio, true)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring, false))]
fn test_thread_close_order(#[case] backend: Backend, #[case] host_failure: bool) {
    // The host failure is a panic, so that run catches panics.
    let order = bounded(move || on_backend!(backend, host_failure, close_order(host_failure)));
    assert_eq!(order, ["resident", "job"], "the job was dropped first");
}

/// Number of jobs scheduled after the one that closes the thread in [close_while_scheduling],
/// enough for several admission batches.
const LATE_JOBS: usize = 3 * 64;

/// A thread that starts closing while it schedules a burst of `spawn_on` jobs drops its pending
/// futures before the factory of any job that never ran, including factories older than the
/// youngest pending future. The burst's first job closes the thread by aborting the lineage that
/// created it, and its last job leaves a pending future if it runs. A resident of the thread
/// submits the whole burst in one poll, so on native runners one host turn takes it. Returns the
/// drop order, in which every job that never ran records its factory's drop.
fn close_while_scheduling<R: Runner>(runner: R, stale: Thread) -> Vec<&'static str>
where
    R::Context: Spawner + Clock + Metrics,
{
    let order = Order::default();
    let recorded = order.clone();
    runner.start(|context| async move {
        let creator = context.child("creator");
        let thread = creator.child("t").thread().build().expect("thread");

        // The resident is supervised outside the creating lineage, so only the close drops it.
        let record = Record::new("resident", &order);
        let resident = context
            .child("resident")
            .spawn_on(&thread, move |local| async move {
                let _record = record;
                let home = local.home().clone();

                // A placed spawn toward a thread of another runner is rejected and aborts the
                // node of the context it consumed, with the thread below it.
                drop((*local).child("closer").spawn_on(&home, move |_| {
                    drop(creator.on(&stale).spawn(|_| async {}));
                    ready(())
                }));
                for _ in 0..LATE_JOBS {
                    let unrun = Record::new("factory", &order);
                    drop((*local).child("late").spawn_on(&home, move |_| {
                        unrun.disarm();
                        ready(())
                    }));
                }
                let unrun = Record::new("factory", &order);
                let young = order.clone();
                drop((*local).child("young").spawn_on(&home, move |_| {
                    unrun.disarm();
                    let record = Record::new("young", &young);
                    async move {
                        let _record = record;
                        pending::<()>().await;
                    }
                }));
                pending::<()>().await;
            });
        assert!(matches!(resident.await, Err(Error::Closed)));
        assert_drained(&context, &thread).await;
    });
    recorded.lock().clone()
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_close_while_scheduling(#[case] backend: Backend) {
    // Deterministic shuffles each ready pass, so the closer runs at a seeded place in the burst.
    let runs = if backend == Backend::Deterministic {
        8
    } else {
        1
    };
    let (mut unrun, mut mixed) = (0, false);
    for seed in 0..runs {
        let stale = stale_thread();
        let order = bounded(move || match backend {
            Backend::Deterministic => close_while_scheduling(
                deterministic::Runner::new(deterministic::Config::default().with_seed(seed)),
                stale,
            ),
            _ => on_backend!(backend, false, close_while_scheduling(stale)),
        });
        let futures = order
            .iter()
            .take_while(|label| **label != "factory")
            .count();
        assert!(
            order[futures..].iter().all(|label| *label == "factory"),
            "a pending future was dropped after an unrun factory: {order:?}"
        );
        assert_eq!(
            order.iter().filter(|label| **label == "resident").count(),
            1
        );
        unrun += order.len() - futures;
        mixed |= order[..futures].contains(&"young") && futures < order.len();
    }
    assert!(unrun > 0, "every late factory ran");
    assert!(
        backend != Backend::Deterministic || mixed,
        "no seed dropped a young future while an older factory was unrun"
    );
}

/// Payload of every panic the panic tests raise.
const PANIC: &str = "thread test panic";

/// Panics with [PANIC] when dropped, after setting its flag.
struct PanicOnDrop(Arc<AtomicBool>);

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        panic!("{PANIC}");
    }
}

/// A future that completes at once with `output`, then panics when dropped, setting `dropped`.
fn ready_then_panic<T: Send + 'static>(
    dropped: Arc<AtomicBool>,
    output: T,
) -> impl Future<Output = T> + Send + 'static {
    let guard = PanicOnDrop(dropped);
    let mut output = Some(output);
    poll_fn(move |_| {
        let _guard = &guard;
        Poll::Ready(output.take().expect("polled after completion"))
    })
}

/// A factory that records that it ran, holding `capture` until it is dropped.
fn capturing<L>(
    capture: PanicOnDrop,
    ran: &Arc<AtomicBool>,
) -> impl FnOnce(L) -> Ready<()> + Send + 'static {
    let ran = ran.clone();
    move |_| {
        let _capture = capture;
        ran.store(true, Ordering::SeqCst);
        ready(())
    }
}

/// Payload of a destructor panic that follows a poll panic.
const DROP_PANIC: &str = "thread test drop panic";

/// A future that panics with [PANIC] when polled, then panics with [DROP_PANIC] when dropped,
/// after setting its flag.
struct PollThenDrop {
    /// Set when the future is dropped.
    dropped: Arc<AtomicBool>,
    /// Whether the future was polled.
    polled: bool,
}

impl Future for PollThenDrop {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<()> {
        self.polled = true;
        panic!("{PANIC}");
    }
}

impl Drop for PollThenDrop {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
        if self.polled {
            panic!("{DROP_PANIC}");
        }
    }
}

/// The output of a `spawn_local` task its handle never took. When the close of its thread drops
/// it, it spawns through its `Local` with a factory whose capture panics, then panics itself.
struct StaleSpawner<C: Spawner> {
    /// The `Local` spawned through once the close took the thread's state.
    local: Option<Local<C>>,
    /// The thread the `Local` belongs to.
    thread: Thread,
    /// Set when the late factory's capture is dropped.
    dropped: Arc<AtomicBool>,
    /// Set if the late factory runs.
    ran: Arc<AtomicBool>,
    /// Set if the `Local` still names its thread and the late spawn resolved `Closed` at once.
    checked: Arc<AtomicBool>,
}

impl<C: Spawner> Drop for StaleSpawner<C> {
    fn drop(&mut self) {
        let local = self.local.take().expect("dropped once");
        let home = local.home() == &self.thread;
        let handle = local.spawn_local(capturing(PanicOnDrop(self.dropped.clone()), &self.ran));
        let closed = matches!(handle.now_or_never(), Some(Err(Error::Closed)));
        self.checked.store(home && closed, Ordering::SeqCst);
        panic!("{PANIC}");
    }
}

/// A panic of the panic matrix.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    /// A `spawn_on` factory panics.
    SpawnOnFactory,
    /// A `spawn_local` factory panics.
    SpawnLocalFactory,
    /// The factory of a builder's root panics.
    RootFactory,
    /// A `spawn_local` future panics in a poll.
    SpawnLocalPoll,
    /// A root future panics in a poll.
    RootPoll,
    /// A placed spawn's future panics in a poll, then panics again when dropped.
    PlacedPollThenDrop,
    /// A `spawn_on` future completes with an output that holds its context and panics when
    /// dropped, then the future panics when dropped, before the output is delivered.
    SpawnOnReadyOutput,
    /// A resident future panics when dropped after an abort.
    AbortDisposal,
    /// Two queued jobs' captures each panic during the same close.
    TwoQueuedCaptures,
    /// A `spawn_local` future completes with an output that panics when dropped, then panics
    /// when dropped itself. Its handle was dropped before the task ran (`true`), or is awaited.
    LocalReady(bool),
    /// A completed `spawn_local` task's output panics when its handle is dropped without
    /// taking it.
    LocalOutputDisposal,
    /// A parked `spawn_local` factory's capture panics when its aborted task is skipped.
    ParkedCapture,
    /// Factory captures panic when `spawn_on` and placed spawns are rejected: toward a closed
    /// thread, toward a thread of another runner, and from an aborted lineage.
    Rejected,
    /// A resident left pending when the run's root returns panics when the shutdown close drops
    /// it, next to a pending shared task.
    LateDisposal,
    /// A [StaleSpawner] output, which the shutdown close drops.
    StaleOutput,
}

impl Scenario {
    /// Whether the panic is reported through the runner's panicker. Disposal panics are
    /// contained on io_uring, but a poll panic that precedes one is still reported.
    const fn reported(self, backend: Backend) -> bool {
        #[cfg(target_os = "linux")]
        if matches!(backend, Backend::Iouring) {
            return matches!(
                self,
                Self::SpawnOnFactory
                    | Self::SpawnLocalFactory
                    | Self::RootFactory
                    | Self::SpawnLocalPoll
                    | Self::RootPoll
                    | Self::PlacedPollThenDrop
            );
        }
        let _ = (self, backend);
        true
    }
}

/// Raise the panic of `scenario`, with `thread` a built thread that outlives it and `stale` a
/// thread of an earlier runner, and assert the outcome of the task that panicked. A scenario
/// whose disposal comes at shutdown leaves its flags to [panic_matrix].
async fn raise<C>(
    context: &C,
    thread: &Thread,
    stale: &Thread,
    scenario: Scenario,
    [dropped, ran, other]: [Arc<AtomicBool>; 3],
) where
    C: Spawner + Clock,
{
    match scenario {
        Scenario::SpawnOnFactory => {
            let handle = context
                .child("factory")
                .spawn_on(thread, |_| -> Ready<()> { panic!("{PANIC}") });
            assert!(matches!(handle.await, Err(Error::Exited)));
        }
        Scenario::SpawnLocalFactory | Scenario::SpawnLocalPoll => {
            let factory = matches!(scenario, Scenario::SpawnLocalFactory);
            let root = context
                .child("local")
                .thread()
                .spawn(move |local| async move {
                    let failed = if factory {
                        let failing = local.child("factory");
                        failing
                            .spawn_local(|_| -> Ready<()> { panic!("{PANIC}") })
                            .await
                    } else {
                        let failing = local.child("poll");
                        failing.spawn_local(|_| async { panic!("{PANIC}") }).await
                    };
                    let next = local.child("next").spawn_local(|_| async { 3 }).await;
                    matches!(failed, Err(Error::Exited)) && matches!(next, Ok(3))
                });
            assert!(root.expect("thread").await.expect("root"));
        }
        Scenario::RootFactory | Scenario::RootPoll => {
            let (root, recorded) = Recorder::new(context.child("root"));
            let handle = if matches!(scenario, Scenario::RootFactory) {
                root.thread().spawn(|_| -> Ready<()> { panic!("{PANIC}") })
            } else {
                root.thread().spawn(|_| async {
                    panic!("{PANIC}");
                })
            };
            assert!(matches!(handle.expect("thread").await, Err(Error::Exited)));

            // The thread closed with its root.
            let probe = context
                .child("probe")
                .spawn_on(&recorded.thread(), |_| pending::<()>());
            assert!(
                matches!(probe.await, Err(Error::Closed)),
                "the thread outlived its panicking root"
            );
        }
        Scenario::PlacedPollThenDrop => {
            let guard = dropped.clone();
            let handle = context
                .child("poll")
                .on(thread)
                .spawn(move |_| PollThenDrop {
                    dropped: guard,
                    polled: false,
                });
            assert!(matches!(handle.await, Err(Error::Exited)));
            assert!(dropped.load(Ordering::SeqCst), "the future was not dropped");
        }
        Scenario::SpawnOnReadyOutput => {
            let output = PanicOnDrop(other.clone());
            let handle = context.child("ready").spawn_on(thread, move |local| {
                ready_then_panic(dropped, (local.into_inner(), output))
            });
            assert!(matches!(handle.await, Err(Error::Closed)));

            // The output that could not be delivered is dropped before the handle resolves.
            assert!(other.load(Ordering::SeqCst), "the output was leaked");
        }
        Scenario::AbortDisposal => {
            let (started, start) = oneshot::channel();
            let guard = dropped.clone();
            let handle = context
                .child("abort")
                .spawn_on(thread, move |_| async move {
                    let _guard = PanicOnDrop(guard);
                    started.send(()).expect("started");
                    pending::<()>().await;
                });
            start.await.expect("started");
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // The future is dropped before the handle resolves.
            assert!(dropped.load(Ordering::SeqCst));
        }
        Scenario::TwoQueuedCaptures => {
            let drops = [flag(), flag()];
            let captures = drops.clone().map(PanicOnDrop);
            let factory = ran.clone();
            let root = context
                .child("queue")
                .thread()
                .spawn(move |local| async move {
                    // Queue the jobs and end the root in the same poll.
                    let home = local.home().clone();
                    captures.map(|capture| {
                        (*local)
                            .child("queued")
                            .spawn_on(&home, capturing(capture, &factory))
                    })
                });
            for handle in root.expect("thread").await.expect("root") {
                assert!(matches!(handle.await, Err(Error::Closed)));
            }

            // The close went on past the first panic.
            settle(context, || {
                drops.iter().all(|drop| drop.load(Ordering::SeqCst))
            })
            .await;
            assert!(!ran.load(Ordering::SeqCst), "a queued factory ran");
        }
        Scenario::LocalReady(detached) => {
            // A dropped handle leaves the task owning its output when its future's destructor
            // panics, and disposing of that output during the unwind would abort the process. A
            // kept handle resolves Closed, so the output is disposed of on the thread and never
            // reaches the root.
            let root = context.child("local").thread().spawn(move |local| {
                let (future_dropped, output_dropped) = (dropped.clone(), other.clone());
                let handle = local.child("ready").spawn_local(move |_| {
                    ready_then_panic(future_dropped, PanicOnDrop(output_dropped))
                });
                let handle = (!detached).then_some(handle);
                async move {
                    let closed = match handle {
                        Some(handle) => matches!(handle.await, Err(Error::Closed)),
                        None => true,
                    };
                    settle(&*local, || {
                        dropped.load(Ordering::SeqCst) && other.load(Ordering::SeqCst)
                    })
                    .await;
                    closed
                }
            });
            assert!(root.expect("thread").await.expect("root"));
        }
        Scenario::LocalOutputDisposal => {
            let root = context
                .child("local")
                .thread()
                .spawn(move |local| async move {
                    let finished = Rc::new(Cell::new(false));
                    let (done, guard) = (finished.clone(), dropped.clone());
                    let handle = local.child("output").spawn_local(move |_| async move {
                        done.set(true);
                        PanicOnDrop(guard)
                    });

                    // The task stores its output in the poll that sets the flag.
                    settle(&*local, || finished.get()).await;
                    let contained = catch_unwind(AssertUnwindSafe(move || drop(handle))).is_ok();
                    contained && dropped.load(Ordering::SeqCst)
                });
            assert!(root.expect("thread").await.expect("root"));
        }
        Scenario::ParkedCapture => {
            let factory = ran.clone();
            let guard = dropped.clone();
            let root = context
                .child("parked")
                .thread()
                .spawn(move |local| async move {
                    // Abort the task in the poll that parked its factory.
                    let handle = local
                        .child("parked")
                        .spawn_local(capturing(PanicOnDrop(guard), &factory));
                    handle.abort();
                    matches!(handle.await, Err(Error::Closed))
                });
            assert!(root.expect("thread").await.expect("root"));
            settle(context, || dropped.load(Ordering::SeqCst)).await;
            assert!(!ran.load(Ordering::SeqCst), "the aborted factory ran");
        }
        Scenario::Rejected => {
            // Each rejection drops the factory, whose capture panics, before the call returns,
            // so an uncaught report fails the run only at the next await.
            let closed = closed_thread(context).await;
            let mut handles = Vec::new();
            let lines = [
                (context.child("rejected"), &closed),
                (context.child("rejected"), stale),
                (aborted_context(context, stale), thread),
            ];
            for (line, target) in lines {
                for placed in [false, true] {
                    dropped.store(false, Ordering::SeqCst);
                    let capture = PanicOnDrop(dropped.clone());
                    let rejected = catch_unwind(AssertUnwindSafe(|| {
                        if placed {
                            line.child("placed")
                                .on(target)
                                .spawn(capturing(capture, &ran))
                        } else {
                            line.child("on").spawn_on(target, capturing(capture, &ran))
                        }
                    }));
                    handles.push(rejected.expect("a rejected spawn unwound into its caller"));
                    assert!(
                        dropped.load(Ordering::SeqCst),
                        "a spawn toward {} kept its factory, placed: {placed}",
                        target.name()
                    );
                }
            }

            // Aborting a rejected spawn's handle does not change its result.
            for handle in handles {
                handle.abort();
                assert!(matches!(handle.await, Err(Error::Closed)));
            }
            assert!(!ran.load(Ordering::SeqCst), "a rejected factory ran");
        }
        Scenario::LateDisposal => {
            let (started, start) = oneshot::channel();
            drop(
                context
                    .child("resident")
                    .spawn_on(thread, move |_| async move {
                        let _guard = PanicOnDrop(dropped);
                        started.send(()).expect("started");
                        pending::<()>().await;
                    }),
            );
            let flag = DropFlag(other);
            drop(context.child("shared").spawn(move |_| async move {
                let _flag = flag;
                pending::<()>().await;
            }));
            start.await.expect("started");
        }
        Scenario::StaleOutput => {
            let (done, finished) = oneshot::channel();
            let home = thread.clone();
            drop(
                context
                    .child("owner")
                    .spawn_on(thread, move |local| async move {
                        let output = StaleSpawner {
                            local: Some(local.child("stale")),
                            thread: home,
                            dropped,
                            ran,
                            checked: other,
                        };
                        let (stored, store) = oneshot::channel();
                        let handle = local.child("output").spawn_local(move |_| async move {
                            stored.send(()).expect("stored");
                            output
                        });

                        // The task stores its output in the poll that sends. Leaking the handle
                        // keeps its slot registered until the close clears it.
                        store.await.expect("stored");
                        mem::forget(handle);
                        done.send(()).expect("done");
                        pending::<()>().await;
                    }),
            );
            finished.await.expect("done");
        }
    }
}

/// Raise the panic of `scenario` on one runner, check that a resident of the same thread and a
/// shared task survive it, and check how the run ends. A reported panic fails the run unless
/// panics are caught. A contained one never does. Disposals at shutdown are checked once the
/// run ended.
fn panic_matrix<R: Runner>(
    runner: R,
    stale: Thread,
    backend: Backend,
    scenario: Scenario,
    catch: bool,
) where
    R::Context: Spawner + Clock,
{
    let flags = [flag(), flag(), flag()];
    let raised = flags.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        runner.start(|context| async move {
            let thread = context.child("built").thread().build().expect("thread");
            let (release, released) = oneshot::channel::<()>();
            let survivor = context.child("survivor").spawn_on(&thread, |_| async move {
                released.await.expect("released");
                5
            });
            raise(&context, &thread, &stale, scenario, raised).await;
            release.send(()).expect("release");
            assert!(
                matches!(survivor.await, Ok(5)),
                "a resident did not survive"
            );
            let after = context.child("after").spawn(|_| async { 7 });
            assert!(
                matches!(after.await, Ok(7)),
                "a shared task did not survive"
            );
        })
    }));
    if scenario.reported(backend) && !catch {
        let panic = result.expect_err("a reported panic did not fail the run");
        assert_eq!(extract_panic_message(&*panic), PANIC);
    } else {
        result.expect("the run failed");
    }
    if matches!(scenario, Scenario::LateDisposal | Scenario::StaleOutput) {
        let [dropped, ran, other] = flags;
        assert!(dropped.load(Ordering::SeqCst), "the shutdown kept a value");
        assert!(!ran.load(Ordering::SeqCst), "a factory ran after the close");
        assert!(
            other.load(Ordering::SeqCst),
            "the shutdown kept the shared task, or the stale spawn did not close at once"
        );
    }
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_panic_matrix(
    #[case] backend: Backend,
    #[values(
        Scenario::SpawnOnFactory,
        Scenario::SpawnLocalFactory,
        Scenario::RootFactory,
        Scenario::SpawnLocalPoll,
        Scenario::RootPoll,
        Scenario::PlacedPollThenDrop,
        Scenario::SpawnOnReadyOutput,
        Scenario::AbortDisposal,
        Scenario::TwoQueuedCaptures,
        Scenario::LocalReady(true),
        Scenario::LocalReady(false),
        Scenario::LocalOutputDisposal,
        Scenario::ParkedCapture,
        Scenario::Rejected,
        Scenario::LateDisposal,
        Scenario::StaleOutput
    )]
    scenario: Scenario,
    #[values(false, true)] catch: bool,
) {
    let stale = stale_thread();
    on_backend!(
        backend,
        catch,
        panic_matrix(stale, backend, scenario, catch)
    );
}

/// Records what each finisher and [ThreadBuilder::available] return when a context is dropped
/// during the shutdown abort.
struct BuildOnDrop<C: Spawner> {
    /// The context the finishers consume.
    context: Option<C>,
    /// Whether each finisher returned `Closed`, in order: build, attach, spawn. Then whether
    /// `available` returned `None`.
    closed: Arc<Mutex<Vec<bool>>>,
    /// Set if the root factory ran.
    ran: Arc<AtomicBool>,
}

impl<C: Spawner> Drop for BuildOnDrop<C> {
    fn drop(&mut self) {
        let Some(context) = self.context.take() else {
            return;
        };
        let available = context.child("probe").thread().available();
        let build = context.child("build").thread().build();
        let attach = context.child("attach").thread().attach();
        let spawn = context.child("spawn").thread().spawn(recording(&self.ran));
        self.closed.lock().extend([
            matches!(build, Err(ThreadError::Closed)),
            matches!(attach, Err(ThreadError::Closed)),
            matches!(spawn, Err(ThreadError::Closed)),
            available.is_none(),
        ]);
    }
}

/// Every finisher returns `Closed` from an aborted lineage and from a drop during the shutdown
/// abort, where `available` returns `None`. A builder created before its lineage was aborted
/// returns `Closed` from `attach`, an empty pin on an aborted lineage returns `EmptyCpus`
/// (CPU validation comes first), and nothing is left behind. With `escape`, a context and a
/// builder (pinned where possible) returned from the run are rejected the same way afterwards,
/// and the rejected root factory is dropped unrun.
fn builder_closed<R: Runner>(
    runner: R,
    stale: Thread,
    escape: bool,
    closed: Arc<Mutex<Vec<bool>>>,
    ran: Arc<AtomicBool>,
) where
    R::Context: Spawner + Clock + Metrics,
{
    let factory = ran.clone();
    let escaped = runner.start(|context| async move {
        // A placed spawn toward a thread of another runner is rejected and aborts the node of
        // the context it consumed, with its whole lineage.
        let lineage = context.child("lineage");
        let early = lineage.child("early");
        let early_name = early.name().label;
        let early = early.thread();
        let contexts = [
            lineage.child("build"),
            lineage.child("attach"),
            lineage.child("spawn"),
            lineage.child("empty"),
        ];
        let rejected = lineage.on(&stale).spawn(|_| async {});
        assert!(matches!(rejected.await, Err(Error::Closed)));
        let [build, attach, spawn, empty] = contexts;
        let names = [
            build.name().label,
            attach.name().label,
            spawn.name().label,
            early_name,
        ];
        assert!(matches!(build.thread().build(), Err(ThreadError::Closed)));
        assert!(matches!(attach.thread().attach(), Err(ThreadError::Closed)));
        assert!(matches!(early.attach(), Err(ThreadError::Closed)));
        let spawned = spawn.thread().spawn(recording(&factory));
        assert!(matches!(spawned, Err(ThreadError::Closed)));
        let none: Vec<usize> = Vec::new();
        assert!(matches!(
            empty.thread().pin(none).build(),
            Err(ThreadError::EmptyCpus)
        ));
        for name in names {
            assert!(matches!(residents(&context, &name), None | Some(0)));
        }

        // A task holding a context until the shutdown abort drops it.
        let (started, start) = oneshot::channel();
        let holder = BuildOnDrop {
            context: Some(context.child("holder")),
            closed,
            ran: factory,
        };
        drop(context.child("task").spawn(move |_| async move {
            let _holder = holder;
            started.send(()).expect("started");
            pending::<()>().await;
        }));
        start.await.expect("started");

        escape.then(|| {
            let builder = context.child("returned").thread();
            let builder = match valid_cpu() {
                Some(cpu) => builder.pin(cpu),
                None => builder,
            };
            (context.child("escaped"), builder)
        })
    });
    if let Some((escaped, builder)) = escaped {
        assert_eq!(builder.available(), None);
        assert!(matches!(builder.build(), Err(ThreadError::Closed)));
        let dropped = flag();
        let capture = DropFlag(dropped.clone());
        let factory = recording(&ran);
        let spawned = escaped.child("closed").thread().spawn(move |local| {
            let _capture = capture;
            factory(local)
        });
        assert!(matches!(spawned, Err(ThreadError::Closed)));
        assert!(
            dropped.load(Ordering::SeqCst),
            "a rejected root factory was kept"
        );
        let none: Vec<usize> = Vec::new();
        assert!(matches!(
            escaped.child("empty").thread().pin(none).build(),
            Err(ThreadError::EmptyCpus)
        ));
    }
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_builder_closed(#[case] backend: Backend) {
    // A deterministic context must not outlive its run.
    let escape = backend != Backend::Deterministic;
    let stale = stale_thread();
    let closed = Arc::new(Mutex::new(Vec::new()));
    let ran = flag();
    on_backend!(
        backend,
        false,
        builder_closed(stale, escape, closed.clone(), ran.clone())
    );
    assert_eq!(
        *closed.lock(),
        [true; 4],
        "a finisher in a shutdown drop did not return Closed, or available was not None"
    );
    assert!(!ran.load(Ordering::SeqCst), "a rejected root ran");
}

/// A CPU the calling thread may run on, which a native runner started on it accepts in a pin.
#[cfg(all(target_os = "linux", not(miri)))]
fn valid_cpu() -> Option<usize> {
    crate::threads::affinity::current().and_then(|cpus| cpus.iter().next())
}

/// A CPU the calling thread may run on, which a native runner started on it accepts in a pin.
#[cfg(not(all(target_os = "linux", not(miri))))]
const fn valid_cpu() -> Option<usize> {
    None
}

/// Check pin validation on one runner whose base set is `base` (`None` if unknown).
fn pin_validation<R: Runner>(runner: R, base: Option<Cpus>)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let pin = |cpus: Cpus| context.child("pinned").thread().pin(cpus).build();

        // An empty set fails first, whatever the base set.
        let none: Vec<usize> = Vec::new();
        assert!(matches!(pin(Cpus::from(none)), Err(ThreadError::EmptyCpus)));
        assert!(matches!(pin(Cpus::from(3..3)), Err(ThreadError::EmptyCpus)));
        assert!(matches!(
            context.child("pinned").thread().pin([0usize; 0]).attach(),
            Err(ThreadError::EmptyCpus)
        ));

        // The builder reports the base set. Without one, every finisher rejects a pin, and an
        // unpinned thread needs none.
        assert_eq!(context.child("probe").thread().available(), base);
        let Some(base) = base else {
            for cpus in [Cpus::from(0), Cpus::from(5000), Cpus::from(0..=usize::MAX)] {
                assert!(matches!(pin(cpus), Err(ThreadError::UnsupportedAffinity)));
            }
            let pinned = || context.child("pinned").thread().pin(0);
            assert!(matches!(
                pinned().attach(),
                Err(ThreadError::UnsupportedAffinity)
            ));
            assert!(matches!(
                pinned().spawn(|_| ready(())),
                Err(ThreadError::UnsupportedAffinity)
            ));
            let unpinned = context.child("unpinned").thread().spawn(|_| ready(()));
            unpinned.expect("thread").await.expect("root");
            return;
        };
        let inside = base.iter().next().expect("empty base set");
        let outside = (0..1024).find(|&id| !base.contains(id)).unwrap_or(1024);
        assert!(pin(Cpus::from(inside)).is_ok());

        // The smallest requested id outside the base set, including ids at or above 1024,
        // which are not stored but still make a pin unavailable rather than empty.
        assert!(matches!(
            pin(Cpus::from(5000)),
            Err(ThreadError::CpuUnavailable(5000))
        ));
        assert!(matches!(
            pin(Cpus::from([inside, 4000, 2000])),
            Err(ThreadError::CpuUnavailable(2000))
        ));
        if outside < 1024 {
            assert!(matches!(
                pin(Cpus::from([4000, outside, inside])),
                Err(ThreadError::CpuUnavailable(id)) if id == outside
            ));
        }

        // A range up to usize::MAX is cut at 1024 when built, so this returns promptly.
        assert!(matches!(
            pin(Cpus::from(0..=usize::MAX)),
            Err(ThreadError::CpuUnavailable(id)) if id == outside
        ));

        // A later pin replaces an earlier one.
        let thread = context
            .child("replaced")
            .thread()
            .pin(5000)
            .pin(inside)
            .build()
            .expect("valid pin");
        assert_eq!(thread.cpus(), Some(&Cpus::from(inside)));
        assert!(matches!(
            context
                .child("replaced")
                .thread()
                .pin(inside)
                .pin(5000)
                .build(),
            Err(ThreadError::CpuUnavailable(5000))
        ));
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_pin_validation(#[case] backend: Backend) {
    if backend == Backend::Deterministic {
        return pin_validation(
            deterministic::Runner::new(deterministic::Config::default().with_cpus(0..=3)),
            Some(Cpus::from(0..=3)),
        );
    }

    // A native runner's base set is the CPU set of the thread that starts it, where the
    // platform reports one, and the second pass makes it unknown.
    #[cfg(all(target_os = "linux", not(miri)))]
    {
        use crate::threads::affinity::{current, tests::override_base};
        on_backend!(backend, false, pin_validation(current()));
        override_base(Some(None));
    }
    on_backend!(backend, false, pin_validation(None));
    #[cfg(all(target_os = "linux", not(miri)))]
    crate::threads::affinity::tests::override_base(None);
}

/// With the OS refusing the thread, every finisher returns `Spawn` and rolls back. The spawn
/// finisher drops its root factory unrun, the residents series stays absent or 0, a child wired
/// from the consumed context keeps running, a later thread from the same parent works, and the
/// run ends, so no reservation leaked.
fn spawn_failure_rollback<R: Runner>(runner: R)
where
    R::Context: Spawner + Metrics,
{
    use crate::utils::thread::tests::fail_spawns;

    runner.start(|context| async move {
        let parent = context.child("parent");
        let consumed = parent.child("t");
        let (release, released) = oneshot::channel::<()>();
        let wired = consumed.child("wired").shared().spawn(move |_| async move {
            released.await.expect("released");
            9
        });

        // The failure is armed on this OS thread, which runs the finisher synchronously.
        fail_spawns(1);
        assert!(matches!(
            consumed.thread().build(),
            Err(ThreadError::Spawn(_))
        ));
        fail_spawns(1);
        let attached = parent.child("t").thread().attach();
        assert!(matches!(attached, Err(ThreadError::Spawn(_))));
        let (dropped, ran) = (flag(), flag());
        let capture = DropFlag(dropped.clone());
        let factory = recording(&ran);
        fail_spawns(1);
        let spawned = parent.child("t").thread().spawn(move |local| {
            let _capture = capture;
            factory(local)
        });
        assert!(matches!(spawned, Err(ThreadError::Spawn(_))));
        assert!(
            dropped.load(Ordering::SeqCst) && !ran.load(Ordering::SeqCst),
            "the refused root ran or was kept"
        );

        let thread = parent.child("t").thread().build().expect("thread");
        assert!(matches!(residents(&context, thread.name()), None | Some(0)));
        let handle = context.child("work").spawn_on(&thread, |_| async { 4 });
        assert!(matches!(handle.await, Ok(4)));

        release.send(()).expect("release");
        assert!(
            matches!(wired.await, Ok(9)),
            "the failed finisher aborted the consumed lineage"
        );
    });
}

#[rstest]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_spawn_failure_rollback(#[case] backend: Backend) {
    bounded(move || on_backend!(backend, false, spawn_failure_rollback()));
}

/// Wait on the calling OS thread, for a bounded time, until `done` holds.
fn block_until(done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "condition did not hold in time");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Holds the first admission after its install inside its critical section for a while, so
/// another side blocks on the lock it holds.
struct AdmissionGate(Arc<AtomicBool>);

impl AdmissionGate {
    /// Install the gate in the admission callback slot, holding the first admission for `hold`.
    fn install(hold: Duration) -> Self {
        let entered = flag();
        let inside = entered.clone();
        set_before_enqueue(Some(Arc::new(move || {
            if !inside.swap(true, Ordering::SeqCst) {
                std::thread::sleep(hold);
            }
        })));
        Self(entered)
    }

    /// Whether an admission entered the callback.
    fn entered(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Drop for AdmissionGate {
    fn drop(&mut self) {
        set_before_enqueue(None);
    }
}

/// On deterministic, the loop schedules a resident of a thread while a submission off the loop
/// holds that thread's admission critical section, and thread creations off the loop race
/// aborts of the node they occupy. The loop keeps running on `reschedule()` meanwhile.
fn deterministic_admission_race(stale: Thread) {
    deterministic::Runner::default().start(|context| async move {
        let thread = context.child("contended").thread().build().expect("thread");
        let first = context.child("first").spawn_on(&thread, |_| async { 2 });
        let gate = AdmissionGate::install(Duration::from_millis(100));
        let submitter = context.child("second").on(&thread);
        let submit = std::thread::spawn(move || submitter.spawn(|_| async { 3 }));

        // Hold the loop until the submission is inside, so the resident's first schedule
        // comes while it is.
        block_until(|| gate.entered());
        while !submit.is_finished() {
            reschedule().await;
        }
        let second = submit.join().expect("submitter");
        drop(gate);
        assert!(
            matches!(first.await, Ok(2)),
            "the contended resident failed"
        );
        assert!(
            matches!(second.await, Ok(3)),
            "the contended submission failed"
        );

        // A thread creation off the loop races an abort of the node it occupies.
        for _ in 0..32 {
            let parent = context.child("creator");
            let creating = parent.child("t");
            let barrier = Arc::new(Barrier::new(2));
            let creator = {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    creating.thread().build()
                })
            };
            let walker = {
                let stale = stale.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    drop(parent.on(&stale).spawn(|_| async {}));
                })
            };
            while !creator.is_finished() || !walker.is_finished() {
                reschedule().await;
            }
            walker.join().expect("walker");
            match creator.join().expect("creator") {
                Ok(thread) => {
                    // The abort came after the registration, so the thread closes and leaves
                    // the table.
                    let inner = thread.inner();
                    settle(&context, || inner.state() == State::Closed).await;
                }
                Err(error) => assert!(matches!(error, ThreadError::Closed)),
            }
        }
    });
}

#[test]
fn test_thread_admission_race_deterministic() {
    let stale = stale_thread();
    bounded(move || deterministic_admission_race(stale));
}

/// For one wrapper, `attach`, `spawn`, `spawn_on` and `spawn_local` all hand their closures
/// the wrapper type with its state (`holds` checks it), and `placed`, `blocking` and `shared`
/// keep that state and reach the inner context.
async fn wrapper_threads<W>(context: W, holds: fn(&W) -> bool)
where
    W: Spawner + Metrics,
{
    assert!(holds(&context));
    let attached = context.child("attached").thread().attach().expect("thread");
    assert!(holds(&attached));

    // A task of the attached context gets the state, and the placement methods keep it and
    // reach the inner context.
    let (held, names) = attached
        .child("placement")
        .spawn(move |task: W| async move {
            let lines = [
                task.child("placed").placed(),
                task.child("blocking").blocking(),
                task.child("shared").placed().shared(),
            ];
            let held = holds(&task) && lines.iter().all(holds);
            let mut names = Vec::new();
            for line in lines {
                names.push(line.name().label);
                line.spawn(|_| async {}).await.expect("spawn");
            }
            (held, names)
        })
        .await
        .expect("placement");
    assert!(
        held,
        "an attached task or a placement method lost the wrapper's state"
    );
    let labels: Vec<_> = names
        .iter()
        .map(|name| executions(&context, name))
        .collect();
    assert_eq!(labels, [["Thread"], ["SharedBlocking"], ["Shared"]]);

    let root = context
        .child("root")
        .thread()
        .spawn(move |local: Local<W>| async move {
            let leaf = local
                .child("leaf")
                .spawn_local(move |leaf: Local<W>| async move { holds(&leaf) })
                .await;
            holds(&local) && matches!(leaf, Ok(true))
        })
        .expect("thread");
    assert!(
        root.await.expect("root"),
        "a root or spawn_local closure lost the wrapper's state"
    );

    let thread = context.child("built").thread().build().expect("thread");
    let remote = context
        .child("remote")
        .spawn_on(&thread, move |local: Local<W>| async move { holds(&local) });
    assert!(
        matches!(remote.await, Ok(true)),
        "a spawn_on closure lost the state"
    );
}

#[test]
fn test_thread_wrapper_contexts() {
    deterministic::Runner::default().start(|context| async move {
        // Each wrapper's state is marked before the threads exist, so a closure that got a
        // fresh state would not see the mark.
        let (recording, recordings) = RecordingContext::new(context.child("recording"));
        let (blob, _) = recording.open("partition", b"blob").await.expect("open");
        blob.write_at(0, b"x".to_vec(), WriteOptions::default())
            .await
            .expect("write");
        drop(blob);
        assert_eq!(recordings.snapshot().writes.len(), 1);
        wrapper_threads(recording, |context| {
            !context.recordings.snapshot().writes.is_empty()
        })
        .await;

        let pending = PendingSyncs::default();
        pending.arm();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: pending.clone(),
        };
        wrapper_threads(delayed, |context| context.pending.lock().len() == 1).await;
        pending.unblock();

        let faulty = MutationFaultContext {
            inner: context.child("faulty"),
            faults: MutationFaults::default(),
        };
        faulty.faults.allow(0);
        assert!(faulty.open("partition", b"refused").await.is_err());
        assert!(faulty.faults.failed());
        wrapper_threads(faulty, |context| context.faults.failed()).await;
    });
}

/// A `spawn_local` factory holding a capture that sets `dropped` when dropped. It sets `ran`
/// if it runs.
fn parked<L>(
    dropped: &Arc<AtomicBool>,
    ran: &Arc<AtomicBool>,
) -> impl FnOnce(L) -> Ready<()> + 'static {
    let capture = DropFlag(dropped.clone());
    let ran = ran.clone();
    move |_| {
        let _capture = capture;
        ran.store(true, Ordering::SeqCst);
        ready(())
    }
}

/// What each side of [test_thread_misdelivered_spawn_local] checks, in the order [misdeliver]
/// reports the outcomes.
const MISDELIVERED: [&str; 6] = [
    "the misdelivered spawn_local did not close",
    "the next reap point kept the parked factory",
    "the later spawn_local failed",
    "a factory stayed parked",
    "the misdelivered factory ran",
    "the thread closed",
];

/// Spawn a resident of `thread` that makes a `spawn_local` through a wrapper delivering its
/// shim to `other`, an open thread of the same runner. Once the factory is parked, it signals
/// `parked_tx` and awaits `check`. Reports whether the factory was still parked, unrun and not
/// dropped once `check` completed, and whether each check of [MISDELIVERED] passed.
fn misdeliver<C: Spawner>(
    context: C,
    thread: &Thread,
    other: Thread,
    parked_tx: oneshot::Sender<()>,
    check: impl Future<Output = ()> + Send + 'static,
) -> Handle<(bool, [bool; 6])> {
    let (wrapper, recorded) = Recorder::new(context);
    wrapper.spawn_on(thread, move |local| async move {
        let (dropped, ran) = (flag(), flag());
        recorded.redirect(other);
        let handle = local
            .child("misdelivered")
            .spawn_local(parked(&dropped, &ran));
        let _ = parked_tx.send(());
        check.await;
        let kept = local.owner().parked() == 1
            && !dropped.load(Ordering::SeqCst)
            && !ran.load(Ordering::SeqCst);
        let closed = matches!(handle.await, Err(Error::Closed));

        // The shim ran elsewhere and was dropped armed, so this thread's next reap point drops
        // the parked factory.
        let later = local.child("later").spawn_local(|_| ready(()));
        let reaped = dropped.load(Ordering::SeqCst);
        let later = later.await.is_ok();
        let checks = [
            closed,
            reaped,
            later,
            local.owner().parked() == 0,
            !ran.load(Ordering::SeqCst),
            local.home().inner().is_open(),
        ];
        (kept, checks)
    })
}

/// A wrapper that delivers a `spawn_local` shim to another open thread of the same runner gets a
/// handle that resolves `Closed`. The shim leaves the factory the other thread parked under the
/// same id, and its home thread drops its own parked factory at its next reap point, a later
/// `spawn_local`, while staying open.
#[test]
fn test_thread_misdelivered_spawn_local() {
    deterministic::Runner::default().start(|context| async move {
        let home = context.child("home").thread().build().expect("thread");
        let other = context.child("other").thread().build().expect("thread");

        // The other side parks its factory first and keeps it parked until the home side's
        // shim ran on its thread.
        let (parked_tx, parked_rx) = oneshot::channel();
        let (check_tx, check_rx) = oneshot::channel::<()>();
        let peer = misdeliver(
            context.child("peer"),
            &other,
            home.clone(),
            parked_tx,
            async move { check_rx.await.expect("check") },
        );
        parked_rx.await.expect("parked");
        let (unused, _) = oneshot::channel();
        let mine = misdeliver(context.child("mine"), &home, other, unused, ready(()));
        let (_, mine) = mine.await.expect("home side");
        check_tx.send(()).expect("check");
        let (kept, peer) = peer.await.expect("other side");
        assert!(
            kept,
            "the home side's shim took the factory parked on the other thread"
        );
        for (side, checks) in [("home", mine), ("other", peer)] {
            for (passed, failure) in checks.into_iter().zip(MISDELIVERED) {
                assert!(passed, "{side}: {failure}");
            }
        }
    });
}
