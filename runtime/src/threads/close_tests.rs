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
    telemetry::metrics::count_running_tasks,
    threads::admission::{State, tests::set_before_enqueue},
    tokio,
    utils::{extract_panic_message, supervision::tests::set_before_thread_abort},
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, future::pending};
use rstest::rstest;
use std::{
    future::{Future, Ready, poll_fn, ready},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
        mpsc::{RecvTimeoutError, channel},
    },
    task::Poll,
    thread::JoinHandle,
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

/// A new flag, initially false.
fn flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// A factory that records that it ran and returns a future that completes at once.
fn recording<L>(ran: &Arc<AtomicBool>) -> impl FnOnce(L) -> Ready<()> + Send + 'static {
    let ran = ran.clone();
    move |_| {
        ran.store(true, Ordering::SeqCst);
        ready(())
    }
}

/// A thread of a runner that already returned, which every later runner rejects.
fn stale_thread() -> Thread {
    deterministic::Runner::default()
        .start(|context| async move { context.child("stale").thread().build().expect("thread") })
}

/// Run `f` on a helper thread, failing if it does not finish in time (a deadlock).
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(value) => {
            worker.join().expect("helper thread");
            value
        }
        Err(RecvTimeoutError::Disconnected) => resume_unwind(worker.join().unwrap_err()),
        Err(RecvTimeoutError::Timeout) => panic!("the test did not finish in time"),
    }
}

/// Poll `done` until it holds, sleeping between checks.
async fn settle(context: &impl Clock, mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    panic!("condition did not settle");
}

/// The value of the `thread_residents` series of threads named `name`, if it exists.
fn residents(metrics: &impl Metrics, name: &str) -> Option<i64> {
    let label = format!("name=\"{name}\"");
    metrics
        .encode()
        .lines()
        .find(|line| line.starts_with("runtime_thread_residents{") && line.contains(&label))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
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

/// What a [Recorder] saw, and what it does to the next `spawn_on`.
#[derive(Default)]
struct Recording {
    /// Every thread `spawn_on` was called with, in order.
    threads: Vec<Thread>,
    /// Where the next `spawn_on` goes instead.
    redirect: Option<Thread>,
    /// Run by the next `spawn_on` before it forwards.
    hook: Option<Box<dyn FnOnce() + Send>>,
}

/// Shared view of a [Recorder]'s recording.
#[derive(Clone)]
struct Recorded(Arc<Mutex<Recording>>);

impl Recorded {
    /// The last thread `spawn_on` was called with.
    fn thread(&self) -> Thread {
        self.0
            .lock()
            .threads
            .last()
            .cloned()
            .expect("no spawn_on recorded")
    }

    /// Send the next `spawn_on` toward `thread` instead.
    fn redirect(&self, thread: Thread) {
        self.0.lock().redirect = Some(thread);
    }

    /// Run `hook` in the next `spawn_on`, before it forwards.
    fn hook(&self, hook: impl FnOnce() + Send + 'static) {
        self.0.lock().hook = Some(Box::new(hook));
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
    fn shared(mut self, blocking: bool) -> Self {
        self.inner = self.inner.shared(blocking);
        self
    }

    fn on(mut self, thread: &Thread) -> Self {
        self.inner = self.inner.on(thread);
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
        F: FnOnce(Self) -> Fut + Send + 'static,
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
        let (redirect, hook) = {
            let mut recording = self.recorded.0.lock();
            recording.threads.push(thread.clone());
            (recording.redirect.take(), recording.hook.take())
        };
        if let Some(hook) = hook {
            hook();
        }
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

/// Spec test 8: once a root's handle resolves, spawns toward its thread are closed at once and
/// never run their factories, both after the root completes and after the root is dropped
/// unrun (forced by redirecting it toward a thread of an earlier runner).
fn root_exit_closes<R: Runner>(runner: R, stale: Thread)
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
    on_backend!(backend, false, root_exit_closes(stale));
}

/// Spec test 18: a `spawn_on` or `spawn_local` aborted before the thread's next turn never
/// runs its factory, aborts the consumed context's node (so a child wired from it is aborted),
/// and leaves no parked `spawn_local` factory once the turn that skipped it ended.
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
                let wired_on = consumed
                    .child("wired")
                    .shared(false)
                    .spawn(|_| pending::<()>());
                let on = consumed.spawn_on(&home, recording(&factory));
                on.abort();
                let consumed = local.child("local");
                let wired_local = (*consumed)
                    .child("wired")
                    .shared(false)
                    .spawn(|_| pending::<()>());
                let ran = factory.clone();
                let spawned = consumed.spawn_local(move |_| {
                    ran.store(true, Ordering::SeqCst);
                    ready(())
                });
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

/// Spec test 19: a thread that closes with a job queued drops the job unrun. Its handle
/// resolves `Closed`, its consumed context's node closes and the residents gauge decrements.
fn close_with_queued_job<R: Runner>(runner: R)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        let ran = flag();
        let factory = ran.clone();

        // The job's context is not below the root, so only the dropped job can close its node.
        let consumed = context.child("job");
        let wired = consumed
            .child("wired")
            .shared(false)
            .spawn(|_| pending::<()>());
        let root = context
            .child("queued")
            .thread()
            .spawn(move |local| async move {
                // Queue a job and end the root in the same poll, so the thread closes with the
                // job queued.
                let home = local.home().clone();
                let job = consumed.spawn_on(&home, recording(&factory));
                let counted = residents(&*local, home.name());
                (job, counted, home)
            })
            .expect("thread");
        let (job, counted, home) = root.await.expect("root");
        assert_eq!(
            counted,
            Some(2),
            "the root and the queued job are residents"
        );
        assert!(matches!(job.await, Err(Error::Closed)));
        assert!(matches!(wired.await, Err(Error::Closed)));
        assert!(!ran.load(Ordering::SeqCst), "the queued factory ran");
        settle(&context, || residents(&context, home.name()) == Some(0)).await;
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_close_with_queued_job(#[case] backend: Backend) {
    on_backend!(backend, false, close_with_queued_job());
}

/// A capture that, when dropped, spawns onto its thread with a `spawn_on` and a placed spawn.
struct Reenter<C: Spawner> {
    /// The context the spawns consume.
    context: Option<C>,
    /// The thread the spawns target.
    thread: Thread,
    /// Set if a factory of those spawns ran.
    ran: Arc<AtomicBool>,
    /// Receives the spawns' handles.
    handles: Arc<Mutex<Vec<Handle<()>>>>,
}

impl<C: Spawner> Drop for Reenter<C> {
    fn drop(&mut self) {
        let Some(context) = self.context.take() else {
            return;
        };
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

/// Spec test 20: a queued job's capture that spawns onto its own thread while the close drops it
/// does not deadlock, and those spawns resolve `Closed`.
fn close_reentrant_drop<R: Runner>(runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let ran = flag();
        let handles = Arc::new(Mutex::new(Vec::new()));
        let reenter = context.child("reenter");
        let (capture_ran, capture_handles) = (ran.clone(), handles.clone());
        let root = context
            .child("reentrant")
            .thread()
            .spawn(move |local| async move {
                let home = local.home().clone();
                let capture = Reenter {
                    context: Some(reenter),
                    thread: home.clone(),
                    ran: capture_ran,
                    handles: capture_handles,
                };
                // A handle in a vector, since an async block yielding a future reads as a
                // missing await.
                vec![(*local).child("queued").spawn_on(&home, move |_| {
                    let _capture = capture;
                    ready(())
                })]
            })
            .expect("thread");
        let queued = root.await.expect("root").pop().expect("queued");
        assert!(matches!(queued.await, Err(Error::Closed)));
        settle(&context, || handles.lock().len() == 2).await;
        for handle in handles.lock().drain(..) {
            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }
        assert!(!ran.load(Ordering::SeqCst), "a spawn from the close ran");
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_close_reentrant_drop(#[case] backend: Backend) {
    within(move || on_backend!(backend, false, close_reentrant_drop()));
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

/// A future that completes at once and then panics when dropped, setting `dropped`.
fn ready_then_panic(dropped: Arc<AtomicBool>) -> impl Future<Output = ()> + Send + 'static {
    let guard = PanicOnDrop(dropped);
    poll_fn(move |_| {
        let _guard = &guard;
        Poll::Ready(())
    })
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
    /// A `spawn_on` future panics in a poll.
    SpawnOnPoll,
    /// A `spawn_local` future panics in a poll.
    SpawnLocalPoll,
    /// A placed spawn's future panics in a poll.
    PlacedPoll,
    /// A root future panics in a poll.
    RootPoll,
    /// A resident future panics when dropped after an abort.
    AbortDisposal,
    /// An output panics when dropped because its handle was dropped.
    OutputDisposal,
    /// A queued job's capture panics when the close drops it.
    QueuedCapture,
    /// Two queued jobs' captures each panic during the same close.
    TwoQueuedCaptures,
    /// A root future completes, then panics when dropped.
    RootReady,
    /// A `spawn_on` future completes, then panics when dropped.
    SpawnOnReady,
    /// A `spawn_local` future completes, then panics when dropped.
    SpawnLocalReady,
    /// A parked `spawn_local` factory's capture panics when its aborted task is skipped.
    ParkedCapture,
}

impl Scenario {
    /// Whether the panic is reported through the runner's panicker. Disposal panics are
    /// contained on io_uring (spec 5.4).
    const fn reported(self, backend: Backend) -> bool {
        match self {
            Self::SpawnOnFactory
            | Self::SpawnLocalFactory
            | Self::RootFactory
            | Self::SpawnOnPoll
            | Self::SpawnLocalPoll
            | Self::PlacedPoll
            | Self::RootPoll => true,
            _ => {
                #[cfg(target_os = "linux")]
                if matches!(backend, Backend::Iouring) {
                    return false;
                }
                let _ = backend;
                true
            }
        }
    }
}

/// Raise the panic of `scenario`, with `thread` a built thread that outlives it, and assert
/// the outcome of the task that panicked (spec 5.4).
async fn raise<C>(context: &C, thread: &Thread, scenario: Scenario)
where
    C: Spawner + Clock,
{
    let dropped = flag();
    let ran = flag();
    match scenario {
        Scenario::SpawnOnFactory => {
            let handle = context
                .child("factory")
                .spawn_on(thread, |_| -> Ready<()> { panic!("{PANIC}") });
            assert!(matches!(handle.await, Err(Error::Exited)));
        }
        Scenario::SpawnLocalFactory => {
            let root = context.child("local").thread().spawn(|local| async move {
                let failed = local
                    .child("factory")
                    .spawn_local(|_| -> Ready<()> { panic!("{PANIC}") })
                    .await;
                let next = local.child("next").spawn_local(|_| async { 3 }).await;
                matches!(failed, Err(Error::Exited)) && matches!(next, Ok(3))
            });
            assert!(root.expect("thread").await.expect("root"));
        }
        Scenario::RootFactory => {
            let (root, recorded) = Recorder::new(context.child("root"));
            let handle = root
                .thread()
                .spawn(|_| -> Ready<()> { panic!("{PANIC}") })
                .expect("thread");
            assert!(matches!(handle.await, Err(Error::Exited)));

            // The thread closed with its root.
            let probe = context
                .child("probe")
                .spawn_on(&recorded.thread(), |_| pending::<()>());
            assert!(matches!(probe.await, Err(Error::Closed)));
        }
        Scenario::SpawnOnPoll => {
            let handle = context.child("poll").spawn_on(thread, |_| async {
                panic!("{PANIC}");
            });
            assert!(matches!(handle.await, Err(Error::Exited)));
        }
        Scenario::SpawnLocalPoll => {
            let root = context.child("local").thread().spawn(|local| async move {
                let failed = local
                    .child("poll")
                    .spawn_local(|_| async {
                        panic!("{PANIC}");
                    })
                    .await;
                matches!(failed, Err(Error::Exited))
            });
            assert!(root.expect("thread").await.expect("root"));
        }
        Scenario::PlacedPoll => {
            let handle = context.child("placed").on(thread).spawn(|_| async {
                panic!("{PANIC}");
            });
            assert!(matches!(handle.await, Err(Error::Exited)));
        }
        Scenario::RootPoll => {
            let handle = context.child("root").thread().spawn(|_| async {
                panic!("{PANIC}");
            });
            assert!(matches!(handle.expect("thread").await, Err(Error::Exited)));
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
        Scenario::OutputDisposal => {
            let (entered, enter) = oneshot::channel();
            let (release, released) = oneshot::channel::<()>();
            let guard = dropped.clone();
            let handle = context
                .child("output")
                .spawn_on(thread, move |_| async move {
                    entered.send(()).expect("entered");
                    released.await.expect("released");
                    PanicOnDrop(guard)
                });
            enter.await.expect("entered");
            drop(handle);
            release.send(()).expect("release");
            settle(context, || dropped.load(Ordering::SeqCst)).await;
        }
        Scenario::QueuedCapture | Scenario::TwoQueuedCaptures => {
            let count = if matches!(scenario, Scenario::QueuedCapture) {
                1
            } else {
                2
            };
            let drops: Vec<_> = (0..count).map(|_| flag()).collect();
            let captures: Vec<_> = drops.iter().map(|drop| PanicOnDrop(drop.clone())).collect();
            let factory = ran.clone();
            let root = context
                .child("queue")
                .thread()
                .spawn(move |local| async move {
                    // Queue the jobs and end the root in the same poll.
                    let home = local.home().clone();
                    captures
                        .into_iter()
                        .map(|capture| {
                            let ran = factory.clone();
                            (*local).child("queued").spawn_on(&home, move |_| {
                                let _capture = capture;
                                ran.store(true, Ordering::SeqCst);
                                ready(())
                            })
                        })
                        .collect::<Vec<_>>()
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
        Scenario::RootReady => {
            let handle = context
                .child("root")
                .thread()
                .spawn(move |_| ready_then_panic(dropped))
                .expect("thread");
            assert!(matches!(handle.await, Err(Error::Closed)));
        }
        Scenario::SpawnOnReady => {
            let handle = context
                .child("ready")
                .spawn_on(thread, move |_| ready_then_panic(dropped));
            assert!(matches!(handle.await, Err(Error::Closed)));
        }
        Scenario::SpawnLocalReady => {
            let root = context
                .child("local")
                .thread()
                .spawn(move |local| async move {
                    let done = local
                        .child("ready")
                        .spawn_local(move |_| ready_then_panic(dropped))
                        .await;
                    matches!(done, Err(Error::Closed))
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
                    let capture = PanicOnDrop(guard);
                    let handle = local.child("parked").spawn_local(move |_| {
                        let _capture = capture;
                        factory.store(true, Ordering::SeqCst);
                        ready(())
                    });
                    handle.abort();
                    matches!(handle.await, Err(Error::Closed))
                });
            assert!(root.expect("thread").await.expect("root"));
            settle(context, || dropped.load(Ordering::SeqCst)).await;
            assert!(!ran.load(Ordering::SeqCst), "the aborted factory ran");
        }
    }
}

/// Spec test 17 for one runner: raise the panic of `scenario`, check that a resident of the
/// same thread and a shared task survive it, and check how the run ends. A reported panic fails
/// the run unless panics are caught. A contained one never does.
fn panic_matrix<R: Runner>(runner: R, backend: Backend, scenario: Scenario, catch: bool)
where
    R::Context: Spawner + Clock,
{
    let result = catch_unwind(AssertUnwindSafe(|| {
        runner.start(|context| async move {
            let thread = context.child("built").thread().build().expect("thread");
            let (release, released) = oneshot::channel::<()>();
            let survivor = context.child("survivor").spawn_on(&thread, |_| async move {
                released.await.expect("released");
                5
            });
            raise(&context, &thread, scenario).await;
            release.send(()).expect("release");
            assert!(matches!(survivor.await, Ok(5)));
            let after = context.child("after").spawn(|_| async { 7 });
            assert!(matches!(after.await, Ok(7)));
        })
    }));
    if scenario.reported(backend) && !catch {
        let panic = result.expect_err("a reported panic did not fail the run");
        assert_eq!(extract_panic_message(&*panic), PANIC);
    } else {
        result.expect("the run failed");
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
        Scenario::SpawnOnPoll,
        Scenario::SpawnLocalPoll,
        Scenario::PlacedPoll,
        Scenario::RootPoll,
        Scenario::AbortDisposal,
        Scenario::OutputDisposal,
        Scenario::QueuedCapture,
        Scenario::TwoQueuedCaptures,
        Scenario::RootReady,
        Scenario::SpawnOnReady,
        Scenario::SpawnLocalReady,
        Scenario::ParkedCapture
    )]
    scenario: Scenario,
    #[values(false, true)] catch: bool,
) {
    on_backend!(backend, catch, panic_matrix(backend, scenario, catch));
}

/// Spec test 28: the run's root returns while a resident is pending, and the resident's
/// destructor panics during the shutdown close. Tokio and deterministic report it, so it fails
/// the run unless panics are caught. io_uring contains it.
fn late_disposal_panic<R: Runner>(runner: R, dropped: Arc<AtomicBool>)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let thread = context.child("late").thread().build().expect("thread");
        let (started, start) = oneshot::channel();
        drop(
            context
                .child("resident")
                .spawn_on(&thread, move |_| async move {
                    let _guard = PanicOnDrop(dropped);
                    started.send(()).expect("started");
                    pending::<()>().await;
                }),
        );
        start.await.expect("started");
    });
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_late_disposal_panic(#[case] backend: Backend, #[values(false, true)] catch: bool) {
    let dropped = flag();
    let resident = dropped.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        on_backend!(backend, catch, late_disposal_panic(resident));
    }));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the resident was not dropped"
    );
    if Scenario::AbortDisposal.reported(backend) && !catch {
        let panic = result.expect_err("the late disposal panic did not fail the run");
        assert_eq!(extract_panic_message(&*panic), PANIC);
    } else {
        result.expect("the run failed");
    }
}

/// Records what each finisher returns when a context is dropped during the shutdown abort.
struct BuildOnDrop<C: Spawner> {
    /// The context the finishers consume.
    context: Option<C>,
    /// Whether each finisher returned `Closed`, in order: build, attach, spawn.
    closed: Arc<Mutex<Vec<bool>>>,
    /// Set if the root factory ran.
    ran: Arc<AtomicBool>,
}

impl<C: Spawner> Drop for BuildOnDrop<C> {
    fn drop(&mut self) {
        let Some(context) = self.context.take() else {
            return;
        };
        let build = context.child("build").thread().build();
        let attach = context.child("attach").thread().attach();
        let spawn = context.child("spawn").thread().spawn(recording(&self.ran));
        self.closed.lock().extend([
            matches!(build, Err(ThreadError::Closed)),
            matches!(attach, Err(ThreadError::Closed)),
            matches!(spawn, Err(ThreadError::Closed)),
        ]);
    }
}

/// Spec test 22: every finisher returns `Closed` from an aborted lineage and from a drop during
/// the shutdown abort, an empty pin on an aborted lineage returns `EmptyCpus` (CPU validation
/// comes first), and nothing is left behind. With `pin`, a pinned builder returned from the run
/// returns `Closed` afterwards.
fn builder_closed<R: Runner>(
    runner: R,
    stale: Thread,
    pin: Option<usize>,
    closed: Arc<Mutex<Vec<bool>>>,
    ran: Arc<AtomicBool>,
) where
    R::Context: Spawner + Clock + Metrics,
{
    let builder = runner.start(|context| async move {
        // A placed spawn toward a thread of another runner is rejected and aborts the node of
        // the context it consumed, with its whole lineage.
        let lineage = context.child("lineage");
        let contexts = [
            lineage.child("build"),
            lineage.child("attach"),
            lineage.child("spawn"),
            lineage.child("empty"),
        ];
        let rejected = lineage.on(&stale).spawn(|_| async {});
        assert!(matches!(rejected.await, Err(Error::Closed)));
        let [build, attach, spawn, empty] = contexts;
        let names = [build.name().label, attach.name().label, spawn.name().label];
        assert!(matches!(build.thread().build(), Err(ThreadError::Closed)));
        assert!(matches!(attach.thread().attach(), Err(ThreadError::Closed)));
        let spawned = spawn.thread().spawn(recording(&ran));
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
            ran,
        };
        drop(context.child("task").spawn(move |_| async move {
            let _holder = holder;
            started.send(()).expect("started");
            pending::<()>().await;
        }));
        start.await.expect("started");

        pin.map(|cpu| context.child("returned").thread().pin(cpu))
    });
    if let Some(builder) = builder {
        assert!(matches!(builder.build(), Err(ThreadError::Closed)));
    }
}

#[rstest]
#[case::deterministic(Backend::Deterministic)]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_builder_closed(#[case] backend: Backend) {
    // A pin the runner accepts, for the builder returned from the run (native runners only:
    // a deterministic context must not outlive its run).
    let pin = if backend == Backend::Deterministic {
        None
    } else {
        valid_cpu()
    };
    let stale = stale_thread();
    let closed = Arc::new(Mutex::new(Vec::new()));
    let ran = flag();
    on_backend!(
        backend,
        false,
        builder_closed(stale, pin, closed.clone(), ran.clone())
    );
    assert_eq!(
        *closed.lock(),
        [true; 3],
        "a finisher in a shutdown drop did not return Closed"
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

/// Spec test 24 for one runner with base set `base` (`None` if unknown).
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

        // An id at or above 1024 is not stored, but the set is not empty.
        assert!(!Cpus::from(5000).is_empty());
        let Some(base) = base else {
            for cpus in [Cpus::from(0), Cpus::from(5000), Cpus::from(0..=usize::MAX)] {
                assert!(matches!(pin(cpus), Err(ThreadError::UnsupportedAffinity)));
            }
            return;
        };
        let inside = base.iter().next().expect("empty base set");
        let outside = (0..1024).find(|&id| !base.contains(id)).unwrap_or(1024);

        // The smallest requested id outside the base set, including ids at or above 1024.
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
    match backend {
        Backend::Deterministic => pin_validation(
            deterministic::Runner::new(deterministic::Config::default().with_cpus(0..=3)),
            Some(Cpus::from(0..=3)),
        ),
        Backend::Tokio => {
            // A native runner's base set is the CPU set of the thread that starts it.
            #[cfg(all(target_os = "linux", not(miri)))]
            {
                use crate::threads::affinity::{current, tests::override_base};
                pin_validation(tokio::Runner::default(), current());
                override_base(Some(None));
                pin_validation(tokio::Runner::default(), None);
                override_base(None);
            }
            #[cfg(not(all(target_os = "linux", not(miri))))]
            pin_validation(tokio::Runner::default(), None);
        }
        #[cfg(target_os = "linux")]
        Backend::Iouring => {
            #[cfg(not(miri))]
            {
                use crate::threads::affinity::{current, tests::override_base};
                pin_validation(iouring::Runner::default(), current());
                override_base(Some(None));
                pin_validation(iouring::Runner::default(), None);
                override_base(None);
            }
            #[cfg(miri)]
            pin_validation(iouring::Runner::default(), None);
        }
    }
}

/// Spec test 29 for one runner: with the OS refusing the thread, every finisher returns
/// `Spawn` and rolls back. The residents series stays absent or 0, a child wired from the
/// consumed context keeps running, a later thread from the same parent works, and the run ends.
fn spawn_failure_rollback<R: Runner>(runner: R)
where
    R::Context: Spawner + Metrics,
{
    use crate::utils::thread::tests::fail_spawns;

    runner.start(|context| async move {
        let parent = context.child("parent");
        let consumed = parent.child("t");
        let (release, released) = oneshot::channel::<()>();
        let wired = consumed
            .child("wired")
            .shared(false)
            .spawn(move |_| async move {
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
        let ran = flag();
        fail_spawns(1);
        let spawned = parent.child("t").thread().spawn(recording(&ran));
        assert!(matches!(spawned, Err(ThreadError::Spawn(_))));
        assert!(!ran.load(Ordering::SeqCst), "the refused root ran");

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
    within(move || on_backend!(backend, false, spawn_failure_rollback()));
}

/// Spawn an OS thread that aborts `context`'s node, with its lineage, off every runtime
/// thread. A placed spawn toward a thread of another runner is rejected synchronously and
/// aborts the node of the context it consumed.
fn abort_off_runtime<C: Spawner>(context: C, stale: Thread) -> JoinHandle<()> {
    std::thread::spawn(move || drop(context.on(&stale).spawn(|_| async {})))
}

/// Wait on the calling OS thread, for a bounded time, until `done` holds.
fn block_until(done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "condition did not hold in time");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Blocks the first thread aborter a tree abort takes, before it runs, until released.
struct AbortGate {
    /// Set once the callback holds an aborter.
    taken: Arc<AtomicBool>,
    /// Lets the held aborter run.
    release: Arc<AtomicBool>,
}

impl AbortGate {
    /// Install the gate in the abort callback slot.
    fn install() -> Self {
        let armed = Arc::new(AtomicBool::new(true));
        let taken = flag();
        let release = flag();
        let (held, released) = (taken.clone(), release.clone());
        set_before_thread_abort(Some(Arc::new(move || {
            if !armed.swap(false, Ordering::SeqCst) {
                return;
            }
            held.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(30);
            while !released.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        })));
        Self { taken, release }
    }

    /// Whether the callback holds an aborter.
    fn taken(&self) -> bool {
        self.taken.load(Ordering::SeqCst)
    }
}

impl Drop for AbortGate {
    fn drop(&mut self) {
        self.release.store(true, Ordering::SeqCst);
        set_before_thread_abort(None);
    }
}

/// Spec test 27 for one native runner: an abort of the thread's node from another OS thread
/// takes the node's aborter and blocks before running it. The root then ends, by completing or
/// by being dropped unrun, and once its handle resolves every spawn toward the thread is closed
/// at once and never runs its factory.
fn root_barrier_external_abort<R: Runner>(runner: R, stale: Thread)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        // The root completes while the abort holds the thread's aborter.
        let gate = AbortGate::install();
        let parent = context.child("parent");
        let (root, recorded) = Recorder::new(parent.child("t"));
        let (finish, finished) = oneshot::channel::<()>();
        let handle = root
            .thread()
            .spawn(move |_| async move {
                finished.await.expect("finish");
                7
            })
            .expect("thread");
        let walker = abort_off_runtime(parent, stale.clone());
        settle(&context, || gate.taken()).await;
        finish.send(()).expect("finish");
        assert!(matches!(handle.await, Ok(7)));
        assert_barrier(&context, &recorded.thread());
        drop(gate);
        settle(&context, || walker.is_finished()).await;
        walker.join().expect("walker");

        // The root is dropped unrun while the abort holds the thread's aborter. The recorder
        // starts the abort once the thread exists, then redirects the root to a stale thread.
        let gate = AbortGate::install();
        let parent = context.child("parent");
        let (root, recorded) = Recorder::new(parent.child("t"));
        let walker = Arc::new(Mutex::new(None));
        let (slot, taken, stale_root) = (walker.clone(), gate.taken.clone(), stale.clone());
        recorded.hook(move || {
            *slot.lock() = Some(abort_off_runtime(parent, stale_root));
            block_until(|| taken.load(Ordering::SeqCst));
        });
        recorded.redirect(stale);
        let ran = flag();
        let handle = root.thread().spawn(recording(&ran)).expect("thread");
        assert!(gate.taken());
        assert!(matches!(handle.await, Err(Error::Closed)));
        assert!(!ran.load(Ordering::SeqCst), "the redirected root ran");
        assert_barrier(&context, &recorded.thread());
        drop(gate);
        let walker = walker.lock().take().expect("walker");
        settle(&context, || walker.is_finished()).await;
        walker.join().expect("walker");
    });
}

#[rstest]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_root_barrier_external_abort(#[case] backend: Backend) {
    let stale = stale_thread();
    within(move || on_backend!(backend, false, root_barrier_external_abort(stale)));
}

/// Holds the first admission inside its critical section, optionally while another OS thread
/// aborts a lineage.
struct AdmissionGate {
    /// Set once an admission entered the callback.
    entered: Arc<AtomicBool>,
    /// The OS thread aborting the lineage, if any.
    walker: Option<JoinHandle<()>>,
}

impl AdmissionGate {
    /// Install the gate in the admission callback slot. The first admission signals, lets
    /// `abort` (a context and a stale thread) start aborting the context's lineage and waits
    /// for it to begin, then holds the critical section for `hold`.
    fn install<C: Spawner>(abort: Option<(C, Thread)>, hold: Duration) -> Self {
        let entered = flag();
        let (go, start) = channel::<()>();
        let (aborting, begun) = channel::<()>();
        let walker = abort.map(|(context, stale)| {
            std::thread::spawn(move || {
                if start.recv_timeout(Duration::from_secs(30)).is_err() {
                    return;
                }
                aborting.send(()).expect("aborting");
                drop(context.on(&stale).spawn(|_| async {}));
            })
        });
        let wait = walker.is_some();
        let signals = Mutex::new(Some((go, begun)));
        let inside = entered.clone();
        set_before_enqueue(Some(Arc::new(move || {
            let Some((go, begun)) = signals.lock().take() else {
                return;
            };
            inside.store(true, Ordering::SeqCst);
            if wait {
                go.send(()).expect("go");
                begun
                    .recv_timeout(Duration::from_secs(30))
                    .expect("aborting");
            }

            // Give the other side time to block on the lock this admission holds.
            std::thread::sleep(hold);
        })));
        Self { entered, walker }
    }

    /// Whether an admission entered the callback.
    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    /// Whether the aborting thread, if any, finished.
    fn walked(&self) -> bool {
        self.walker.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for AdmissionGate {
    fn drop(&mut self) {
        set_before_enqueue(None);
        if let Some(walker) = self.walker.take() {
            walker.join().expect("walker");
        }
    }
}

/// Which submission races an abort in [admission_race].
#[derive(Clone, Copy, Debug)]
enum Submission {
    /// A placed spawn.
    Placed,
    /// A `spawn_on`.
    SpawnOn,
}

/// Wait until `thread` finished closing with nothing queued and no resident counted.
async fn assert_drained<C: Clock + Metrics>(context: &C, thread: &Thread) {
    let inner = thread.inner();
    settle(context, || inner.state() == State::Closed).await;
    assert_eq!(inner.queued(), 0, "a job stayed queued on a closed thread");
    settle(context, || residents(context, thread.name()) == Some(0)).await;
}

/// Spec test 35 for one native runner: a submission on a runtime thread holds its admission
/// critical section while another OS thread aborts the thread's lineage. The submission either
/// runs or resolves `Closed`, and the thread closes with nothing left queued.
fn admission_race<R: Runner>(runner: R, stale: Thread, submission: Submission)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        let parent = context.child("parent");
        let thread = parent.child("t").thread().build().expect("thread");
        let gate = AdmissionGate::install(Some((parent, stale)), Duration::from_millis(50));
        let handle = match submission {
            Submission::Placed => context.child("sub").on(&thread).spawn(|_| async { 1 }),
            Submission::SpawnOn => context.child("sub").spawn_on(&thread, |_| async { 1 }),
        };
        assert!(
            gate.entered(),
            "the submission skipped the admission callback"
        );
        assert!(matches!(handle.await, Ok(1) | Err(Error::Closed)));
        settle(&context, || gate.walked()).await;
        drop(gate);
        assert_drained(&context, &thread).await;
    });
}

#[rstest]
#[case::tokio(Backend::Tokio)]
#[cfg_attr(target_os = "linux", case::iouring(Backend::Iouring))]
fn test_thread_admission_race(
    #[case] backend: Backend,
    #[values(Submission::Placed, Submission::SpawnOn)] submission: Submission,
) {
    let stale = stale_thread();
    within(move || on_backend!(backend, false, admission_race(stale, submission)));
}

/// Spec test 35 on deterministic. The loop keeps running on `reschedule()` while other OS
/// threads submit, create threads and abort lineages.
fn deterministic_admission_race(stale: Thread) {
    deterministic::Runner::default().start(|context| async move {
        // A placed spawn submitted off the loop races an abort of the thread's lineage.
        let parent = context.child("parent");
        let thread = parent.child("t").thread().build().expect("thread");
        let gate = AdmissionGate::install(Some((parent, stale.clone())), Duration::from_millis(50));
        let submitter = context.child("sub").on(&thread);
        let submit = std::thread::spawn(move || submitter.spawn(|_| async { 1 }));
        while !submit.is_finished() || !gate.walked() {
            reschedule().await;
        }
        let handle = submit.join().expect("submitter");
        assert!(
            gate.entered(),
            "the submission skipped the admission callback"
        );
        drop(gate);
        assert!(matches!(handle.await, Ok(1) | Err(Error::Closed)));
        assert_drained(&context, &thread).await;
        settle(&context, || count_running_tasks(&context, "sub") == 0).await;

        eprintln!("PHASE contended");
        // The loop first schedules a resident of a thread while a submission off the loop
        // holds that thread's admission critical section.
        let thread = context.child("contended").thread().build().expect("thread");
        let first = context.child("first").spawn_on(&thread, |_| async { 2 });
        let gate = AdmissionGate::install(
            None::<(deterministic::Context, Thread)>,
            Duration::from_millis(100),
        );
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
        assert!(matches!(first.await, Ok(2)));
        assert!(matches!(second.await, Ok(3)));

        eprintln!("PHASE creation");
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
    within(move || deterministic_admission_race(stale));
}

/// Spec test 31 for one wrapper: `attach`, `spawn`, `spawn_on` and `spawn_local` all hand
/// their closures the wrapper type with its state (`holds` checks it), and the root barrier of
/// spec test 8 holds through the wrapper, after completion and after a root dropped unrun.
async fn wrapper_threads<W>(context: W, holds: fn(&W) -> bool, stale: Thread)
where
    W: Spawner,
{
    assert!(holds(&context));

    let attached = context.child("attached").thread().attach().expect("thread");
    assert!(holds(&attached));
    let task = attached
        .child("task")
        .spawn(move |task: W| async move { holds(&task) });
    assert!(matches!(task.await, Ok(true)));

    let root = context
        .child("root")
        .thread()
        .spawn(move |local: Local<W>| async move {
            let leaf = local
                .child("leaf")
                .spawn_local(move |leaf: Local<W>| async move { holds(&leaf) })
                .await;
            (
                holds(&local) && matches!(leaf, Ok(true)),
                local.home().clone(),
            )
        })
        .expect("thread");
    let (held, home) = root.await.expect("root");
    assert!(
        held,
        "a root or spawn_local closure lost the wrapper's state"
    );
    assert_barrier(&context, &home);

    let thread = context.child("built").thread().build().expect("thread");
    let remote = context
        .child("remote")
        .spawn_on(&thread, move |local: Local<W>| async move { holds(&local) });
    assert!(matches!(remote.await, Ok(true)));

    let (root, recorded) = Recorder::new(context.child("unrun"));
    recorded.redirect(stale);
    let ran = flag();
    let handle = root.thread().spawn(recording(&ran)).expect("thread");
    assert!(matches!(handle.await, Err(Error::Closed)));
    assert!(!ran.load(Ordering::SeqCst), "the redirected root ran");
    assert_barrier(&context, &recorded.thread());
}

#[test]
fn test_thread_wrapper_contexts() {
    let stale = stale_thread();
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
        wrapper_threads(
            recording,
            |context| !context.recordings.snapshot().writes.is_empty(),
            stale.clone(),
        )
        .await;

        let pending = PendingSyncs::default();
        pending.arm();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: pending.clone(),
        };
        wrapper_threads(
            delayed,
            |context| context.pending.lock().len() == 1,
            stale.clone(),
        )
        .await;
        pending.unblock();

        let faulty = MutationFaultContext {
            inner: context.child("faulty"),
            faults: MutationFaults::default(),
        };
        faulty.faults.allow(0);
        assert!(faulty.open("partition", b"refused").await.is_err());
        assert!(faulty.faults.failed());
        wrapper_threads(faulty, |context| context.faults.failed(), stale).await;
    });
}
