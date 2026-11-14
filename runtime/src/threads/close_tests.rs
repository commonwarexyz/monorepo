//! Tests of closing runtime threads, their root barrier and their panics, on every runner.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{
    Blob as _, Clock, Cpus, Error, Handle, Local, Metrics, Name, Runner as _, Spawner,
    Storage as _, Supervisor, Thread, ThreadBuilder, ThreadError, WriteOptions, deterministic,
    mocks::{
        DelayedSyncContext, MutationFaultContext, MutationFaults, PendingSyncs, RecordingContext,
    },
    reschedule,
    signal::Signal,
    threads::{
        admission::{State, tests::set_before_enqueue},
        testing::{
            DropFlag, OnDrop, TestRunner, bounded, capturing, closed, executions, flag, is_set,
            on_drop, park, recording, residents, settle,
        },
    },
    tokio,
    utils::{extract_panic_message, thread::tests::fail_spawns},
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{
    FutureExt as _,
    future::{BoxFuture, pending},
};
use rstest::rstest;
use std::{
    future::{Future, poll_fn, ready},
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

/// A thread of a runner that already returned, which every later runner rejects.
fn stale_thread() -> Thread {
    deterministic::Runner::default()
        .start(|context| async move { context.child("stale").thread().build().unwrap() })
}

/// Abort the lineage of `context`. A placed spawn toward a thread of another runner is rejected
/// at once and aborts the node of the context it consumed.
fn abort_lineage<C: Spawner>(context: C, stale: &Thread) {
    drop(context.on(stale).spawn(|_| async {}));
}

/// The last thread a [Recorder]'s `spawn_on` received, and where its next one goes instead.
type Seen = Arc<Mutex<(Option<Thread>, Option<Thread>)>>;

/// A wrapper context whose `spawn_on` records the thread it receives and can send its job
/// toward another one. [ThreadBuilder::spawn] and [Local::spawn_local] call `spawn_on` on the
/// context they hold, so this gets the thread of a root that never runs and misdelivers a job.
#[derive(Clone)]
struct Recorder<E>(E, Seen);

impl<E: Supervisor> Supervisor for Recorder<E> {
    fn name(&self) -> Name {
        self.0.name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self(self.0.child(label), self.1.clone())
    }

    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self(self.0.with_attribute(key, value), self.1)
    }
}

impl<E: Spawner> Spawner for Recorder<E> {
    fn shared(self) -> Self {
        Self(self.0.shared(), self.1)
    }

    fn blocking(self) -> Self {
        Self(self.0.blocking(), self.1)
    }

    fn on(self, thread: &Thread) -> Self {
        Self(self.0.on(thread), self.1)
    }

    fn placed(self) -> Self {
        Self(self.0.placed(), self.1)
    }

    fn thread(self) -> ThreadBuilder<Self> {
        self.0.thread().map(move |inner| Self(inner, self.1))
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.0.spawn(move |inner| f(Self(inner, self.1)))
    }

    fn spawn_on<F, Fut, T>(self, thread: &Thread, f: F) -> Handle<T>
    where
        F: FnOnce(Local<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let Self(inner, seen) = self;
        let redirect = mem::replace(&mut *seen.lock(), (Some(thread.clone()), None)).1;
        let target = redirect.as_ref().unwrap_or(thread);
        inner.spawn_on(target, move |local| f(local.map(|inner| Self(inner, seen))))
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.0.stop(value, timeout).await
    }

    fn stopped(&self) -> Signal {
        self.0.stopped()
    }
}

/// Assert the root barrier of the thread `seen` recorded, whose root handle resolved. A
/// `spawn_on` and a placed spawn toward it are closed when they return, and neither factory runs.
fn assert_barrier<C: Spawner>(context: &C, seen: &Seen) {
    let thread = seen.lock().0.take().unwrap();
    let ran = flag();
    let on = context.child("late").spawn_on(&thread, recording(&ran));
    let placed = context.child("late").on(&thread).spawn(recording(&ran));
    assert_eq!(closed(on).now_or_never(), Some(true));
    assert_eq!(closed(placed).now_or_never(), Some(true));
    assert!(!is_set(&ran), "a factory ran after the root barrier");
}

// Once a root's handle resolves, spawns toward its thread are closed at once and never run their
// factories: after the root completes, after it is aborted at once, and after it is dropped
// unrun, redirected toward a thread of an earlier runner. An aborted root resolves Closed, and
// on deterministic the abort comes before its factory can run.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_root_exit_closes<R: TestRunner>(#[case] runner: R) {
    let stale = stale_thread();
    bounded(move || {
        runner.start(|context| async move {
            // Native threads may close concurrently with the caller, so repeat to expose a race.
            let seen = Seen::default();
            for _ in 0..16 {
                let root = Recorder(context.child("done"), seen.clone());
                let handle = root.thread().spawn(|_| async { 7 }).unwrap();
                assert!(matches!(handle.await, Ok(7)));
                assert_barrier(&context, &seen);

                let root = Recorder(context.child("aborted"), seen.clone());
                let ran = flag();
                let factory = ran.clone();
                let root = root.thread().spawn(move |_| {
                    factory.store(true, Ordering::SeqCst);
                    pending::<()>()
                });
                let handle = root.unwrap();
                handle.abort();
                assert!(closed(handle).await, "the aborted root did not close");
                assert!(R::NATIVE || !is_set(&ran), "the root ran before its abort");
                assert_barrier(&context, &seen);

                let root = Recorder(context.child("unrun"), seen.clone());
                seen.lock().1 = Some(stale.clone());
                let ran = flag();
                let handle = root.thread().spawn(recording(&ran)).unwrap();
                assert!(closed(handle).await, "the redirected root did not close");
                assert!(!is_set(&ran), "the redirected root ran");
                assert_barrier(&context, &seen);
            }
        })
    });
}

// A spawn_on or spawn_local aborted before the thread's next turn never runs its factory, aborts
// the consumed context's node, so a child wired from it is aborted, and leaves no parked
// spawn_local factory once the turn that skipped it ended.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_skipped_factory_aborts_node<R: TestRunner>(#[case] runner: R) {
    runner.start(|context| async move {
        let ran = flag();
        let factory = ran.clone();
        let root = context.child("skip").thread();
        let root = root.spawn(move |local| async move {
            // Everything up to the first await happens in this poll, before the host can take a
            // turn.
            let consumed = (*local).child("on");
            let wired_on = consumed.child("wired").shared().spawn(|_| pending::<()>());
            let on = consumed.spawn_on(local.home(), recording(&factory));
            on.abort();
            let consumed = local.child("local");
            let wired_local = (*consumed).child("wired").shared();
            let wired_local = wired_local.spawn(|_| pending::<()>());
            let spawned = consumed.spawn_local(recording(&factory));
            spawned.abort();

            // The thread stays open while these resolve, so only the skipped jobs can close them.
            assert!(closed(on).await, "the aborted spawn_on stayed open");
            assert!(closed(spawned).await, "the aborted spawn_local stayed open");
            assert!(closed(wired_on).await, "a spawn_on node stayed open");
            assert!(closed(wired_local).await, "a spawn_local node stayed open");
            assert_eq!(local.owner().parked(), 0, "a skipped factory stayed parked");
        });
        root.unwrap().await.unwrap();
        assert!(!is_set(&ran), "a skipped factory ran");
    });
}

/// The labels of dropped [record]s, in drop order.
type Order = Arc<Mutex<Vec<&'static str>>>;

/// A value that records `label` in `order` when dropped, unless disarmed first.
fn record(label: &'static str, order: &Order) -> OnDrop<impl FnOnce() + Send + use<>> {
    let order = order.clone();
    on_drop(move || order.lock().push(label))
}

/// Wait until `thread` finished closing with nothing queued and no resident counted.
async fn drained<C: Clock + Metrics>(context: &C, thread: &Thread) {
    let inner = thread.inner();
    settle(context, || inner.state() == State::Closed).await;
    assert_eq!(inner.queued(), 0, "a job stayed queued on a closed thread");
    settle(context, || residents(context, thread.name()) == Some(0)).await;
}

// A root queues a job and returns in the same poll, so its thread closes with the job queued and
// a resident pending. The close drops the resident before the job, whose factory never runs. The
// job's handle and a child wired from its context resolve Closed, spawns its capture makes toward
// the closing thread while dropped resolve Closed without running, and the thread ends drained.
// In the host failure case, the Tokio host panics as the thread starts closing, so that run
// catches panics.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), false)]
#[case::tokio_host_failure(tokio::Runner::catching(true), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), false))]
fn test_thread_close_order<R: TestRunner>(#[case] runner: R, #[case] host_failure: bool) {
    let order = Order::default();
    let recorded = order.clone();
    bounded(move || {
        runner.start(|context| async move {
            if host_failure {
                tokio::inject_host_failure();
            }
            let (home, homed) = oneshot::channel();
            let (queue, queued) = oneshot::channel();
            let root = context.child("order").thread();
            let root = root.spawn(move |local| async move {
                home.send(local.home().clone()).unwrap();

                // Queue the job and return in the same poll, so the thread closes with it queued.
                let (consumed, factory): (R::Context, _) = queued.await.unwrap();
                let job = consumed.spawn_on(local.home(), factory);
                (job, residents(&*local, local.home().name()))
            });
            let thread = homed.await.unwrap();

            // The resident is supervised outside the thread, so only the close can drop it.
            let (started, start) = oneshot::channel();
            let record = record("resident", &order);
            let resident = context.child("resident");
            let resident = resident.spawn_on(&thread, |_| park(record, Some(started)));
            start.await.unwrap();

            // The job's context is not below the root, so only the dropped job can close its node.
            // When dropped, its capture spawns toward the closing thread and keeps the handles.
            let consumed = context.child("job");
            let wired = consumed.child("wired").shared().spawn(|_| pending::<()>());
            let (ran, handles) = (flag(), Arc::new(Mutex::new(Vec::new())));
            let capture = on_drop({
                let (context, home) = (context.child("reenter"), thread.clone());
                let (ran, handles) = (ran.clone(), handles.clone());
                move || {
                    order.lock().push("job");
                    let on = context.child("on").spawn_on(&home, recording(&ran));
                    let placed = context.child("placed").on(&home).spawn(recording(&ran));
                    handles.lock().extend([on, placed]);
                }
            });
            let job = (consumed, capturing(capture, &ran));
            queue.send(job).ok().unwrap();

            let (job, counted) = root.unwrap().await.unwrap();
            assert_eq!(counted, Some(3), "the root, resident and job are residents");
            assert!(closed(job).await, "the job did not close");
            assert!(closed(resident).await, "the resident did not close");
            assert!(closed(wired).await, "a child of the job's context survived");
            settle(&context, || handles.lock().len() == 2).await;
            for handle in handles.lock().drain(..) {
                let closed = closed(handle).now_or_never();
                assert_eq!(closed, Some(true), "a spawn from the job's drop was open");
            }
            assert!(!is_set(&ran), "a factory ran during the close");
            drained(&context, &thread).await;
        })
    });
    if host_failure {
        assert!(
            !tokio::host_failure_pending(),
            "the host failure did not fire"
        );
    }
    assert_eq!(*recorded.lock(), ["resident", "job"], "wrong drop order");
}

/// Jobs scheduled after the one that closes the thread in [test_thread_close_while_scheduling],
/// enough for several admission batches.
const LATE_JOBS: usize = 3 * 64;

// A thread that starts closing while it schedules a burst of spawn_on jobs drops its pending
// futures before the factory of any job that never ran, including factories older than the
// youngest pending future. The burst's first job closes the thread by aborting the lineage that
// created it, and its last job leaves a pending future if it runs. A resident of the thread
// submits the whole burst in one poll, so on native runners one host turn takes it. Deterministic
// shuffles each ready pass, so its closer runs at a seeded place in the burst.
#[rstest]
#[case::deterministic((0..8).map(deterministic::Runner::seeded).collect())]
#[case::tokio(vec![tokio::Runner::default()])]
#[cfg_attr(target_os = "linux", case::iouring(vec![iouring::Runner::default()]))]
fn test_thread_close_while_scheduling<R: TestRunner>(#[case] runners: Vec<R>) {
    let (mut unrun, mut mixed) = (0, false);
    for runner in runners {
        let stale = stale_thread();
        let order = Order::default();
        let recorded = order.clone();
        bounded(move || {
            runner.start(|context| async move {
                let creator = context.child("creator");
                let thread = creator.child("t").thread().build().unwrap();

                // The resident is supervised outside the creating lineage, so only the close
                // drops it.
                let resident = context.child("resident");
                let resident = resident.spawn_on(&thread, move |local| async move {
                    let _record = record("resident", &order);
                    drop((*local).child("closer").spawn_on(local.home(), move |_| {
                        abort_lineage(creator, &stale);
                        ready(())
                    }));

                    // A job that never runs records its factory's drop.
                    for job in 0..=LATE_JOBS {
                        let (unrun, order) = (record("factory", &order), order.clone());
                        drop((*local).child("late").spawn_on(local.home(), move |_| {
                            unrun.disarm();
                            let young = (job == LATE_JOBS).then(|| record("young", &order));
                            async move {
                                if let Some(_young) = young {
                                    pending::<()>().await;
                                }
                            }
                        }));
                    }
                    pending::<()>().await;
                });
                assert!(closed(resident).await);
                drained(&context, &thread).await;
            })
        });
        let order = recorded.lock().clone();
        let futures = order.iter().take_while(|label| **label != "factory");
        let futures = futures.count();
        let ordered = order[futures..].iter().all(|label| *label == "factory");
        assert!(ordered, "a future was dropped after a factory: {order:?}");
        let resident = order[..futures].contains(&"resident");
        assert!(resident, "the resident was not among the dropped futures");
        unrun += order.len() - futures;
        mixed |= order[..futures].contains(&"young") && futures < order.len();
    }
    assert!(unrun > 0, "every late factory ran");
    assert!(R::NATIVE || mixed, "no seed left an older factory unrun");
}

/// Payload of the panics the panic matrix raises.
const PANIC: &str = "thread test panic";

/// Payload of a destructor panic that follows a poll panic.
const DROP_PANIC: &str = "thread test drop panic";

/// Sets its flag, then panics with [PANIC], when dropped.
struct PanicOnDrop(Arc<AtomicBool>);

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        panic!("{PANIC}");
    }
}

/// A factory that panics with [PANIC], when called if `at_once` and in its future's first poll
/// otherwise.
fn panicking<L>(at_once: bool) -> impl FnOnce(L) -> BoxFuture<'static, ()> + Send + 'static {
    move |_| {
        assert!(!at_once, "{PANIC}");
        async { panic!("{PANIC}") }.boxed()
    }
}

/// A future that holds `guard` until it is dropped. Its first poll completes with `output`, or
/// panics with [PANIC] without one.
fn holding<T: Send + 'static>(
    guard: impl Send + 'static,
    mut output: Option<T>,
) -> impl Future<Output = T> + Send + 'static {
    poll_fn(move |_| {
        let _guard = &guard;
        Poll::Ready(output.take().unwrap_or_else(|| panic!("{PANIC}")))
    })
}

/// A panic of the panic matrix. The first six are raised by a factory or a poll, which every
/// runner reports. The others are raised by a destructor, which io_uring contains.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
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
    /// The captures of two queued jobs each panic during the same close.
    TwoQueuedCaptures,
    /// A `spawn_local` future completes with an output that panics when dropped, then panics
    /// when dropped itself. Its handle was dropped before the task ran.
    DetachedLocalReady,
    /// The same with a handle that is awaited.
    RetainedLocalReady,
    /// The output of a completed `spawn_local` task panics when its handle is dropped without
    /// taking it.
    LocalOutputDisposal,
    /// The capture of a parked `spawn_local` factory panics when its aborted task is skipped.
    ParkedCapture,
    /// Factory captures panic when `spawn_on` and placed spawns are rejected: toward a closed
    /// thread, toward a thread of another runner, and from an aborted lineage.
    Rejected,
    /// A resident left pending when the run's root returns panics when the shutdown close drops
    /// it, next to a pending shared task.
    LateDisposal,
    /// A `spawn_local` output its handle never took is dropped by the shutdown close. It then
    /// spawns through its `Local` with a factory whose capture panics, and panics itself.
    StaleOutput,
}

/// Raise the panic of `scenario`, with `thread` a built thread that outlives it and `stale` a
/// thread of an earlier runner, and assert the outcome of the task that panicked. A scenario
/// whose disposal comes at shutdown leaves its flags to [test_thread_panic_matrix].
async fn raise<C: Spawner + Clock>(
    context: &C,
    thread: &Thread,
    stale: &Thread,
    scenario: Scenario,
    [dropped, ran, other]: [Arc<AtomicBool>; 3],
) {
    use Scenario::*;
    let root = |label| context.child(label).thread();
    let at_once = matches!(scenario, SpawnOnFactory | SpawnLocalFactory | RootFactory);
    match scenario {
        SpawnOnFactory => {
            let handle = context.child("factory").spawn_on(thread, panicking(true));
            assert!(matches!(handle.await, Err(Error::Exited)));
        }
        SpawnLocalFactory | SpawnLocalPoll => {
            // The thread keeps running local tasks afterwards.
            let root = root("local").spawn(move |local| async move {
                let failed = local.child("failing").spawn_local(panicking(at_once));
                assert!(matches!(failed.await, Err(Error::Exited)));
                let next = local.child("next").spawn_local(|_| ready(3));
                assert!(matches!(next.await, Ok(3)));
            });
            root.unwrap().await.unwrap();
        }
        RootFactory | RootPoll => {
            let seen = Seen::default();
            let root = Recorder(context.child("root"), seen.clone());
            let handle = root.thread().spawn(panicking(at_once)).unwrap();
            assert!(matches!(handle.await, Err(Error::Exited)));
            let home = seen.lock().0.take().unwrap();
            let probe = context.child("probe").spawn_on(&home, |_| pending::<()>());
            assert!(closed(probe).await, "the thread outlived its root");
        }
        PlacedPollThenDrop => {
            let guard = dropped.clone();
            let guard = on_drop(move || {
                guard.store(true, Ordering::SeqCst);
                panic!("{DROP_PANIC}");
            });
            let future = holding(guard, None::<()>);
            let handle = context.child("poll").on(thread).spawn(move |_| future);
            assert!(matches!(handle.await, Err(Error::Exited)));
            assert!(is_set(&dropped), "the future was not dropped");
        }
        SpawnOnReadyOutput => {
            let output = PanicOnDrop(other.clone());
            let handle = context.child("ready").spawn_on(thread, move |local| {
                holding(PanicOnDrop(dropped), Some((local.into_inner(), output)))
            });

            // The output that could not be delivered is dropped before the handle resolves.
            assert!(closed(handle).await);
            assert!(is_set(&other), "the output was leaked");
        }
        AbortDisposal => {
            let (started, start) = oneshot::channel();
            let guard = PanicOnDrop(dropped.clone());
            let resident = context.child("abort");
            let handle = resident.spawn_on(thread, move |_| park(guard, Some(started)));
            start.await.unwrap();
            handle.abort();

            // The future is dropped before the handle resolves.
            assert!(closed(handle).await);
            assert!(is_set(&dropped), "the aborted future was kept");
        }
        TwoQueuedCaptures => {
            let drops = [flag(), flag()];
            let (captures, factory) = (drops.clone().map(PanicOnDrop), ran.clone());
            let root = root("queue").spawn(move |local| async move {
                // Queue the jobs and end the root in the same poll.
                captures.map(|capture| {
                    let job = (*local).child("queued");
                    job.spawn_on(local.home(), capturing(capture, &factory))
                })
            });
            for handle in root.unwrap().await.unwrap() {
                assert!(closed(handle).await);
            }

            // The close went on past the first panic.
            settle(context, || drops.iter().all(|drop| is_set(drop))).await;
            assert!(!is_set(&ran), "a queued factory ran");
        }
        DetachedLocalReady | RetainedLocalReady => {
            // A dropped handle leaves the task owning its output when its future's destructor
            // panics, and disposing of that output during the unwind would abort the process. A
            // kept handle resolves Closed, so the output is disposed of on the thread and never
            // reaches the root.
            let root = root("local").spawn(move |local| {
                let output = PanicOnDrop(other.clone());
                let future = holding(PanicOnDrop(dropped.clone()), Some(output));
                let handle = local.child("ready").spawn_local(move |_| future);
                let handle = (scenario == RetainedLocalReady).then_some(handle);
                async move {
                    if let Some(handle) = handle {
                        assert!(closed(handle).await);
                    }
                    settle(&*local, || is_set(&dropped) && is_set(&other)).await;
                }
            });
            root.unwrap().await.unwrap();
        }
        LocalOutputDisposal => {
            let root = root("local").spawn(move |local| async move {
                let (finished, finish) = oneshot::channel();
                let output = PanicOnDrop(dropped.clone());
                let handle = local.child("output").spawn_local(move |_| async move {
                    finished.send(()).unwrap();
                    output
                });

                // The task stores its output in the poll that sends.
                finish.await.unwrap();
                let contained = catch_unwind(AssertUnwindSafe(move || drop(handle))).is_ok();
                assert!(contained, "the output's panic escaped the handle's drop");
                assert!(is_set(&dropped), "the output was kept");
            });
            root.unwrap().await.unwrap();
        }
        ParkedCapture => {
            let (guard, factory) = (PanicOnDrop(dropped.clone()), ran.clone());
            let root = root("parked").spawn(move |local| async move {
                // Abort the task in the poll that parked its factory.
                let parked = local.child("parked");
                let handle = parked.spawn_local(capturing(guard, &factory));
                handle.abort();
                assert!(closed(handle).await);
            });
            root.unwrap().await.unwrap();
            settle(context, || is_set(&dropped)).await;
            assert!(!is_set(&ran), "the aborted factory ran");
        }
        Rejected => {
            let gone = root("closed").spawn(|local| ready(local.home().clone()));
            let gone = gone.unwrap().await.unwrap();
            let lineage = context.child("lineage");
            let aborted = lineage.child("aborted");
            abort_lineage(lineage, stale);
            let lines = [
                (context.child("rejected"), &gone),
                (context.child("rejected"), stale),
                (aborted, thread),
            ];

            // Each rejection drops the factory, whose capture panics, before the call returns,
            // so an uncaught report fails the run only at the next await.
            let mut handles = Vec::new();
            for (line, target) in lines {
                for placed in [false, true] {
                    dropped.store(false, Ordering::SeqCst);
                    let capture = PanicOnDrop(dropped.clone());
                    let handle = catch_unwind(AssertUnwindSafe(|| {
                        if placed {
                            let line = line.child("placed").on(target);
                            line.spawn(capturing(capture, &ran))
                        } else {
                            line.child("on").spawn_on(target, capturing(capture, &ran))
                        }
                    }));
                    handles.push(handle.expect("a rejected spawn unwound into its caller"));
                    assert!(is_set(&dropped), "{}, placed {placed}", target.name());
                }
            }

            // Aborting a rejected spawn's handle does not change its result.
            for handle in handles {
                handle.abort();
                assert!(closed(handle).await);
            }
            assert!(!is_set(&ran), "a rejected factory ran");
        }
        LateDisposal => {
            let (started, start) = oneshot::channel();
            let guard = PanicOnDrop(dropped);
            let resident = context.child("resident");
            drop(resident.spawn_on(thread, move |_| park(guard, Some(started))));
            let shared = context.child("shared");
            drop(shared.spawn(move |_| park(DropFlag(other), None)));
            start.await.unwrap();
        }
        StaleOutput => {
            let (done, finished) = oneshot::channel();
            let home = thread.clone();
            let owner = context.child("owner");
            drop(owner.spawn_on(thread, move |local| async move {
                // The close took the thread's state by the time it drops the output, which still
                // names its thread and gets a late spawn that is closed at once.
                let stale = local.child("stale");
                let output = on_drop(move || {
                    let at_home = stale.home() == &home;
                    let late = stale.spawn_local(capturing(PanicOnDrop(dropped), &ran));
                    let closed = closed(late).now_or_never() == Some(true);
                    other.store(at_home && closed, Ordering::SeqCst);
                    panic!("{PANIC}");
                });
                let (stored, store) = oneshot::channel();
                let handle = local.child("output").spawn_local(move |_| async move {
                    stored.send(()).unwrap();
                    output
                });

                // The task stores its output in the poll that sends. Leaking the handle keeps its
                // slot registered until the close clears it.
                store.await.unwrap();
                mem::forget(handle);
                park((), Some(done)).await;
            }));
            finished.await.unwrap();
        }
    }
}

// Raise the panic of each scenario on each runner, check that a resident of the same thread and
// a shared task survive it, and check how the run ends. A reported panic fails the run unless
// panics are caught, and a contained one never does. Disposals at shutdown are checked once the
// run ended.
#[rstest]
#[case::deterministic(deterministic::Runner::catching)]
#[case::tokio(tokio::Runner::catching)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::catching))]
fn test_thread_panic_matrix<R: TestRunner>(
    #[case] runner: fn(bool) -> R,
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
        Scenario::DetachedLocalReady,
        Scenario::RetainedLocalReady,
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
    let flags = [flag(), flag(), flag()];
    let raised = flags.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        runner(catch).start(|context| async move {
            let thread = context.child("built").thread().build().unwrap();
            let (release, released) = oneshot::channel::<()>();
            let survivor = context.child("survivor").spawn_on(&thread, |_| released);
            raise(&context, &thread, &stale, scenario, raised).await;
            release.send(()).unwrap();
            assert!(matches!(survivor.await, Ok(Ok(()))), "a resident died");
            let after = context.child("after").spawn(|_| async { 7 });
            assert!(matches!(after.await, Ok(7)), "a shared task died");
        })
    }));
    if (R::REPORTS || scenario <= Scenario::PlacedPollThenDrop) && !catch {
        let panic = result.expect_err("a reported panic did not fail the run");
        assert_eq!(extract_panic_message(&*panic), PANIC);
    } else {
        result.expect("the run failed");
    }
    if scenario >= Scenario::LateDisposal {
        let [dropped, ran, other] = flags.map(|flag| is_set(&flag));
        assert!(dropped, "the shutdown kept a value");
        assert!(!ran, "a factory ran after the close");
        assert!(other, "a shared task was kept, or a stale spawn was open");
    }
}

/// Whether `build`, `attach` and `spawn`, each called on its own context, return `Closed`, and
/// `spawn` dropped its root factory unrun before it returned.
fn rejected<C: Spawner>([build, attach, spawn]: [C; 3]) -> bool {
    let (dropped, ran) = (flag(), flag());
    let factory = capturing(DropFlag(dropped.clone()), &ran);
    let spawned = spawn.thread().spawn(factory);
    matches!(build.thread().build(), Err(ThreadError::Closed))
        && matches!(attach.thread().attach(), Err(ThreadError::Closed))
        && matches!(spawned, Err(ThreadError::Closed))
        && is_set(&dropped)
        && !is_set(&ran)
}

// Every finisher returns Closed from an aborted lineage and from a drop during the shutdown
// abort, where available returns None. A builder created before its lineage was aborted returns
// Closed from attach, an empty pin on an aborted lineage returns EmptyCpus, since CPU validation
// comes first, and no resident is left counted. On native runners, a context and a builder,
// pinned where possible, that the run returned are rejected the same way afterwards. A
// deterministic context must not outlive its run.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_builder_closed<R: TestRunner>(#[case] runner: R) {
    const FINISHERS: [&str; 3] = ["build", "attach", "spawn"];
    let stale = stale_thread();
    let at_shutdown = flag();
    let checked = at_shutdown.clone();
    let escaped = runner.start(|context| async move {
        let lineage = context.child("lineage");
        let early = lineage.child("early").thread();
        let finishers = FINISHERS.map(|label| lineage.child(label));
        let empty = lineage.child("empty").thread().pin(Vec::new());
        abort_lineage(lineage, &stale);
        assert!(rejected(finishers), "an aborted lineage built a thread");
        assert!(matches!(early.attach(), Err(ThreadError::Closed)));
        assert!(matches!(empty.build(), Err(ThreadError::EmptyCpus)));
        let left =
            |line: &str| line.starts_with("runtime_thread_residents{") && !line.ends_with(" 0");
        assert!(!context.encode().lines().any(left), "a resident is counted");

        // A task holds a context until the shutdown abort drops it.
        let (started, start) = oneshot::channel();
        let holder = context.child("holder");
        let holder = on_drop(move || {
            let unavailable = holder.child("probe").thread().available().is_none();
            let closed = rejected(FINISHERS.map(|label| holder.child(label)));
            checked.store(unavailable && closed, Ordering::SeqCst);
        });
        let task = context.child("task");
        drop(task.spawn(move |_| park(holder, Some(started))));
        start.await.unwrap();

        R::NATIVE.then(|| {
            let mut builder = context.child("returned").thread();
            if let Some(cpu) = builder.available().and_then(|cpus| cpus.iter().next()) {
                builder = builder.pin(cpu);
            }
            (context.child("escaped"), builder)
        })
    });
    assert!(is_set(&at_shutdown), "a shutdown drop built a thread");
    if let Some((escaped, builder)) = escaped {
        assert_eq!(builder.available(), None);
        assert!(matches!(builder.build(), Err(ThreadError::Closed)));
        let finishers = FINISHERS.map(|label| escaped.child(label));
        assert!(rejected(finishers), "an ended run built a thread");
        let empty = escaped.child("empty").thread().pin(Vec::new());
        assert!(matches!(empty.build(), Err(ThreadError::EmptyCpus)));
    }
}

/// Check pin validation on one runner whose base set is `base`, if known.
fn pin_validation<R: TestRunner>(runner: R, base: Option<Cpus>) {
    runner.start(|context| async move {
        let pin = |cpus: Cpus| context.child("pinned").thread().pin(cpus).build();
        let refused = |cpus: Cpus| match pin(cpus) {
            Err(ThreadError::CpuUnavailable(id)) => Some(id),
            _ => None,
        };

        // An empty set fails first, whatever the base set.
        let empty = pin(Cpus::from(Vec::new()));
        assert!(matches!(empty, Err(ThreadError::EmptyCpus)));
        assert!(matches!(pin(Cpus::from(3..3)), Err(ThreadError::EmptyCpus)));
        let attached = context.child("pinned").thread().pin([0usize; 0]).attach();
        assert!(matches!(attached, Err(ThreadError::EmptyCpus)));

        // The builder reports the base set. Without one, every finisher rejects a pin, and an
        // unpinned thread needs none.
        assert_eq!(context.child("probe").thread().available(), base);
        let Some(base) = base else {
            for cpus in [Cpus::from(0), Cpus::from(5000), Cpus::from(0..=usize::MAX)] {
                assert!(matches!(pin(cpus), Err(ThreadError::UnsupportedAffinity)));
            }
            let pinned = || context.child("pinned").thread().pin(0);
            let attached = pinned().attach();
            assert!(matches!(attached, Err(ThreadError::UnsupportedAffinity)));
            let spawned = pinned().spawn(|_| ready(()));
            assert!(matches!(spawned, Err(ThreadError::UnsupportedAffinity)));
            let unpinned = context.child("unpinned").thread().spawn(|_| ready(()));
            return unpinned.unwrap().await.unwrap();
        };
        let inside = base.iter().next().unwrap();
        let outside = (0..1024).find(|&id| !base.contains(id)).unwrap_or(1024);
        assert!(pin(Cpus::from(inside)).is_ok());

        // The smallest requested id outside the base set, including ids at or above 1024, which
        // are not stored but still make a pin unavailable rather than empty.
        assert_eq!(refused(Cpus::from(5000)), Some(5000));
        assert_eq!(refused(Cpus::from([inside, 4000, 2000])), Some(2000));
        if outside < 1024 {
            assert_eq!(refused(Cpus::from([4000, outside, inside])), Some(outside));
        }

        // A range up to usize::MAX is cut at 1024 when built, so this returns promptly.
        assert_eq!(refused(Cpus::from(0..=usize::MAX)), Some(outside));

        // A later pin replaces an earlier one.
        let replaced = || context.child("replaced").thread();
        let thread = replaced().pin(5000).pin(inside).build().unwrap();
        assert_eq!(thread.cpus(), Some(&Cpus::from(inside)));
        let earlier = replaced().pin(inside).pin(5000).build();
        assert!(matches!(earlier, Err(ThreadError::CpuUnavailable(5000))));
    });
}

// An empty pin fails with EmptyCpus, then an unknown base set with UnsupportedAffinity, then the
// smallest id outside the base set with CpuUnavailable, in every finisher. The deterministic base
// set is its configured one. A native runner's is the CPU set of the thread that starts it, where
// the platform reports one, and a second pass makes it unknown.
#[rstest]
#[case::deterministic(
    || deterministic::Runner::new(deterministic::Config::default().with_cpus(0..=3))
)]
#[case::tokio(tokio::Runner::default)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default))]
fn test_thread_pin_validation<R: TestRunner>(#[case] runner: fn() -> R) {
    if !R::NATIVE {
        return pin_validation(runner(), Some(Cpus::from(0..=3)));
    }
    #[cfg(all(target_os = "linux", not(miri)))]
    {
        use crate::threads::affinity::{current, tests::override_base};
        pin_validation(runner(), current());
        override_base(Some(None));
    }
    pin_validation(runner(), None);
    #[cfg(all(target_os = "linux", not(miri)))]
    crate::threads::affinity::tests::override_base(None);
}

// With the OS refusing the thread, every finisher returns Spawn and rolls back. The spawn
// finisher drops its root factory unrun, the residents series stays absent or 0, a child wired
// from the consumed context keeps running, a later thread from the same parent works, and the
// run ends, so no reservation leaked.
#[rstest]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_spawn_failure_rollback<R: TestRunner>(#[case] runner: R) {
    bounded(move || {
        runner.start(|context| async move {
            let parent = context.child("parent");
            let consumed = parent.child("t");
            let (release, released) = oneshot::channel::<()>();
            let wired = consumed.child("wired").shared().spawn(|_| released);

            // The failure is armed on this OS thread, which runs the finisher synchronously.
            fail_spawns(1);
            let built = consumed.thread().build();
            assert!(matches!(built, Err(ThreadError::Spawn(_))));
            fail_spawns(1);
            let attached = parent.child("t").thread().attach();
            assert!(matches!(attached, Err(ThreadError::Spawn(_))));
            let (dropped, ran) = (flag(), flag());
            let factory = capturing(DropFlag(dropped.clone()), &ran);
            fail_spawns(1);
            let spawned = parent.child("t").thread().spawn(factory);
            assert!(matches!(spawned, Err(ThreadError::Spawn(_))));
            assert!(is_set(&dropped) && !is_set(&ran), "root kept or run");

            let thread = parent.child("t").thread().build().unwrap();
            assert!(matches!(residents(&context, thread.name()), None | Some(0)));
            let handle = context.child("work").spawn_on(&thread, |_| async { 4 });
            assert!(matches!(handle.await, Ok(4)));
            release.send(()).unwrap();
            assert!(matches!(wired.await, Ok(Ok(()))), "the lineage was aborted");
        })
    });
}

// On deterministic, the loop schedules a resident of a thread while a submission off the loop
// holds that thread's admission critical section, and thread creations off the loop race aborts
// of the node they occupy. The loop keeps running on reschedule() meanwhile.
#[test]
fn test_thread_admission_race_deterministic() {
    let stale = stale_thread();
    bounded(move || {
        deterministic::Runner::default().start(|context| async move {
            let thread = context.child("contended").thread().build().unwrap();
            let first = context.child("first").spawn_on(&thread, |_| async { 2 });

            // The next admission holds the admission lock for a while. The guard removes the
            // callback again.
            let entered = flag();
            let inside = entered.clone();
            set_before_enqueue(Some(Arc::new(move || {
                if !inside.swap(true, Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            })));
            let gate = on_drop(|| set_before_enqueue(None));
            let submitter = context.child("second").on(&thread);
            let submit = std::thread::spawn(move || submitter.spawn(|_| async { 3 }));

            // Hold the loop until the submission is inside, so the resident's first schedule
            // comes while it is.
            while !is_set(&entered) {
                std::thread::sleep(Duration::from_millis(1));
            }
            while !submit.is_finished() {
                reschedule().await;
            }
            let second = submit.join().unwrap();
            drop(gate);
            assert!(matches!(first.await, Ok(2)), "the resident failed");
            assert!(matches!(second.await, Ok(3)), "the submission failed");

            // A thread creation off the loop races an abort of the node it occupies.
            for _ in 0..32 {
                let parent = context.child("creator");
                let creating = parent.child("t");
                let barrier = Arc::new(Barrier::new(2));
                let (ready, stale) = (barrier.clone(), stale.clone());
                let creator = std::thread::spawn(move || {
                    ready.wait();
                    creating.thread().build()
                });
                let walker = std::thread::spawn(move || {
                    barrier.wait();
                    abort_lineage(parent, &stale);
                });
                while !creator.is_finished() || !walker.is_finished() {
                    reschedule().await;
                }
                walker.join().unwrap();

                // If the abort came after the registration, the thread closes and leaves the
                // table.
                match creator.join().unwrap() {
                    Ok(thread) => {
                        settle(&context, || thread.inner().state() == State::Closed).await;
                    }
                    Err(error) => assert!(matches!(error, ThreadError::Closed)),
                }
            }
        })
    });
}

/// For one wrapper, `attach`, `spawn`, `spawn_on` and `spawn_local` hand their closures the
/// wrapper with its state, which `holds` checks, and `placed`, `blocking` and `shared` keep that
/// state and reach the inner context.
async fn wrapper_threads<W: Spawner + Metrics>(context: W, holds: fn(&W) -> bool) {
    let attached = context.child("attached").thread().attach().unwrap();
    assert!(holds(&context) && holds(&attached), "attach lost the state");
    let placement = attached.child("placement");
    let placement = placement.spawn(move |task: W| async move {
        let lines = [
            task.child("placed").placed(),
            task.child("blocking").blocking(),
            task.child("shared").placed().shared(),
        ];
        let held = holds(&task) && lines.iter().all(holds);
        assert!(held, "a placement lost the state");
        let mut labels = Vec::new();
        for line in lines {
            let name = line.name().label;
            line.spawn(|_| async {}).await.unwrap();
            labels.push(executions(&task, &name));
        }
        labels
    });
    let labels = placement.await.unwrap();
    assert_eq!(labels, [["Thread"], ["SharedBlocking"], ["Shared"]]);

    let root = context.child("root").thread();
    let root = root.spawn(move |local: Local<W>| async move {
        let leaf = local.child("leaf");
        let leaf = leaf.spawn_local(move |leaf: Local<W>| ready(holds(&leaf)));
        holds(&local) && matches!(leaf.await, Ok(true))
    });
    assert!(root.unwrap().await.unwrap(), "root or leaf lost the state");
    let thread = context.child("built").thread().build().unwrap();
    let remote = context.child("remote");
    let remote = remote.spawn_on(&thread, move |local: Local<W>| ready(holds(&local)));
    assert!(matches!(remote.await, Ok(true)), "spawn_on lost the state");
}

// Each mock wrapper keeps thread semantics. Its state is marked before the threads exist, so a
// closure that got a fresh state would not see the mark.
#[test]
fn test_thread_wrapper_contexts() {
    deterministic::Runner::default().start(|context| async move {
        let (recording, _) = RecordingContext::new(context.child("recording"));
        let (blob, _) = recording.open("partition", b"blob").await.unwrap();
        let write = blob.write_at(0, b"x".to_vec(), WriteOptions::default());
        write.await.unwrap();
        let written = |mock: &RecordingContext<_>| !mock.recordings.snapshot().writes.is_empty();
        wrapper_threads(recording, written).await;

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
        wrapper_threads(faulty, |context| context.faults.failed()).await;
    });
}

/// Spawn a resident of `thread` that makes a `spawn_local` through a wrapper delivering its
/// shim to `other`, an open thread of the same runner, then signals `parked` and awaits `check`.
/// Returns whether the factory was still parked, unrun and not dropped after that. The resident
/// asserts that its handle resolves `Closed` and that its next reap point, a later `spawn_local`,
/// drops the parked factory unrun while its thread stays open.
fn misdeliver<C: Spawner>(
    context: C,
    thread: &Thread,
    other: Thread,
    parked: oneshot::Sender<()>,
    check: oneshot::Receiver<()>,
) -> Handle<bool> {
    let seen = Seen::default();
    Recorder(context, seen.clone()).spawn_on(thread, move |local| async move {
        let (dropped, ran) = (flag(), flag());
        seen.lock().1 = Some(other);
        let factory = capturing(DropFlag(dropped.clone()), &ran);
        let handle = local.child("misdelivered").spawn_local(factory);
        let _ = parked.send(());
        let _ = check.await;
        let kept = local.owner().parked() == 1 && !is_set(&dropped) && !is_set(&ran);
        assert!(closed(handle).await, "the misdelivered task stayed open");

        // The shim ran elsewhere and was dropped armed.
        let later = local.child("later").spawn_local(|_| ready(()));
        assert!(is_set(&dropped), "the reap point kept the parked factory");
        assert!(later.await.is_ok(), "the later spawn_local failed");
        assert_eq!(local.owner().parked(), 0, "a factory stayed parked");
        assert!(!is_set(&ran), "the misdelivered factory ran");
        assert!(local.home().inner().is_open(), "the thread closed");
        kept
    })
}

// A wrapper that delivers a spawn_local shim to another open thread of the same runner gets a
// handle that resolves Closed. The shim leaves the factory the other thread parked under the same
// id, and its home thread drops its own parked factory at its next reap point while staying open.
#[test]
fn test_thread_misdelivered_spawn_local() {
    deterministic::Runner::default().start(|context| async move {
        let home = context.child("home").thread().build().unwrap();
        let other = context.child("other").thread().build().unwrap();

        // The other side parks its factory first and keeps it parked until the home side's shim
        // ran on its thread.
        let (parked, wait) = oneshot::channel();
        let (check, checked) = oneshot::channel();
        let peer = misdeliver(context.child("peer"), &other, home.clone(), parked, checked);
        wait.await.unwrap();
        let (unused, unchecked) = (oneshot::channel().0, oneshot::channel().1);
        let mine = misdeliver(context.child("mine"), &home, other, unused, unchecked);
        mine.await.unwrap();
        check.send(()).unwrap();
        assert!(peer.await.unwrap(), "a shim took the other side's factory");
    });
}
