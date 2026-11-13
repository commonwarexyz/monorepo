//! Tests of runtime threads on every runner.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{
    Clock, ContextCell, Error, Handle, Local, LocalHandle, Metrics, Runner, Spawner, Supervisor,
    Thread, deterministic, reschedule,
    threads::{
        admission::State,
        testing::{DropFlag, bounded, executions, flag, recording, residents, settle},
    },
    tokio,
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, future::pending};
use rstest::rstest;
use std::{
    cell::{Cell, RefCell},
    future::{Ready, ready},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread::{JoinHandle, ThreadId},
    time::Duration,
};

/// The OS thread running the caller.
fn os() -> ThreadId {
    std::thread::current().id()
}

/// Spawn a task from `context` and return the OS thread it ran on and the context's label.
async fn ran_on<C: Spawner>(context: C) -> (ThreadId, String) {
    let name = context.name().label;
    let id = context.spawn(|_| async { os() }).await.unwrap();
    (id, name)
}

/// The OS thread a `Local`'s task runs on, and where spawns from its context run, unplaced and
/// placed.
async fn local_spawns<C: Spawner>(local: Local<C>) -> (ThreadId, [(ThreadId, String); 2]) {
    let here = os();
    let inner = ran_on(local.child("inner").into_inner()).await;
    let placed = ran_on(local.child("placed").into_inner().placed()).await;
    (here, [inner, placed])
}

/// The number of OS threads in this process, where the platform reports it.
fn os_threads() -> Option<usize> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            std::fs::read_dir("/proc/self/task").ok().map(Iterator::count)
        } else {
            None
        }
    }
}

/// Where a test expects a task to run.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// On the thread.
    Thread,
    /// On the shared executor.
    Shared,
    /// On the shared executor, as blocking work.
    Blocking,
}

/// Assert that the task spawned under a label, which ran on an OS thread, ran as `expect` says,
/// relative to the OS thread `thread` of the runtime thread. Native runners compare OS threads,
/// and every runner checks the execution label.
fn assert_ran(
    metrics: &impl Metrics,
    (ran, name): (ThreadId, String),
    expect: Expect,
    thread: ThreadId,
    native: bool,
) {
    let label = match expect {
        Expect::Thread => "Thread",
        Expect::Shared => "Shared",
        Expect::Blocking => "SharedBlocking",
    };
    assert_eq!(executions(metrics, &name), [label], "{name}");
    if native {
        assert_eq!(
            ran == thread,
            matches!(expect, Expect::Thread),
            "{name} ran on the wrong OS thread"
        );
    }
}

/// An actor that spawns its loop the way `spawn_cell!` does, then spawns from the restored
/// context. The macro itself cannot be named by path inside this crate.
struct CellActor<E> {
    /// The actor's context, restored in the spawned closure.
    context: ContextCell<E>,
}

impl<E: Spawner> CellActor<E> {
    /// Spawn the actor's loop, as `spawn_cell!(self.context, self.run())` expands.
    fn start(mut self) -> Handle<[(ThreadId, String); 2]> {
        let context = self.context.take();
        context.spawn(move |context| {
            self.context.restore(context);
            self.run()
        })
    }

    /// Spawn from the restored context, then again after placing it.
    async fn run(self) -> [(ThreadId, String); 2] {
        [
            ran_on(self.context.child("plain")).await,
            ran_on(self.context.child("placed").placed()).await,
        ]
    }
}

/// Spawns a local task from `Drop` and reports whether its handle resolved Closed at once and
/// whether its factory ran.
struct SpawnOnDrop<C: Spawner> {
    /// The proof to spawn with.
    local: Option<Local<C>>,
    /// Receives the outcome.
    report: Option<oneshot::Sender<(bool, bool)>>,
}

impl<C: Spawner> Drop for SpawnOnDrop<C> {
    fn drop(&mut self) {
        let local = self.local.take().unwrap();
        let ran = Rc::new(Cell::new(false));
        let mut handle = local.child("on_drop").spawn_local({
            let ran = ran.clone();
            move |_| {
                ran.set(true);
                async {}
            }
        });
        let closed = matches!((&mut handle).now_or_never(), Some(Err(Error::Closed)));
        let _ = self.report.take().unwrap().send((closed, ran.get()));
    }
}

/// A `!Send` output that reports the OS thread it is dropped on.
struct Probe {
    /// Receives the OS thread.
    report: Option<oneshot::Sender<ThreadId>>,
    /// Makes the output `!Send`.
    _local: Rc<()>,
}

impl Probe {
    /// A probe reporting to `report`.
    fn new(report: oneshot::Sender<ThreadId>) -> Self {
        Self {
            report: Some(report),
            _local: Rc::new(()),
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            let _ = report.send(os());
        }
    }
}

thread_local! {
    /// A local handle kept past its thread's close.
    static HELD: RefCell<Option<LocalHandle<Probe>>> = const { RefCell::new(None) };
}

/// Spawn a resident of `thread` from `context` that spawns a local task, both pending forever,
/// and wait until it started. Returns its OS thread and receivers of the OS threads the
/// resident's future and the local task's future are dropped on.
async fn probes<C: Spawner>(
    context: C,
    thread: &Thread,
) -> (ThreadId, [oneshot::Receiver<ThreadId>; 2]) {
    let (report, dropped) = oneshot::channel();
    let (report_local, dropped_local) = oneshot::channel();
    let (started, start) = oneshot::channel();
    drop(context.spawn_on(thread, move |local| {
        let (probe, probe_local) = (Probe::new(report), Probe::new(report_local));
        drop(local.child("local").spawn_local(move |_| async move {
            let _probe = probe_local;
            pending::<()>().await;
        }));
        started.send(os()).unwrap();
        async move {
            let _probe = probe;
            pending::<()>().await;
        }
    }));
    (start.await.unwrap(), [dropped, dropped_local])
}

/// Run a runner of another instance on its own OS thread and hold its root until the returned
/// sender is used. Returns what `make` built from the root's context, the sender, and the
/// runner's OS thread.
fn hold_open<R, T>(
    runner: R,
    make: impl FnOnce(&R::Context) -> T + Send + 'static,
) -> (T, mpsc::Sender<()>, JoinHandle<()>)
where
    R: Runner + Send + 'static,
    T: Send + 'static,
{
    let (hold, held) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        runner.start(|context| async move {
            hold.send(make(&context)).unwrap();
            released.recv().unwrap();
        });
    });
    (held.recv().unwrap(), release, other)
}

/// An open thread of another runner, held by [hold_open].
fn foreign_thread<R>(runner: R) -> (Thread, mpsc::Sender<()>, JoinHandle<()>)
where
    R: Runner + Send + 'static,
    R::Context: Spawner,
{
    hold_open(runner, |context| {
        context.child("foreign").thread().build().unwrap()
    })
}

/// Spawn toward a thread of each runner in `others` from `runner`, then release them.
fn wrong_runtime<R: Runner + Send + 'static>(
    runner: R,
    others: Vec<(Thread, mpsc::Sender<()>, JoinHandle<()>)>,
) where
    R::Context: Spawner,
{
    let threads: Vec<Thread> = others.iter().map(|(thread, _, _)| thread.clone()).collect();
    bounded(move || {
        runner.start(|context| async move {
            for thread in threads {
                assert!(thread.inner().is_open());
                let ran = flag();

                let placed = context.child("placed").on(&thread);
                let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
                let handle = placed.spawn(recording(&ran));
                assert!(matches!(handle.await, Err(Error::Closed)));
                assert!(matches!(wired.await, Err(Error::Closed)));

                let on = context.child("on");
                let wired = on.child("wired").spawn(|_| pending::<()>());
                let handle = on.spawn_on(&thread, recording(&ran));
                assert!(matches!(handle.await, Err(Error::Closed)));
                assert!(matches!(wired.await, Err(Error::Closed)));
                assert!(!ran.load(Ordering::SeqCst));
            }
        })
    });
    for (_, release, other) in others {
        release.send(()).unwrap();
        other.join().unwrap();
    }
}

// Spawns run where the last of shared, blocking and on placed their context, and child and
// with_attribute keep it. A spawn hands its task an unplaced context, which spawns on the shared
// executor until placed places it where the task runs. Residents of a thread share its OS
// thread, which is not the runner's, and a spawned thread's root has its own. Contexts a thread
// hands out keep the creating context's label. The unit tests of Place cover the combinations.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_thread_placement_matrix<R: Runner>(#[case] runner: R, #[case] native: bool)
where
    R::Context: Spawner + Metrics,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        assert_eq!(thread.name(), "t");
        let home = context
            .child("home")
            .spawn_on(&thread, |_| async { os() })
            .await
            .unwrap();
        assert!(
            !native || home != os(),
            "a resident ran on the runner's OS thread"
        );
        let check = |ran, expect| assert_ran(&context, ran, expect, home, native);

        // Each placement, and child and with_attribute after one.
        let on = |label| context.child(label).on(&thread);
        let lines = [
            (on("on"), Expect::Thread),
            (on("on_shared").shared(), Expect::Shared),
            (on("on_blocking").blocking(), Expect::Blocking),
            (on("on_child").child("child"), Expect::Thread),
            (on("on_attr").with_attribute("k", 1), Expect::Thread),
            (
                context
                    .child("blocking_attr")
                    .blocking()
                    .with_attribute("k", 1),
                Expect::Blocking,
            ),
            (context.child("fresh_placed").placed(), Expect::Shared),
        ];
        for (line, expect) in lines {
            check(ran_on(line).await, expect);
        }

        // A task placed on the thread receives an unplaced context, and so does a task it spawns
        // through placed. The placement belongs to the context, not to the task that holds it.
        let handed = context
            .child("handed")
            .on(&thread)
            .spawn(|context| async move {
                let plain = ran_on(context.child("plain")).await;
                let placed = ran_on(context.child("placed").placed()).await;
                let nested = context
                    .child("nested")
                    .placed()
                    .spawn(|context| async move {
                        let plain = ran_on(context.child("plain")).await;
                        (plain, ran_on(context.child("placed").placed()).await)
                    })
                    .await
                    .unwrap();
                let saved = context.child("saved");
                let saved = context
                    .child("elsewhere")
                    .spawn(move |_| async move { ran_on(saved.placed()).await })
                    .await
                    .unwrap();
                [
                    (plain, Expect::Shared),
                    (placed, Expect::Thread),
                    (nested.0, Expect::Shared),
                    (nested.1, Expect::Thread),
                    (saved, Expect::Thread),
                ]
            })
            .await
            .unwrap();
        for (ran, expect) in handed {
            check(ran, expect);
        }

        // spawn_cell! restores the context the spawn handed to its task, which is unplaced.
        let [plain, placed] = CellActor {
            context: ContextCell::new(context.child("cell").on(&thread)),
        }
        .start()
        .await
        .unwrap();
        check(plain, Expect::Shared);
        check(placed, Expect::Thread);

        // A task on the shared executor or the blocking pool receives an unplaced context that
        // remembers it. Each blocking task runs on a thread of its own, so a blocking task's
        // placed spawns do not run on its thread.
        for (label, expect) in [
            ("shared_task", Expect::Shared),
            ("blocking_task", Expect::Blocking),
        ] {
            let blocking = matches!(expect, Expect::Blocking);
            let line = context.child(label);
            let line = if blocking { line.blocking() } else { line };
            let (plain, placed, parent) = line
                .spawn(|context| async move {
                    let parent = os();
                    let plain = ran_on(context.child("plain")).await;
                    let placed = ran_on(context.child("placed").placed()).await;
                    (plain, placed, parent)
                })
                .await
                .unwrap();
            assert!(
                !native || !blocking || placed.0 != parent,
                "a blocking task's placed spawn ran on its thread"
            );
            check(plain, Expect::Shared);
            check(placed, expect);
        }

        // A Local's context is unplaced on its thread, for a spawn_on task, a spawn_local task
        // and a root alike. A root and its spawn_local task share an OS thread of their own.
        let (here, spawns) = context
            .child("local")
            .spawn_on(&thread, local_spawns)
            .await
            .unwrap();
        let (local, task_spawns) = context
            .child("spawn_local")
            .spawn_on(&thread, |local| async move {
                local.child("task").spawn_local(local_spawns).await.unwrap()
            })
            .await
            .unwrap();
        assert!(
            !native || (here == home && local == home),
            "a resident left its thread"
        );
        for (ran, expect) in spawns
            .into_iter()
            .chain(task_spawns)
            .zip([Expect::Shared, Expect::Thread].repeat(2))
        {
            check(ran, expect);
        }
        let ((root, spawns), (leaf, leaf_spawns)) = context
            .child("root")
            .thread()
            .spawn(|local| async move {
                let leaf = local.child("leaf").spawn_local(local_spawns);
                (local_spawns(local).await, leaf.await.unwrap())
            })
            .unwrap()
            .await
            .unwrap();
        assert!(
            !native || (root == leaf && root != home && root != os()),
            "a root does not share its own OS thread with its residents"
        );
        for (ran, expect) in spawns
            .into_iter()
            .chain(leaf_spawns)
            .zip([Expect::Shared, Expect::Thread].repeat(2))
        {
            assert_ran(&context, ran, expect, root, native);
        }

        // An attached context is placed on its thread, and a task spawned from it can spawn
        // there again through placed. Contexts handed out by attach and by the builder's spawn
        // keep the creating label.
        let attached = context.child("attached").thread().attach().unwrap();
        assert_eq!(attached.name().label, "attached");
        let (attached_home, plain, placed) = attached
            .child("task")
            .spawn(|context| async move {
                let plain = ran_on(context.child("plain")).await;
                (os(), plain, ran_on(context.child("placed").placed()).await)
            })
            .await
            .unwrap();
        assert_ran(&context, plain, Expect::Shared, attached_home, native);
        assert_ran(&context, placed, Expect::Thread, attached_home, native);
        assert_ran(
            &context,
            ran_on(attached).await,
            Expect::Thread,
            attached_home,
            native,
        );
        let names = context
            .child("spawned")
            .thread()
            .spawn(|local| async move { (local.name().label, local.home().name().to_string()) })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(names, ("spawned".to_string(), "spawned".to_string()));
    });
}

// Placement creates no supervision edge, and a thread lives as long as the lineage that built
// it. Aborting a context placed on a thread aborts its tasks and the residents it spawned with
// spawn_on, with their spawn_local tasks, and leaves the thread open. Once a task ended, spawns
// from a context it handed out resolve Closed without running their factory, placed or not.
// Once the lineage that built a thread ends, the thread closes and aborts only its residents,
// wherever they are supervised, and a later placed spawn resolves Closed without running its
// factory and closes the consumed context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_supervision<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("t").thread().build().unwrap();
            let ran = flag();

            // Abort a placed task, then a placed lineage with a child and a resident.
            let task = context
                .child("placed")
                .on(&thread)
                .spawn(|_| pending::<()>());
            task.abort();
            assert!(
                matches!(task.await, Err(Error::Closed)),
                "an aborted placed task did not close"
            );
            let dropped = flag();
            let (tx, rx) = oneshot::channel();
            let lineage = context.child("lineage").on(&thread).spawn({
                let (thread, flag) = (thread.clone(), DropFlag(dropped.clone()));
                move |context| async move {
                    let inner = context.child("inner").spawn(|_| pending::<()>());
                    let resident = context.child("resident").spawn_on(&thread, move |local| {
                        drop(local.child("local").spawn_local(move |_| async move {
                            let _flag = flag;
                            pending::<()>().await;
                        }));
                        pending::<()>()
                    });
                    tx.send((inner, resident)).ok().unwrap();
                    pending::<()>().await;
                }
            });
            let (inner, resident) = rx.await.unwrap();
            lineage.abort();
            for handle in [lineage, inner, resident] {
                assert!(
                    matches!(handle.await, Err(Error::Closed)),
                    "a task of the aborted lineage did not close"
                );
            }
            settle(&context, || dropped.load(Ordering::SeqCst)).await;
            let after = context.child("after").spawn_on(&thread, |_| async { 5 });
            assert_eq!(after.await.unwrap(), 5, "the abort closed the thread");

            // The handle resolves before the task's completing poll aborts its node. The thread
            // polls its residents one at a time, so once another resident has run, that poll is
            // over.
            let saved = context
                .child("task")
                .on(&thread)
                .spawn(|context| async move { context.child("saved") })
                .await
                .unwrap();
            context
                .child("barrier")
                .spawn_on(&thread, |_| async {})
                .await
                .unwrap();
            for line in [saved.child("late"), saved.child("late").placed()] {
                let handle = line.spawn(recording(&ran));
                assert!(
                    matches!(handle.await, Err(Error::Closed)),
                    "a spawn from an ended task's context was admitted"
                );
            }

            // A thread whose building lineage ends, with residents and tasks that are not: a
            // sibling, a task moved off the thread, and a task of a lineage that also spawns a
            // resident.
            let (tx, rx) = oneshot::channel();
            let (end, ended) = oneshot::channel::<()>();
            let creator = context.child("creator").spawn(move |context| async move {
                tx.send(context.thread().build().unwrap()).unwrap();
                ended.await.unwrap();
            });
            let closing = rx.await.unwrap();
            let lineage = context.child("resident");
            let mut gates = Vec::new();
            let mut others = Vec::new();
            for line in [
                context.child("sibling"),
                context.child("moved").on(&closing).shared(),
                lineage.child("kept"),
            ] {
                let (go, wait) = oneshot::channel::<()>();
                gates.push(go);
                others.push(line.spawn(move |_| async move { wait.await.unwrap() }));
            }
            let dropped = flag();
            let (started, start) = oneshot::channel();
            let resident = lineage.child("on").spawn_on(&closing, {
                let dropped = dropped.clone();
                move |local| {
                    let flag = DropFlag(dropped);
                    drop(local.child("local").spawn_local(move |_| async move {
                        let _flag = flag;
                        pending::<()>().await;
                    }));
                    started.send(()).unwrap();
                    pending::<()>()
                }
            });
            let placed = context
                .child("resident_placed")
                .on(&closing)
                .spawn(|_| pending::<()>());
            start.await.unwrap();
            end.send(()).unwrap();
            creator.await.unwrap();
            for handle in [resident, placed] {
                assert!(
                    matches!(handle.await, Err(Error::Closed)),
                    "a resident outlived its thread"
                );
            }

            // Nothing orders the local resident's drop before the other handles resolve.
            settle(&context, || dropped.load(Ordering::SeqCst)).await;
            for go in gates {
                go.send(()).unwrap();
            }
            for handle in others {
                assert!(
                    handle.await.is_ok(),
                    "the close aborted a task that is not a resident"
                );
            }
            let late = context.child("late").on(&closing);
            let wired = late.child("wired").shared().spawn(|_| pending::<()>());
            assert!(matches!(
                late.spawn(recording(&ran)).await,
                Err(Error::Closed)
            ));
            assert!(
                matches!(wired.await, Err(Error::Closed)),
                "a rejected spawn left its context's node open"
            );
            assert!(!ran.load(Ordering::SeqCst), "a rejected factory ran");
            let still = context.child("still").spawn_on(&thread, |_| async { 7 });
            assert_eq!(
                still.await.unwrap(),
                7,
                "another thread's close closed this one"
            );
        })
    });
}

// An attached context keeps its thread while its lineage lives, also when it is used only
// through child and then dropped, or when an actor derived from it with child ends first. The
// thread closes once the task that consumes the context ends, so a task that attaches a thread
// per epoch, whose consumers complete or are aborted, leaves no OS thread behind.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_attach<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    /// Epochs the orchestrator runs.
    const EPOCHS: u64 = 16;

    bounded(move || {
        runner.start(|context| async move {
            // Used only through child, then dropped.
            let (tx, rx) = oneshot::channel();
            let lineage = context.child("lineage").spawn(move |context| async move {
                let attached = context.child("t").thread().attach().unwrap();
                tx.send(attached.child("probe").spawn(|_| pending::<()>()))
                    .ok()
                    .unwrap();
                drop(attached);
                pending::<()>().await;
            });
            let mut probe = rx.await.unwrap();
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                (&mut probe).now_or_never().is_none(),
                "dropping the attached context closed its thread"
            );
            lineage.abort();
            assert!(matches!(probe.await, Err(Error::Closed)));

            // An actor derived with child ends first, then the consuming task runs.
            let attached = context.child("subsystem").thread().attach().unwrap();
            attached.child("actor").spawn(|_| async {}).await.unwrap();
            let saved = attached.child("saved");
            let (release, released) = oneshot::channel::<()>();
            let main = attached.spawn(|_| async move { released.await.unwrap() });
            let open = saved.child("open").spawn(|_| async { 1 });
            assert_eq!(
                open.await.unwrap(),
                1,
                "the thread closed before its consumer ended"
            );
            release.send(()).unwrap();
            main.await.unwrap();

            // A resident of the same thread runs after the consumer's completing poll, which
            // aborts its node, or is aborted with it.
            let _ = saved.child("barrier").spawn(|_| async {}).await;
            let late = saved.child("late").spawn(|_| async {});
            assert!(
                matches!(late.await, Err(Error::Closed)),
                "a spawn from the consumed context was admitted after its consumer ended"
            );

            let orchestrator = context.child("orchestrator").spawn(|context| async move {
                let baseline = os_threads();
                for epoch in 0..EPOCHS {
                    let engine = context
                        .child("engine")
                        .with_attribute("epoch", epoch)
                        .thread()
                        .attach()
                        .unwrap();
                    let aborted = epoch % 2 == 0;
                    let main = engine.spawn(move |context| async move {
                        // A long-lived actor runs next to the engine until the engine ends.
                        drop(context.child("actor").placed().spawn(|_| pending::<()>()));
                        if aborted {
                            pending::<()>().await;
                        }
                    });
                    if aborted {
                        main.abort();
                        assert!(matches!(main.await, Err(Error::Closed)));
                    } else {
                        main.await.unwrap();
                    }
                }

                // The OS threads of native runners exit once their close completes. The count
                // covers the whole process, so this relies on nextest running each test in its
                // own process.
                if let Some(baseline) = baseline {
                    settle(&context, || os_threads().unwrap() <= baseline).await;
                }
            });
            orchestrator.await.unwrap();
        })
    });
}

// spawn_local runs its factory after the caller's poll, on the caller's thread, so residents
// share Rc<RefCell<_>> state and spawn_local works from a factory, a poll and a Drop during the
// close without a BorrowMutError, and a spawn_on toward the caller's own thread does not run
// inside its poll either. A LocalHandle delivers a !Send output, resolves Closed once aborted,
// detaches its task when dropped, and an output it never took is dropped on its thread at close.
// On deterministic a later poll of that handle resolves Closed.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_thread_spawn_local<R: Runner + Send + 'static>(#[case] runner: R, #[case] native: bool)
where
    R::Context: Spawner + Clock,
{
    bounded(move || {
        runner.start(|context| async move {
            let (tx, rx) = oneshot::channel();
            let creator = context.child("creator").spawn(move |context| async move {
                tx.send(context.thread().build().unwrap()).unwrap();
                pending::<()>().await;
            });
            let thread = rx.await.unwrap();

            let (order, deferred, output, aborted, detached) = context
                .child("caller")
                .spawn_on(&thread, |local| {
                    // From the factory of spawn_on, from a spawn_local factory, and from a poll.
                    let shared = Rc::new(RefCell::new(Vec::new()));
                    let from_factory = local.child("factory").spawn_local({
                        let shared = shared.clone();
                        move |local| {
                            shared.borrow_mut().push(1);
                            let nested = local
                                .child("nested")
                                .spawn_local(move |_| async move { shared.borrow_mut().push(2) });
                            async move { nested.await.unwrap() }
                        }
                    });
                    async move {
                        from_factory.await.unwrap();
                        let from_poll = shared.clone();
                        local
                            .child("poll")
                            .spawn_local(move |_| async move { from_poll.borrow_mut().push(3) })
                            .await
                            .unwrap();

                        // A factory that borrows what the caller holds during the call, and a
                        // spawn_on toward this thread.
                        let ran = Rc::new(Cell::new(None));
                        let remote = flag();
                        let (deferred, on) = {
                            let mut borrow = shared.borrow_mut();
                            let deferred = local.child("deferred").spawn_local({
                                let (shared, ran) = (shared.clone(), ran.clone());
                                move |_| {
                                    ran.set(Some(os()));
                                    shared.borrow_mut().push(5);
                                    async {}
                                }
                            });
                            let on = local
                                .child("on")
                                .into_inner()
                                .spawn_on(local.home(), recording(&remote));
                            borrow.push(4);
                            (deferred, on)
                        };
                        let inline = ran.get().is_some() || remote.load(Ordering::SeqCst);
                        deferred.await.unwrap();
                        on.await.unwrap();
                        let deferred = !inline && ran.get() == Some(os());

                        // A !Send output, an aborted handle, and a dropped handle whose task
                        // finishes.
                        let output = local
                            .child("output")
                            .spawn_local(|_| async { Rc::new(5) })
                            .await
                            .unwrap();
                        let handle = local.child("abort").spawn_local(|_| pending::<()>());
                        handle.abort();
                        let aborted = matches!(handle.await, Err(Error::Closed));
                        let (done, finished) = oneshot::channel::<()>();
                        drop(local.child("detach").spawn_local(move |_| async move {
                            reschedule().await;
                            done.send(()).unwrap();
                        }));
                        let detached = finished.await.is_ok();
                        let order = shared.borrow().clone();
                        (order, deferred, *output, aborted, detached)
                    }
                })
                .await
                .unwrap();
            assert_eq!(
                order,
                [1, 2, 3, 4, 5],
                "a spawn_local factory ran out of order"
            );
            assert!(
                deferred,
                "a factory ran inside its caller's poll or off its thread"
            );
            assert_eq!(output, 5);
            assert!(aborted, "an aborted local handle did not resolve Closed");
            assert!(detached, "a dropped local handle cancelled its task");

            // From a resident's Drop while the thread closes.
            let (report, outcome) = oneshot::channel();
            let (started, start) = oneshot::channel();
            let _dropper = context.child("dropper").spawn_on(&thread, move |local| {
                let probe = SpawnOnDrop {
                    local: Some(local),
                    report: Some(report),
                };
                started.send(()).unwrap();
                async move {
                    let _probe = probe;
                    pending::<()>().await;
                }
            });
            start.await.unwrap();
            creator.abort();
            assert_eq!(
                outcome.await.unwrap(),
                (true, false),
                "a spawn_local from a Drop during the close ran or did not close at once"
            );

            // A thread that closes with a finished output its handle never took.
            let (report, dropped) = oneshot::channel();
            let home = context
                .child("closing")
                .thread()
                .spawn(move |local| async move {
                    let (finished, finish) = oneshot::channel::<()>();
                    let handle = local.child("output").spawn_local(move |_| async move {
                        finished.send(()).unwrap();
                        Probe::new(report)
                    });
                    finish.await.unwrap();
                    HELD.with(|held| *held.borrow_mut() = Some(handle));
                    os()
                })
                .unwrap()
                .await
                .unwrap();
            let dropped = dropped.await.unwrap();
            if native {
                assert_eq!(
                    dropped, home,
                    "an unclaimed output was dropped off its thread"
                );
            } else {
                let handle = HELD.with(|held| held.borrow_mut().take()).unwrap();
                assert!(matches!(handle.await, Err(Error::Closed)));
            }
        })
    });
}

// A runner returns with idle threads built by the root or by a task, and with a Thread held by
// the value start returns and by a clone on another OS thread. The held thread is closed by then,
// although its residents never wake and spawned local residents, and on native runners leaked a
// Local.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_thread_shutdown_with_held_thread<R: Runner + Send + 'static>(
    #[case] runner: R,
    #[case] native: bool,
) where
    R::Context: Spawner,
{
    let (hold, held) = mpsc::channel::<Thread>();
    let (release, released) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let thread = held.recv().unwrap();
        released.recv().unwrap();
        drop(thread);
    });
    let thread = bounded(move || {
        runner.start(|context| async move {
            drop(context.child("root").thread().build().unwrap());
            let task = context.child("task").spawn(|context| async move {
                drop(context.child("inner").thread().build().unwrap());
            });
            task.await.unwrap();

            let thread = context.child("held").thread().build().unwrap();
            let mut starts = Vec::new();
            for _ in 0..4 {
                let (started, start) = oneshot::channel();
                drop(context.child("resident").spawn_on(&thread, move |local| {
                    drop(local.child("local").spawn_local(|_| pending::<()>()));
                    if native {
                        std::mem::forget(local.child("leaked"));
                    }
                    started.send(()).unwrap();
                    pending::<()>()
                }));
                starts.push(start);
            }
            drop(
                context
                    .child("placed")
                    .on(&thread)
                    .spawn(|_| pending::<()>()),
            );
            for start in starts {
                start.await.unwrap();
            }
            hold.send(thread.clone()).unwrap();
            thread
        })
    });
    assert_eq!(thread.name(), "held");
    assert_eq!(
        thread.inner().state(),
        State::Closed,
        "the held thread did not close"
    );
    release.send(()).unwrap();
    holder.join().unwrap();
}

// Futures of residents are dropped on their thread, whether they complete, are aborted, panic,
// or are discarded by a close or by shutdown.
#[rstest]
#[case::tokio(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
#[cfg_attr(
    target_os = "linux",
    case::iouring(iouring::Runner::new(iouring::Config::default().with_catch_panics(true)))
)]
fn test_thread_drop_on_owner_thread<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    let (home, at_shutdown) = bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("t").thread().build().unwrap();
            let home = context
                .child("home")
                .spawn_on(&thread, |_| async { os() })
                .await
                .unwrap();
            for action in ["complete", "abort", "panic"] {
                let (report, dropped) = oneshot::channel();
                let (started, start) = oneshot::channel();
                let handle = context.child(action).spawn_on(&thread, move |_| {
                    let probe = Probe::new(report);
                    async move {
                        let _probe = probe;
                        started.send(()).unwrap();
                        match action {
                            "complete" => {}
                            "abort" => pending::<()>().await,
                            _ => {
                                reschedule().await;
                                panic!("resident poll");
                            }
                        }
                    }
                });
                start.await.unwrap();
                if action == "abort" {
                    handle.abort();
                }
                let result = handle.await;
                assert!(
                    match action {
                        "complete" => result.is_ok(),
                        "abort" => matches!(result, Err(Error::Closed)),
                        _ => matches!(result, Err(Error::Exited)),
                    },
                    "{action}: the handle resolved wrongly"
                );
                assert_eq!(
                    dropped.await.unwrap(),
                    home,
                    "{action}: dropped off its thread"
                );
            }

            // A close, for a spawn_on future and a spawn_local future.
            let (tx, rx) = oneshot::channel();
            let creator = context.child("creator").spawn(move |context| async move {
                tx.send(context.thread().build().unwrap()).unwrap();
                pending::<()>().await;
            });
            let closing = rx.await.unwrap();
            let (closing_home, dropped) = probes(context.child("close"), &closing).await;
            creator.abort();
            for dropped in dropped {
                assert_eq!(
                    dropped.await.unwrap(),
                    closing_home,
                    "close: dropped off its thread"
                );
            }

            // Shutdown, checked after start returns.
            probes(context.child("shutdown"), &thread).await
        })
    });
    for mut dropped in at_shutdown {
        assert_eq!(
            dropped.try_recv().unwrap(),
            home,
            "shutdown: dropped off its thread"
        );
    }
}

// A placed spawn and a spawn_on toward an open thread of another runner, of the same or another
// backend, resolve Closed without running the factory, and close the consumed context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_wrong_runtime<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner,
{
    wrong_runtime(
        runner,
        vec![
            foreign_thread(deterministic::Runner::default()),
            foreign_thread(tokio::Runner::default()),
        ],
    );
}

// The same toward an open thread of an io_uring runner, in a test whose every case needs io_uring.
#[cfg(target_os = "linux")]
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[case::iouring(iouring::Runner::default())]
fn test_thread_wrong_runtime_iouring_target<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner,
{
    wrong_runtime(runner, vec![foreign_thread(iouring::Runner::default())]);
}

// Thread tasks carry the Thread execution label, including a spawn_on task from a blocking
// context. The residents gauge counts queued and running tasks, not finished outputs waiting in
// a slot, drops with dropped tickets, and threads with one label share one series.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_metrics<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        context
            .child("placed")
            .on(&thread)
            .spawn(|_| async {})
            .await
            .unwrap();
        assert_eq!(executions(&context, "placed"), ["Thread"]);
        context
            .child("blocking")
            .blocking()
            .spawn_on(&thread, |_| async {})
            .await
            .unwrap();
        assert_eq!(executions(&context, "blocking"), ["Thread"]);

        // Count from a resident of its own thread, which cannot take a turn during its poll.
        let gauge = context.child("gauge").thread().build().unwrap();
        context
            .child("counter")
            .spawn_on(&gauge, |local| async move {
                let context = &*local;
                assert_eq!(residents(context, "gauge"), Some(1));

                // Queued jobs count at once, including ones aborted before they run.
                let mut running: Vec<_> = (0..5)
                    .map(|_| {
                        context
                            .child("job")
                            .spawn_on(local.home(), |_| pending::<()>())
                    })
                    .collect();
                let skipped = running.split_off(3);
                assert_eq!(residents(context, "gauge"), Some(6));
                for handle in &skipped {
                    handle.abort();
                }

                // Dropped tickets of skipped jobs decrement it.
                for handle in skipped {
                    assert!(matches!(handle.await, Err(Error::Closed)));
                }
                settle(context, || residents(context, "gauge") == Some(4)).await;

                // A finished output waiting in its slot does not count.
                let (finished, finish) = oneshot::channel::<()>();
                let output = local.child("output").spawn_local(move |_| async move {
                    finished.send(()).unwrap();
                    Rc::new(1)
                });
                finish.await.unwrap();
                settle(context, || residents(context, "gauge") == Some(4)).await;
                assert_eq!(*output.await.unwrap(), 1);

                for handle in &running {
                    handle.abort();
                }
                for handle in running {
                    assert!(matches!(handle.await, Err(Error::Closed)));
                }
                settle(context, || residents(context, "gauge") == Some(1)).await;
            })
            .await
            .unwrap();
        settle(&context, || residents(&context, "gauge") == Some(0)).await;

        // Two threads with one label share one series.
        let first = context.child("same").thread().build().unwrap();
        let second = context.child("same").thread().build().unwrap();
        assert_ne!(first, second);
        let a = context.child("a").spawn_on(&first, |_| pending::<()>());
        let b = context.child("b").spawn_on(&second, |_| pending::<()>());
        settle(&context, || residents(&context, "same") == Some(2)).await;
        let series = context
            .encode()
            .lines()
            .filter(|line| {
                line.starts_with("runtime_thread_residents{") && line.contains("name=\"same\"")
            })
            .count();
        assert_eq!(series, 1, "threads with one label have separate series");
        a.abort();
        b.abort();
        settle(&context, || residents(&context, "same") == Some(0)).await;
    });
}

// The proof of a Local is its owner, not its context. With a context of another thread or a
// shared context assigned into it, spawn_local still runs on home() and hands out a Local of
// home(). With a context of another runner, spawn_local resolves Closed and drops its factory
// before it returns.
#[rstest]
#[case::deterministic(
    deterministic::Runner::default(),
    deterministic::Runner::default(),
    false
)]
#[case::tokio(tokio::Runner::default(), tokio::Runner::default(), true)]
#[cfg_attr(
    target_os = "linux",
    case::iouring(iouring::Runner::default(), iouring::Runner::default(), true)
)]
fn test_thread_local_context_swap<R: Runner + Send + 'static>(
    #[case] runner: R,
    #[case] other: R,
    #[case] native: bool,
) where
    R::Context: Spawner,
{
    let (foreign, release, other) = hold_open(other, |context| context.child("foreign"));
    runner.start(|context| async move {
        let a = context.child("a").thread().build().unwrap();
        let b = context.child("b").thread().build().unwrap();

        // A context of thread b, from a resident that outlives its use.
        let (send, from_b) = oneshot::channel();
        let (unhold, unheld) = oneshot::channel::<()>();
        let holder = context.child("holder").spawn_on(&b, move |local| {
            send.send(local.child("from_b").into_inner()).ok().unwrap();
            async move { unheld.await.unwrap() }
        });
        let from_b = from_b.await.unwrap();

        let swapped = context
            .child("swap")
            .spawn_on(&a, move |local| async move {
                let home = os();

                // A context of another thread, then a shared context.
                let mut swapped = local.child("other_thread");
                *swapped = from_b;
                let mut shared = local.child("shared");
                *shared = (*local).child("plain").shared();
                for swapped in [swapped, shared] {
                    let (ran, same) = swapped
                        .spawn_local(|local| async move { (os(), local.home().name().to_string()) })
                        .await
                        .unwrap();
                    assert_eq!(same, "a");
                    assert!(!native || ran == home);
                }

                // A context of another runner.
                let mut stale = local.child("stale");
                *stale = foreign;
                let (dropped, ran) = (flag(), Rc::new(Cell::new(false)));
                let flag = DropFlag(dropped.clone());
                let handle = stale.spawn_local({
                    let ran = ran.clone();
                    move |_| {
                        let _flag = flag;
                        ran.set(true);
                        async {}
                    }
                });
                assert!(dropped.load(Ordering::SeqCst));
                assert!(!ran.get());
                matches!(handle.await, Err(Error::Closed))
            })
            .await
            .unwrap();
        assert!(swapped);
        unhold.send(()).unwrap();
        holder.await.unwrap();
    });
    release.send(()).unwrap();
    other.join().unwrap();
}

// The factory of an ordinary spawn runs on the caller before spawn returns, wherever the future
// runs, so it may borrow the caller's !Send state to build a Send future. A placed spawn's future
// runs on its thread, and a panic in its factory unwinds out of spawn and closes the consumed
// context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_spawn_factory_reads_local_state<R: Runner + Send + 'static>(
    #[case] runner: R,
    #[case] native: bool,
) where
    R::Context: Spawner + Metrics,
{
    bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("other").thread().build().unwrap();
            let home = context
                .child("home")
                .spawn_on(&thread, |_| async { os() })
                .await
                .unwrap();
            let target = thread.clone();
            let (factories, futures, caller, placed) = context
                .child("t")
                .thread()
                .spawn(move |local| async move {
                    let state = Rc::new(RefCell::new(Vec::new()));
                    let read = |id: usize| {
                        let state = &state;
                        move |_| {
                            state.borrow_mut().push(id);
                            async { os() }
                        }
                    };
                    let context = local.into_inner();
                    let placed = context.child("placed");
                    let name = placed.name().label;
                    let handles = [
                        context.child("shared").spawn(read(1)),
                        placed.on(&target).spawn(read(2)),
                        context.child("blocking").blocking().spawn(read(3)),
                    ];
                    let factories = state.borrow().clone();
                    let mut futures = Vec::new();
                    for handle in handles {
                        futures.push(handle.await.unwrap());
                    }
                    (factories, futures, os(), name)
                })
                .unwrap()
                .await
                .unwrap();
            assert_eq!(
                factories,
                [1, 2, 3],
                "a factory ran after its spawn returned"
            );
            assert_eq!(executions(&context, &placed), ["Thread"]);
            assert!(
                !native || (futures[1] == home && caller != home),
                "a placed future ran off its thread"
            );

            let placed = context.child("panics").on(&thread);
            let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
            let result = catch_unwind(AssertUnwindSafe(|| {
                placed.spawn(|_| -> Ready<()> { panic!("placed factory") })
            }));
            assert!(
                result.is_err(),
                "a placed factory's panic did not unwind out of spawn"
            );
            assert!(
                matches!(wired.await, Err(Error::Closed)),
                "a panicking factory left its context's node open"
            );
        })
    });
}

// A burst of jobs queued in one poll, across several admission batches, starts in submission
// order. While another OS thread keeps the ingress of a thread non-empty, a resident keeps being
// polled, and its spawn_local factory runs after the jobs submitted before it and before the jobs
// submitted after it.
#[rstest]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_busy_producer<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner,
{
    /// Jobs of the burst, three admission batches.
    const JOBS: usize = 3 * 64;

    bounded(move || {
        runner.start(|context| async move {
            let order = context
                .child("burst")
                .thread()
                .spawn(|local| async move {
                    let order = Arc::new(Mutex::new(Vec::new()));
                    let handles: Vec<_> = (0..JOBS)
                        .map(|i| {
                            let order = order.clone();
                            (*local).child("job").spawn_on(local.home(), move |_| {
                                order.lock().push(i);
                                ready(())
                            })
                        })
                        .collect();
                    assert_eq!(local.home().inner().queued(), JOBS);
                    for handle in handles {
                        handle.await.unwrap();
                    }
                    order.lock().clone()
                })
                .unwrap()
                .await
                .unwrap();
            assert!(
                order.into_iter().eq(0..JOBS),
                "the burst did not start in order"
            );

            let thread = context.child("busy").thread().build().unwrap();

            // Jobs the producer started to submit, finished submitting, and that ran.
            let counts: [_; 3] = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
            let stop = flag();
            let producer = std::thread::spawn({
                let (context, thread) = (context.child("producer"), thread.clone());
                let ([started, submitted, admitted], stop) = (counts.clone(), stop.clone());
                move || {
                    while !stop.load(Ordering::SeqCst) {
                        if thread.inner().queued() >= 4 * 64 {
                            std::thread::yield_now();
                            continue;
                        }
                        started.fetch_add(1, Ordering::SeqCst);
                        let admitted = admitted.clone();
                        drop(context.child("job").spawn_on(&thread, move |_| {
                            admitted.fetch_add(1, Ordering::SeqCst);
                            ready(())
                        }));
                        submitted.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
            let [started, submitted, admitted] = counts;
            let (ahead, behind, ran) = context
                .child("resident")
                .spawn_on(&thread, move |local| async move {
                    // Polled again and again while jobs are queued, until the ingress is full.
                    let mut contended = 0;
                    while contended < 100 || local.home().inner().queued() < 200 {
                        if local.home().inner().queued() > 0 {
                            contended += 1;
                        }
                        reschedule().await;
                    }

                    // No factory of this thread runs during this poll. Jobs submitted before the
                    // child are ahead of it, and jobs started after it are behind it.
                    let start = admitted.load(Ordering::SeqCst);
                    let ahead = submitted.load(Ordering::SeqCst).saturating_sub(start);
                    let child = local.child("child").spawn_local({
                        let admitted = admitted.clone();
                        move |_| ready(admitted.load(Ordering::SeqCst))
                    });
                    let behind = started.load(Ordering::SeqCst) - start;
                    (ahead, behind, child.await.unwrap() - start)
                })
                .await
                .unwrap();
            stop.store(true, Ordering::SeqCst);
            producer.join().unwrap();
            assert!(ahead >= 200, "the ingress was not full");
            assert!(
                (ahead..=behind).contains(&ran),
                "{ran} jobs ran before the child, expected {ahead} to {behind}"
            );
        })
    });
}
