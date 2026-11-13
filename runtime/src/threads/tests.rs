//! Tests of runtime threads on every runner.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{
    Clock, ContextCell, Error, Local, LocalHandle, Metrics, Spawner, Supervisor, Thread,
    deterministic, reschedule,
    threads::{
        admission::State,
        testing::{
            DropFlag, OnDrop, TestRunner, bounded, capturing, closed, executions, flag, is_set,
            on_drop, park, recording, residents, settle,
        },
    },
    tokio,
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, future::pending};
use rstest::rstest;
use std::{
    cell::{Cell, RefCell},
    future::{Ready, ready},
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread::ThreadId,
    time::Duration,
};

/// The OS thread running the caller.
fn os() -> ThreadId {
    std::thread::current().id()
}

/// Spawn a task from `context` and return the OS thread it ran on and the context's label.
async fn ran_on<C: Spawner>(context: C) -> (ThreadId, String) {
    let name = context.name().label;
    (context.spawn(|_| async { os() }).await.unwrap(), name)
}

/// Where spawns from children of `context` run, unplaced and after `placed`.
async fn spawns<C: Spawner>(context: &C) -> [(ThreadId, String); 2] {
    let plain = ran_on(context.child("plain")).await;
    [plain, ran_on(context.child("placed").placed()).await]
}

/// The OS thread a `Local`'s task runs on, and the [spawns] of its context.
async fn local_spawns<C: Spawner>(local: Local<C>) -> (ThreadId, [(ThreadId, String); 2]) {
    (os(), spawns(&*local).await)
}

/// Assert that the task spawned under a label, which ran on an OS thread, has the execution
/// label `expect`. On native runners, it ran on the OS thread `thread` of a runtime thread only if
/// that label is `Thread`.
fn assert_ran<R: TestRunner>(
    metrics: &R::Context,
    (ran, name): (ThreadId, String),
    expect: &str,
    thread: ThreadId,
) {
    assert_eq!(executions(metrics, &name), [expect], "{name}");
    let placed = !R::NATIVE || (ran == thread) == (expect == "Thread");
    assert!(placed, "{name} ran on the wrong OS thread");
}

/// Assert that the unplaced task of [spawns] ran on the shared executor and the placed one as
/// `placed` says, relative to `thread`.
fn assert_spawns<R: TestRunner>(
    metrics: &R::Context,
    [plain, ran]: [(ThreadId, String); 2],
    placed: &str,
    thread: ThreadId,
) {
    assert_ran::<R>(metrics, plain, "Shared", thread);
    assert_ran::<R>(metrics, ran, placed, thread);
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

/// A `!Send` value that reports the OS thread it is dropped on.
type Probe = OnDrop<Box<dyn FnOnce()>>;

/// A [Probe] reporting to `report`.
fn probe(report: oneshot::Sender<ThreadId>) -> Probe {
    on_drop(Box::new(move || {
        let _ = report.send(os());
    }))
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
        let held = probe(report_local);
        drop(local.child("local").spawn_local(move |_| park(held, None)));
        started.send(os()).unwrap();
        park(probe(report), None)
    }));
    (start.await.unwrap(), [dropped, dropped_local])
}

/// Run a runner of another instance on its own OS thread and hold its root open. Returns what
/// `make` built from the root's context, and a function that lets the runner return.
fn hold_open<R: TestRunner, T: Send + 'static>(
    runner: R,
    make: impl FnOnce(&R::Context) -> T + Send + 'static,
) -> (T, Box<dyn FnOnce()>) {
    let (hold, held) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        runner.start(|context| async move {
            hold.send(make(&context)).unwrap();
            released.recv().unwrap();
        });
    });
    let release = move || {
        release.send(()).unwrap();
        other.join().unwrap();
    };
    (held.recv().unwrap(), Box::new(release))
}

/// An open thread of another runner, held by [hold_open].
fn foreign_thread<R: TestRunner>(runner: R) -> (Thread, Box<dyn FnOnce()>) {
    hold_open(runner, |context| {
        context.child("foreign").thread().build().unwrap()
    })
}

/// Spawn toward a thread of each runner in `others` from `runner`, then release them.
fn wrong_runtime<R: TestRunner>(runner: R, others: Vec<(Thread, Box<dyn FnOnce()>)>) {
    let (threads, releases): (Vec<_>, Vec<_>) = others.into_iter().unzip();
    bounded(move || {
        runner.start(|context| async move {
            for thread in threads {
                assert!(thread.inner().is_open());
                let ran = flag();
                let placed = context.child("placed").on(&thread);
                let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
                assert!(closed(placed.spawn(recording(&ran))).await);
                assert!(closed(wired).await, "a placed spawn left its node open");
                let on = context.child("on");
                let wired = on.child("wired").spawn(|_| pending::<()>());
                assert!(closed(on.spawn_on(&thread, recording(&ran))).await);
                assert!(closed(wired).await, "a spawn_on left its node open");
                assert!(!is_set(&ran), "a rejected factory ran");
            }
        })
    });
    for release in releases {
        release();
    }
}

// Spawns run where the last of shared, blocking and on placed their context, and child and
// with_attribute keep it. A spawn hands its task an unplaced context, which spawns on the shared
// executor until placed places it where the task runs. Residents of a thread share its OS
// thread, which is not the runner's, and a spawned thread's root has its own. Contexts a thread
// hands out keep the creating context's label. The unit tests of Place cover the combinations.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_placement_matrix<R: TestRunner>(#[case] runner: R) {
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        assert_eq!(thread.name(), "t");
        let home = context.child("home");
        let home = home.spawn_on(&thread, |local| ready((os(), local.home().clone())));
        let (home, named) = home.await.unwrap();
        assert_eq!(named, thread, "two handles of one thread differ");
        assert!(!R::NATIVE || home != os(), "a resident ran off its thread");
        let check = |ran, expect| assert_ran::<R>(&context, ran, expect, home);
        let check_spawns = |ran, placed, thread| assert_spawns::<R>(&context, ran, placed, thread);

        // Each placement, and child and with_attribute after one.
        let on = |label| context.child(label).on(&thread);
        let blocking = context.child("blocking_attr").blocking();
        let lines = [
            (on("on"), "Thread"),
            (on("on_shared").shared(), "Shared"),
            (on("on_blocking").blocking(), "SharedBlocking"),
            (on("on_child").child("child"), "Thread"),
            (on("on_attr").with_attribute("k", 1), "Thread"),
            (blocking.with_attribute("k", 1), "SharedBlocking"),
            (context.child("fresh_placed").placed(), "Shared"),
        ];
        for (line, expect) in lines {
            check(ran_on(line).await, expect);
        }

        // A task placed on the thread receives an unplaced context, and so does a task it spawns
        // through placed. The placement belongs to the context, not to the task that holds it.
        let handed = context.child("handed").on(&thread);
        let handed = handed.spawn(|context| async move {
            let nested = context.child("nested").placed();
            let nested = nested.spawn(|context| async move { spawns(&context).await });
            let saved = context.child("saved");
            let saved = context.child("elsewhere").spawn(|_| ran_on(saved.placed()));
            let own = spawns(&context).await;
            (own, nested.await.unwrap(), saved.await.unwrap())
        });
        let (own, nested, saved) = handed.await.unwrap();
        check_spawns(own, "Thread", home);
        check_spawns(nested, "Thread", home);
        check(saved, "Thread");

        // spawn_cell! restores the context the spawn handed to its task, which is unplaced. The
        // macro cannot be named by path inside this crate, so this spawns as it expands.
        let mut cell = ContextCell::new(context.child("cell").on(&thread));
        let restored = cell.take().spawn(move |context| {
            cell.restore(context);
            async move { spawns(&*cell).await }
        });
        check_spawns(restored.await.unwrap(), "Thread", home);

        // A task on the shared executor or the blocking pool receives an unplaced context that
        // remembers it. Each blocking task runs on a thread of its own, so a blocking task's
        // placed spawns do not run on its thread.
        let lines = [
            (context.child("shared_task"), "Shared"),
            (context.child("blocking_task").blocking(), "SharedBlocking"),
        ];
        for (line, expect) in lines {
            let task = line.spawn(|context| async move { (os(), spawns(&context).await) });
            let (parent, ran) = task.await.unwrap();
            let moved = expect == "Shared" || ran[1].0 != parent;
            assert!(!R::NATIVE || moved, "a blocking thread ran a placed spawn");
            check_spawns(ran, expect, home);
        }

        // A Local's context is unplaced on its thread, for a spawn_on task, a spawn_local task
        // and a root alike. A root and its spawn_local task share an OS thread of their own, and
        // the root's context and thread keep the creating label.
        let resident = context.child("local").spawn_on(&thread, local_spawns);
        let task = context.child("spawn_local");
        let task = task.spawn_on(&thread, |local| async move {
            local.child("task").spawn_local(local_spawns).await.unwrap()
        });
        let root = context.child("root").thread().spawn(|local| async move {
            let names = [local.name().label, local.home().name().to_string()];
            let leaf = local.child("leaf").spawn_local(local_spawns);
            (names, local_spawns(local).await, leaf.await.unwrap())
        });
        let (names, root, leaf) = root.unwrap().await.unwrap();
        assert_eq!(names, ["root", "root"]);
        let own = root.0;
        let apart = own == leaf.0 && own != home && own != os();
        assert!(!R::NATIVE || apart, "a root is not alone on its OS thread");
        let residents = [
            (resident.await.unwrap(), home),
            (task.await.unwrap(), home),
            (root, own),
            (leaf, own),
        ];
        for ((here, ran), thread) in residents {
            assert!(!R::NATIVE || here == thread, "a resident left its thread");
            check_spawns(ran, "Thread", thread);
        }

        // An attached context is placed on its thread and keeps the creating label, and a task
        // spawned from it can spawn there again through placed.
        let attached = context.child("attached").thread().attach().unwrap();
        assert_eq!(attached.name().label, "attached");
        let task = attached.child("task");
        let task = task.spawn(|context| async move { (os(), spawns(&context).await) });
        let (attached_home, ran) = task.await.unwrap();
        check_spawns(ran, "Thread", attached_home);
        assert_ran::<R>(&context, ran_on(attached).await, "Thread", attached_home);
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
fn test_thread_supervision<R: TestRunner>(#[case] runner: R) {
    bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("t").thread().build().unwrap();
            let ran = flag();

            // Abort a placed task, then a placed lineage with a child and a resident.
            let task = context.child("placed").on(&thread);
            let task = task.spawn(|_| pending::<()>());
            task.abort();
            assert!(closed(task).await, "an aborted placed task did not close");
            let dropped = flag();
            let (tx, rx) = oneshot::channel();
            let lineage = context.child("lineage").on(&thread).spawn({
                let (thread, flag) = (thread.clone(), DropFlag(dropped.clone()));
                move |context| async move {
                    let inner = context.child("inner").spawn(|_| pending::<()>());
                    let resident = context.child("resident").spawn_on(&thread, |local| {
                        drop(local.child("local").spawn_local(|_| park(flag, None)));
                        pending::<()>()
                    });
                    tx.send((inner, resident)).ok().unwrap();
                    pending::<()>().await;
                }
            });
            let (inner, resident) = rx.await.unwrap();
            lineage.abort();
            for handle in [lineage, inner, resident] {
                assert!(closed(handle).await, "the aborted lineage kept a task");
            }
            settle(&context, || is_set(&dropped)).await;
            let after = context.child("after").spawn_on(&thread, |_| async { 5 });
            assert_eq!(after.await.unwrap(), 5, "the abort closed the thread");

            // The handle resolves before the task's completing poll aborts its node. The thread
            // polls its residents one at a time, so once another resident has run, that poll is
            // over.
            let task = context.child("task").on(&thread);
            let task = task.spawn(|context| async move { context.child("saved") });
            let saved = task.await.unwrap();
            let barrier = context.child("barrier").spawn_on(&thread, |_| async {});
            barrier.await.unwrap();
            for line in [saved.child("late"), saved.child("late").placed()] {
                let late = closed(line.spawn(recording(&ran))).await;
                assert!(late, "a spawn from an ended task's context was admitted");
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
            let lines = [
                context.child("sibling"),
                context.child("moved").on(&closing).shared(),
                lineage.child("kept"),
            ];
            let gated = lines.map(|line| {
                let (go, wait) = oneshot::channel::<()>();
                (go, line.spawn(|_| wait))
            });
            let dropped = flag();
            let flag = DropFlag(dropped.clone());
            let (started, start) = oneshot::channel();
            let resident = lineage.child("on").spawn_on(&closing, move |local| {
                drop(local.child("local").spawn_local(|_| park(flag, None)));
                started.send(()).unwrap();
                pending::<()>()
            });
            let placed = context.child("resident_placed").on(&closing);
            let placed = placed.spawn(|_| pending::<()>());
            start.await.unwrap();
            end.send(()).unwrap();
            creator.await.unwrap();
            for handle in [resident, placed] {
                assert!(closed(handle).await, "a resident outlived its thread");
            }

            // Nothing orders the local resident's drop before the other handles resolve.
            settle(&context, || is_set(&dropped)).await;
            for (go, handle) in gated {
                go.send(()).unwrap();
                let survived = matches!(handle.await, Ok(Ok(())));
                assert!(survived, "the close aborted a task that is not a resident");
            }
            let late = context.child("late").on(&closing);
            let wired = late.child("wired").shared().spawn(|_| pending::<()>());
            assert!(closed(late.spawn(recording(&ran))).await);
            assert!(closed(wired).await, "a rejected spawn left its node open");
            assert!(!is_set(&ran), "a rejected factory ran");
            let still = context.child("still").spawn_on(&thread, |_| async { 7 });
            assert_eq!(still.await.unwrap(), 7, "a close closed another thread");
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
fn test_thread_attach<R: TestRunner>(#[case] runner: R) {
    bounded(move || {
        runner.start(|context| async move {
            // Used only through child, then dropped.
            let (tx, rx) = oneshot::channel();
            let lineage = context.child("lineage").spawn(move |context| async move {
                let attached = context.child("t").thread().attach().unwrap();
                let probe = attached.child("probe").spawn(|_| pending::<()>());
                tx.send(probe).ok().unwrap();
                drop(attached);
                pending::<()>().await;
            });
            let mut probe = rx.await.unwrap();
            context.sleep(Duration::from_millis(10)).await;
            let open = (&mut probe).now_or_never().is_none();
            assert!(open, "dropping the attached context closed its thread");
            lineage.abort();
            assert!(closed(probe).await);

            // An actor derived with child ends first, then the consuming task runs.
            let attached = context.child("subsystem").thread().attach().unwrap();
            attached.child("actor").spawn(|_| async {}).await.unwrap();
            let saved = attached.child("saved");
            let (release, released) = oneshot::channel::<()>();
            let main = attached.spawn(|_| released);
            let open = saved.child("open").spawn(|_| async { 1 });
            assert_eq!(open.await.unwrap(), 1, "the thread closed with an actor");
            release.send(()).unwrap();
            main.await.unwrap().unwrap();

            // A resident of the same thread runs after the consumer's completing poll, which
            // aborts its node, or is aborted with it.
            let _ = saved.child("barrier").spawn(|_| async {}).await;
            let late = closed(saved.child("late").spawn(|_| async {})).await;
            assert!(late, "a spawn from the consumed context was admitted late");

            // Sixteen epochs, whose engines complete or are aborted in turn.
            let orchestrator = context.child("orchestrator").spawn(|context| async move {
                let baseline = os_threads();
                for epoch in 0..16 {
                    let engine = context.child("engine").with_attribute("epoch", epoch);
                    let engine = engine.thread().attach().unwrap();
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
                    }
                    assert_eq!(closed(main).await, aborted);
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
// detaches its task when dropped, and an output it never took is dropped on its thread at close,
// after the factories that were still parked. On deterministic a later poll of that handle
// resolves Closed.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_spawn_local<R: TestRunner>(#[case] runner: R) {
    bounded(move || {
        runner.start(|context| async move {
            let (tx, rx) = oneshot::channel();
            let creator = context.child("creator").spawn(move |context| async move {
                tx.send(context.thread().build().unwrap()).unwrap();
                pending::<()>().await;
            });
            let thread = rx.await.unwrap();
            let caller = context.child("caller").spawn_on(&thread, |local| {
                // From the factory of spawn_on, from a spawn_local factory, and from a poll.
                let shared = Rc::new(RefCell::new(Vec::new()));
                let from_factory = local.child("factory").spawn_local({
                    let shared = shared.clone();
                    move |local| {
                        shared.borrow_mut().push(1);
                        let nested = local.child("nested");
                        nested.spawn_local(move |_| async move { shared.borrow_mut().push(2) })
                    }
                });
                async move {
                    from_factory.await.unwrap().unwrap();
                    let (poll, from_poll) = (local.child("poll"), shared.clone());
                    let poll =
                        poll.spawn_local(move |_| async move { from_poll.borrow_mut().push(3) });
                    poll.await.unwrap();

                    // A factory that borrows what the caller holds during the call, and a
                    // spawn_on toward this thread.
                    let (ran, remote) = (Rc::new(Cell::new(None)), flag());
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
                        let on = local.child("on").into_inner();
                        let on = on.spawn_on(local.home(), recording(&remote));
                        borrow.push(4);
                        let inline = ran.get().is_some() || is_set(&remote);
                        assert!(!inline, "a factory ran inside its caller's poll");
                        (deferred, on)
                    };
                    deferred.await.unwrap();
                    on.await.unwrap();
                    assert_eq!(ran.get(), Some(os()), "a factory ran off its thread");
                    assert_eq!(*shared.borrow(), [1, 2, 3, 4, 5], "wrong factory order");

                    // A !Send output, an aborted handle, and a dropped handle whose task
                    // finishes.
                    let output = local.child("output").spawn_local(|_| async { Rc::new(5) });
                    assert_eq!(*output.await.unwrap(), 5);
                    let handle = local.child("abort").spawn_local(|_| pending::<()>());
                    handle.abort();
                    assert!(closed(handle).await, "an aborted local handle stayed open");
                    let (done, finished) = oneshot::channel::<()>();
                    drop(local.child("detach").spawn_local(move |_| async move {
                        reschedule().await;
                        done.send(()).unwrap();
                    }));
                    assert!(finished.await.is_ok(), "a dropped handle cancelled a task");
                }
            });
            caller.await.unwrap();

            // From a resident's Drop while the thread closes.
            let (report, outcome) = oneshot::channel();
            let (started, start) = oneshot::channel();
            let _dropper = context.child("dropper").spawn_on(&thread, move |local| {
                let guard = on_drop(move || {
                    let ran = flag();
                    let handle = local.child("on_drop").spawn_local(recording(&ran));
                    let _ = report.send((closed(handle).now_or_never(), is_set(&ran)));
                });
                park(guard, Some(started))
            });
            start.await.unwrap();
            creator.abort();
            let outcome = outcome.await.unwrap();
            assert_eq!(outcome, (Some(true), false), "a spawn_local in a Drop ran");

            // A thread that closes with a finished output its handle never took, and with a
            // factory its root parked in the poll that ended it.
            let (report, dropped) = oneshot::channel();
            let (parked, ran) = (flag(), flag());
            let factory = capturing(DropFlag(parked.clone()), &ran);
            let root = context.child("closing").thread().spawn(|local| async move {
                let (finished, finish) = oneshot::channel::<()>();
                let handle = local.child("output").spawn_local(|_| async move {
                    finished.send(()).unwrap();
                    probe(report)
                });
                finish.await.unwrap();
                HELD.set(Some(handle));
                drop(local.child("parked").spawn_local(factory));
                os()
            });
            let home = root.unwrap().await.unwrap();
            let dropped = dropped.await.unwrap();
            assert!(is_set(&parked) && !is_set(&ran), "parked: kept or run");
            if R::NATIVE {
                assert_eq!(dropped, home, "an unclaimed output dropped off its thread");
            } else {
                assert!(closed(HELD.take().unwrap()).await);
            }
        })
    });
}

// A runner returns with idle threads built by the root or by a task, and with a Thread held by
// the value start returns and by a clone on another OS thread. The held thread is closed by then,
// although its residents never wake and spawned local residents, and on native runners leaked a
// Local.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_shutdown_with_held_thread<R: TestRunner>(#[case] runner: R) {
    let (hold, held) = mpsc::channel::<Thread>();
    let (release, released) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _thread = held.recv().unwrap();
        released.recv().unwrap();
    });
    let thread = bounded(move || {
        runner.start(|context| async move {
            drop(context.child("root").thread().build().unwrap());
            let task = context.child("task").spawn(|context| async move {
                drop(context.child("inner").thread().build().unwrap());
            });
            task.await.unwrap();

            let thread = context.child("held").thread().build().unwrap();
            for _ in 0..4 {
                let (started, start) = oneshot::channel();
                drop(context.child("resident").spawn_on(&thread, move |local| {
                    drop(local.child("local").spawn_local(|_| pending::<()>()));
                    if R::NATIVE {
                        mem::forget(local.child("leaked"));
                    }
                    started.send(()).unwrap();
                    pending::<()>()
                }));
                start.await.unwrap();
            }
            let placed = context.child("placed").on(&thread);
            drop(placed.spawn(|_| pending::<()>()));
            hold.send(thread.clone()).unwrap();
            thread
        })
    });
    assert_eq!(thread.name(), "held");
    let state = thread.inner().state();
    assert_eq!(state, State::Closed, "the held thread did not close");
    release.send(()).unwrap();
    holder.join().unwrap();
}

// Futures of residents are dropped on their thread, whether they complete, are aborted, panic,
// or are discarded by a close or by shutdown.
#[rstest]
#[case::tokio(tokio::Runner::catching(true))]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::catching(true)))]
fn test_thread_drop_on_owner_thread<R: TestRunner>(#[case] runner: R) {
    let (home, at_shutdown) = bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("t").thread().build().unwrap();
            let home = context.child("home").spawn_on(&thread, |_| async { os() });
            let home = home.await.unwrap();
            for action in ["complete", "abort", "panic"] {
                let (report, dropped) = oneshot::channel();
                let (started, start) = oneshot::channel();
                let handle = context.child(action).spawn_on(&thread, move |_| {
                    let probe = probe(report);
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
                let expected = match action {
                    "complete" => result.is_ok(),
                    "abort" => matches!(result, Err(Error::Closed)),
                    _ => matches!(result, Err(Error::Exited)),
                };
                assert!(expected, "{action}: the handle resolved wrongly");
                assert_eq!(dropped.await.unwrap(), home, "{action}: wrong thread");
            }

            // A close, for a spawn_on future and a spawn_local future.
            let (tx, rx) = oneshot::channel();
            let creator = context.child("creator").spawn(move |context| async move {
                tx.send(context.thread().build().unwrap()).unwrap();
                pending::<()>().await;
            });
            let closing = rx.await.unwrap();
            let (owner, dropped) = probes(context.child("close"), &closing).await;
            creator.abort();
            for dropped in dropped {
                assert_eq!(dropped.await.unwrap(), owner, "close: wrong thread");
            }

            // Shutdown, checked after start returns.
            probes(context.child("shutdown"), &thread).await
        })
    });
    for mut dropped in at_shutdown {
        assert_eq!(dropped.try_recv().unwrap(), home, "shutdown: wrong thread");
    }
}

// A placed spawn and a spawn_on toward an open thread of another runner, of the same or another
// backend, resolve Closed without running the factory, and close the consumed context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_wrong_runtime<R: TestRunner>(#[case] runner: R) {
    let others = vec![
        foreign_thread(deterministic::Runner::default()),
        foreign_thread(tokio::Runner::default()),
    ];
    wrong_runtime(runner, others);
}

// The same toward an open thread of an io_uring runner, in a test whose every case needs io_uring.
#[cfg(target_os = "linux")]
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[case::iouring(iouring::Runner::default())]
fn test_thread_wrong_runtime_iouring_target<R: TestRunner>(#[case] runner: R) {
    wrong_runtime(runner, vec![foreign_thread(iouring::Runner::default())]);
}

// Thread tasks carry the Thread execution label, including a spawn_on task from a blocking
// context. The residents gauge counts queued and running tasks, not finished outputs waiting in
// a slot, drops with dropped jobs, and threads with one label share one series.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_metrics<R: TestRunner>(#[case] runner: R) {
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let placed = context.child("placed").on(&thread);
        placed.spawn(|_| async {}).await.unwrap();
        assert_eq!(executions(&context, "placed"), ["Thread"]);
        let blocking = context.child("blocking").blocking();
        blocking.spawn_on(&thread, |_| async {}).await.unwrap();
        assert_eq!(executions(&context, "blocking"), ["Thread"]);

        // Count from a resident of its own thread, which cannot take a turn during its poll.
        let gauge = context.child("gauge").thread().build().unwrap();
        let counter = context.child("counter");
        let counter = counter.spawn_on(&gauge, |local| async move {
            let context = &*local;
            let count = || residents(context, "gauge");
            assert_eq!(count(), Some(1));

            // Queued jobs count at once, including ones aborted before they run.
            let home = local.home();
            let job = |_| context.child("job").spawn_on(home, |_| pending::<()>());
            let mut running: Vec<_> = (0..5).map(job).collect();
            let skipped = running.split_off(3);
            assert_eq!(count(), Some(6));
            skipped.iter().for_each(|handle| handle.abort());

            // Skipped jobs stop counting once they are dropped.
            for handle in skipped {
                assert!(closed(handle).await);
            }
            settle(context, || count() == Some(4)).await;

            // A finished output waiting in its slot does not count.
            let (finished, finish) = oneshot::channel::<()>();
            let output = local.child("output").spawn_local(move |_| async move {
                finished.send(()).unwrap();
                Rc::new(1)
            });
            finish.await.unwrap();
            settle(context, || count() == Some(4)).await;
            assert_eq!(*output.await.unwrap(), 1);
            running.iter().for_each(|handle| handle.abort());
            for handle in running {
                assert!(closed(handle).await);
            }
            settle(context, || count() == Some(1)).await;
        });
        counter.await.unwrap();
        settle(&context, || residents(&context, "gauge") == Some(0)).await;

        // Two threads with one label share one series.
        let first = context.child("same").thread().build().unwrap();
        let second = context.child("same").thread().build().unwrap();
        assert_ne!(first, second);
        let a = context.child("a").spawn_on(&first, |_| pending::<()>());
        let b = context.child("b").spawn_on(&second, |_| pending::<()>());
        settle(&context, || residents(&context, "same") == Some(2)).await;
        let same = |line: &&str| {
            line.starts_with("runtime_thread_residents{") && line.contains("name=\"same\"")
        };
        let series = context.encode().lines().filter(same).count();
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
#[case::deterministic(deterministic::Runner::default)]
#[case::tokio(tokio::Runner::default)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default))]
fn test_thread_local_context_swap<R: TestRunner>(#[case] runner: fn() -> R) {
    let (foreign, release) = hold_open(runner(), |context| context.child("foreign"));
    runner().start(|context| async move {
        let a = context.child("a").thread().build().unwrap();
        let b = context.child("b").thread().build().unwrap();

        // A context of thread b, from a resident that outlives its use.
        let (send, from_b) = oneshot::channel();
        let (unhold, unheld) = oneshot::channel::<()>();
        let holder = context.child("holder").spawn_on(&b, move |local| {
            send.send(local.child("from_b").into_inner()).ok().unwrap();
            unheld
        });
        let from_b = from_b.await.unwrap();
        let swap = context.child("swap").spawn_on(&a, move |local| async move {
            // A context of another thread, then a shared context.
            let mut swapped = local.child("other_thread");
            *swapped = from_b;
            let mut shared = local.child("shared");
            *shared = (*local).child("plain").shared();
            for swapped in [swapped, shared] {
                let task = swapped.spawn_local(|local| ready((os(), local.home().clone())));
                let (ran, home) = task.await.unwrap();
                assert_eq!(home.name(), "a");
                assert!(!R::NATIVE || ran == os());
            }

            // A context of another runner.
            let mut stale = local.child("stale");
            *stale = foreign;
            let (dropped, ran) = (flag(), flag());
            let handle = stale.spawn_local(capturing(DropFlag(dropped.clone()), &ran));
            assert!(is_set(&dropped) && !is_set(&ran), "factory kept or run");
            assert!(closed(handle).await);
        });
        swap.await.unwrap();
        unhold.send(()).unwrap();
        holder.await.unwrap().unwrap();
    });
    release();
}

// The factory of an ordinary spawn runs on the caller before spawn returns, wherever the future
// runs, so it may borrow the caller's !Send state to build a Send future. A placed spawn's future
// runs on its thread, and a panic in its factory unwinds out of spawn and closes the consumed
// context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_spawn_factory_reads_local_state<R: TestRunner>(#[case] runner: R) {
    bounded(move || {
        runner.start(|context| async move {
            let thread = context.child("other").thread().build().unwrap();
            let home = context.child("home").spawn_on(&thread, |_| async { os() });
            let home = home.await.unwrap();
            let target = thread.clone();
            let root = context.child("t").thread().spawn(move |local| async move {
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
                assert_eq!(*state.borrow(), [1, 2, 3], "a factory ran after its spawn");
                let mut futures = Vec::new();
                for handle in handles {
                    futures.push(handle.await.unwrap());
                }
                (futures[1], os(), name)
            });
            let (placed, caller, name) = root.unwrap().await.unwrap();
            assert_eq!(executions(&context, &name), ["Thread"]);
            let on_thread = placed == home && caller != home;
            assert!(!R::NATIVE || on_thread, "a placed future left its thread");

            let placed = context.child("panics").on(&thread);
            let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
            let result = catch_unwind(AssertUnwindSafe(|| {
                placed.spawn(|_| -> Ready<()> { panic!("placed factory") })
            }));
            assert!(result.is_err(), "a factory's panic stayed inside spawn");
            assert!(closed(wired).await, "a factory's panic left its node open");
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
fn test_thread_busy_producer<R: TestRunner>(#[case] runner: R) {
    /// Jobs of the burst, three admission batches.
    const JOBS: usize = 3 * 64;

    bounded(move || {
        runner.start(|context| async move {
            let burst = context.child("burst").thread().spawn(|local| async move {
                let order = Arc::new(Mutex::new(Vec::new()));
                let job = |i| {
                    let order = order.clone();
                    (*local).child("job").spawn_on(local.home(), move |_| {
                        order.lock().push(i);
                        ready(())
                    })
                };
                let handles: Vec<_> = (0..JOBS).map(job).collect();
                assert_eq!(local.home().inner().queued(), JOBS);
                for handle in handles {
                    handle.await.unwrap();
                }
                order.lock().clone()
            });
            let order = burst.unwrap().await.unwrap();
            assert!(order.into_iter().eq(0..JOBS), "the burst started unordered");

            // Jobs the producer started to submit, finished submitting, and that ran.
            let thread = context.child("busy").thread().build().unwrap();
            let counts: [_; 3] = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
            let stop = flag();
            let producer = std::thread::spawn({
                let (context, thread) = (context.child("producer"), thread.clone());
                let ([started, submitted, admitted], stop) = (counts.clone(), stop.clone());
                move || {
                    while !is_set(&stop) {
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
            let resident = context.child("resident");
            let resident = resident.spawn_on(&thread, move |local| async move {
                // Polled again and again while jobs are queued, until the ingress is full. The
                // producer counts a job as submitted after it queued it, so this waits for one
                // job more than the check below needs.
                let queued = || local.home().inner().queued();
                let mut contended = 0;
                while contended < 100 || queued() <= 200 {
                    contended += usize::from(queued() > 0);
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
            });
            let (ahead, behind, ran) = resident.await.unwrap();
            stop.store(true, Ordering::SeqCst);
            producer.join().unwrap();
            assert!(ahead >= 200, "the ingress was not full");
            let between = (ahead..=behind).contains(&ran);
            assert!(between, "{ran} jobs ran first, not {ahead} to {behind}");
        })
    });
}
