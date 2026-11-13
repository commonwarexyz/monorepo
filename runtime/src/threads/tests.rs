//! Tests of runtime threads on every runner.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{
    Clock, ContextCell, Error, Handle, Local, LocalHandle, Metrics, Runner, Spawner, Supervisor,
    Thread, ThreadError, deterministic, reschedule, tokio,
};
use commonware_macros::select;
use commonware_utils::channel::oneshot;
use futures::future::pending;
use rstest::rstest;
use std::{
    cell::{Cell, RefCell},
    future::Future,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::ThreadId,
    time::Duration,
};

/// Run `body` on a helper thread and fail if it does not return in time, so a runner that hangs
/// on shutdown fails the test instead of blocking it.
fn bounded<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let helper = std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(value) => {
            helper.join().unwrap();
            value
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(helper.join().unwrap_err())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("the runner did not return"),
    }
}

/// The OS thread running the caller.
fn os() -> ThreadId {
    std::thread::current().id()
}

/// Await `future`, failing if it does not complete in time, so a rule that would leave a task
/// pending forever fails instead of hanging.
async fn within<F: Future>(context: &impl Clock, future: F) -> F::Output {
    select! {
        output = future => output,
        _ = context.sleep(Duration::from_secs(10)) => panic!("timed out"),
    }
}

/// The execution labels of the tasks spawned under `name`, from the runner's task metrics.
pub(super) fn executions(metrics: &impl Metrics, name: &str) -> Vec<String> {
    let needle = format!("name=\"{name}\"");
    metrics
        .encode()
        .lines()
        .filter(|line| line.starts_with("runtime_tasks_spawned_total{") && line.contains(&needle))
        .filter_map(|line| {
            let execution = line.split("execution=\"").nth(1)?.split('"').next()?;
            Some(execution.to_string())
        })
        .collect()
}

/// Spawn a task from `context` and return the OS thread it ran on and the context's label.
async fn ran_on<C: Spawner>(context: C) -> (ThreadId, String) {
    let name = context.name().label;
    let id = context.spawn(|_| async { os() }).await.unwrap();
    (id, name)
}

/// A context whose runtime thread a test can read.
trait PlacedOn {
    /// The runtime thread the context's spawns run on.
    fn placed_on(&self) -> Thread;
}

impl PlacedOn for deterministic::Context {
    fn placed_on(&self) -> Thread {
        self.placed_thread().cloned().expect("placed on a thread")
    }
}

impl PlacedOn for tokio::Context {
    fn placed_on(&self) -> Thread {
        self.placed_thread().cloned().expect("placed on a thread")
    }
}

#[cfg(target_os = "linux")]
impl PlacedOn for iouring::Context {
    fn placed_on(&self) -> Thread {
        self.placed_thread().cloned().expect("placed on a thread")
    }
}

/// Wait until `thread` stops admitting work.
async fn closes(context: &impl Clock, thread: &Thread) {
    within(context, async {
        while thread.inner().is_open() {
            context.sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
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

/// Sets a flag when dropped.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
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
        let closed = matches!(
            futures::FutureExt::now_or_never(&mut handle),
            Some(Err(Error::Closed))
        );
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

/// Run a runner of another instance on its own OS thread, holding a thread of it open until the
/// returned sender is used. Returns the thread, the sender, and the runner's OS thread.
fn hold_open<R: Runner + Send + 'static>(
    runner: R,
) -> (Thread, mpsc::Sender<()>, std::thread::JoinHandle<()>)
where
    R::Context: Spawner,
{
    let (hold, held) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        runner.start(|context| async move {
            hold.send(context.child("foreign").thread().build().unwrap())
                .unwrap();
            released.recv().unwrap();
        });
    });
    (held.recv().unwrap(), release, other)
}

/// Spawn toward a thread of each runner in `others` from `runner`, then release them.
fn wrong_runtime<R: Runner>(
    runner: R,
    others: Vec<(Thread, mpsc::Sender<()>, std::thread::JoinHandle<()>)>,
) where
    R::Context: Spawner + Clock,
{
    let threads: Vec<Thread> = others.iter().map(|(thread, _, _)| thread.clone()).collect();
    runner.start(|context| async move {
        for thread in threads {
            assert!(thread.inner().is_open());
            let ran = Arc::new(AtomicBool::new(false));

            let placed = context.child("placed").on(&thread);
            let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
            let handle = placed.spawn({
                let ran = ran.clone();
                move |_| {
                    ran.store(true, Ordering::SeqCst);
                    async {}
                }
            });
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(matches!(within(&context, wired).await, Err(Error::Closed)));

            let on = context.child("on");
            let wired = on.child("wired").spawn(|_| pending::<()>());
            let handle = on.spawn_on(&thread, {
                let ran = ran.clone();
                move |_| {
                    ran.store(true, Ordering::SeqCst);
                    async {}
                }
            });
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(matches!(within(&context, wired).await, Err(Error::Closed)));
            assert!(!ran.load(Ordering::SeqCst));
        }
    });
    for (_, release, other) in others {
        release.send(()).unwrap();
        other.join().unwrap();
    }
}

/// The series of the residents gauge for threads named `name`, as (count, value of the last).
fn residents(metrics: &impl Metrics, name: &str) -> (usize, Option<i64>) {
    let needle = format!("name=\"{name}\"");
    let values: Vec<i64> = metrics
        .encode()
        .lines()
        .filter(|line| line.starts_with("runtime_thread_residents{") && line.contains(&needle))
        .filter_map(|line| line.trim_end().rsplit(' ').next()?.parse().ok())
        .collect();
    (values.len(), values.last().copied())
}

/// Wait until the residents gauge of threads named `name` reads `expected`. Gauges lag handles
/// on native runners.
async fn settle(context: &(impl Metrics + Clock), name: &str, expected: i64) {
    within(context, async {
        while residents(context, name).1 != Some(expected) {
            context.sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
}

#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_smoke<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        // A root task with !Send state shared by its residents.
        let value = context
            .child("root")
            .thread()
            .spawn(|local| async move {
                let shared = Rc::new(RefCell::new(0));
                let mut handles = Vec::new();
                for _ in 0..10 {
                    let shared = shared.clone();
                    handles.push(local.child("leaf").spawn_local(move |_| async move {
                        reschedule().await;
                        *shared.borrow_mut() += 1;
                        Rc::new(7)
                    }));
                }
                let mut total = 0;
                for handle in handles {
                    total += *handle.await.unwrap();
                }
                let count = *shared.borrow();
                total + count
            })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(value, 80);

        // A built thread hosting placed spawns and spawn_on tasks.
        let thread = context.child("built").thread().build().unwrap();
        let placed = context.child("placed").on(&thread);
        let a = placed.spawn(|_| async { 1 });
        let b = context
            .child("remote")
            .spawn_on(&thread, |local| async move {
                let inner = local.child("inner").spawn_local(|_| async { Rc::new(2) });
                *inner.await.unwrap()
            });
        assert_eq!(a.await.unwrap() + b.await.unwrap(), 3);

        // An attached context.
        let attached = context.child("attached").thread().attach().unwrap();
        let c = attached.child("x").spawn(|ctx| async move {
            ctx.sleep(Duration::from_millis(1)).await;
            3
        });
        assert_eq!(c.await.unwrap(), 3);

        // Closing a thread aborts its residents.
        let lineage = context.child("lineage");
        let (tx, rx) = futures::channel::oneshot::channel();
        let owner = lineage.spawn(move |ctx| async move {
            let thread = ctx.child("t").thread().build().unwrap();
            let probe = ctx.child("probe").spawn_on(&thread, |_| pending::<()>());
            tx.send((thread, probe)).ok().unwrap();
            pending::<()>().await;
        });
        let (thread, probe) = rx.await.unwrap();
        owner.abort();
        assert!(matches!(probe.await, Err(Error::Closed)));
        let late = context.child("late").spawn_on(&thread, |_| pending::<()>());
        assert!(matches!(late.await, Err(Error::Closed)));

        // Pins validate.
        let empty: Vec<usize> = Vec::new();
        assert!(matches!(
            context.child("empty").thread().pin(empty).build(),
            Err(ThreadError::EmptyCpus)
        ));
    });
}

// The last of shared, blocking and on decides where a spawn runs, and child and with_attribute keep
// it. A spawn hands its task an unplaced context, which spawns on the shared executor until placed
// places it where the task runs, and placed does nothing on a context placed explicitly.
// Contexts a thread hands out keep the creating context's label.
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
        let check = |ran, expect| assert_ran(&context, ran, expect, home, native);

        // The last of shared, blocking and on wins.
        check(
            ran_on(context.child("on").on(&thread)).await,
            Expect::Thread,
        );
        check(
            ran_on(context.child("on_shared").on(&thread).shared()).await,
            Expect::Shared,
        );
        check(
            ran_on(context.child("on_blocking").on(&thread).blocking()).await,
            Expect::Blocking,
        );
        check(
            ran_on(context.child("blocking_on").blocking().on(&thread)).await,
            Expect::Thread,
        );
        check(
            ran_on(context.child("blocking_shared").blocking().shared()).await,
            Expect::Shared,
        );
        check(
            ran_on(context.child("shared_blocking").shared().blocking()).await,
            Expect::Blocking,
        );

        // child and with_attribute keep the placement, the blocking pool included.
        check(
            ran_on(context.child("on_child").on(&thread).child("child")).await,
            Expect::Thread,
        );
        check(
            ran_on(context.child("on_attr").on(&thread).with_attribute("k", 1)).await,
            Expect::Thread,
        );
        check(
            ran_on(context.child("blocking_child").blocking().child("child")).await,
            Expect::Blocking,
        );
        check(
            ran_on(
                context
                    .child("blocking_attr")
                    .blocking()
                    .with_attribute("k", 1),
            )
            .await,
            Expect::Blocking,
        );

        // placed does nothing on a context that no spawn handed out, or that was placed
        // explicitly.
        check(
            ran_on(context.child("fresh_placed").placed()).await,
            Expect::Shared,
        );
        check(
            ran_on(context.child("on_placed").on(&thread).placed()).await,
            Expect::Thread,
        );
        check(
            ran_on(context.child("shared_placed").on(&thread).shared().placed()).await,
            Expect::Shared,
        );
        check(
            ran_on(context.child("blocking_placed").blocking().placed()).await,
            Expect::Blocking,
        );

        // A task placed on the thread receives an unplaced context. Its spawns, and those of the
        // contexts derived from it, run on the shared executor until placed places them, and an
        // explicit placement replaces what they remember.
        let handed = context
            .child("handed")
            .on(&thread)
            .spawn(|context| async move {
                let plain = ran_on(context.child("plain")).await;
                let derived = ran_on(context.child("derived").with_attribute("k", 1)).await;
                let placed = ran_on(context.child("placed").placed()).await;
                let derived_placed = ran_on(
                    context
                        .child("derived_placed")
                        .with_attribute("k", 1)
                        .placed(),
                )
                .await;
                let blocking = ran_on(context.child("blocking").blocking().placed()).await;
                let shared = ran_on(context.child("shared").shared().placed()).await;

                // A placed context stays placed through child and with_attribute.
                let hoisted = context.child("hoisted").placed();
                let hoisted_child = ran_on(hoisted.child("peer")).await;
                let hoisted_attr = ran_on(hoisted.with_attribute("k", 1)).await;

                // A task spawned through placed receives an unplaced context as well.
                let nested = context
                    .child("nested")
                    .placed()
                    .spawn(|context| async move {
                        let plain = ran_on(context.child("plain")).await;
                        let placed = ran_on(context.child("placed").placed()).await;
                        (plain, placed)
                    })
                    .await
                    .unwrap();

                // The placement belongs to the context, not to the task that holds it.
                let saved = context.child("saved");
                let saved = context
                    .child("elsewhere")
                    .spawn(move |_| async move { ran_on(saved.placed()).await })
                    .await
                    .unwrap();
                [
                    (plain, Expect::Shared),
                    (derived, Expect::Shared),
                    (placed, Expect::Thread),
                    (derived_placed, Expect::Thread),
                    (blocking, Expect::Blocking),
                    (shared, Expect::Shared),
                    (hoisted_child, Expect::Thread),
                    (hoisted_attr, Expect::Thread),
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
        for blocking in [false, true] {
            let line = context.child(if blocking {
                "blocking_task"
            } else {
                "shared_task"
            });
            let line = if blocking { line.blocking() } else { line };
            let (plain, placed, hoisted, parent) = line
                .spawn(|context| async move {
                    let parent = os();
                    let plain = ran_on(context.child("plain")).await;
                    let placed = ran_on(context.child("placed").placed()).await;
                    let hoisted = ran_on(context.child("hoisted").placed().child("peer")).await;
                    (plain, placed, hoisted, parent)
                })
                .await
                .unwrap();
            if native && blocking {
                assert_ne!(placed.0, parent);
                assert_ne!(hoisted.0, parent);
            }
            let expect = if blocking {
                Expect::Blocking
            } else {
                Expect::Shared
            };
            check(plain, Expect::Shared);
            check(placed, expect);
            check(hoisted, expect);
        }

        // A Local's context is unplaced on its thread, through into_inner and through a deref
        // child, for a spawn_on task, a root and a spawn_local task alike.
        let (inner, deref, placed) = context
            .child("local")
            .spawn_on(&thread, |local| async move {
                let deref = ran_on((*local).child("deref")).await;
                let placed = ran_on(local.child("placed").into_inner().placed()).await;
                let inner = ran_on(local.child("inner").into_inner()).await;
                (inner, deref, placed)
            })
            .await
            .unwrap();
        check(inner, Expect::Shared);
        check(deref, Expect::Shared);
        check(placed, Expect::Thread);
        let (inner, placed, root) = context
            .child("root")
            .thread()
            .spawn(|local| async move {
                let root = os();
                let placed = ran_on(local.child("placed").into_inner().placed()).await;
                let inner = ran_on(local.child("inner").into_inner()).await;
                (inner, placed, root)
            })
            .unwrap()
            .await
            .unwrap();
        assert_ran(&context, inner, Expect::Shared, root, native);
        assert_ran(&context, placed, Expect::Thread, root, native);
        let (inner, placed) = context
            .child("spawn_local")
            .spawn_on(&thread, |local| async move {
                local
                    .child("task")
                    .spawn_local(|local| async move {
                        let placed = ran_on(local.child("placed").into_inner().placed()).await;
                        let inner = ran_on(local.child("inner").into_inner()).await;
                        (inner, placed)
                    })
                    .await
                    .unwrap()
            })
            .await
            .unwrap();
        check(inner, Expect::Shared);
        check(placed, Expect::Thread);

        // An attached context is placed on its thread, and a task spawned from it can spawn there
        // again through placed. Contexts handed out by attach and by the builder's spawn keep the
        // creating label.
        let attached = context.child("attached").thread().attach().unwrap();
        assert_eq!(attached.name().label, "attached");
        let attached_home = attached
            .child("home")
            .spawn(|_| async { os() })
            .await
            .unwrap();
        let (plain, placed) = attached
            .child("task")
            .spawn(|context| async move {
                let plain = ran_on(context.child("plain")).await;
                let placed = ran_on(context.child("placed").placed()).await;
                (plain, placed)
            })
            .await
            .unwrap();
        assert_ran(&context, plain, Expect::Shared, attached_home, native);
        assert_ran(&context, placed, Expect::Thread, attached_home, native);
        let (_, name) = ran_on(attached.placed()).await;
        assert_eq!(executions(&context, &name), ["Thread"]);
        let (label, home) = context
            .child("spawned")
            .thread()
            .spawn(|local| async move { (local.name().label, local.home().name().to_string()) })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(label, "spawned");
        assert_eq!(home, "spawned");
    });
}

// An unplaced context belongs to its task's supervision node, so once the task ends a spawn from it
// resolves Closed without running its factory, whether or not it was placed.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_placed_after_task_ends<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let saved = context
            .child("task")
            .on(&thread)
            .spawn(|context| async move { context.child("saved") })
            .await
            .unwrap();

        // The handle resolves before the task's completing poll aborts its node. The thread polls
        // its residents one at a time, so once another resident has run, that poll is over.
        context
            .child("barrier")
            .spawn_on(&thread, |_| async {})
            .await
            .unwrap();
        for placed in [false, true] {
            let line = saved.child("late");
            let line = if placed { line.placed() } else { line };
            let ran = Arc::new(AtomicBool::new(false));
            let factory = ran.clone();
            let handle = line.spawn(move |_| {
                factory.store(true, Ordering::SeqCst);
                async {}
            });
            assert!(matches!(handle.await, Err(Error::Closed)));
            assert!(!ran.load(Ordering::SeqCst), "the factory ran");
        }
    });
}

// Placed spawns, spawn_on and spawn_local tasks of one thread run on one OS thread, which is not
// the runner's.
#[rstest]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_residents_share_os_thread<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let root = os();
        let thread = context.child("t").thread().build().unwrap();
        let placed = context
            .child("placed")
            .on(&thread)
            .spawn(|_| async { os() })
            .await
            .unwrap();
        let (on, local) = context
            .child("on")
            .spawn_on(&thread, |local| async move {
                let on = os();
                let local = local
                    .child("local")
                    .spawn_local(|_| async { os() })
                    .await
                    .unwrap();
                (on, local)
            })
            .await
            .unwrap();
        assert_eq!(placed, on);
        assert_eq!(on, local);
        assert_ne!(on, root);

        // The root of a spawned thread shares its own OS thread with its residents.
        let (spawned, local) = context
            .child("spawned")
            .thread()
            .spawn(|local| async move {
                let spawned = os();
                let inner = local
                    .child("local")
                    .spawn_local(|_| async { os() })
                    .await
                    .unwrap();
                (spawned, inner)
            })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(spawned, local);
        assert_ne!(spawned, on);
        assert_ne!(spawned, root);
    });
}

// Placement creates no supervision edge. Aborting a context placed on a thread leaves the
// thread open, and closing a thread aborts only its residents.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_no_supervision_edge<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();

        // Abort a placed task, then a placed lineage with a placed child.
        let task = context
            .child("placed")
            .on(&thread)
            .spawn(|_| pending::<()>());
        task.abort();
        assert!(matches!(task.await, Err(Error::Closed)));
        let (tx, rx) = oneshot::channel();
        let lineage = context
            .child("lineage")
            .on(&thread)
            .spawn(move |context| async move {
                let inner = context.child("inner").spawn(|_| pending::<()>());
                tx.send(inner).ok().unwrap();
                pending::<()>().await;
            });
        let inner = rx.await.unwrap();
        lineage.abort();
        assert!(matches!(lineage.await, Err(Error::Closed)));
        assert!(matches!(inner.await, Err(Error::Closed)));

        // The thread is still open.
        let on = context.child("after").spawn_on(&thread, |_| async { 5 });
        assert_eq!(on.await.unwrap(), 5);
        let placed = context
            .child("after_placed")
            .on(&thread)
            .spawn(|_| async { 6 });
        assert_eq!(placed.await.unwrap(), 6);

        // A thread that closes when its creating task is aborted.
        let (tx, rx) = oneshot::channel();
        let creator = context.child("creator").spawn(move |context| async move {
            tx.send(context.thread().build().unwrap()).ok().unwrap();
            pending::<()>().await;
        });
        let closing = rx.await.unwrap();

        // Tasks that are not residents: a sibling, a task moved off the thread, and a task of a
        // lineage that also spawns a resident.
        let (go_sibling, wait) = oneshot::channel::<u32>();
        let sibling = context
            .child("sibling")
            .spawn(move |_| async move { wait.await.unwrap() });
        let (go_moved, wait) = oneshot::channel::<u32>();
        let moved = context
            .child("moved")
            .on(&closing)
            .shared()
            .spawn(move |_| async move { wait.await.unwrap() });
        let lineage = context.child("resident");
        let (go_kept, wait) = oneshot::channel::<u32>();
        let kept = lineage
            .child("kept")
            .spawn(move |_| async move { wait.await.unwrap() });

        // Residents of the closing thread.
        let resident = lineage.child("on").spawn_on(&closing, |_| pending::<()>());
        let placed = context
            .child("resident_placed")
            .on(&closing)
            .spawn(|_| pending::<()>());

        creator.abort();
        assert!(matches!(
            within(&context, resident).await,
            Err(Error::Closed)
        ));
        assert!(matches!(within(&context, placed).await, Err(Error::Closed)));
        go_sibling.send(1).unwrap();
        go_moved.send(2).unwrap();
        go_kept.send(3).unwrap();
        assert_eq!(sibling.await.unwrap(), 1);
        assert_eq!(moved.await.unwrap(), 2);
        assert_eq!(kept.await.unwrap(), 3);

        // The first thread is unaffected.
        let on = context.child("still").spawn_on(&thread, |_| async { 7 });
        assert_eq!(on.await.unwrap(), 7);
    });
}

// A built thread that nothing uses closes with its lineage, whether it was built from the root
// or from a task, so start returns.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_build_idle_shutdown<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner,
{
    bounded(move || {
        runner.start(|context| async move {
            drop(context.child("root").thread().build().unwrap());
            let task = context.child("task").spawn(|context| async move {
                drop(context.child("inner").thread().build().unwrap());
            });
            task.await.unwrap();
        });
    });
}

// An attached context used only through child keeps its thread open after it is dropped, until
// its lineage is aborted, so start returns.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_attach_lifetime<R: Runner + Send + 'static>(#[case] runner: R)
where
    R::Context: Spawner + Clock + PlacedOn,
{
    bounded(move || {
        runner.start(|context| async move {
            let (tx, rx) = oneshot::channel();
            let lineage = context.child("lineage").spawn(move |context| async move {
                let attached = context.child("t").thread().attach().unwrap();
                let thread = attached.placed_on();
                let probe = attached.child("probe").spawn(|_| pending::<()>());
                drop(attached);
                tx.send((thread, probe)).ok().unwrap();
                pending::<()>().await;
            });
            let (thread, mut probe) = rx.await.unwrap();

            // Dropping the attached context leaves its thread running the probe.
            context.sleep(Duration::from_millis(10)).await;
            assert!(futures::FutureExt::now_or_never(&mut probe).is_none());
            assert!(thread.inner().is_open());

            lineage.abort();
            assert!(matches!(within(&context, probe).await, Err(Error::Closed)));
            closes(&context, &thread).await;
        });
    });
}

// An attached thread closes when the task that consumes the attached context ends. An actor
// derived from that context with child ending first leaves it open.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_attach_closes_with_consumer<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock + PlacedOn,
{
    runner.start(|context| async move {
        let attached = context.child("subsystem").thread().attach().unwrap();
        let thread = attached.placed_on();

        // The thread polls its residents one at a time, so once another resident ran, the
        // completing poll of the actor, which aborts its node, is over.
        attached.child("actor").spawn(|_| async {}).await.unwrap();
        context
            .child("barrier")
            .spawn_on(&thread, |_| async {})
            .await
            .unwrap();
        assert!(thread.inner().is_open());

        // The thread stays open while the consuming task runs, and closes once it ends.
        let (release, released) = oneshot::channel::<()>();
        let main = attached.spawn(|_| async move { released.await.unwrap() });
        context
            .child("barrier")
            .spawn_on(&thread, |_| async {})
            .await
            .unwrap();
        assert!(thread.inner().is_open());
        release.send(()).unwrap();
        main.await.unwrap();
        closes(&context, &thread).await;
        let late = context.child("late").spawn_on(&thread, |_| async {});
        assert!(matches!(late.await, Err(Error::Closed)));
    });
}

// A long-lived task that attaches a thread per epoch leaves no thread open, because each
// epoch's thread closes with the task that consumed its context, whether that task completed
// or was aborted. OS threads do not accumulate either.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_attach_per_epoch<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock + PlacedOn,
{
    /// Epochs the orchestrator runs.
    const EPOCHS: u64 = 16;

    runner.start(|context| async move {
        let orchestrator = context.child("orchestrator").spawn(|context| async move {
            let baseline = os_threads();
            let mut threads = Vec::new();
            for epoch in 0..EPOCHS {
                let engine = context
                    .child("engine")
                    .with_attribute("epoch", epoch)
                    .thread()
                    .attach()
                    .unwrap();
                let thread = engine.placed_on();
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
                closes(&context, &thread).await;
                threads.push(thread);
            }

            // The OS threads of native runners exit once their close completes. The count covers
            // the whole process, so this relies on nextest running each test in its own process.
            if let Some(baseline) = baseline {
                within(&context, async {
                    while os_threads().unwrap() > baseline {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                })
                .await;
            }
            threads
        });
        let threads = orchestrator.await.unwrap();
        assert_eq!(threads.len(), EPOCHS as usize);
        assert!(threads.iter().all(|thread| !thread.inner().is_open()));
    });
}

// A built thread lives as long as the task that built it. Once the task ended, the thread
// closes, later placed spawns resolve Closed without running their factory, and each rejected
// spawn closes its context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_build_lives_with_lineage<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let thread = context
            .child("creator")
            .spawn(|context| async move { context.thread().build().unwrap() })
            .await
            .unwrap();

        // The creating task's node is aborted after it published, so a probe may be admitted
        // first, and the close aborts it.
        let probe = context
            .child("probe")
            .spawn_on(&thread, |_| pending::<()>());
        assert!(matches!(within(&context, probe).await, Err(Error::Closed)));

        // New placed spawns are rejected without running their factory, and the rejection
        // aborts a child wired from the consumed context.
        let placed = context.child("placed").on(&thread);
        let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
        let ran = Arc::new(AtomicBool::new(false));
        let handle = placed.spawn({
            let ran = ran.clone();
            move |_| {
                ran.store(true, Ordering::SeqCst);
                async {}
            }
        });
        assert!(matches!(handle.await, Err(Error::Closed)));
        assert!(!ran.load(Ordering::SeqCst));
        assert!(matches!(within(&context, wired).await, Err(Error::Closed)));
    });
}

// Aborting a root at once closes its thread and resolves Closed, whether or not its factory
// started. On deterministic both calls happen in one poll, so the factory never runs.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), true)]
#[case::tokio(tokio::Runner::default(), false)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), false))]
fn test_thread_root_abort_before_start<R: Runner + Send + 'static>(
    #[case] runner: R,
    #[case] unrun: bool,
) where
    R::Context: Spawner + Clock,
{
    bounded(move || {
        runner.start(|context| async move {
            let ran = Arc::new(AtomicBool::new(false));
            let handle = context
                .child("t")
                .thread()
                .spawn({
                    let ran = ran.clone();
                    move |_| {
                        ran.store(true, Ordering::SeqCst);
                        pending::<()>()
                    }
                })
                .unwrap();
            handle.abort();
            assert!(matches!(within(&context, handle).await, Err(Error::Closed)));
            if unrun {
                assert!(!ran.load(Ordering::SeqCst));
            }
        });
    });
}

// A panic in the root factory or the root poll resolves the root handle with Exited, and the
// thread closes.
#[rstest]
#[case::deterministic(deterministic::Runner::new(
    deterministic::Config::default().with_catch_panics(true)
))]
#[case::tokio(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
#[cfg_attr(
    target_os = "linux",
    case::iouring(iouring::Runner::new(iouring::Config::default().with_catch_panics(true)))
)]
fn test_thread_root_panic<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let (tx, rx) = oneshot::channel();
        let handle = context
            .child("factory")
            .thread()
            .spawn(move |local| -> std::future::Ready<()> {
                tx.send(local.home().clone()).unwrap();
                panic!("root factory");
            })
            .unwrap();
        assert!(matches!(within(&context, handle).await, Err(Error::Exited)));
        let thread = rx.await.unwrap();
        let probe = context
            .child("probe")
            .spawn_on(&thread, |_| pending::<()>());
        assert!(matches!(within(&context, probe).await, Err(Error::Closed)));

        let (tx, rx) = oneshot::channel();
        let handle = context
            .child("poll")
            .thread()
            .spawn(move |local| {
                let home = local.home().clone();
                async move {
                    tx.send(home).unwrap();
                    reschedule().await;
                    panic!("root poll");
                }
            })
            .unwrap();
        assert!(matches!(within(&context, handle).await, Err(Error::Exited)));
        let thread = rx.await.unwrap();
        let probe = context
            .child("probe")
            .spawn_on(&thread, |_| pending::<()>());
        assert!(matches!(within(&context, probe).await, Err(Error::Closed)));
    });
}

// Closing a thread when its creating lineage finishes aborts residents supervised by an
// unrelated lineage, which keeps running.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_close_cancels_foreign_residents<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let (tx, rx) = oneshot::channel();
        let (end, ended) = oneshot::channel::<()>();
        let creator = context.child("creator").spawn(move |context| async move {
            tx.send(context.thread().build().unwrap()).unwrap();
            ended.await.unwrap();
        });
        let thread = rx.await.unwrap();

        // An unrelated lineage places a spawn_on resident, which spawns a local resident, and
        // a placed resident, then waits for both.
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, start) = oneshot::channel();
        let unrelated = context.child("unrelated").spawn({
            let dropped = dropped.clone();
            move |context| async move {
                let on = context.child("on").spawn_on(&thread, move |local| {
                    let flag = DropFlag(dropped);
                    drop(local.child("local").spawn_local(move |_| async move {
                        let _flag = flag;
                        pending::<()>().await;
                    }));
                    started.send(()).unwrap();
                    pending::<()>()
                });
                let placed = context
                    .child("placed")
                    .on(&thread)
                    .spawn(|_| pending::<()>());
                (on.await, placed.await)
            }
        });
        start.await.unwrap();

        // The creating lineage finishes, which closes the thread.
        end.send(()).unwrap();
        creator.await.unwrap();
        let (on, placed) = within(&context, unrelated).await.unwrap();
        assert!(matches!(on, Err(Error::Closed)));
        assert!(matches!(placed, Err(Error::Closed)));

        // Nothing orders the local resident's drop before the other handles resolve, so wait
        // for it.
        within(&context, async {
            while !dropped.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
    });
}

// A spawn_on resident is supervised by the calling context, and so is a resident it spawns
// with spawn_local. Aborting the caller aborts both and leaves the thread open.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_spawn_on_supervised_by_caller<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let (tx, rx) = oneshot::channel();
        let caller = context.child("caller").spawn({
            let thread = thread.clone();
            let dropped = dropped.clone();
            move |context| async move {
                let flag = DropFlag(dropped);
                let resident = context.child("resident").spawn_on(&thread, move |local| {
                    drop(local.child("local").spawn_local(move |_| async move {
                        let _flag = flag;
                        pending::<()>().await;
                    }));
                    pending::<()>()
                });
                tx.send(resident).ok().unwrap();
                pending::<()>().await;
            }
        });
        let resident = rx.await.unwrap();
        caller.abort();
        assert!(matches!(
            within(&context, resident).await,
            Err(Error::Closed)
        ));
        within(&context, async {
            while !dropped.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
        })
        .await;

        // The thread is still open.
        let on = context.child("after").spawn_on(&thread, |_| async { 1 });
        assert_eq!(within(&context, on).await.unwrap(), 1);
    });
}

// Residents share Rc<RefCell<_>> state, and spawn_local works from a factory, from a poll, and
// from a resident's Drop during close, without a BorrowMutError.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_spawn_local_rc_and_reentrancy<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let (tx, rx) = oneshot::channel();
        let creator = context.child("creator").spawn(move |context| async move {
            tx.send(context.thread().build().unwrap()).unwrap();
            pending::<()>().await;
        });
        let thread = rx.await.unwrap();

        // From the factory of spawn_on, from a spawn_local factory, and from a poll.
        let order = context
            .child("shared")
            .spawn_on(&thread, |local| {
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
                    let from_poll = local.child("poll").spawn_local({
                        let shared = shared.clone();
                        move |_| async move { shared.borrow_mut().push(3) }
                    });
                    from_poll.await.unwrap();
                    shared.borrow().clone()
                }
            })
            .await
            .unwrap();
        assert_eq!(order, [1, 2, 3]);

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
        let (closed, ran) = within(&context, outcome).await.unwrap();
        assert!(closed);
        assert!(!ran);
    });
}

// A spawn_local factory runs after the caller's poll, so it can take a borrow the caller holds
// during the call. A spawn_on factory toward the caller's own thread does not run inside the
// caller's poll either.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_spawn_local_deferred<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let (value, same) = context
            .child("caller")
            .spawn_on(&thread, |local| async move {
                let cell = Rc::new(RefCell::new(0));
                let ran = Rc::new(Cell::new(None));
                let handle = {
                    let mut borrow = cell.borrow_mut();
                    let handle = local.child("deferred").spawn_local({
                        let cell = cell.clone();
                        let ran = ran.clone();
                        move |_| {
                            ran.set(Some(os()));
                            *cell.borrow_mut() += 1;
                            async {}
                        }
                    });
                    assert!(ran.get().is_none());
                    *borrow = 41;
                    handle
                };

                // A spawn_on toward this thread waits for a later turn too.
                let remote = Arc::new(AtomicBool::new(false));
                let on = local.child("on").into_inner().spawn_on(local.home(), {
                    let remote = remote.clone();
                    move |_| {
                        remote.store(true, Ordering::SeqCst);
                        async {}
                    }
                });
                assert!(ran.get().is_none());
                assert!(!remote.load(Ordering::SeqCst));

                handle.await.unwrap();
                on.await.unwrap();
                assert!(remote.load(Ordering::SeqCst));
                let value = *cell.borrow();
                (value, ran.get() == Some(os()))
            })
            .await
            .unwrap();
        assert_eq!(value, 42);
        assert!(same);
    });
}

// A LocalHandle delivers a !Send output, resolves Closed once aborted, detaches its task when
// dropped, and an output it never took is dropped on the thread at close. On deterministic a
// later poll of that handle resolves Closed.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_thread_local_handle<R: Runner>(#[case] runner: R, #[case] native: bool)
where
    R::Context: Spawner + Clock,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let (output, aborted, detached) = context
            .child("caller")
            .spawn_on(&thread, |local| async move {
                // A !Send output.
                let output = local
                    .child("output")
                    .spawn_local(|_| async { Rc::new(5) })
                    .await
                    .unwrap();

                // Abort.
                let handle = local.child("abort").spawn_local(|_| pending::<()>());
                handle.abort();
                let aborted = matches!(handle.await, Err(Error::Closed));

                // Drop the handle, then let the task finish.
                let (go, wait) = oneshot::channel::<()>();
                let (done, finished) = oneshot::channel::<()>();
                drop(local.child("detach").spawn_local(move |_| async move {
                    wait.await.unwrap();
                    done.send(()).unwrap();
                }));
                go.send(()).unwrap();
                let detached = finished.await.is_ok();
                (*output, aborted, detached)
            })
            .await
            .unwrap();
        assert_eq!(output, 5);
        assert!(aborted);
        assert!(detached);

        // A thread that closes with a finished output its handle never took.
        let (report, dropped) = oneshot::channel();
        let home = context
            .child("closing")
            .thread()
            .spawn(move |local| async move {
                let (finished, finish) = oneshot::channel::<()>();
                let handle = local.child("output").spawn_local(move |_| async move {
                    finished.send(()).unwrap();
                    Probe {
                        report: Some(report),
                        _local: Rc::new(()),
                    }
                });
                finish.await.unwrap();
                HELD.with(|held| *held.borrow_mut() = Some(handle));
                os()
            })
            .unwrap()
            .await
            .unwrap();
        let dropped = within(&context, dropped).await.unwrap();
        if native {
            assert_eq!(dropped, home);
        } else {
            let handle = HELD.with(|held| held.borrow_mut().take()).unwrap();
            assert!(matches!(handle.await, Err(Error::Closed)));
        }
    });
}

// A runner returns while a Thread is held, by the value start returns and by a clone on another
// OS thread.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_shutdown_with_held_thread<R: Runner + Send + 'static>(#[case] runner: R)
where
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
            let thread = context.child("held").thread().build().unwrap();
            drop(
                context
                    .child("probe")
                    .spawn_on(&thread, |_| pending::<()>()),
            );
            hold.send(thread.clone()).unwrap();
            thread
        })
    });
    assert_eq!(thread.name(), "held");
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
fn test_thread_drop_on_owner_thread<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    let make_probe = |report| Probe {
        report: Some(report),
        _local: Rc::new(()),
    };
    let (shutdown_report, at_shutdown) = oneshot::channel();
    let (shutdown_home, local_at_shutdown) = runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();

        // Completion.
        let (report, dropped) = oneshot::channel();
        let home = context
            .child("complete")
            .spawn_on(&thread, move |_| {
                let probe = make_probe(report);
                async move {
                    let _probe = probe;
                    os()
                }
            })
            .await
            .unwrap();
        assert_eq!(within(&context, dropped).await.unwrap(), home);

        // Abort.
        let (report, dropped) = oneshot::channel();
        let (started, start) = oneshot::channel();
        let handle = context.child("abort").spawn_on(&thread, move |_| {
            let probe = make_probe(report);
            started.send(()).unwrap();
            async move {
                let _probe = probe;
                pending::<()>().await;
            }
        });
        start.await.unwrap();
        handle.abort();
        assert!(matches!(handle.await, Err(Error::Closed)));
        assert_eq!(within(&context, dropped).await.unwrap(), home);

        // Poll panic.
        let (report, dropped) = oneshot::channel();
        let handle = context.child("panic").spawn_on(&thread, move |_| {
            let probe = make_probe(report);
            async move {
                let _probe = probe;
                reschedule().await;
                panic!("resident poll");
            }
        });
        assert!(matches!(handle.await, Err(Error::Exited)));
        assert_eq!(within(&context, dropped).await.unwrap(), home);

        // Close, for a spawn_on future and a spawn_local future.
        let (tx, rx) = oneshot::channel();
        let creator = context.child("creator").spawn(move |context| async move {
            tx.send(context.thread().build().unwrap()).unwrap();
            pending::<()>().await;
        });
        let closing = rx.await.unwrap();
        let (report, dropped) = oneshot::channel();
        let (report_local, dropped_local) = oneshot::channel();
        let (started, start) = oneshot::channel();
        drop(context.child("close").spawn_on(&closing, move |local| {
            let probe = make_probe(report);
            let probe_local = make_probe(report_local);
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
        let closing_home = start.await.unwrap();
        creator.abort();
        assert_eq!(within(&context, dropped).await.unwrap(), closing_home);
        assert_eq!(within(&context, dropped_local).await.unwrap(), closing_home);

        // Shutdown, for a spawn_on future and a spawn_local future, checked after start
        // returns.
        let (report_local, dropped_local) = oneshot::channel();
        let (started, start) = oneshot::channel();
        drop(context.child("shutdown").spawn_on(&thread, move |local| {
            let probe = make_probe(shutdown_report);
            let probe_local = make_probe(report_local);
            drop(local.child("local").spawn_local(move |_| async move {
                let _probe = probe_local;
                pending::<()>().await;
            }));
            started.send(()).unwrap();
            async move {
                let _probe = probe;
                pending::<()>().await;
            }
        }));
        start.await.unwrap();
        (home, dropped_local)
    });
    let mut at_shutdown = at_shutdown;
    let mut local_at_shutdown = local_at_shutdown;
    assert_eq!(at_shutdown.try_recv().unwrap(), shutdown_home);
    assert_eq!(local_at_shutdown.try_recv().unwrap(), shutdown_home);
}

// A placed spawn and a spawn_on toward an open thread of another runner, of the same or another
// backend, resolve Closed without running the factory, and close the consumed context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_wrong_runtime<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    wrong_runtime(
        runner,
        vec![
            hold_open(deterministic::Runner::default()),
            hold_open(tokio::Runner::default()),
        ],
    );
}

// The same toward an open thread of an io_uring runner, in a test whose every case needs io_uring.
#[cfg(target_os = "linux")]
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[case::iouring(iouring::Runner::default())]
fn test_thread_wrong_runtime_iouring_target<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock,
{
    wrong_runtime(runner, vec![hold_open(iouring::Runner::default())]);
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
                assert_eq!(residents(context, "gauge"), (1, Some(1)));

                // Queued jobs count at once, including ones aborted before they run.
                let running: Vec<_> = (0..3)
                    .map(|_| {
                        context
                            .child("running")
                            .spawn_on(local.home(), |_| pending::<()>())
                    })
                    .collect();
                let skipped: Vec<_> = (0..2)
                    .map(|_| {
                        context
                            .child("skipped")
                            .spawn_on(local.home(), |_| pending::<()>())
                    })
                    .collect();
                assert_eq!(residents(context, "gauge"), (1, Some(6)));
                for handle in &skipped {
                    handle.abort();
                }

                // Dropped tickets of skipped jobs decrement it.
                for handle in skipped {
                    assert!(matches!(handle.await, Err(Error::Closed)));
                }
                settle(context, "gauge", 4).await;

                // A finished output waiting in its slot does not count.
                let (finished, finish) = oneshot::channel::<()>();
                let output = local.child("output").spawn_local(move |_| async move {
                    finished.send(()).unwrap();
                    Rc::new(1)
                });
                finish.await.unwrap();
                settle(context, "gauge", 4).await;
                assert_eq!(*output.await.unwrap(), 1);

                for handle in &running {
                    handle.abort();
                }
                for handle in running {
                    assert!(matches!(handle.await, Err(Error::Closed)));
                }
                settle(context, "gauge", 1).await;
            })
            .await
            .unwrap();
        settle(&context, "gauge", 0).await;

        // Two threads with one label share one series.
        let first = context.child("same").thread().build().unwrap();
        let second = context.child("same").thread().build().unwrap();
        assert_ne!(first, second);
        let a = context.child("a").spawn_on(&first, |_| pending::<()>());
        let b = context.child("b").spawn_on(&second, |_| pending::<()>());
        settle(&context, "same", 2).await;
        assert_eq!(residents(&context, "same").0, 1);
        a.abort();
        b.abort();
        settle(&context, "same", 0).await;
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
    R::Context: Spawner + Clock,
{
    // Another runner, alive on its own OS thread until its context was consumed.
    let (send, foreign) = mpsc::channel();
    let done = Arc::new(AtomicBool::new(false));
    let other = std::thread::spawn({
        let done = done.clone();
        move || {
            other.start(|context| async move {
                send.send(context.child("foreign")).unwrap();
                while !done.load(Ordering::SeqCst) {
                    reschedule().await;
                }
            });
        }
    });

    runner.start(|context| async move {
        let a = context.child("a").thread().build().unwrap();
        let b = context.child("b").thread().build().unwrap();

        // A context of thread b, from a resident that outlives its use.
        let (send, from_b) = oneshot::channel();
        let (release, released) = oneshot::channel::<()>();
        let holder = context.child("holder").spawn_on(&b, move |local| {
            send.send(local.child("from_b").into_inner()).ok().unwrap();
            async move { released.await.unwrap() }
        });
        let from_b = from_b.await.unwrap();

        let swapped = context
            .child("swap")
            .spawn_on(&a, move |local| async move {
                let home = os();

                // A context of another thread.
                let mut swapped = local.child("other_thread");
                *swapped = from_b;
                let (ran, same) = swapped
                    .spawn_local(|local| async move { (os(), local.home().name().to_string()) })
                    .await
                    .unwrap();
                assert_eq!(same, "a");
                assert!(!native || ran == home);

                // A shared context.
                let mut swapped = local.child("shared");
                *swapped = (*local).child("plain").shared();
                let (ran, same) = swapped
                    .spawn_local(|local| async move { (os(), local.home().name().to_string()) })
                    .await
                    .unwrap();
                assert_eq!(same, "a");
                assert!(!native || ran == home);

                // A context of another runner.
                let foreign = loop {
                    if let Ok(foreign) = foreign.try_recv() {
                        break foreign;
                    }
                    reschedule().await;
                };
                let mut stale = local.child("stale");
                *stale = foreign;
                let dropped = Arc::new(AtomicBool::new(false));
                let ran = Rc::new(Cell::new(false));
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
                done.store(true, Ordering::SeqCst);
                matches!(handle.await, Err(Error::Closed))
            })
            .await
            .unwrap();
        assert!(swapped);
        release.send(()).unwrap();
        holder.await.unwrap();
    });
    other.join().unwrap();
}

// A placed ordinary spawn runs its factory on the caller, synchronously, and its future on the
// thread. A panic in that factory unwinds out of spawn and closes the consumed context's node.
#[rstest]
#[case::deterministic(deterministic::Runner::default(), false)]
#[case::tokio(tokio::Runner::default(), true)]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default(), true))]
fn test_thread_placed_spawn_factory<R: Runner>(#[case] runner: R, #[case] native: bool)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        let thread = context.child("t").thread().build().unwrap();
        let home = context
            .child("home")
            .spawn_on(&thread, |_| async { os() })
            .await
            .unwrap();
        let caller = os();
        let factory = Arc::new(commonware_utils::sync::Mutex::new(None));
        let handle = context.child("placed").on(&thread).spawn({
            let factory = factory.clone();
            move |_| {
                *factory.lock() = Some(os());
                async { os() }
            }
        });
        assert_eq!(factory.lock().take(), Some(caller));
        let ran = handle.await.unwrap();
        assert_eq!(executions(&context, "placed"), ["Thread"]);
        if native {
            assert_eq!(ran, home);
            assert_ne!(caller, home);
        }

        let placed = context.child("panics").on(&thread);
        let wired = placed.child("wired").shared().spawn(|_| pending::<()>());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            placed.spawn(|_| -> std::future::Ready<()> { panic!("placed factory") })
        }));
        assert!(result.is_err());
        assert!(matches!(within(&context, wired).await, Err(Error::Closed)));
    });
}

// The factory of an ordinary spawn runs on the caller before spawn returns, wherever the future
// runs, so it may borrow the caller's !Send state to build a Send future.
#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_spawn_factory_reads_local_state<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner,
{
    runner.start(|context| async move {
        let total = context
            .child("t")
            .thread()
            .spawn(|local| async move {
                let state = Rc::new(RefCell::new(Vec::new()));
                let read = |id: usize| {
                    let state = &state;
                    move |_| {
                        state.borrow_mut().push(id);
                        let value = state.borrow().len();
                        async move { value }
                    }
                };
                let context = local.into_inner();
                let handles = [
                    context.child("shared").spawn(read(1)),
                    context.child("placed").placed().spawn(read(2)),
                    context.child("blocking").blocking().spawn(read(3)),
                ];
                assert_eq!(*state.borrow(), [1, 2, 3]);
                let mut total = 0;
                for handle in handles {
                    total += handle.await.unwrap();
                }
                total
            })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(total, 6);
    });
}
