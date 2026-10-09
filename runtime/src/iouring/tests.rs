//! Runtime configuration, task placement, worker reservations, pool, and cleanup tests.

use super::{
    super::{
        driver::tests::fail_after_completion,
        operation::Operation,
        request::{RecvRequest, Request},
        task::{Task, tests::cancelled},
        tasks::tests::AFTER_INSERT,
        waker::tests::state_bits,
    },
    *,
};
use crate::{
    Blob as _, IoBufMut, Listener as _, Metrics as _, Network as _, ReadOptions, Resolver as _,
    Runner as _, Sink as _, Storage as _, Stream as _, WriteOptions,
    utils::{extract_panic_message, reschedule},
};
use futures::{
    FutureExt,
    executor::block_on,
    future::{pending, poll_fn},
    task::{ArcWake, waker},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    fs::{self, File},
    future::{Pending, Ready},
    io::{self, Write as _},
    os::{fd::OwnedFd, unix::net::UnixStream},
    panic::panic_any,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    task::Wake,
    thread::{self, ThreadId},
};

/// Bound individual synchronous channel waits within the test process.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

thread_local! {
    /// Whether the current test root requires progress without entering the idle path.
    static FORBID_PARK: Cell<bool> = const { Cell::new(false) };
    /// Pool worker whose startup fails, and whether its thread launch fails instead.
    static POOL_FAIL_AT: Cell<Option<(usize, bool)>> = const { Cell::new(None) };
    /// Shared services of the runner whose pool last started, to observe their release.
    static POOL_SHARED: RefCell<Weak<Shared>> = const { RefCell::new(Weak::new()) };
}

/// Fail pool worker `index`'s startup after the workers before it have started.
pub fn before_pool_worker(shared: &Arc<Shared>, index: usize) -> Option<impl Drop> {
    let (fail_at, launch) = POOL_FAIL_AT.get()?;
    POOL_SHARED.with(|slot| *slot.borrow_mut() = Arc::downgrade(shared));
    if index != fail_at {
        return None;
    }
    POOL_FAIL_AT.set(None);
    assert!(!launch, "injected pool thread launch failure");
    Some(inject_worker_fault(&shared.workers, WorkerFault::Startup))
}

/// Clear the current thread's parking assertion when its test root finishes or unwinds.
struct ParkGuard;

impl Drop for ParkGuard {
    fn drop(&mut self) {
        FORBID_PARK.set(false);
    }
}

/// One event intercepted within a selected runner's worker lifecycle.
enum WorkerFault {
    /// Reject thread creation after taking ownership of its launch payload.
    Launch,
    /// Fail ring initialization on the newly created worker thread.
    Startup,
    /// Pause a worker after it releases its registration.
    AfterRelease(Box<dyn FnOnce() + Send>),
}

/// Fault state shared between a test and its one-off worker threads.
struct WorkerFaultEntry {
    /// Worker registry identity without retaining the runtime's shared services.
    workers: Weak<Workers>,
    /// Event consumed once, leaving the registration until its guard drops.
    fault: Option<WorkerFault>,
}

/// Scoped injections indexed by registry so parallel runners cannot share faults.
static WORKER_FAULTS: Mutex<Vec<WorkerFaultEntry>> = Mutex::new(Vec::new());

/// Remove a runner's injection on scope exit, including if it was never consumed.
struct WorkerFaultGuard(Weak<Workers>);

impl Drop for WorkerFaultGuard {
    fn drop(&mut self) {
        let entry = {
            let mut faults = WORKER_FAULTS.lock();
            let index = faults
                .iter()
                .position(|entry| entry.workers.ptr_eq(&self.0))
                .expect("worker fault registration missing");
            faults.swap_remove(index)
        };

        // An unused callback can own arbitrary captures. Drop it after unlocking.
        drop(entry);
    }
}

/// Install a single lifecycle injection until the returned guard is dropped.
fn inject_worker_fault(registry: &Arc<Workers>, fault: WorkerFault) -> WorkerFaultGuard {
    let registry = Arc::downgrade(registry);
    let mut faults = WORKER_FAULTS.lock();
    assert!(
        !faults.iter().any(|entry| entry.workers.ptr_eq(&registry)),
        "worker fault already installed"
    );
    faults.push(WorkerFaultEntry {
        workers: registry.clone(),
        fault: Some(fault),
    });
    WorkerFaultGuard(registry)
}

/// Detach the selected event so it can run without holding the injection lock.
fn take_worker_fault(
    registry: &Arc<Workers>,
    matches: impl FnOnce(&WorkerFault) -> bool,
) -> Option<WorkerFault> {
    let mut faults = WORKER_FAULTS.lock();
    let entry = faults
        .iter_mut()
        .find(|entry| ptr::eq(entry.workers.as_ptr(), Arc::as_ptr(registry)))?;

    if entry.fault.as_ref().is_some_and(matches) {
        entry.fault.take()
    } else {
        None
    }
}

/// Model a rejected thread destroying its payload before reporting launch failure.
pub(super) fn before_launch(payload: Launch) -> Launch {
    if take_worker_fault(&payload.active.0, |fault| {
        matches!(fault, WorkerFault::Launch)
    })
    .is_some()
    {
        // Dispose before raising the injected panic so a destructor can itself
        // panic without causing a second panic during unwinding.
        drop(payload);
        panic!("failed to spawn thread: injected worker launch failure");
    }

    payload
}

/// Reject native initialization on the selected worker before creating its ring.
pub(super) fn before_startup(registry: &Arc<Workers>) -> io::Result<()> {
    if take_worker_fault(registry, |fault| matches!(fault, WorkerFault::Startup)).is_some() {
        return Err(io::Error::other(
            "injected native worker initialization failure",
        ));
    }

    Ok(())
}

/// Run a one-shot callback after the worker count and its lock have been released.
pub(super) fn after_release(registry: &Arc<Workers>) {
    if let Some(WorkerFault::AfterRelease(callback)) = take_worker_fault(registry, |fault| {
        matches!(fault, WorkerFault::AfterRelease(_))
    }) {
        callback();
    }
}

/// Count destruction of captures and futures across worker boundaries.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Panic payload that can raise one further panic during destruction.
struct PanicPayload {
    /// Number of payloads destroyed, including an incorrectly dropped secondary payload.
    drops: Arc<AtomicUsize>,
    /// Whether destruction should panic with a non-panicking replacement payload.
    panics: bool,
}

impl Drop for PanicPayload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        if self.panics {
            panic_any(Self {
                drops: self.drops.clone(),
                panics: false,
            });
        }
    }
}

/// Rejected future whose destructor checks that worker tracking still covers it.
struct RejectedPayload {
    /// Worker registry kept unlocked with one active worker during disposal.
    workers: Arc<Workers>,
    /// Number of times the rejected future was destroyed.
    drops: Arc<AtomicUsize>,
    /// Whether disposal also raises a failure for containment to handle.
    panic_on_drop: bool,
}

impl Future for RejectedPayload {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
        panic!("rejected payload must never be polled");
    }
}

impl Drop for RejectedPayload {
    fn drop(&mut self) {
        // Taking the lock also checks that launch released it before disposal.
        assert_eq!(self.workers.state.lock().active, 1);
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_on_drop, "rejected payload destructor failed");
    }
}

/// One worker with idle spinning disabled, so tests that set no worker count
/// place tasks deterministically and exercise the parking paths.
fn config() -> Config {
    Config::new()
        .with_worker_threads(1)
        .with_idle_spinner(SpinnerConfig::disabled())
}

/// Select a placement while preserving the unmodified default as a separate case.
fn placed(context: Context, mode: Option<Execution>) -> Context {
    match mode {
        None => context,
        Some(Execution::Dedicated) => context.dedicated(),
        Some(Execution::Shared(blocking)) => context.shared(blocking),
    }
}

/// Reject parking while the calling thread's test root is waiting for local progress.
fn forbid_park() -> ParkGuard {
    assert!(
        !FORBID_PARK.replace(true),
        "parking assertion already installed"
    );
    ParkGuard
}

/// Fail at the idle boundary if this test root still requires runnable work.
pub fn before_park() {
    assert!(!FORBID_PARK.get(), "callback work reached the idle path");
}

/// A point in a pool worker's park sequence where a test hook runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParkPoint {
    /// After the worker's last readiness check, before it publishes itself
    /// idle.
    BeforeIdle,
    /// After the worker publishes itself idle and finds the inject queue
    /// empty, before it waits.
    BeforeWait,
}

/// A callback for one pool worker's next park, keyed by the pool's address,
/// the worker's index, and the point.
type ParkHook = (usize, u32, ParkPoint, Box<dyn FnOnce() + Send>);

/// Whether a park hook was ever installed, so parks otherwise skip the lock.
static PARK_HOOKS_ARMED: AtomicBool = AtomicBool::new(false);

/// Callbacks each run once by one pool worker at one point of its park.
static PARK_HOOKS: Mutex<Vec<ParkHook>> = Mutex::new(Vec::new());

/// Run `hook` on worker `index` of `pool` when it next reaches `point`.
fn on_next_park(pool: &Table, index: u32, point: ParkPoint, hook: impl FnOnce() + Send + 'static) {
    PARK_HOOKS
        .lock()
        .push((ptr::from_ref(pool).addr(), index, point, Box::new(hook)));
    PARK_HOOKS_ARMED.store(true, Ordering::Release);
}

/// Run the hook installed for this worker at this point of its park, if any.
pub fn at_park(pool: &Table, index: u32, point: ParkPoint) {
    if !PARK_HOOKS_ARMED.load(Ordering::Acquire) {
        return;
    }
    let key = ptr::from_ref(pool).addr();
    let hook = {
        let mut hooks = PARK_HOOKS.lock();
        hooks
            .iter()
            .position(|hook| hook.0 == key && hook.1 == index && hook.2 == point)
            .map(|at| hooks.swap_remove(at).3)
    };
    if let Some(hook) = hook {
        hook();
    }
}

thread_local! {
    /// Callback run once by this thread's runner after the pool has closed and
    /// before the supervision tree is aborted.
    static BEFORE_ABORT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

/// Run the callback a test installed for the window before the abort.
pub fn before_abort() {
    if let Some(callback) = BEFORE_ABORT.with(RefCell::take) {
        callback();
    }
}

/// Count destruction before injecting a task-disposal panic.
struct PanickingDrop(Arc<AtomicUsize>);

impl Drop for PanickingDrop {
    fn drop(&mut self) {
        // Count only after checking the borrow. Otherwise contain could
        // swallow a borrow panic and make the disposal test pass anyway.
        if let Some(local) = Local::current() {
            let _borrow = local.borrow_mut();
        }
        self.0.fetch_add(1, Ordering::Relaxed);
        panic!("task disposal panic");
    }
}

#[test]
fn test_config_validation_before_startup() {
    let mut rounded = config().with_ring_config(RingConfig {
        size: 3,
        ..RingConfig::default()
    });
    rounded.validate();
    assert_eq!(rounded.ring_config.size, 4);

    // Rounding must not admit zero or exceed the configured ring-size limit.
    for size in [0, 32_769, u32::MAX] {
        let mut invalid = config().with_ring_config(RingConfig {
            size,
            ..RingConfig::default()
        });

        assert!(catch_unwind(AssertUnwindSafe(|| invalid.validate())).is_err());
    }

    // Check both timeout settings at the unsupported ends of the range.
    for timeout in [
        Duration::ZERO,
        TimeoutWheel::MAX_TIMEOUT + Duration::from_nanos(1),
    ] {
        for mut invalid in [
            config().with_connect_timeout(timeout),
            config().with_read_write_timeout(timeout),
        ] {
            assert!(catch_unwind(AssertUnwindSafe(|| invalid.validate())).is_err());
        }
    }

    let invalid_layouts = [Duration::ZERO, Duration::from_nanos(1), Duration::MAX].map(|tick| {
        config().with_ring_config(RingConfig {
            timeout_wheel_tick: tick,
            ..RingConfig::default()
        })
    });
    let invalid_spinner = config().with_idle_spinner(SpinnerConfig {
        budget_us: 2,
        max_budget_us: 1,
        ..SpinnerConfig::default()
    });
    let invalid_workers = [0, MAX_WORKERS + 1].map(|workers| config().with_worker_threads(workers));
    let invalid_interval = config().with_global_queue_interval(0);

    for invalid in invalid_layouts
        .into_iter()
        .chain([invalid_spinner, invalid_interval])
        .chain(invalid_workers)
    {
        let directory = invalid.storage_directory().clone();
        let called = AtomicBool::new(false);

        assert!(!directory.exists());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                Runner::new(invalid).start(|_| {
                    called.store(true, Ordering::SeqCst);
                    async {}
                });
            }))
            .is_err()
        );

        // Invalid settings must fail before acquiring storage resources or
        // invoking user code, including layouts whose slot arithmetic overflows.
        assert!(!called.load(Ordering::SeqCst));
        assert!(!directory.exists());
    }

    // The maximum supported timeout remains valid with a representable wheel.
    let mut boundary = config()
        .with_connect_timeout(TimeoutWheel::MAX_TIMEOUT)
        .with_read_write_timeout(TimeoutWheel::MAX_TIMEOUT)
        .with_ring_config(RingConfig {
            timeout_wheel_tick: Duration::from_secs(3600),
            ..RingConfig::default()
        });
    boundary.validate();
}

#[test]
fn test_nested_same_directory_rejected_before_closure_and_outer_remains_usable() {
    let config = config();
    let directory = config.storage_directory().clone();
    Runner::new(config).start(|context| async move {
        let called = Arc::new(AtomicBool::new(false));
        let nested_called = called.clone();
        let rejected = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(Config::new().with_storage_directory(directory)).start(move |_| {
                nested_called.store(true, Ordering::SeqCst);
                async {}
            });
        }));

        assert!(rejected.is_err());
        assert!(!called.load(Ordering::SeqCst));

        // Rejection must leave the outer worker and its storage ownership intact.
        assert_eq!(
            context
                .child("after_rejection")
                .spawn(|_| async { 7 })
                .await
                .unwrap(),
            7
        );
        context.sleep(Duration::from_millis(1)).await;
    });

    assert!(Local::current().is_none());
}

#[test]
fn test_resolver_handles_numeric_hosts_and_invalid_input() {
    let escaped = Runner::new(config()).start(|context| async move {
        // Numeric hosts and embedded NUL avoid external DNS dependencies
        // while covering address families and the resolver error mapping.
        for host in ["127.0.0.1", "::1"] {
            assert_eq!(
                context.resolve(host).await.unwrap(),
                vec![host.parse::<IpAddr>().unwrap()]
            );
        }

        assert!(matches!(
            context.resolve("\0").await,
            Err(Error::ResolveFailed(_))
        ));
        context
    });

    assert!(matches!(
        block_on(escaped.resolve("127.0.0.1")),
        Err(Error::ResolveFailed(_))
    ));
}

#[test]
fn test_root_borrows_non_send_state_across_pending_poll() {
    let state = Rc::new(Cell::new(0));
    let text = String::from("borrowed root output");
    let origin = thread::current().id();

    let output = Runner::new(config()).start(|context| {
        let state = &state;
        let text = &text;

        async move {
            // Holding an Rc reference across suspension exercises both the
            // borrowed root lifetime and its lack of a Send requirement.
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(thread::current().id(), origin);
            state.set(state.get() + 1);
            text.as_str()
        }
    });

    assert_eq!(output, "borrowed root output");
    assert_eq!(state.get(), 1);
}

#[test]
fn test_root_self_wake_survives_pending_poll() {
    Runner::new(config()).start(|_| async move {
        let mut polls = 0;

        // Every pending poll relies on its own wake to be polled again.
        poll_fn(|cx| {
            polls += 1;
            if polls == 1000 {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;

        assert_eq!(polls, 1000);
    });
}

#[test]
fn test_root_constructor_panic_drops_unpolled_tasks_and_clears_scope() {
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = DropCount(drops.clone());

    // Register a child during construction, then fail before either future polls.
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config()).start(move |context| -> Pending<()> {
            context.child("never_polled").spawn(move |_| async move {
                let _payload = payload;
                pending::<()>().await;
            });

            panic!("root constructor failed");
        });
    }));

    assert!(result.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(Local::current().is_none());
    assert_eq!(Runner::new(config()).start(|_| async { 9 }), 9);
}

#[test]
fn test_root_poll_or_drop_panic_clears_scope() {
    /// Fail during polling or disposal, with exactly one panic in either case.
    struct FailingRoot {
        /// Choose polling failure instead of destruction failure.
        fail_poll: bool,
        /// Count root destruction even when its poll panics.
        drops: Arc<AtomicUsize>,
    }

    impl Future for FailingRoot {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
            assert!(!self.fail_poll, "primary root poll failure");
            Poll::Ready(())
        }
    }

    impl Drop for FailingRoot {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            assert!(self.fail_poll, "root destruction failure");
        }
    }

    for fail_poll in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(|_| FailingRoot {
                fail_poll,
                drops: drops.clone(),
            });
        }));

        let panic = result.expect_err("root execution must fail the runner");
        assert_eq!(
            extract_panic_message(&*panic),
            if fail_poll {
                "primary root poll failure"
            } else {
                "root destruction failure"
            }
        );
        assert!(Local::current().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn test_root_destruction_can_spawn_work_before_shutdown() {
    /// Ready root that publishes a task while its destructor still owns a context.
    struct Root {
        /// Context consumed by the destructor to register the child.
        context: Option<Context>,
        /// Whether spawning invoked the child's factory.
        invoked: Arc<AtomicBool>,
        /// Number of child captures disposed of before the runner returns.
        drops: Arc<AtomicUsize>,
    }

    impl Future for Root {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
            Poll::Ready(())
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let invoked = self.invoked.clone();
            let payload = DropCount(self.drops.clone());
            self.context.take().unwrap().spawn(move |_| {
                invoked.store(true, Ordering::SeqCst);
                async move {
                    let _payload = payload;
                    pending::<()>().await;
                }
            });
        }
    }

    for dedicated in [false, true] {
        let invoked = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));

        Runner::new(config()).start(|context| {
            let context = context.child("root_drop");
            Root {
                context: Some(if dedicated {
                    context.dedicated()
                } else {
                    context
                }),
                invoked: invoked.clone(),
                drops: drops.clone(),
            }
        });

        // The root can still spawn during disposal. Shutdown must drain its child.
        assert!(invoked.load(Ordering::SeqCst));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(Local::current().is_none());
    }
}

#[test]
fn test_failure_queued_before_root_poll_interrupts_root() {
    // Publish during construction so the interrupt wrapper sees the failure
    // before the user's root future is polled.
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config()).start(|context| {
            context
                .shared
                .panicker
                .notify(Box::new("queued worker panic"));

            async { panic!("interrupted root must not be polled") }
        });
    }));

    assert_eq!(
        extract_panic_message(&*result.expect_err("queued failure must interrupt the root")),
        "queued worker panic"
    );
}

#[test]
fn test_execution_modes_share_ordinary_descendants() {
    let ordinary = thread::current().id();
    Runner::new(config()).start(|context| async move {
        for mode in [
            None,
            Some(Execution::Shared(false)),
            Some(Execution::Dedicated),
            Some(Execution::Shared(true)),
        ] {
            let child = placed(context.child("mode"), mode);
            let parent = child
                .spawn(move |context| async move {
                    let parent = thread::current().id();

                    // Ordinary children run on the pool, here its only worker,
                    // even when their parent owns a dedicated or blocking worker.
                    for explicit in [false, true] {
                        let child = context.child("ordinary_child");
                        let child = if explicit { child.shared(false) } else { child };
                        assert_eq!(
                            child
                                .spawn(|_| async { thread::current().id() })
                                .await
                                .unwrap(),
                            ordinary
                        );
                    }

                    // Nested one-off tasks each receive a separate worker.
                    for blocking in [false, true] {
                        let nested = context.child("one_off");
                        let nested = if blocking {
                            nested.shared(true)
                        } else {
                            nested.dedicated()
                        };
                        nested
                            .spawn(move |context| async move {
                                assert_ne!(thread::current().id(), ordinary);
                                assert_ne!(thread::current().id(), parent);
                                assert_eq!(
                                    context
                                        .child("ordinary")
                                        .spawn(|_| async { thread::current().id() })
                                        .await
                                        .unwrap(),
                                    ordinary
                                );
                            })
                            .await
                            .unwrap();
                    }

                    parent
                })
                .await
                .unwrap();

            assert_eq!(
                parent == ordinary,
                matches!(mode, None | Some(Execution::Shared(false)))
            );
        }
    });
}

#[test]
fn test_factories_execute_synchronously_on_the_caller() {
    let modes = [
        None,
        Some(Execution::Shared(false)),
        Some(Execution::Dedicated),
        Some(Execution::Shared(true)),
    ];

    for catch in [false, true] {
        Runner::new(config().with_catch_panics(catch)).start(|context| async move {
            for parent_mode in modes {
                placed(context.child("parent"), parent_mode)
                    .spawn(move |context| async move {
                        let caller = thread::current().id();

                        for mode in modes {
                            let invoked = Arc::new(AtomicBool::new(false));
                            let observed = invoked.clone();

                            // Construction must finish on the caller before spawn
                            // returns, independent of the future's placement.
                            let handle = placed(context.child("factory"), mode).spawn(move |_| {
                                assert_eq!(thread::current().id(), caller);
                                invoked.store(true, Ordering::SeqCst);
                                async {}
                            });

                            assert!(observed.load(Ordering::SeqCst));
                            handle.await.unwrap();

                            // Constructor panics also belong to the caller, which
                            // must remain usable after catching the failure.
                            let result = catch_unwind(AssertUnwindSafe(|| {
                                placed(context.child("panic"), mode).spawn(|_| -> Ready<()> {
                                    panic!("task constructor failed");
                                })
                            }));

                            assert!(result.is_err());
                            assert_eq!(
                                context
                                    .child("sibling")
                                    .spawn(|_| async { 7 })
                                    .await
                                    .unwrap(),
                                7
                            );
                        }
                    })
                    .await
                    .unwrap();
            }
        });
    }
}

#[test]
fn test_blocking_parents_can_wait_for_ordinary_descendants() {
    let ordinary = thread::current().id();
    Runner::new(config()).start(|context| async move {
        for blocking in [false, true] {
            let parent = context.child("parent");
            let parent = if blocking {
                parent.shared(true)
            } else {
                parent.dedicated()
            };
            parent
                .spawn(move |context| async move {
                    assert_ne!(thread::current().id(), ordinary);
                    for explicit in [false, true] {
                        let (sender, receiver) = mpsc::channel();
                        let child = context.child("child");
                        let child = if explicit { child.shared(false) } else { child };
                        child.spawn(move |_| async move {
                            sender.send(thread::current().id()).unwrap();
                        });

                        // The root awaits this parent asynchronously, leaving the ordinary
                        // worker available while this dedicated thread blocks.
                        assert_eq!(receiver.recv_timeout(TEST_TIMEOUT).unwrap(), ordinary);
                    }
                })
                .await
                .unwrap();
        }
    });
}

#[test]
fn test_foreign_context_can_spawn_await_and_abort_ordinary_work() {
    let ordinary = thread::current().id();
    Runner::new(config()).start(|context| async move {
        let remote = context.child("foreign");
        let (finished, completion) = oneshot::channel();
        let foreign = thread::spawn(move || {
            let executed = block_on(
                remote
                    .child("owned")
                    .spawn(|_| async { thread::current().id() }),
            )
            .unwrap();
            assert_eq!(executed, ordinary);

            let aborted = remote.child("aborted").spawn(|_| pending::<()>());
            aborted.abort();
            assert!(block_on(aborted).is_err());

            finished.send(()).unwrap();
        });

        // Keep the root polling while the foreign thread blocks on its handles.
        completion.await.unwrap();
        foreign.join().unwrap();
    });
}

#[test]
fn test_aborted_context_skips_factories_for_every_placement() {
    Runner::new(config()).start(|context| async move {
        context.tree.abort();

        for execution in [
            Execution::Shared(false),
            Execution::Dedicated,
            Execution::Shared(true),
        ] {
            let mut rejected = context.child("rejected");
            rejected.execution = execution;
            let handle = rejected.spawn(|_| -> Ready<()> {
                panic!("an aborted context must not invoke its factory");
            });

            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }

        assert_eq!(context.shared.workers.state.lock().active, 0);
    });
}

#[test]
fn test_closed_task_set_skips_local_and_foreign_factories() {
    for foreign in [false, true] {
        Runner::new(config()).start(|context| async move {
            // Close only the set, leaving the worker and the inject queue open,
            // so the refusal comes from the spawn's check of the set.
            context.shared.tasks.close();

            // Spawn from the worker's thread and from another thread.
            let spawn = move || {
                context.spawn(|_| -> Ready<()> {
                    panic!("a closed task set must not invoke its factory");
                })
            };
            let handle = if foreign {
                thread::spawn(spawn).join().unwrap()
            } else {
                spawn()
            };

            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        });
    }
}

#[test]
fn test_closed_registry_skips_one_off_factories() {
    Runner::new(config()).start(|context| async move {
        // Leave supervision open so rejection must come from worker registration.
        context.shared.workers.close();

        for execution in [Execution::Dedicated, Execution::Shared(true)] {
            let mut rejected = context.child("rejected");
            rejected.execution = execution;
            let handle = rejected.spawn(|_| -> Ready<()> {
                panic!("a closed registry must not invoke its factory");
            });

            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }

        assert_eq!(context.shared.workers.state.lock().active, 0);
    });
}

#[test]
fn test_closed_runner_rejects_one_off_payload_without_invoking_closure() {
    let escaped = Runner::new(config()).start(|context| async { context });
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = DropCount(drops.clone());

    let handle = escaped
        .child("closed")
        .shared(true)
        .spawn(move |_| -> Ready<()> {
            let _payload = payload;
            panic!("closed worker invoked user closure");
        });

    assert!(matches!(block_on(handle), Err(Error::Closed)));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn test_reservation_before_close_remains_counted_until_release() {
    let registry = Arc::new(Workers::default());
    let worker_registry = registry.clone();
    let (reserved, reservation) = mpsc::channel();
    let (release, released) = mpsc::channel();

    let worker = thread::spawn(move || {
        let active = worker_registry.reserve().unwrap();
        reserved.send(()).unwrap();
        released.recv_timeout(TEST_TIMEOUT).unwrap();
        drop(active);
    });

    // Close only after the worker owns a lease. Closure rejects new reservations
    // while retaining responsibility for this worker.
    reservation.recv_timeout(TEST_TIMEOUT).unwrap();
    registry.close();
    assert_eq!(registry.state.lock().active, 1);
    assert!(registry.reserve().is_none());

    let waiting_registry = registry.clone();
    let (finished, completion) = mpsc::channel();
    let waiter = thread::spawn(move || {
        waiting_registry.wait();
        finished.send(()).unwrap();
    });

    assert!(matches!(
        completion.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    // Releasing the last lease permits the registry wait to finish.
    release.send(()).unwrap();
    completion.recv_timeout(TEST_TIMEOUT).unwrap();
    worker.join().unwrap();
    waiter.join().unwrap();

    assert_eq!(registry.state.lock().active, 0);
}

#[test]
fn test_closure_before_reservation_rejects_without_tracking() {
    let registry = Arc::new(Workers::default());
    registry.close();
    let worker_registry = registry.clone();
    thread::spawn(move || assert!(worker_registry.reserve().is_none()))
        .join()
        .unwrap();

    assert_eq!(registry.state.lock().active, 0);
    registry.wait();
}

#[test]
fn test_shutdown_does_not_wait_for_an_unpublished_ordinary_factory() {
    let drops = Arc::new(AtomicUsize::new(0));
    let polled = Arc::new(AtomicBool::new(false));
    let payload = DropCount(drops.clone());
    let future_polled = polled.clone();
    let (release, released) = mpsc::channel();

    let publisher = Runner::new(config()).start(|context| async move {
        let (entered, entering) = oneshot::channel();
        let publisher = thread::spawn(move || {
            context.child("foreign").spawn(move |_| {
                entered.send(()).unwrap();
                released.recv_timeout(TEST_TIMEOUT).unwrap();
                async move {
                    let _payload = payload;
                    future_polled.store(true, Ordering::Relaxed);
                }
            })
        });

        entering.await.unwrap();
        publisher
    });

    // Shutdown completed while the foreign factory still owns its captures.
    // Its subsequent publication must dispose of the future without polling it.
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    release.send(()).unwrap();
    let handle = publisher.join().unwrap();

    assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(!polled.load(Ordering::Relaxed));
}

#[test]
fn test_one_off_reservation_covers_factory_construction_through_shutdown() {
    /// Signal worker registration closure while ordinary tasks are destroyed.
    struct Closing(mpsc::Sender<()>);

    impl Drop for Closing {
        fn drop(&mut self) {
            self.0.send(()).unwrap();
        }
    }

    for execution in [Execution::Dedicated, Execution::Shared(true)] {
        let drops = Arc::new(AtomicUsize::new(0));
        let polled = Arc::new(AtomicBool::new(false));
        let payload = DropCount(drops.clone());
        let future_polled = polled.clone();
        let (metadata, received) = mpsc::channel();
        let (closing, closed) = mpsc::channel();
        let (release, released) = mpsc::channel();

        let runner = thread::spawn(move || {
            Runner::new(config()).start(|context| async move {
                // Ordinary task disposal follows registry closure. Its signal
                // observes shutdown without depending on root Drop ordering.
                let closing = Closing(closing);
                context
                    .child("shutdown_witness")
                    .spawn(move |_| async move {
                        let _closing = closing;
                        pending::<()>().await;
                    });

                let registry = context.shared.workers.clone();
                let (entered, entering) = oneshot::channel();
                let mut child = context.child("foreign");
                child.execution = execution;
                let publisher = thread::spawn(move || {
                    child.spawn(move |_| {
                        entered.send(()).unwrap();
                        released.recv_timeout(TEST_TIMEOUT).unwrap();
                        async move {
                            let _payload = payload;
                            future_polled.store(true, Ordering::Relaxed);
                        }
                    })
                });

                entering.await.unwrap();
                metadata.send((registry, publisher)).unwrap();
            });
        });

        // Worker registration is closed while the foreign factory remains blocked.
        let (registry, publisher) = received.recv_timeout(TEST_TIMEOUT).unwrap();
        closed.recv_timeout(TEST_TIMEOUT).unwrap();
        assert!(registry.state.lock().closed);
        assert_eq!(registry.state.lock().active, 1);
        assert!(!runner.is_finished());
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // The lease covers construction through rejected publication and disposal.
        release.send(()).unwrap();
        let handle = publisher.join().unwrap();
        runner.join().unwrap();

        assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        assert_eq!(registry.state.lock().active, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(!polled.load(Ordering::Relaxed));
    }
}

#[test]
fn test_factory_panic_finishes_metrics_and_releases_reservation() {
    for catch in [false, true] {
        Runner::new(config().with_catch_panics(catch)).start(|context| async move {
            for execution in [
                Execution::Shared(false),
                Execution::Dedicated,
                Execution::Shared(true),
            ] {
                let registry = context.shared.workers.clone();
                let mut child = context.child("panicking_factory");
                child.execution = execution;
                let label = Label::task(child.name.clone(), execution);
                let metrics = &context.shared.metrics;
                let running = metrics.tasks_running.get_or_create(&label).clone();
                let spawned = metrics.tasks_spawned.get_or_create(&label).clone();
                let factory_running = running.clone();

                let result = catch_unwind(AssertUnwindSafe(|| {
                    child.spawn(move |_| -> Ready<()> {
                        // One-off factories retain their reservation without holding its lock.
                        let reserved = usize::from(matches!(
                            execution,
                            Execution::Dedicated | Execution::Shared(true)
                        ));
                        assert_eq!(registry.state.lock().active, reserved);
                        assert_eq!(factory_running.get(), 1);
                        panic!("factory failed");
                    })
                }));

                // Factory panics reach the caller under either task-panic policy.
                let panic = result.err().expect("factory panic must reach its caller");
                assert_eq!(panic.downcast_ref::<&str>(), Some(&"factory failed"));

                // Keep the attempted spawn counted, but finish its running metric immediately.
                assert_eq!(spawned.get(), 1);
                assert_eq!(running.get(), 0);
                assert_eq!(context.shared.workers.state.lock().active, 0);

                assert_eq!(
                    context
                        .child("sibling")
                        .spawn(|_| async { 7 })
                        .await
                        .unwrap(),
                    7
                );
            }
        });
    }
}

#[test]
fn test_retained_descendant_context_is_closed_before_parent_result() {
    Runner::new(config()).start(|context| async move {
        let retained = context
            .child("parent")
            .spawn(|context| async move { context.child("retained") })
            .await
            .unwrap();
        let invoked = Arc::new(AtomicBool::new(false));
        let called = invoked.clone();
        let result = retained
            .spawn(move |_| {
                called.store(true, Ordering::SeqCst);
                async {}
            })
            .await;

        assert!(matches!(result, Err(Error::Closed)));
        assert!(!invoked.load(Ordering::SeqCst));

        // Check that the parent metric exists so an empty match cannot pass.
        let metrics = context.encode();
        let parent_metrics: Vec<_> = metrics
            .lines()
            .filter(|line| line.starts_with("runtime_tasks_running{") && line.contains("parent"))
            .collect();
        assert!(!parent_metrics.is_empty());
        assert!(parent_metrics.iter().all(|line| line.ends_with(" 0")));
    });
}

#[test]
fn test_one_off_completion_cancels_local_and_remote_descendants() {
    for blocking in [false, true] {
        Runner::new(config()).start(|context| async move {
            let parent = context.child("parent");
            let parent = if blocking {
                parent.shared(true)
            } else {
                parent.dedicated()
            };
            let descendants = parent
                .spawn(|context| async move {
                    let local = context.child("local").spawn(|_| pending::<()>());
                    let remote = context
                        .child("remote")
                        .dedicated()
                        .spawn(|_| pending::<()>());
                    [local, remote]
                })
                .await
                .unwrap();

            for descendant in descendants {
                assert!(matches!(descendant.await, Err(Error::Closed)));
            }

            assert_eq!(
                context
                    .child("sibling")
                    .spawn(|_| async { 7 })
                    .await
                    .unwrap(),
                7
            );
        });
    }
}

#[test]
fn test_root_shutdown_cancels_descendants_across_workers() {
    let handles = Runner::new(config()).start(|context| async move {
        let (published, descendants) = oneshot::channel();
        let parent = context
            .child("parent")
            .dedicated()
            .spawn(|context| async move {
                let local = context.child("local").spawn(|_| pending::<()>());
                let remote = context
                    .child("remote")
                    .shared(true)
                    .spawn(|_| pending::<()>());
                assert!(published.send([local, remote]).is_ok());
                pending::<()>().await;
            });
        let [local, remote] = descendants.await.unwrap();
        [parent, local, remote]
    });

    for handle in handles {
        assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
    }
}

#[test]
fn test_completed_one_off_worker_does_not_close_sibling_registry() {
    Runner::new(config()).start(|context| async move {
        context
            .child("first")
            .dedicated()
            .spawn(|_| async {})
            .await
            .unwrap();

        // Spawning remains available to a later sibling and its own one-off children.
        let result = context
            .child("second")
            .dedicated()
            .spawn(|context| async move {
                context
                    .child("nested")
                    .dedicated()
                    .spawn(|_| async { 11 })
                    .await
                    .unwrap()
            })
            .await
            .unwrap();

        assert_eq!(result, 11);
    });
}

#[test]
fn test_completed_workers_release_tracking_before_subsequent_launches() {
    Runner::new(config()).start(|context| async move {
        for _ in 0..8 {
            context
                .child("finished")
                .shared(true)
                .spawn(|_| async {})
                .await
                .unwrap();

            // Handle completion can precede worker cleanup. Wait for the lease
            // to retire before checking another launch for accumulated tracking.
            poll_fn(|cx| {
                if context.shared.workers.state.lock().active == 0 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
    });
}

#[rstest::rstest]
#[case::io(false)]
#[case::timer(true)]
fn test_worker_closure_wakes_shared_observers_before_forwarding(#[case] timer: bool) {
    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    for cancel in [false, true] {
        Runner::new(config()).start(|context| async move {
            // Both registrations stay pending until their dedicated worker closes.
            let mut future = if timer {
                let sleep = context.sleep(Duration::from_secs(60));
                async move {
                    sleep.await;
                    Ok(())
                }
                .boxed()
            } else {
                let mut listener = context.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
                async move { listener.accept().await.map(|_| ()) }.boxed()
            };

            // Hold the first inner poll open so another Shared clone can register
            // its waker without polling the operation or forwarding its observer.
            let (entered, ready) = oneshot::channel();
            let mut entered = Some(entered);
            let (release, wait) = mpsc::channel();
            let polls = Arc::new(AtomicUsize::new(0));
            let inner_polls = polls.clone();
            let mut shared = poll_fn(move |cx| {
                inner_polls.fetch_add(1, Ordering::Relaxed);
                let result = future.as_mut().poll(cx);

                // Disconnection releases the gate if the observing task fails.
                if let Some(entered) = entered.take() {
                    assert!(result.is_pending());
                    entered.send(()).unwrap();
                    let _ = wait.recv_timeout(TEST_TIMEOUT);
                }
                result
            })
            .boxed()
            .shared();

            // The source worker exits after its first poll, once the gate is released.
            let mut source = shared.clone();
            let task = context
                .child("source")
                .dedicated()
                .spawn(move |_| async move {
                    assert!(futures::poll!(&mut source).is_pending());
                });
            ready.await.unwrap();

            // Register a second observer while Shared's poll lock is held. Count
            // notifications independently so a wake cannot cause another inner poll.
            let counter = Arc::new(Counter(AtomicUsize::new(0)));
            let waker = std::task::Waker::from(counter.clone());
            assert!(
                shared
                    .poll_unpin(&mut std::task::Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(polls.load(Ordering::Relaxed), 1);
            assert_eq!(counter.0.load(Ordering::Relaxed), 0);

            // In the cancellation case, dropping the external clone removes its waker.
            // Source exit then drops the last Shared clone and must complete worker cleanup.
            let mut observer = (!cancel).then_some(shared);
            release.send(()).unwrap();
            task.await.unwrap();

            // Task completion can precede worker cleanup. Wait for registrations
            // to retire before inspecting notifications.
            poll_fn(|cx| {
                if context.shared.workers.state.lock().active == 0 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;

            // A surviving observer must be notified of closure and observe it on its next poll.
            if let Some(observer) = &mut observer {
                assert!(
                    counter.0.load(Ordering::Relaxed) > 0,
                    "worker closure lost observer wake: timer={timer}"
                );

                // I/O reports closure as an error. Sleep cannot complete before
                // its deadline.
                let result = catch_unwind(AssertUnwindSafe(|| {
                    observer.poll_unpin(&mut std::task::Context::from_waker(&waker))
                }));
                if timer {
                    assert!(result.is_err());
                } else {
                    assert!(matches!(result.unwrap(), Poll::Ready(Err(_))));
                }
            } else {
                // Shared removed this clone's waker before the source was released.
                assert_eq!(counter.0.load(Ordering::Relaxed), 0);
            }
        });
    }
}

#[test]
fn test_creation_failure_destroys_payload_before_releasing_tracking() {
    for panic_on_drop in [false, true] {
        Runner::new(config()).start(|context| async move {
            let drops = Arc::new(AtomicUsize::new(0));
            let payload = RejectedPayload {
                workers: context.shared.workers.clone(),
                drops: drops.clone(),
                panic_on_drop,
            };
            let _fault = inject_worker_fault(&context.shared.workers, WorkerFault::Launch);
            let result = catch_unwind(AssertUnwindSafe(|| {
                drop(
                    context
                        .child("failed_launch")
                        .shared(true)
                        .spawn(move |_| payload),
                );
            }));

            assert!(result.is_err());
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(context.shared.workers.state.lock().active, 0);
        });
    }
}

#[test]
fn test_launch_failure_destroys_reentrant_payload_after_unlocking_registry() {
    /// Retry worker creation from a rejected capture's destructor.
    struct ReentrantDrop {
        /// Context consumed by the nested spawn.
        context: Option<Context>,
        /// Number of rejected captures destroyed.
        drops: Arc<AtomicUsize>,
    }

    impl Drop for ReentrantDrop {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            self.context
                .take()
                .unwrap()
                .shared(true)
                .spawn(|_| async {});
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let observed = drops.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config()).start(move |context| async move {
            let payload = ReentrantDrop {
                context: Some(context.child("reentrant")),
                drops,
            };
            let _fault = inject_worker_fault(&context.shared.workers, WorkerFault::Launch);
            context
                .child("failed_launch")
                .shared(true)
                .spawn(move |_| async move {
                    let _payload = payload;
                });
        });
    }));

    let panic = result.expect_err("thread creation failure must panic in its caller");
    assert!(extract_panic_message(&*panic).contains("failed to spawn thread"));
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[test]
fn test_creation_failure_in_caught_task_leaves_runner_usable() {
    for dedicated in [false, true] {
        Runner::new(config().with_catch_panics(true)).start(|context| async move {
            let caller = context.child("launch_caller");
            let caller = if dedicated {
                caller.dedicated()
            } else {
                caller
            };
            let result = caller
                .spawn(|context| async move {
                    let _fault = inject_worker_fault(&context.shared.workers, WorkerFault::Launch);
                    context
                        .child("failed_launch")
                        .dedicated()
                        .spawn(|_| async {})
                        .await
                        .unwrap();
                })
                .await;

            assert!(matches!(result, Err(Error::Exited)));
            assert_eq!(
                context
                    .child("survivor")
                    .spawn(|_| async { 7 })
                    .await
                    .unwrap(),
                7
            );
        });
    }
}

#[test]
fn test_worker_startup_failure_uses_configured_panic_policy() {
    for blocking in [false, true] {
        for catch in [false, true] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_catch_panics(catch)).start(|context| async move {
                    let _fault = inject_worker_fault(&context.shared.workers, WorkerFault::Startup);
                    let worker = context.child("failed_worker");
                    let worker = if blocking {
                        worker.shared(true)
                    } else {
                        worker.dedicated()
                    };
                    let failed = worker.spawn(|_| async {});

                    assert!(matches!(failed.await, Err(Error::Closed)));
                    if !catch {
                        // Keep the root active until it observes the worker failure.
                        pending::<()>().await;
                    }

                    context
                        .child("sibling")
                        .spawn(|_| async { 11 })
                        .await
                        .unwrap()
                })
            }));

            if catch {
                assert_eq!(result.unwrap(), 11);
            } else {
                let panic = result.expect_err("an uncaught worker failure must interrupt the root");
                assert!(
                    extract_panic_message(&*panic)
                        .contains("injected native worker initialization failure")
                );
            }
        }
    }
}

#[test]
fn test_startup_failure_survives_rejected_payload_destructor_panic() {
    let drops = Arc::new(AtomicUsize::new(0));
    let observed = drops.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config().with_catch_panics(false)).start(|context| async move {
            let payload = RejectedPayload {
                workers: context.shared.workers.clone(),
                drops,
                panic_on_drop: true,
            };
            let _fault = inject_worker_fault(&context.shared.workers, WorkerFault::Startup);
            drop(
                context
                    .child("failed_launch")
                    .shared(true)
                    .spawn(move |_| payload),
            );
            pending::<()>().await;
        });
    }));

    let panic = result.expect_err("native startup failure must fail the runner");
    assert!(
        extract_panic_message(&*panic).contains("injected native worker initialization failure")
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[test]
fn test_service_error_preserves_completions_before_cleanup() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    peer.write_all(b"x").unwrap();
    let request = Request::Recv(RecvRequest {
        fd: Arc::new(socket.into()),
        buf: IoBufMut::with_capacity(1),
        offset: 0,
        len: 1,
        exact: true,
        deadline: None,
    });
    let retained = Arc::new(Mutex::new(None));
    let operation = retained.clone();

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config()).start(|_| async move {
            *operation.lock() = Some(Operation::register(request));
            let _fault =
                fail_after_completion(Local::current().unwrap().borrow().driver.as_ref().unwrap());

            // Keep the observer alive beyond root destruction so cleanup must
            // preserve its terminal resources before closing local observation.
            poll_fn(|cx| {
                assert!(
                    Pin::new(operation.lock().as_mut().unwrap())
                        .poll(cx)
                        .is_pending()
                );
                Poll::<()>::Pending
            })
            .await;
        });
    }));

    let panic = result.expect_err("injected service failure must fail the runner");
    let message = extract_panic_message(&*panic);
    assert!(message.contains("io_uring driver service failed"));
    assert!(message.contains("injected service failure after completion"));

    // The escaped future can be destroyed after its worker has closed.
    drop(retained);
}

#[test]
fn test_cancelled_task_disposal_is_contained() {
    for catch in [false, true] {
        for execution in [
            Execution::default(),
            Execution::Dedicated,
            Execution::Shared(true),
        ] {
            let drops = Arc::new(AtomicUsize::new(0));
            let task_drops = drops.clone();

            Runner::new(Config::default().with_catch_panics(catch)).start(|context| async move {
                let child = context.child("cancelled");
                let child = match execution {
                    Execution::Dedicated => child.dedicated(),
                    Execution::Shared(blocking) => child.shared(blocking),
                };
                let (started, ready) = oneshot::channel();
                let handle = child.spawn(|context| async move {
                    let _guard = PanickingDrop(task_drops);
                    assert!(started.send(context.child("retained")).is_ok());
                    pending::<()>().await;
                });

                // Abort after the task has installed its guard. The panic
                // comes from cancellation, regardless of user-poll policy.
                let retained = ready.await.unwrap();
                handle.abort();
                assert!(matches!(handle.await, Err(Error::Closed)));

                // Disposal must close the supervision subtree before the
                // parent handle resolves, even when destruction panics.
                let invoked = Arc::new(AtomicBool::new(false));
                let factory_invoked = invoked.clone();
                let result = retained
                    .spawn(move |_| {
                        factory_invoked.store(true, Ordering::Relaxed);
                        async {}
                    })
                    .await;
                assert!(
                    !invoked.load(Ordering::Relaxed),
                    "cancelled descendant invoked its spawn factory"
                );
                assert!(matches!(result, Err(Error::Closed)));

                context.child("survivor").spawn(|_| async {}).await.unwrap();
            });

            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn test_unpolled_task_disposal_is_contained() {
    for catch in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let guard = PanickingDrop(drops.clone());
        let polled = Arc::new(AtomicBool::new(false));
        let task_polled = polled.clone();

        Runner::new(Config::default().with_catch_panics(catch)).start(|context| async move {
            // The root returns without yielding, leaving the guard captured
            // in an accepted task that shutdown must destroy without polling.
            context.child("unpolled").spawn(|_| async move {
                let _guard = guard;
                task_polled.store(true, Ordering::Relaxed);
                pending::<()>().await;
            });
        });

        assert!(!polled.load(Ordering::Relaxed));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn test_self_woken_task_requeues_behind_queued_work() {
    // A task that wakes itself during its poll runs again only after the work
    // already queued, and completed tasks leave the task set.
    let order = Runner::new(config()).start(|context| async move {
        let order = Arc::new(Mutex::new(Vec::new()));
        let first = context.child("first").spawn({
            let order = order.clone();
            move |_| async move {
                order.lock().push("first");
                reschedule().await;
                order.lock().push("first again");
            }
        });
        let second = context.child("second").spawn({
            let order = order.clone();
            move |_| async move { order.lock().push("second") }
        });
        first.await.unwrap();
        second.await.unwrap();

        // Only the runner's service task is still registered.
        assert_eq!(context.shared.tasks.live(), 1);
        order.lock().clone()
    });
    assert_eq!(order, ["first", "second", "first again"]);
}

#[test]
fn test_shutdown_cancels_tasks_before_destruction() {
    /// Inspect supervision and metrics when the user future is destroyed.
    struct Cleanup {
        /// Total future destructions, including those before a first poll.
        drops: Arc<AtomicUsize>,
        /// Destructions that observed closed supervision and zero running tasks.
        cancelled: Arc<AtomicUsize>,
        /// Running-task metric updated by the execution wrapper.
        gauge: raw::Gauge,
        /// Retained descendant used to probe whether the supervision tree is closed.
        descendant: Arc<Tree>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Record ordering without panicking inside the task disposal boundary.
            if self.gauge.get() == 0 && Tree::child(&self.descendant).1 {
                self.cancelled.fetch_add(1, Ordering::Relaxed);
            }
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How far the ordinary tasks progress before the root returns with one
    /// worker. A second worker can also poll the tasks the first leaves queued.
    #[derive(Clone, Copy, Debug)]
    enum Placement {
        /// Registered locally but never polled.
        Local,
        /// Registered from another thread, with its first runnable still in
        /// the inject queue.
        Foreign,
        /// Polled once and suspended before shutdown.
        Pending,
    }

    for workers in [1, 2] {
        for placement in [Placement::Local, Placement::Foreign, Placement::Pending] {
            let drops = Arc::new(AtomicUsize::new(0));
            let cancelled = Arc::new(AtomicUsize::new(0));
            let gauge = raw::Gauge::default();
            let handles = Runner::new(config().with_worker_threads(workers)).start(|context| {
                // Hold worker zero between the pool's close and the abort, so a
                // worker that drained the set before the abort would be caught.
                if workers > 1 {
                    BEFORE_ABORT.with(|slot| {
                        *slot.borrow_mut() =
                            Some(Box::new(|| thread::sleep(Duration::from_millis(20))));
                    });
                }
                let drops = &drops;
                let cancelled = &cancelled;
                let gauge = &gauge;

                async move {
                    // Build both wrappers directly so a shared gauge can check that
                    // the whole subtree is cancelled before either future is destroyed.
                    let tree = Tree::child(&context.tree).0;
                    let descendant = Tree::child(&tree).0;
                    let mut handles = Vec::new();
                    let mut receivers = Vec::new();

                    for tree in [tree, descendant.clone()] {
                        let cleanup = Cleanup {
                            drops: drops.clone(),
                            cancelled: cancelled.clone(),
                            gauge: gauge.clone(),
                            descendant: descendant.clone(),
                        };
                        let (started, ready) = oneshot::channel();
                        let (future, handle) = Handle::init(
                            async move {
                                let _cleanup = cleanup;
                                let _ = started.send(());
                                pending::<()>().await;
                            },
                            MetricHandle::new(gauge.clone()),
                            context.shared.panicker.clone(),
                            tree.clone(),
                        );
                        let shared = context.shared.clone();
                        let pool = Arc::downgrade(&shared.pool);
                        if matches!(placement, Placement::Foreign) {
                            thread::spawn(move || {
                                assert!(shared.tasks.register(future, pool).is_ok())
                            })
                            .join()
                            .unwrap();
                        } else {
                            assert!(shared.tasks.register(future, pool).is_ok());
                        }

                        handles.push(handle);
                        receivers.push(ready);
                    }

                    // Only this case waits for the futures to reach their
                    // suspension point.
                    if matches!(placement, Placement::Pending) {
                        for ready in receivers {
                            ready.await.unwrap();
                        }
                    }

                    handles
                }
            });

            let case = format!("workers={workers} placement={placement:?}");
            assert_eq!(drops.load(Ordering::Relaxed), 2, "{case}");
            assert_eq!(cancelled.load(Ordering::Relaxed), 2, "{case}");
            assert_eq!(gauge.get(), 0, "{case}");

            for handle in handles {
                assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
            }
        }
    }
}

/// A foreign spawn's task joins the set before a worker takes the first
/// runnable, and leaves it on completion.
#[test]
fn test_foreign_spawn_joins_the_task_set_before_its_worker_runs() {
    Runner::new(config()).start(|context| async move {
        // Only the runner's service task is registered.
        assert_eq!(context.shared.tasks.live(), 1);

        // The root has not yielded, so no worker has taken the first runnable
        // from the inject queue, yet the set already retains the task.
        let remote = context.child("foreign");
        let handle = thread::spawn(move || remote.spawn(|_| async {}))
            .join()
            .unwrap();
        assert_eq!(context.shared.tasks.live(), 2);

        // Completion on the worker removes it again.
        handle.await.unwrap();
        assert_eq!(context.shared.tasks.live(), 1);
    });
}

/// Shutdown between a foreign registration and delivery of its first runnable
/// clears the task without polling it.
#[test]
fn test_shutdown_between_registration_and_first_runnable_clears_the_task() {
    let drops = Arc::new(AtomicUsize::new(0));
    let polled = Arc::new(AtomicBool::new(false));
    let payload = DropCount(drops.clone());
    let future_polled = polled.clone();
    let (release, released) = mpsc::channel::<()>();

    let publisher = Runner::new(config()).start(|context| async move {
        let (inserted, inserting) = oneshot::channel();
        let publisher = thread::spawn(move || {
            // Pause this thread's registration once the set holds the task,
            // before its first runnable reaches the pool.
            AFTER_INSERT.set(Some(Box::new(move || {
                inserted.send(()).unwrap();
                released.recv_timeout(TEST_TIMEOUT).unwrap();
            })));
            context.child("foreign").spawn(move |_| async move {
                let _payload = payload;
                future_polled.store(true, Ordering::Relaxed);
            })
        });

        // Shut down while the publisher holds the only runnable.
        inserting.await.unwrap();
        publisher
    });

    // Teardown drained the set and dropped the future without polling it.
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(!polled.load(Ordering::Relaxed));

    // The pool's inject queue has closed, so delivery discards the runnable,
    // and the handle is already closed.
    release.send(()).unwrap();
    let handle = publisher.join().unwrap();
    assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(!polled.load(Ordering::Relaxed));
}

/// A spawn the task set refuses after its factory ran is disposed of on its
/// caller, on the worker's thread and on another thread.
#[test]
fn test_spawn_refused_by_the_closed_task_set_is_disposed_on_its_caller() {
    /// Record the thread that drops a future.
    struct ThreadDrop(Arc<Mutex<Vec<thread::ThreadId>>>);

    impl Drop for ThreadDrop {
        fn drop(&mut self) {
            self.0.lock().push(thread::current().id());
        }
    }

    for foreign in [false, true] {
        let drops = Arc::new(Mutex::new(Vec::new()));
        Runner::new(config()).start(|context| {
            let drops = drops.clone();
            async move {
                let shared = context.shared.clone();
                let spawner = context.child("refused");
                let spawn = move || {
                    let payload = ThreadDrop(drops.clone());
                    let handle = spawner.spawn(move |context| {
                        // Close the set while the factory runs, as the worker
                        // can when it begins closing, so only registration
                        // can refuse the task.
                        context.shared.tasks.close();
                        async move {
                            let _payload = payload;
                            pending::<()>().await;
                        }
                    });

                    // The factory ran, and the caller disposed of the future
                    // before spawn returned.
                    assert!(shared.tasks.is_closed());
                    assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
                    assert_eq!(*drops.lock(), [thread::current().id()]);
                };
                if foreign {
                    thread::spawn(spawn).join().unwrap();
                } else {
                    spawn();
                }
            }
        });
        assert_eq!(drops.lock().len(), 1, "foreign={foreign}");
    }
}

/// Teardown drops every idle or queued future, spawned locally or from
/// another thread, while the worker's timers are still registered.
#[test]
fn test_teardown_drops_every_future_before_clearing_timers() {
    /// Record whether the worker still holds timers when a future is dropped.
    struct TimerCheck {
        /// Futures dropped.
        drops: Arc<AtomicUsize>,
        /// Futures dropped while the worker's timer table was still open.
        early: Arc<AtomicUsize>,
    }

    impl Drop for TimerCheck {
        fn drop(&mut self) {
            // The future's own sleep drops after this guard, so its timer is
            // still registered unless teardown has already closed the table.
            let local = Local::current().expect("future dropped off its worker");
            if local.borrow_mut().timers.next_deadline().is_some() {
                self.early.fetch_add(1, Ordering::Relaxed);
            }
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    const TASKS: usize = 32;
    let drops = Arc::new(AtomicUsize::new(0));
    let early = Arc::new(AtomicUsize::new(0));
    let idle = Runner::new(config()).start(|context| {
        let (drops, early) = (drops.clone(), early.clone());
        async move {
            let mut started = Vec::new();
            let mut wakes = Vec::new();
            for index in 0..TASKS {
                let (ready, ready_receiver) = oneshot::channel();
                let (wake, woken) = oneshot::channel::<()>();
                let guard = TimerCheck {
                    drops: drops.clone(),
                    early: early.clone(),
                };
                let spawner = context.child("pending");
                let spawn = move || {
                    spawner.spawn(move |context| async move {
                        let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
                        assert!(futures::poll!(&mut sleep).is_pending());
                        let _guard = guard;
                        ready.send(()).unwrap();
                        let _ = woken.await;
                        sleep.await;
                    })
                };

                // Half the tasks are spawned from another thread.
                if index % 2 == 0 {
                    spawn();
                } else {
                    thread::spawn(spawn).join().unwrap();
                }
                started.push(ready_receiver);
                wakes.push(wake);
            }
            for ready in started {
                ready.await.unwrap();
            }

            // Wake half the tasks, whose runnables stay queued since the root
            // returns without yielding. The rest stay idle, since their senders
            // outlive the runner.
            let (woken, idle): (Vec<_>, Vec<_>) = wakes
                .into_iter()
                .enumerate()
                .partition(|(index, _)| index % 4 < 2);
            for (_, wake) in woken {
                wake.send(()).unwrap();
            }
            idle
        }
    });

    assert_eq!(drops.load(Ordering::Relaxed), TASKS);
    assert_eq!(early.load(Ordering::Relaxed), TASKS);
    drop(idle);
}

#[test]
fn test_shutdown_waits_for_one_off_task_destruction() {
    /// Hold task disposal open until the test inspects the shutdown wait.
    struct HeldDestructor {
        /// Tell the test that destruction has begun.
        entered: mpsc::Sender<()>,
        /// Keep the worker active until the test permits destruction to finish.
        release: mpsc::Receiver<()>,
    }

    impl Drop for HeldDestructor {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv_timeout(TEST_TIMEOUT);
        }
    }

    let (metadata, received) = mpsc::channel();
    let (entered, entering) = mpsc::channel();
    let (release, released) = mpsc::channel();

    let runner = thread::spawn(move || {
        Runner::new(config()).start(|context| async move {
            metadata.send(context.shared.workers.clone()).unwrap();
            let (started, starting) = oneshot::channel();
            context
                .child("cancelled_worker")
                .dedicated()
                .spawn(move |_| async move {
                    let _payload = HeldDestructor {
                        entered,
                        release: released,
                    };
                    started.send(()).unwrap();
                    pending::<()>().await;
                });
            starting.await.unwrap();
        });
    });

    // Destruction has started, but shutdown still owes this worker's lease.
    let registry = received.recv_timeout(TEST_TIMEOUT).unwrap();
    entering.recv_timeout(TEST_TIMEOUT).unwrap();
    assert!(registry.state.lock().closed);
    assert_eq!(registry.state.lock().active, 1);
    assert!(!runner.is_finished());

    release.send(()).unwrap();
    runner.join().unwrap();

    assert_eq!(registry.state.lock().active, 0);
}

#[test]
fn test_shutdown_waits_for_workers_without_observing_late_panics() {
    /// Signal the end of root execution before allowing a worker failure to publish.
    struct RootWithLatePublisher {
        /// Notify the publisher when root destruction begins.
        dropped: Option<mpsc::Sender<()>>,
        /// Whether the root has its own failure that must remain authoritative.
        fail: bool,
    }

    impl Future for RootWithLatePublisher {
        type Output = u8;

        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Self::Output> {
            assert!(!self.fail, "primary root failure");
            Poll::Ready(7)
        }
    }

    impl Drop for RootWithLatePublisher {
        fn drop(&mut self) {
            self.dropped.take().unwrap().send(()).unwrap();
        }
    }

    for root_fails in [false, true] {
        let (metadata, received) = mpsc::channel();
        let (publishing, publication) = mpsc::channel();
        let (release, released) = mpsc::channel();

        let runner = thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_catch_panics(false)).start(move |context| {
                    let registry = context.shared.workers.clone();
                    let active = registry.reserve().unwrap();
                    let panicker = context.shared.panicker.clone();
                    let (dropped, root_dropped) = mpsc::channel();
                    let publisher = thread::spawn(move || {
                        // Root destruction ends execution. Shutdown still waits
                        // for this publisher to release its worker responsibility.
                        root_dropped.recv_timeout(TEST_TIMEOUT).unwrap();
                        publishing.send(()).unwrap();
                        released.recv_timeout(TEST_TIMEOUT).unwrap();
                        panicker.notify(Box::new("delayed worker failure"));
                        drop(active);
                    });
                    metadata.send((registry, publisher)).unwrap();

                    RootWithLatePublisher {
                        dropped: Some(dropped),
                        fail: root_fails,
                    }
                })
            }));

            result.map_err(|panic| extract_panic_message(&*panic))
        });

        // The root is finished, but its runner must wait for the late publisher.
        let (registry, publisher) = received.recv_timeout(TEST_TIMEOUT).unwrap();
        publication.recv_timeout(TEST_TIMEOUT).unwrap();
        assert_eq!(registry.state.lock().active, 1);
        assert!(!runner.is_finished());

        // Publish after root execution ends. It must not replace the root result.
        release.send(()).unwrap();
        publisher.join().unwrap();

        assert_eq!(
            runner.join().unwrap(),
            if root_fails {
                Err("primary root failure".into())
            } else {
                Ok(7)
            }
        );
        assert_eq!(registry.state.lock().active, 0);
    }
}

#[test]
fn test_worker_releases_storage_and_durable_io_before_tracking_ends() {
    let cfg = config();
    let directory = cfg.storage_directory().clone();
    let (released, after_release) = mpsc::channel();
    let (finish, finished) = mpsc::channel();

    let (shared, registry, _fault) = Runner::new(cfg).start(|context| async move {
        let shared = Arc::downgrade(&context.shared);
        let registry = context.shared.workers.clone();
        let fault = inject_worker_fault(
            &registry,
            WorkerFault::AfterRelease(Box::new(move || {
                // Keep the guard and thread-entry locals alive after count zero,
                // so their destruction cannot hide a retained Shared reference.
                let _ = released.send(());
                let _ = finished.recv_timeout(TEST_TIMEOUT);
            })),
        );
        context
            .child("durable_worker")
            .dedicated()
            .spawn(move |context| async move {
                let (blob, _) = context.open("partition", b"retained").await.unwrap();

                // Drop the write after registration so shutdown must finish its
                // durable I/O without an observer.
                let write = blob.write_at(0, b"durable", WriteOptions::SYNC);
                assert!(write.now_or_never().is_none());
                drop(blob);
            })
            .await
            .unwrap();
        (shared, registry, fault)
    });

    // Tracking reached zero while thread-entry locals are deliberately held alive.
    after_release.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_eq!(registry.state.lock().active, 0);
    assert!(shared.upgrade().is_none());

    // Runtime cleanup must already have released both the lock and durable I/O.
    let contender = File::options()
        .write(true)
        .open(directory.join(".hold"))
        .unwrap();
    contender
        .try_lock()
        .expect("runtime cleanup must release storage before tracking ends");
    let bytes = fs::read(
        directory
            .join("partition")
            .join(commonware_formatting::hex(b"retained")),
    )
    .unwrap();
    assert!(bytes.ends_with(b"durable"));

    finish.send(()).unwrap();
    drop(contender);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
// Retain the task handle to check its result after the runner closes the pool.
#[allow(clippy::async_yields_async)]
fn test_queued_foreign_task_disposal_is_contained_at_shutdown() {
    for catch in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = PanickingDrop(drops.clone());

        let handle = Runner::new(config().with_catch_panics(catch)).start(|context| async move {
            let remote = context.child("queued_foreign");

            // Joining only the publisher leaves its accepted task in the
            // inject queue when this root completes its first poll.
            thread::spawn(move || {
                remote.spawn(move |_| async move {
                    let _payload = payload;
                    panic!("queued task must not be polled");
                })
            })
            .join()
            .unwrap()
        });

        assert!(matches!(block_on(handle), Err(Error::Closed)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn test_ready_future_destructor_closes_handle_and_leaves_runner_usable() {
    /// Complete on the first poll, then fail before the wrapper can publish success.
    struct ReadyDrop {
        /// Count polls to reject any attempt to resume the completed future.
        polls: Arc<AtomicUsize>,
        /// Count disposal despite its panic.
        drops: Arc<AtomicUsize>,
    }

    impl Future for ReadyDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
            assert_eq!(self.polls.fetch_add(1, Ordering::SeqCst), 0);
            Poll::Ready(())
        }
    }

    impl Drop for ReadyDrop {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            panic!("ready future destructor failed");
        }
    }

    for catch in [false, true] {
        for dedicated in [false, true] {
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let future = ReadyDrop {
                polls: polls.clone(),
                drops: drops.clone(),
            };

            Runner::new(config().with_catch_panics(catch)).start(|context| async move {
                let child = context.child("ready_drop");
                let child = if dedicated { child.dedicated() } else { child };

                // Disposal escapes the shared wrapper's user-poll boundary
                // before it publishes a result. Task disposal remains contained.
                let result = child.spawn(move |_| future).await;
                assert!(matches!(result, Err(Error::Closed)));

                context.child("survivor").spawn(|_| async {}).await.unwrap();
            });

            assert_eq!(polls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn test_contain_handles_panicking_payloads() {
    assert_eq!(Panics::contain(|| 7), Some(7));

    for panics in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = PanicPayload {
            drops: drops.clone(),
            panics,
        };

        assert!(Panics::contain(|| panic_any(payload)).is_none());

        // Dispose of the original payload, but leave a secondary panic's
        // payload untouched so destruction cannot start another failure.
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn test_callback_failure_does_not_skip_siblings() {
    /// Record a wake before optionally panicking so later callbacks remain observable.
    struct Callback {
        /// Total invocations across both wakers.
        calls: Arc<AtomicUsize>,
        /// Whether this callback fails after recording its invocation.
        panics: bool,
    }

    impl ArcWake for Callback {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.calls.fetch_add(1, Ordering::Relaxed);
            assert!(!arc_self.panics, "wake failed");
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let callbacks = [true, false].map(|panics| {
        waker(Arc::new(Callback {
            calls: calls.clone(),
            panics,
        }))
    });
    let mut deferred = Deferred {
        wakes: callbacks.into(),
        ..Deferred::default()
    };
    let mut panics = Panics::default();

    assert!(panics.take().is_none());

    // The first wake fails, but the rest of the batch must still run.
    deferred.run(&mut panics);

    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(deferred.is_empty());

    assert_eq!(
        panics.take().unwrap().downcast_ref::<&str>(),
        Some(&"wake failed")
    );
    assert!(panics.take().is_none());
}

#[test]
fn test_unreported_panic_payloads_are_not_destroyed() {
    /// Detect destruction of payloads that panic accumulation must leave untouched.
    struct Dangerous;

    impl Drop for Dangerous {
        fn drop(&mut self) {
            panic!("payload destructor must not run");
        }
    }

    let mut panics = Panics::default();
    panics.retain(Box::new("first"));
    panics.retain(Box::new(Dangerous));

    // A later failure must preserve the original payload without dropping its own.
    assert_eq!(
        panics.take().unwrap().downcast_ref::<&str>(),
        Some(&"first")
    );

    // Dropping the accumulator must also leave an unclaimed payload alone.
    panics.retain(Box::new(Dangerous));
    drop(panics);
}

#[test]
fn test_callback_generated_work_prevents_parking() {
    /// Progress produced only when the final deferred destructor runs.
    enum Work {
        /// Make the current task ready and wake its existing registration.
        Wake(Waker, Arc<AtomicBool>),
        /// Register a child that publishes readiness through a channel.
        Spawn(Context, oneshot::Sender<()>),
    }

    /// Chain deferred destructors before generating runnable work.
    struct Callback {
        /// Number of further deferred batches to create before producing work.
        remaining: usize,
        /// Action transferred down the chain and consumed by the final destructor.
        work: Option<Work>,
    }

    // The destructor performs the callback, which Waker::noop cannot model.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for Callback {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for Callback {
        fn drop(&mut self) {
            let work = self.work.take().unwrap();
            if self.remaining != 0 {
                Local::current()
                    .unwrap()
                    .borrow_mut()
                    .deferred
                    .drops
                    .push(Waker::from(Arc::new(Self {
                        remaining: self.remaining - 1,
                        work: Some(work),
                    })));
                return;
            }

            match work {
                Work::Wake(waker, ready) => {
                    ready.store(true, Ordering::SeqCst);
                    waker.wake();
                }
                Work::Spawn(context, sender) => {
                    context.spawn(|_| async move {
                        sender.send(()).unwrap();
                    });
                }
            }
        }
    }

    for spinner in [SpinnerConfig::disabled(), SpinnerConfig::default()] {
        for spawn in [false, true] {
            for remaining in [0, 2] {
                Runner::new(config().with_idle_spinner(spinner.clone())).start(
                    |context| async move {
                        let _park = forbid_park();
                        let (sender, mut receiver) = oneshot::channel();
                        let mut sender = Some(sender);
                        let ready = Arc::new(AtomicBool::new(false));
                        let mut queued = false;

                        poll_fn(|cx| {
                            if !queued {
                                queued = true;
                                let work = if spawn {
                                    Work::Spawn(
                                        context.child("callback_work"),
                                        sender.take().unwrap(),
                                    )
                                } else {
                                    Work::Wake(cx.waker().clone(), ready.clone())
                                };
                                let local = Local::current().unwrap();
                                let mut local = local.borrow_mut();

                                // Longer chains leave a fresh batch after both normal
                                // callback passes. All progress is local to this worker.
                                local.deferred.drops.push(Waker::from(Arc::new(Callback {
                                    remaining,
                                    work: Some(work),
                                })));
                            }

                            if spawn {
                                Pin::new(&mut receiver).poll(cx).map(Result::unwrap)
                            } else if ready.load(Ordering::SeqCst) {
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        })
                        .await;
                    },
                );
            }
        }
    }
}

#[test]
fn test_final_callbacks_finish_before_tls_removal() {
    /// Observe disposal of a successful root result when shutdown fails.
    #[derive(Debug)]
    struct Output(Arc<AtomicUsize>);

    impl Drop for Output {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("root output drop panic");
        }
    }

    /// Observe final timer disposal through the registered waker's destructor.
    struct Callback(Arc<AtomicUsize>);

    // This waker owns a reentrant destructor, which Waker::noop cannot model.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for Callback {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for Callback {
        fn drop(&mut self) {
            let local = Local::current().expect("callback ran after TLS removal");
            assert!(local.try_borrow_mut().unwrap().closing);

            // Public callbacks cannot register another timer on a closed worker.
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let panic = catch_unwind(AssertUnwindSafe(|| {
                Pin::new(&mut sleep).poll(&mut TaskContext::from_waker(Waker::noop()))
            }))
            .expect_err("sleep must reject polling after worker closure");
            assert_eq!(
                extract_panic_message(&*panic),
                "io_uring sleep polled after its worker closed"
            );

            // The outer assertion must observe successful validation even when
            // the runtime contains this callback's deliberate secondary panic.
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("terminal callback panic");
        }
    }

    for root_panics in [true, false] {
        let drops = Arc::new(AtomicUsize::new(0));
        let observed = drops.clone();
        let output_drops = Arc::new(AtomicUsize::new(0));
        let observed_output = output_drops.clone();
        let mut escaped = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(|_| async {
                let mut sleep = Sleep::new(Duration::from_secs(60));
                let waker = Waker::from(Arc::new(Callback(drops)));
                assert!(
                    Pin::new(&mut sleep)
                        .poll(&mut TaskContext::from_waker(&waker))
                        .is_pending()
                );
                drop(waker);
                escaped = Some(sleep);
                if root_panics {
                    panic!("primary root panic");
                }
                Output(output_drops)
            })
        }));

        assert_eq!(
            extract_panic_message(&*result.unwrap_err()),
            if root_panics {
                "primary root panic"
            } else {
                "terminal callback panic"
            }
        );
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed_output.load(Ordering::SeqCst),
            usize::from(!root_panics)
        );
        drop(escaped);
    }
}

#[test]
fn test_finished_worker_tls_can_wait_for_live_root_work() {
    /// Spawn onto the live root after the worker has finished runtime cleanup.
    struct OnExit {
        /// Ordinary context retained until native TLS destruction.
        context: Option<Context>,
        /// Tell the root that its task was registered from TLS destruction.
        entered: Option<oneshot::Sender<()>>,
        /// Keep the ordinary task pending until the root permits completion.
        release: Option<oneshot::Receiver<()>>,
        /// Tell the root that the TLS destructor's blocking wait completed.
        done: Option<oneshot::Sender<()>>,
    }

    impl Drop for OnExit {
        fn drop(&mut self) {
            // Awaiting done_rx keeps worker registration open during TLS destruction.
            // A panic escaping this TLS destructor would abort the process.
            let context = self.context.take().unwrap();
            let release = self.release.take().unwrap();
            let handle = context.spawn(move |_| async move {
                release.await.unwrap();
            });
            self.entered.take().unwrap().send(()).unwrap();
            block_on(handle).unwrap();
            self.done.take().unwrap().send(()).unwrap();
        }
    }

    thread_local! {
        /// Destructor that outlives the worker's runtime scope.
        static EXIT: RefCell<Option<OnExit>> = const { RefCell::new(None) };
    }

    Runner::new(config()).start(|context| async move {
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let exit_context = context.child("tls_dependency");

        context
            .child("first_worker")
            .dedicated()
            .spawn(move |_| async move {
                EXIT.with(|slot| {
                    *slot.borrow_mut() = Some(OnExit {
                        context: Some(exit_context),
                        entered: Some(entered),
                        release: Some(release_rx),
                        done: Some(done),
                    });
                });
            })
            .await
            .unwrap();

        // The first worker now blocks in native TLS, outside runtime tracking.
        // Another worker can start while the root releases the ordinary task.
        entered_rx.await.unwrap();
        let second = context
            .child("second_worker")
            .dedicated()
            .spawn(|_| async {});
        release.send(()).unwrap();
        second.await.unwrap();
        done_rx.await.unwrap();
    });
}

#[test]
fn test_foreign_tls_destructor_can_wake_after_current_key_destruction() {
    /// Wake after the runtime's current-worker TLS key becomes unavailable.
    struct OnExit {
        /// Live root waker retained past destruction of the current-worker key.
        waker: Waker,
        /// Report any contained panic to the still-running root.
        result: mpsc::Sender<bool>,
    }

    impl Drop for OnExit {
        fn drop(&mut self) {
            // Catch inside TLS destruction so a regression fails the test
            // instead of aborting the process with an escaping panic.
            let panicked = catch_unwind(AssertUnwindSafe(|| self.waker.wake_by_ref())).is_err();
            let _ = self.result.send(panicked);
        }
    }

    thread_local! {
        /// Initialized before CURRENT so it is destroyed after that key.
        static EXIT: RefCell<Option<OnExit>> = const { RefCell::new(None) };
    }

    let panicked = Runner::new(config()).start(|_| {
        poll_fn(|cx| {
            let waker = cx.waker().clone();
            let (result, received) = mpsc::channel();

            thread::spawn(move || {
                // Initialize user TLS first. The foreign wake initializes
                // CURRENT afterward, so CURRENT is destroyed before EXIT.
                EXIT.with(|slot| {
                    *slot.borrow_mut() = Some(OnExit {
                        waker: waker.clone(),
                        result,
                    });
                });
                waker.wake_by_ref();
            })
            .join()
            .unwrap();

            // Keep the owning runner alive through foreign TLS destruction.
            Poll::Ready(received.recv_timeout(TEST_TIMEOUT).unwrap())
        })
    });

    assert!(!panicked, "ordinary wake accessed destroyed runtime TLS");
}

/// Spin on the calling thread until `started` holds a thread, then return it.
/// Called from the root, this keeps worker zero from polling anything else.
fn wait_started(started: &Mutex<Option<ThreadId>>) -> ThreadId {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if let Some(thread) = *started.lock() {
            return thread;
        }
        assert!(Instant::now() < deadline, "task never started");
        std::hint::spin_loop();
    }
}

/// Spawn `f` from a thread outside the pool, so its first runnable goes to the
/// inject queue, and block the calling worker until another worker has started
/// it. Returns the task's handle and the thread that started it.
fn spawn_elsewhere<T, Fut>(context: &Context, f: Fut) -> (Handle<T>, ThreadId)
where
    T: Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    let started = Arc::new(Mutex::new(None));
    let child = context.child("elsewhere");
    let handle = thread::spawn({
        let started = started.clone();
        move || {
            child.spawn(move |_| async move {
                *started.lock() = Some(thread::current().id());
                f.await
            })
        }
    })
    .join()
    .unwrap();
    let thread = wait_started(&started);
    assert_ne!(thread, thread::current().id(), "task started on the caller");
    (handle, thread)
}

#[test]
fn test_tasks_spread_across_workers_and_complete() {
    for count in [1, 2, 4] {
        let borrowed = Rc::new(Cell::new(0));
        let state = &borrowed;
        let cfg = config().with_worker_threads(count);
        assert_eq!(cfg.worker_threads(), count);
        Runner::new(cfg).start(|context| async move {
            let root = thread::current().id();
            let started = Arc::new(AtomicUsize::new(0));
            let mut tasks = Vec::new();
            for _ in 0..count * 3 {
                let started = started.clone();
                tasks.push(context.child("worker").spawn(move |_| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    thread::current().id()
                }));
            }

            // Worker zero keeps the first spawn and injects the rest, so with
            // other workers they start while the root holds this one.
            if count > 1 {
                let deadline = Instant::now() + TEST_TIMEOUT;
                while started.load(Ordering::SeqCst) < count * 3 - 1 {
                    assert!(Instant::now() < deadline, "injected tasks never started");
                    std::hint::spin_loop();
                }
            }

            let mut ids = Vec::new();
            for task in tasks {
                ids.push(task.await.unwrap());
            }
            let distinct = ids.iter().collect::<HashSet<_>>();
            assert!(distinct.len() <= count);
            if count == 1 {
                assert!(ids.iter().all(|id| *id == root));
            } else {
                assert_eq!(ids[0], root, "a quiet worker keeps its spawn");
                assert!(ids[1..].iter().all(|id| *id != root));
            }
            state.set(1);
        });
        assert_eq!(borrowed.get(), 1);
        assert!(Local::current().is_none());
    }
}

/// A wake of an idle task queues it on the waker's worker, so a pair started
/// on two workers converges onto the first waker's worker and stays there.
#[test]
fn test_chatty_pair_converges_onto_one_worker() {
    Runner::new(config().with_worker_threads(2)).start(|context| async move {
        let (request, mut requests) = commonware_utils::channel::mpsc::channel::<ThreadId>(1);
        let (response, mut responses) = commonware_utils::channel::mpsc::channel::<ThreadId>(1);

        // The responder starts on worker one. That worker parks only after the
        // responder's first poll returns, which leaves the responder idle. A
        // wake that finds a task mid-poll leaves it on its poller instead.
        let idle = Arc::new(AtomicBool::new(false));
        let (responder, responder_first) = spawn_elsewhere(&context, {
            let pool = context.shared.pool.clone();
            let idle = idle.clone();
            async move {
                on_next_park(&pool, 1, ParkPoint::BeforeIdle, move || {
                    idle.store(true, Ordering::Release);
                });
                let mut seen = Vec::new();
                while let Some(requester) = requests.recv().await {
                    seen.push((requester, thread::current().id()));
                    response.send(thread::current().id()).await.unwrap();
                }
                seen
            }
        });
        let deadline = Instant::now() + TEST_TIMEOUT;
        while !idle.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "responder never went idle");
            std::hint::spin_loop();
        }

        // The requester starts here. Its first request moves the responder
        // here, after which each task is woken only by the other on this
        // worker while idle.
        let requester = context.child("requester").spawn(move |_| async move {
            let mut seen = Vec::new();
            for _ in 0..200 {
                let sent_from = thread::current().id();
                request.send(sent_from).await.unwrap();
                let responder = responses.recv().await.unwrap();
                seen.push((sent_from, responder));
            }
            seen
        });

        let requester_seen = requester.await.unwrap();
        let responder_seen = responder.await.unwrap();
        let home = thread::current().id();
        assert_ne!(responder_first, home);
        assert!(
            requester_seen
                .iter()
                .chain(&responder_seen)
                .all(|(a, b)| *a == home && *b == home),
            "pair did not converge"
        );
    });
}

#[test]
fn test_shutdown_destroys_tasks_on_a_worker() {
    struct OwnedDrop(Arc<AtomicUsize>);
    impl Drop for OwnedDrop {
        fn drop(&mut self) {
            assert!(Local::current().is_some());
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for panic_root in [false, true] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = dropped.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_worker_threads(4)).start(|context| async move {
                let mut ready = Vec::new();
                for _ in 0..12 {
                    let (started, receiver) = oneshot::channel();
                    ready.push(receiver);
                    let dropped = dropped.clone();
                    context.child("pending").spawn(move |context| async move {
                        let _guard = OwnedDrop(dropped);
                        let sleep = context.sleep(Duration::from_secs(3600));
                        let mut sleep = pin!(sleep);
                        assert!(futures::poll!(&mut sleep).is_pending());
                        started.send(()).unwrap();
                        sleep.await;
                    });
                }
                for receiver in ready {
                    receiver.await.unwrap();
                }
                assert!(!panic_root, "root failure");
            });
        }));
        assert_eq!(result.is_err(), panic_root);
        assert_eq!(observed.load(Ordering::Relaxed), 12);
    }
}

#[test]
fn test_partial_startup_failure_releases_all_workers() {
    for launch in [false, true] {
        for catch in [false, true] {
            POOL_FAIL_AT.set(Some((2, launch)));
            let called = Cell::new(false);
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_worker_threads(4).with_catch_panics(catch)).start(|_| {
                    called.set(true);
                    async {}
                });
            }));
            let panic = result.expect_err("partial pool startup must fail");
            assert!(extract_panic_message(&*panic).contains("injected"));
            assert!(!called.get());
            assert!(POOL_SHARED.with(|slot| slot.borrow().upgrade().is_none()));
            assert!(Local::current().is_none());
        }
    }
}

#[test]
fn test_network_and_storage_on_multiple_workers() {
    Runner::new(config().with_worker_threads(2)).start(|context| async move {
        let mut listener = context.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = context.child("server").spawn(move |_| async move {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let received = stream.recv(4).await.unwrap();
            assert_eq!(received.clone().coalesce().as_ref(), b"ping");
            sink.send(received).await.unwrap();
        });
        let (client, _) = spawn_elsewhere(&context, {
            let context = context.child("client");
            async move {
                let (mut sink, mut stream) = context.dial(address).await.unwrap();
                sink.send(b"ping".to_vec()).await.unwrap();
                let received = stream.recv(4).await.unwrap();
                let (blob, _) = context.open("multi", b"blob").await.unwrap();
                blob.write_at(0, received, WriteOptions::default())
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
                let data = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
                assert_eq!(data.coalesce().as_ref(), b"ping");
            }
        });
        client.await.unwrap();
        server.await.unwrap();
    });
}

#[test]
fn test_remote_task_panic_respects_policy() {
    for catch in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_worker_threads(2).with_catch_panics(catch)).start(
                |context| async move {
                    let (task, _) = spawn_elsewhere(&context, async {
                        panic!("remote ordinary task failed");
                    });
                    if catch {
                        assert!(matches!(task.await, Err(Error::Exited)));
                        let survivor = context.child("survivor").spawn(|_| async { 7 });
                        assert_eq!(survivor.await.unwrap(), 7);
                    } else {
                        pending::<()>().await;
                    }
                },
            );
        }));
        assert_eq!(result.is_err(), !catch);
    }
}

#[test]
fn test_shutdown_drains_queued_writes_on_every_ring() {
    let cfg = config()
        .with_worker_threads(2)
        .with_ring_config(RingConfig {
            size: 1,
            ..Default::default()
        });
    Runner::new(cfg.clone()).start(|context| async move {
        for actor in 0_u8..4 {
            let write = {
                let context = context.child("writer");
                async move {
                    let (blob, _) = context.open("retained", &[actor]).await.unwrap();
                    for offset in 0..8 {
                        let write = blob.write_at(offset, vec![actor + 1], WriteOptions::default());
                        let mut write = pin!(write);
                        // Dropping a registered write retains its kernel work,
                        // including submissions queued behind the single slot.
                        let _ = futures::poll!(&mut write);
                    }
                    pending::<()>().await;
                }
            };

            // The first writer stays here, and the others start on worker one.
            if actor == 0 {
                context.child("writer").spawn(move |_| write);
            } else {
                let _ = spawn_elsewhere(&context, write);
            }
        }
        // The first writer runs once the root yields.
        reschedule().await;
    });
    Runner::new(cfg).start(|context| async move {
        for actor in 0_u8..4 {
            let (blob, size) = context.open("retained", &[actor]).await.unwrap();
            assert_eq!(size, 8);
            let data = blob.read_at(0, 8, ReadOptions::default()).await.unwrap();
            assert_eq!(data.coalesce().as_ref(), &[actor + 1; 8]);
        }
    });
}

#[test]
fn test_remote_driver_failure_interrupts_root_even_when_task_panics_are_caught() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    peer.write_all(b"x").unwrap();
    let request = Request::Recv(RecvRequest {
        fd: Arc::new(socket.into()),
        buf: IoBufMut::with_capacity(1),
        offset: 0,
        len: 1,
        exact: true,
        deadline: None,
    });
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config().with_worker_threads(2).with_catch_panics(true)).start(
            |context| async move {
                let _ = spawn_elsewhere(&context, async move {
                    let _fault = fail_after_completion(
                        Local::current().unwrap().borrow().driver.as_ref().unwrap(),
                    );
                    Operation::register(request).await.unwrap();
                    pending::<()>().await;
                });
                pending::<()>().await;
            },
        );
    }));
    let panic = result.expect_err("losing a pool worker must interrupt the root");
    assert!(extract_panic_message(&*panic).contains("injected service failure after completion"));
    assert!(Local::current().is_none());
}

#[test]
fn test_wake_from_another_runtime_stays_in_its_own_pool() {
    // Runtime A owns the waiting task. Runtime B's worker performs the wake
    // from inside one of its own task polls, so the current thread has a
    // worker, but one of the wrong pool.
    let (to_b, from_a) = mpsc::channel::<oneshot::Sender<()>>();
    let (report, reports) = mpsc::channel::<(ThreadId, ThreadId)>();
    let (to_a, from_b) = mpsc::channel::<ThreadId>();
    let a = thread::spawn(move || {
        Runner::new(config().with_worker_threads(2)).start(|context| async move {
            let (wake, waiter) = oneshot::channel::<()>();
            let task = context.child("waiter").spawn(|_| async move {
                let before = thread::current().id();
                waiter.await.unwrap();
                (before, thread::current().id())
            });

            // The waiter starts on this worker and waits before the root
            // runs again, so runtime B's send has a waker to wake.
            reschedule().await;
            to_b.send(wake).unwrap();
            report.send(task.await.unwrap()).unwrap();
            to_a.send(thread::current().id()).unwrap();
        });
    });
    let sender = Runner::new(config().with_worker_threads(2)).start(|context| async move {
        let wake = from_a.recv().unwrap();
        context
            .child("sender")
            .spawn(|_| async move {
                wake.send(()).unwrap();
                thread::current().id()
            })
            .await
            .unwrap()
    });
    let (before, after) = reports.recv().unwrap();
    let _ = from_b.recv().unwrap();
    a.join().unwrap();
    assert_ne!(after, sender, "task polled on another runtime's worker");
    assert_ne!(before, sender);
}

#[test]
fn test_worker_count_scales_default_buffer_pools() {
    let cfg = config().with_worker_threads(4);
    assert_eq!(
        cfg.resolved_network_buffer_pool_config()
            .parallelism()
            .get(),
        4
    );
    assert_eq!(
        cfg.resolved_storage_buffer_pool_config()
            .parallelism()
            .get(),
        4
    );
    let explicit = BufferPoolConfig::for_network().with_parallelism(NZUsize!(2));
    let cfg = cfg.with_network_buffer_pool_config(explicit);
    assert_eq!(
        cfg.resolved_network_buffer_pool_config()
            .parallelism()
            .get(),
        2
    );
}

/// A task registers a receive and a sleep on worker zero, then a wake from
/// another worker moves it there. Polled on that worker, both stay pending
/// through a forward from worker zero, which holds the registrations, and the
/// receive's result arrives through its forward.
#[test]
fn test_operation_and_sleep_follow_their_task_to_another_worker() {
    Runner::new(config().with_worker_threads(2)).start(|context| async move {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let (move_task, moved) = oneshot::channel::<()>();
        let (release, released) = oneshot::channel::<()>();

        // The task registers here, on worker zero, then waits for a wake.
        let mover = context.child("mover").spawn(move |context| async move {
            let registered = thread::current().id();
            let fd: Arc<OwnedFd> = Arc::new(socket.into());
            let mut recv = Operation::register(Request::Recv(RecvRequest {
                fd,
                buf: IoBufMut::with_capacity(1),
                offset: 0,
                len: 1,
                exact: true,
                deadline: None,
            }));
            let sleep = context.sleep(Duration::from_secs(3600));
            let mut sleep = pin!(sleep);
            assert!(futures::poll!(&mut recv).is_pending());
            assert!(futures::poll!(&mut sleep).is_pending());

            // The wake comes from the other worker, which polls this task and
            // forwards both registrations from worker zero.
            moved.await.unwrap();
            let polled = thread::current().id();
            assert!(futures::poll!(&mut recv).is_pending());
            assert!(futures::poll!(&mut sleep).is_pending());
            released.await.unwrap();
            let received = recv.await.unwrap();
            (registered, polled, received)
        });
        reschedule().await;

        let (waker, other) = spawn_elsewhere(&context, async move {
            move_task.send(()).unwrap();
        });
        waker.await.unwrap();
        peer.write_all(b"x").unwrap();
        release.send(()).unwrap();

        let (registered, polled, received) = mover.await.unwrap();
        assert_eq!(registered, thread::current().id());
        assert_eq!(polled, other);
        assert!(matches!(received, RequestOutput::Recv(Ok((_, 1)))));
        drop(peer);
    });
}

/// A wake on a pool worker queues the woken task on that worker, even while
/// another worker is parked and could take it from the inject queue.
#[test]
fn test_wake_on_a_pool_worker_keeps_the_task_there() {
    Runner::new(config().with_worker_threads(3)).start(|context| async move {
        let (wake, woken) = oneshot::channel::<()>();
        let polled_on = Arc::new(Mutex::new(None));

        // The sleeper waits on worker zero until the wake.
        let sleeper = context.child("sleeper").spawn({
            let polled_on = polled_on.clone();
            move |_| async move {
                woken.await.unwrap();
                *polled_on.lock() = Some(thread::current().id());
            }
        });
        reschedule().await;

        // The waker runs on another worker, wakes the sleeper, and keeps its
        // worker busy while another worker stays parked.
        let (waker, waker_thread) = spawn_elsewhere(&context, async move {
            wake.send(()).unwrap();
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until {
                std::hint::spin_loop();
            }
        });
        waker.await.unwrap();
        sleeper.await.unwrap();
        assert_eq!(*polled_on.lock(), Some(waker_thread));
    });
}

/// Start a task on worker one that holds a receive in its ring when
/// `in_ring`, so worker one waits in its ring rather than on its futex.
/// Returns worker one's thread and the receive's peer.
fn occupy_worker_one(context: &Context, in_ring: bool) -> (ThreadId, Option<UnixStream>) {
    if !in_ring {
        return (spawn_elsewhere(context, async {}).1, None);
    }
    let (socket, peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    let (_, other) = spawn_elsewhere(context, async move {
        let fd: Arc<OwnedFd> = Arc::new(socket.into());
        let _ = Operation::register(Request::Recv(RecvRequest {
            fd,
            buf: IoBufMut::with_capacity(1),
            offset: 0,
            len: 1,
            exact: true,
            deadline: None,
        }))
        .await;
    });
    (other, Some(peer))
}

/// A push racing a worker's park reaches it in either wait. A push before the
/// worker publishes itself idle finds no idle bit, so the worker's look at the
/// inject queue after publishing must find it. A push after the worker finds
/// the queue empty claims its idle bit and wakes it. Either way the worker
/// leaves the idle set.
#[test]
fn test_push_racing_a_park_reaches_the_worker() {
    for point in [ParkPoint::BeforeIdle, ParkPoint::BeforeWait] {
        for in_ring in [false, true] {
            Runner::new(config().with_worker_threads(2)).start(|context| async move {
                let pool = context.shared.pool.clone();
                let (other, _peer) = occupy_worker_one(&context, in_ring);

                // Only worker one can start the target while the root holds
                // this worker.
                let started = Arc::new(Mutex::new(None));
                let idle = Arc::new(AtomicBool::new(true));
                on_next_park(&pool, 1, point, {
                    let context = context.child("target");
                    let started = started.clone();
                    let idle = idle.clone();
                    let pool = pool.clone();
                    move || {
                        thread::spawn(move || {
                            context.spawn(move |_| async move {
                                idle.store(pool.is_idle(1), Ordering::SeqCst);
                                *started.lock() = Some(thread::current().id());
                            });
                        })
                        .join()
                        .unwrap();
                    }
                });

                // Waking worker one sends it through its loop to that park.
                let _ = spawn_elsewhere(&context, async {});
                assert_eq!(wait_started(&started), other);
                assert!(
                    !idle.load(Ordering::SeqCst),
                    "busy worker left in the idle set"
                );
            });
        }
    }
}

/// A spin outlasting the test's timeout, so only a push's wake signal can end
/// it, as no message is published.
fn endless_spinner() -> SpinnerConfig {
    SpinnerConfig {
        budget_us: 60_000_000,
        max_budget_us: 60_000_000,
        quick_wake_us: 60_000_000,
    }
}

/// A push into the inject queue ends a spinning worker's spin through its
/// wake signal.
#[test]
fn test_push_ends_a_spin_through_the_wake_signal() {
    let cfg = config()
        .with_worker_threads(2)
        .with_idle_spinner(endless_spinner());
    Runner::new(cfg).start(|context| async move {
        let (_, other) = spawn_elsewhere(&context, async {});
        for _ in 0..20 {
            let (_, thread) = spawn_elsewhere(&context, async {});
            assert_eq!(thread, other);
        }
    });
}

/// A worker whose spin ended on a push's wake signal consumes it, so once idle
/// again it spins out and sleeps on its futex rather than spinning on the
/// stale signal forever.
#[test]
fn test_spinning_worker_sleeps_after_a_signalled_spin() {
    let spinner = SpinnerConfig {
        budget_us: 1_000,
        max_budget_us: 1_000,
        quick_wake_us: 1_000,
    };
    let cfg = config().with_worker_threads(2).with_idle_spinner(spinner);
    Runner::new(cfg).start(|context| async move {
        let pool = context.shared.pool.clone();
        let (_, other) = spawn_elsewhere(&context, async {});
        for _ in 0..5 {
            let (_, thread) = spawn_elsewhere(&context, async {});
            assert_eq!(thread, other);
        }
        let deadline = Instant::now() + TEST_TIMEOUT;
        while state_bits(&pool.mailbox(1).waker) & 1 == 0 {
            assert!(Instant::now() < deadline, "worker one never slept");
            std::hint::spin_loop();
        }
    });
}

/// A worker whose own queue never runs dry still takes from the inject queue
/// every configured interval, and takes a share of it, so a burst of foreign
/// wakes waits about one interval in all rather than one interval each.
#[test]
fn test_busy_worker_takes_a_share_of_the_inject_queue_every_interval() {
    const BURST: usize = 64;
    for interval in [config().global_queue_interval(), 4] {
        Runner::new(config().with_global_queue_interval(interval)).start(|context| async move {
            let stop = Arc::new(AtomicBool::new(false));
            let yields = Arc::new(AtomicUsize::new(0));
            let yielder = context.child("yielder").spawn({
                let stop = stop.clone();
                let yields = yields.clone();
                move |_| async move {
                    while !stop.load(Ordering::Relaxed) {
                        let count = yields.fetch_add(1, Ordering::Relaxed);
                        assert!(count < 100_000, "inject queue starved");
                        reschedule().await;
                    }
                }
            });

            // Idle tasks waiting for a wake from outside the pool.
            let lags = Arc::new(Mutex::new(Vec::new()));
            let mut senders = Vec::new();
            let mut waiters = Vec::new();
            for _ in 0..BURST {
                let (sender, receiver) = oneshot::channel::<usize>();
                senders.push(sender);
                let lags = lags.clone();
                let yields = yields.clone();
                waiters.push(context.child("waiter").spawn(move |_| async move {
                    let before = receiver.await.unwrap();
                    lags.lock().push(yields.load(Ordering::Relaxed) - before);
                }));
            }
            for _ in 0..4 {
                reschedule().await;
            }

            let before = yields.load(Ordering::Relaxed);
            thread::spawn(move || {
                for sender in senders {
                    sender.send(before).unwrap();
                }
            })
            .join()
            .unwrap();
            for waiter in waiters {
                waiter.await.unwrap();
            }
            stop.store(true, Ordering::Relaxed);
            yielder.await.unwrap();

            let lags = lags.lock();
            assert_eq!(lags.len(), BURST);
            let last = lags.iter().max().unwrap();
            assert!(
                *last <= 2 * interval as usize,
                "last foreign wake waited {last} polls with interval {interval}"
            );
        });
    }
}

/// A task that completes on a worker other than the one that spawned it
/// leaves the task set there.
#[test]
fn test_task_completing_away_from_its_spawner_retires() {
    Runner::new(config().with_worker_threads(2)).start(|context| async move {
        let tasks = || context.shared.tasks.live();
        let baseline = tasks();
        let (finish, finished) = oneshot::channel::<()>();
        let task = context.child("traveller").spawn(|_| async move {
            let spawned_on = thread::current().id();
            finished.await.unwrap();
            (spawned_on, thread::current().id())
        });
        reschedule().await;
        assert_eq!(tasks(), baseline + 1);

        let (waker, other) = spawn_elsewhere(&context, async move {
            finish.send(()).unwrap();
        });
        waker.await.unwrap();
        let (spawned_on, completed_on) = task.await.unwrap();
        assert_eq!(spawned_on, thread::current().id());
        assert_eq!(completed_on, other);

        // The handle resolves inside the final poll, and the worker removes
        // the task once that poll returns.
        let deadline = Instant::now() + TEST_TIMEOUT;
        while tasks() != baseline {
            assert!(Instant::now() < deadline, "completed task not retired");
            reschedule().await;
        }
    });
}

/// Shutdown while a task's poll runs on another worker. That poll can still
/// forward a sleep registered on worker zero, whose mailbox stays open until
/// every pool worker has finished polling. Teardown leaves the future to the
/// poller, which drops it on its own thread once the poll returns.
#[test]
fn test_shutdown_while_a_task_is_mid_poll_on_another_worker() {
    struct Dropped(Arc<Mutex<Option<ThreadId>>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            assert!(Local::current().is_some());
            *self.0.lock() = Some(thread::current().id());
        }
    }

    let dropped = Arc::new(Mutex::new(None));
    let polled = Arc::new(Mutex::new(None));
    let forwarded = Arc::new(Mutex::new(None::<String>));
    Runner::new(config().with_worker_threads(2)).start(|context| {
        let dropped = dropped.clone();
        let polled = polled.clone();
        let forwarded = forwarded.clone();
        async move {
            // Registered on worker zero by this first poll.
            let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
            assert!(futures::poll!(&mut sleep).is_pending());

            // Registered without a handle, so no abort ends the task: only
            // teardown's clear can, while the poll runs.
            let shared = context.shared.clone();
            let this: Arc<OnceLock<Task>> = Arc::new(OnceLock::new());
            let future = {
                let shared = shared.clone();
                let this = this.clone();
                let guard = Dropped(dropped);
                let started = polled.clone();
                poll_fn(move |_| {
                    let _ = &guard;
                    *started.lock() = Some(thread::current().id());
                    let deadline = Instant::now() + TEST_TIMEOUT;
                    while !shared.tasks.is_closed() {
                        assert!(Instant::now() < deadline, "the runner never closed");
                        std::hint::spin_loop();
                    }

                    // Give worker zero time to reach its drain, then poll the
                    // sleep, which forwards from worker zero.
                    thread::sleep(Duration::from_millis(20));
                    let waker = futures::task::noop_waker();
                    let poll = catch_unwind(AssertUnwindSafe(|| {
                        sleep.as_mut().poll(&mut TaskContext::from_waker(&waker))
                    }));
                    *forwarded.lock() = Some(match poll {
                        Ok(Poll::Pending) => "pending".into(),
                        Ok(Poll::Ready(())) => "ready".into(),
                        Err(panic) => extract_panic_message(&*panic),
                    });

                    // Return pending only once teardown has cleared the task
                    // during this poll.
                    while !cancelled(this.get().unwrap()) {
                        assert!(Instant::now() < deadline, "teardown never cleared");
                        std::hint::spin_loop();
                    }
                    Poll::<()>::Pending
                })
            };
            let (task, runnable) = Task::new(future, &shared.tasks, Arc::downgrade(&shared.pool));
            assert!(this.set(task.clone()).is_ok());
            assert!(shared.tasks.insert(task).is_ok());

            // From outside the pool, so the runnable goes to the inject queue
            // and worker one starts it while the root holds this worker.
            thread::spawn(move || runnable.spawn()).join().unwrap();
            let other = wait_started(&polled);
            assert_ne!(other, thread::current().id());
        }
    });
    assert_eq!(forwarded.lock().as_deref(), Some("pending"));
    let poller = polled.lock().expect("task polled");
    assert_eq!(
        *dropped.lock(),
        Some(poller),
        "future dropped off its poller"
    );
}

/// Shutdown while worker zero holds a forward it took from its mailbox but has
/// not applied. A batch of root wakes ahead of the forward completes the root
/// first. The task that sent the forward is still mid-poll on another worker,
/// so its sleep stays pending until every pool worker has finished polling.
#[test]
fn test_shutdown_retains_a_taken_forward_until_polling_ends() {
    let forwarded = Arc::new(Mutex::new(None::<String>));
    Runner::new(config().with_worker_threads(2)).start(|context| {
        let forwarded = forwarded.clone();
        async move {
            // Registered on worker zero by this first poll.
            let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
            assert!(futures::poll!(&mut sleep).is_pending());
            let root = poll_fn(|cx| Poll::Ready(cx.waker().clone())).await;

            // Registered without a handle, so no abort ends the task: only
            // teardown's clear can, while the poll runs.
            let shared = context.shared.clone();
            let this: Arc<OnceLock<Task>> = Arc::new(OnceLock::new());
            let queued = Arc::new(AtomicBool::new(false));
            let future = {
                let this = this.clone();
                let queued = queued.clone();
                poll_fn(move |_| {
                    let waker = futures::task::noop_waker();
                    let mut cx = TaskContext::from_waker(&waker);

                    // Queue a full batch of root wakes on worker zero, then
                    // the sleep's forward behind them.
                    for _ in 0..BATCH_SIZE {
                        root.wake_by_ref();
                    }
                    assert!(sleep.as_mut().poll(&mut cx).is_pending());
                    queued.store(true, Ordering::Release);

                    // Teardown clears this task once worker zero has begun
                    // its cleanup. Poll the sleep again while still mid-poll.
                    let deadline = Instant::now() + TEST_TIMEOUT;
                    while !cancelled(this.get().unwrap()) {
                        assert!(Instant::now() < deadline, "teardown never cleared");
                        std::hint::spin_loop();
                    }
                    let poll = catch_unwind(AssertUnwindSafe(|| sleep.as_mut().poll(&mut cx)));
                    *forwarded.lock() = Some(match poll {
                        Ok(Poll::Pending) => "pending".into(),
                        Ok(Poll::Ready(())) => "ready".into(),
                        Err(panic) => extract_panic_message(&*panic),
                    });
                    Poll::<()>::Pending
                })
            };
            let (task, runnable) = Task::new(future, &shared.tasks, Arc::downgrade(&shared.pool));
            assert!(this.set(task.clone()).is_ok());
            assert!(shared.tasks.insert(task).is_ok());

            // From outside the pool, so worker one starts it while the root
            // holds this worker until every message is queued, and this worker
            // takes the wakes and the forward in one batch.
            thread::spawn(move || runnable.spawn()).join().unwrap();
            let deadline = Instant::now() + TEST_TIMEOUT;
            while !queued.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "messages never queued");
                std::hint::spin_loop();
            }

            // Return pending once without waking, so the batch's root wakes
            // poll the root again and it completes before the forward applies.
            let mut yielded = false;
            poll_fn(move |_| {
                if mem::replace(&mut yielded, true) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    });
    assert_eq!(forwarded.lock().as_deref(), Some("pending"));
}

/// Teardown clears two idle tasks whose destructors wake each other, so
/// whichever is cleared first wakes the other while it is still idle, on a
/// closing worker. The closing worker's wake goes to the closed inject queue,
/// which discards it, rather than leaving a runnable in its own queue.
#[test]
fn test_wake_from_a_destructor_during_teardown_leaves_no_runnable() {
    struct WakeOther(Arc<Mutex<Option<Waker>>>);
    impl Drop for WakeOther {
        fn drop(&mut self) {
            if let Some(waker) = self.0.lock().take() {
                waker.wake();
            }
        }
    }
    for workers in [1, 2] {
        Runner::new(config().with_worker_threads(workers)).start(|context| async move {
            let slots = [(); 2].map(|_| Arc::new(Mutex::new(None::<Waker>)));
            for (own, other) in [(0, 1), (1, 0)] {
                let own = slots[own].clone();
                let guard = WakeOther(slots[other].clone());

                // Registered without a handle, so no abort wakes it first.
                let future = poll_fn(move |cx| {
                    let _ = &guard;
                    *own.lock() = Some(cx.waker().clone());
                    Poll::<()>::Pending
                });
                let shared = context.shared.clone();
                assert!(
                    shared
                        .tasks
                        .register(future, Arc::downgrade(&shared.pool))
                        .is_ok()
                );
            }
            while slots.iter().any(|slot| slot.lock().is_none()) {
                reschedule().await;
            }
        });
    }
}

/// A waker whose destruction panics, so releasing its timer fails the worker
/// that holds it.
struct PanicOnDrop;

impl ArcWake for PanicOnDrop {
    fn wake_by_ref(_: &Arc<Self>) {}
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        if !thread::panicking() {
            panic!("injected pool worker failure during shutdown");
        }
    }
}

/// A pool worker that fails during shutdown, after the pool has closed, still
/// fails the runner.
#[test]
fn test_pool_worker_failure_during_shutdown_fails_the_runner() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config().with_worker_threads(2)).start(|context| async move {
            let (handle, _) = spawn_elsewhere(&context, {
                let context = context.child("faulty");
                async move {
                    let sleep = context.sleep(Duration::from_secs(3600));
                    let mut sleep = pin!(sleep);
                    let waker = waker(Arc::new(PanicOnDrop));
                    assert!(
                        sleep
                            .as_mut()
                            .poll(&mut TaskContext::from_waker(&waker))
                            .is_pending()
                    );
                    drop(waker);
                    pending::<()>().await;
                }
            });
            mem::forget(handle);
        });
    }));
    let panic = result.expect_err("a pool worker failure during shutdown must fail the runner");
    assert!(
        extract_panic_message(&*panic).contains("injected pool worker failure during shutdown")
    );
}

/// An unwind between the root and the runner's shutdown still stops the other
/// pool workers, so worker zero's cleanup does not wait for them forever.
#[test]
fn test_unwind_before_shutdown_stops_the_pool() {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_worker_threads(2)).start(|_| {
                BEFORE_ABORT.with(|slot| {
                    *slot.borrow_mut() =
                        Some(Box::new(|| panic!("injected unwind before the abort")));
                });
                async {}
            })
        }));
        let _ = done.send(result.map_err(|panic| extract_panic_message(&*panic)));
    });
    let result = finished
        .recv_timeout(TEST_TIMEOUT)
        .expect("worker zero waited for a pool worker it never stopped");
    assert!(
        result
            .unwrap_err()
            .contains("injected unwind before the abort")
    );
}

/// A task panic published while the root's state is destroyed is not
/// observed: task panics interrupt only a running root.
#[test]
fn test_task_panic_during_root_destruction_is_not_observed() {
    struct PublishOnDrop(Option<Panicker>);
    impl Future for PublishOnDrop {
        type Output = u8;
        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<u8> {
            Poll::Ready(7)
        }
    }
    impl Drop for PublishOnDrop {
        fn drop(&mut self) {
            self.0
                .take()
                .unwrap()
                .notify(Box::new("published during root destruction"));
        }
    }
    for workers in [1, 2] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(
                config()
                    .with_worker_threads(workers)
                    .with_catch_panics(false),
            )
            .start(|context| PublishOnDrop(Some(context.shared.panicker.clone())))
        }));
        assert_eq!(
            result.map_err(|panic| extract_panic_message(&*panic)),
            Ok(7)
        );
    }
}

/// Wakes a stored task waker, which queues that task on the current worker,
/// then panics, failing the worker with the task's runnable still queued.
struct WakeThenPanic(Mutex<Option<Waker>>);

impl ArcWake for WakeThenPanic {
    fn wake_by_ref(this: &Arc<Self>) {
        if let Some(waker) = this.0.lock().take() {
            waker.wake();
        }
        panic!("injected pool worker callback failure");
    }
}

/// A pool worker that fails while the pool is open, with a runnable still in
/// its ready queue, interrupts the root, and shutdown discards that runnable
/// once the pool has closed.
#[test]
fn test_failed_pool_worker_with_queued_runnables_shuts_down() {
    for catch in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let cfg = config().with_worker_threads(2).with_catch_panics(catch);
            Runner::new(cfg).start(|context| async move {
                let (handle, _) = spawn_elsewhere(&context, {
                    let context = context.child("faulty");
                    async move {
                        // Task A goes idle on this worker, leaving its waker.
                        let trigger = Arc::new(WakeThenPanic(Mutex::new(None)));
                        let a = context.child("a").spawn({
                            let trigger = trigger.clone();
                            move |_| {
                                poll_fn(move |cx| {
                                    *trigger.0.lock() = Some(cx.waker().clone());
                                    Poll::<()>::Pending
                                })
                            }
                        });
                        reschedule().await;
                        assert!(trigger.0.lock().is_some(), "a was not polled here");

                        // The timer's callback wakes A into this worker's
                        // ready queue, then fails the worker.
                        let sleep = context.sleep(Duration::from_millis(20));
                        let mut sleep = pin!(sleep);
                        let waker = waker(trigger);
                        assert!(
                            sleep
                                .as_mut()
                                .poll(&mut TaskContext::from_waker(&waker))
                                .is_pending()
                        );
                        let _ = a.await;
                    }
                });
                let _ = handle.await;
                pending::<()>().await;
            });
        }));
        let panic = result.expect_err("a pool worker failure must fail the runner");
        assert!(extract_panic_message(&*panic).contains("injected pool worker callback failure"));
        assert!(Local::current().is_none());
    }
}

/// Pending operations registered on several pool workers leave the aggregate
/// gauge at zero once shutdown has retired them.
#[test]
fn test_pending_operations_gauge_returns_to_zero_across_workers() {
    let mut peers = Vec::new();
    let shared = Runner::new(config().with_worker_threads(4)).start(|context| {
        let mut sockets = Vec::new();
        for _ in 0..6 {
            let (socket, peer) = UnixStream::pair().unwrap();
            socket.set_nonblocking(true).unwrap();
            sockets.push(socket);
            peers.push(peer);
        }
        async move {
            for (index, socket) in sockets.into_iter().enumerate() {
                let task = async move {
                    let fd: Arc<OwnedFd> = Arc::new(socket.into());
                    let _ = Operation::register(Request::Recv(RecvRequest {
                        fd,
                        buf: IoBufMut::with_capacity(1),
                        offset: 0,
                        len: 1,
                        exact: true,
                        deadline: None,
                    }))
                    .await;
                };
                if index == 0 {
                    context.child("here").spawn(move |_| task);
                    reschedule().await;
                } else {
                    let (handle, _) = spawn_elsewhere(&context, task);
                    mem::forget(handle);
                }
            }

            // Let every worker submit its receive.
            context.sleep(Duration::from_millis(20)).await;
            assert!(context.shared.pending_operations.get() > 0);
            context.shared.clone()
        }
    });
    assert_eq!(shared.pending_operations.get(), 0);
    drop(peers);
}
