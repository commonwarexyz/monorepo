//! Runtime configuration, task placement, worker reservations, and cleanup tests.

use super::{
    super::{
        driver::tests::fail_after_completion,
        operation::Operation,
        request::{RecvRequest, Request},
    },
    *,
};
use crate::{
    Blob as _, IoBufMut, Metrics as _, Resolver as _, Runner as _, Storage as _, WriteOptions,
    utils::extract_panic_message,
};
use futures::{
    FutureExt,
    executor::block_on,
    future::{pending, poll_fn},
    task::{ArcWake, waker},
};
use std::{
    cell::Cell,
    fs::{self, File},
    future::{Pending, Ready},
    io::{self, Write as _},
    os::unix::net::UnixStream,
    panic::panic_any,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    task::Wake,
    thread,
};

/// Bound individual synchronous channel waits within the test process.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

thread_local! {
    /// Whether the current test root requires progress without entering the idle path.
    static FORBID_PARK: Cell<bool> = const { Cell::new(false) };
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

/// Disable idle spinning so tests exercise the worker's parking paths.
fn config() -> Config {
    Config::new().with_idle_spinner(SpinnerConfig::disabled())
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

    for invalid in invalid_layouts.into_iter().chain([invalid_spinner]) {
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

                    // Ordinary children return to the original worker even when
                    // their parent owns a dedicated or blocking worker.
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
fn test_closed_origin_skips_local_and_foreign_factories() {
    for foreign in [false, true] {
        Runner::new(config()).start(|context| async move {
            if foreign {
                let mailbox = context.origin.upgrade().unwrap();
                drop(mailbox.close());
            } else {
                // The local spawn check must see closure without consulting
                // the mailbox, which remains open until worker shutdown.
                Local::current().unwrap().borrow_mut().closing = true;
            }

            // Test the caller-local check and the foreign mailbox check separately.
            let spawn = move || {
                context.spawn(|_| -> Ready<()> {
                    panic!("a closed origin must not invoke its factory");
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
            // preserve its terminal resources before closing ordinary observation.
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

    /// How far the ordinary tasks progress before the root returns.
    #[derive(Clone, Copy, Debug)]
    enum Placement {
        /// Registered locally but never polled.
        Local,
        /// Published from another thread but not taken from the mailbox.
        Foreign,
        /// Polled once and suspended before shutdown.
        Pending,
    }

    for placement in [Placement::Local, Placement::Foreign, Placement::Pending] {
        let drops = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let gauge = raw::Gauge::default();
        let handles = Runner::new(config()).start(|context| {
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
                            started.send(()).unwrap();
                            pending::<()>().await;
                        },
                        MetricHandle::new(gauge.clone()),
                        context.shared.panicker.clone(),
                        tree.clone(),
                    );
                    tree.register(handle.aborter().unwrap());
                    let task: BoxedTask = Box::pin(future);
                    if matches!(placement, Placement::Foreign) {
                        let origin = context.origin.clone();
                        thread::spawn(move || assert!(Tasks::register(&origin, task).is_ok()))
                            .join()
                            .unwrap();
                    } else {
                        assert!(Tasks::register(&context.origin, task).is_ok());
                    }

                    handles.push(handle);
                    receivers.push(ready);
                }

                // Only this case lets the futures reach their suspension point.
                if matches!(placement, Placement::Pending) {
                    for ready in receivers {
                        ready.await.unwrap();
                    }
                }

                handles
            }
        });

        assert_eq!(drops.load(Ordering::Relaxed), 2, "placement={placement:?}");
        assert_eq!(
            cancelled.load(Ordering::Relaxed),
            2,
            "placement={placement:?}"
        );
        assert_eq!(gauge.get(), 0, "placement={placement:?}");

        for handle in handles {
            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }
    }
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
// Retain the task handle to check its result after the runner closes its mailbox.
#[allow(clippy::async_yields_async)]
fn test_queued_foreign_task_disposal_is_contained_at_shutdown() {
    /// Record disposal before raising a panic from an unpolled task's captures.
    struct PanickingDrop(Arc<AtomicUsize>);

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("queued task destructor failed");
        }
    }

    for catch in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = PanickingDrop(drops.clone());

        let handle = Runner::new(config().with_catch_panics(catch)).start(|context| async move {
            let remote = context.child("queued_foreign");

            // Joining only the publisher leaves its accepted task in the
            // mailbox when this root completes its first poll.
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

    let drops = Arc::new(AtomicUsize::new(0));
    let observed = drops.clone();
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
            panic!("primary root panic");
        });
    }));

    assert_eq!(
        extract_panic_message(&*result.unwrap_err()),
        "primary root panic"
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    drop(escaped);
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
