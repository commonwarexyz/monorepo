//! Controlled checks of worker admission, cleanup, and failure publication.

use super::{
    super::{
        operation::Operation,
        request::{RecvRequest, Request},
    },
    *,
};
use crate::{
    Blob as _, IoBufMut, Runner as _, Storage as _, WriteOptions, utils::extract_panic_message,
};
use futures::FutureExt;
use std::{
    fs::{self, File},
    io::Write as _,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

fn config() -> Config {
    Config::new().with_idle_spinner(SpinnerConfig::disabled())
}

#[test]
fn shutdown_cancels_tasks_before_destruction() {
    struct Cleanup {
        drops: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
        gauge: raw::Gauge,
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

    // Cover unpolled local tasks, queued foreign spawns, and pending tasks.
    for placement in 0..3 {
        let drops = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let gauge = raw::Gauge::default();
        let handles = Runner::new(config()).start(|context| {
            let drops = &drops;
            let cancelled = &cancelled;
            let gauge = &gauge;
            async move {
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
                            futures::future::pending::<()>().await;
                        },
                        MetricHandle::new(gauge.clone()),
                        context.shared.panicker.clone(),
                        tree.clone(),
                    );
                    tree.register(handle.aborter().unwrap());
                    let task = Task::boxed(future);
                    if placement == 1 {
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
                if placement == 2 {
                    for ready in receivers {
                        ready.await.unwrap();
                    }
                }
                handles
            }
        });
        assert_eq!(drops.load(Ordering::Relaxed), 2, "placement={placement}");
        assert_eq!(
            cancelled.load(Ordering::Relaxed),
            2,
            "placement={placement}"
        );
        assert_eq!(gauge.get(), 0, "placement={placement}");
        for handle in handles {
            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }
    }
}

#[test]
fn one_off_completion_cancels_local_and_remote_descendants() {
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
                    let local = context
                        .child("local")
                        .spawn(|_| futures::future::pending::<()>());
                    let remote = context
                        .child("remote")
                        .dedicated()
                        .spawn(|_| futures::future::pending::<()>());
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
fn root_shutdown_cancels_descendants_across_workers() {
    let handles = Runner::new(config()).start(|context| async move {
        let (published, descendants) = oneshot::channel();
        let parent = context
            .child("parent")
            .dedicated()
            .spawn(|context| async move {
                let local = context
                    .child("local")
                    .spawn(|_| futures::future::pending::<()>());
                let remote = context
                    .child("remote")
                    .shared(true)
                    .spawn(|_| futures::future::pending::<()>());
                assert!(published.send([local, remote]).is_ok());
                futures::future::pending::<()>().await;
            });
        let [local, remote] = descendants.await.unwrap();
        [parent, local, remote]
    });
    for handle in handles {
        assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
    }
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
            current()
                .unwrap()
                .borrow_mut()
                .driver
                .as_mut()
                .unwrap()
                .fail_service_after_completion = true;
            // Keep the observer alive beyond root destruction so cleanup must
            // preserve its terminal resources before closing ordinary observation.
            futures::future::poll_fn(|cx| {
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
fn admission_before_close_remains_counted_until_release() {
    let registry = Arc::new(Registry::default());
    let worker_registry = registry.clone();
    let (admitted, admission) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        let active = worker_registry.admit().unwrap();
        admitted.send(()).unwrap();
        released.recv().unwrap();
        drop(active);
    });
    admission.recv().unwrap();
    registry.close();
    assert_eq!(registry.state.lock().active, 1);
    assert!(registry.admit().is_none());

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
    release.send(()).unwrap();
    completion.recv().unwrap();
    worker.join().unwrap();
    waiter.join().unwrap();
    assert_eq!(registry.state.lock().active, 0);
}

#[test]
fn closure_before_admission_rejects_without_tracking() {
    let registry = Arc::new(Registry::default());
    registry.close();
    let worker_registry = registry.clone();
    thread::spawn(move || assert!(worker_registry.admit().is_none()))
        .join()
        .unwrap();
    assert_eq!(registry.state.lock().active, 0);
    registry.wait();
}

struct RejectedPayload {
    registry: Arc<Registry>,
    drops: Arc<AtomicUsize>,
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
        assert_eq!(self.registry.state.lock().active, 1);
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_on_drop, "rejected payload destructor failed");
    }
}

#[test]
fn creation_failure_destroys_payload_before_releasing_tracking() {
    for panic_on_drop in [false, true] {
        Runner::new(config()).start(|context| async move {
            let drops = Arc::new(AtomicUsize::new(0));
            let payload = RejectedPayload {
                registry: context.shared.workers.clone(),
                drops: drops.clone(),
                panic_on_drop,
            };
            context.shared.fail_launch.store(true, Ordering::Relaxed);
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

struct RootWithLatePublisher {
    dropped: Option<mpsc::Sender<()>>,
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

#[test]
fn shutdown_waits_for_workers_without_observing_late_panics() {
    for root_fails in [false, true] {
        let (metadata, received) = mpsc::channel();
        let (publishing, publication) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let runner = thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_catch_panics(false)).start(move |context| {
                    let registry = context.shared.workers.clone();
                    let active = registry.admit().unwrap();
                    let panicker = context.shared.panicker.clone();
                    let (dropped, root_dropped) = mpsc::channel();
                    let publisher = thread::spawn(move || {
                        // Root destruction ends execution. Shutdown still waits
                        // for this publisher to release its worker responsibility.
                        root_dropped.recv().unwrap();
                        publishing.send(()).unwrap();
                        released.recv().unwrap();
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
        let (registry, publisher) = received.recv().unwrap();
        publication.recv().unwrap();
        assert_eq!(registry.state.lock().active, 1);
        assert!(!runner.is_finished());
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
fn worker_startup_failure_uses_configured_panic_policy() {
    for catch in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_catch_panics(catch)).start(|context| async move {
                context.shared.fail_startup.store(true, Ordering::Relaxed);
                let failed = context
                    .child("failed_worker")
                    .dedicated()
                    .spawn(|_| async {});
                assert!(matches!(failed.await, Err(Error::Closed)));
                if !catch {
                    // Keep the root active until it observes the worker failure.
                    futures::future::pending::<()>().await;
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

#[test]
fn shutdown_waits_for_one_off_task_destruction() {
    struct HeldDestructor {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl Drop for HeldDestructor {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv();
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
                    futures::future::pending::<()>().await;
                });
            starting.await.unwrap();
        });
    });
    let registry = received.recv().unwrap();
    entering.recv().unwrap();
    assert!(registry.state.lock().closed);
    assert_eq!(registry.state.lock().active, 1);
    assert!(!runner.is_finished());
    release.send(()).unwrap();
    runner.join().unwrap();
    assert_eq!(registry.state.lock().active, 0);
}

#[test]
fn worker_releases_storage_and_durable_io_before_tracking_ends() {
    let cfg = config();
    let directory = cfg.storage_directory().clone();
    let (released, after_release) = mpsc::channel();
    let (finish, finished) = mpsc::channel();
    let (shared, registry) = Runner::new(cfg).start(|context| async move {
        let shared = Arc::downgrade(&context.shared);
        let registry = context.shared.workers.clone();
        *registry.after_release.lock() = Some(Box::new(move || {
            // Keep the guard and thread-entry locals alive after count zero,
            // so their destruction cannot hide a retained Shared reference.
            let _ = released.send(());
            let _ = finished.recv();
        }));
        context
            .child("durable_worker")
            .dedicated()
            .spawn(move |context| async move {
                let (blob, _) = context.open("partition", b"retained").await.unwrap();
                let write = blob.write_at(0, b"durable", WriteOptions::SYNC);
                assert!(write.now_or_never().is_none());
                drop(blob);
            })
            .await
            .unwrap();
        (shared, registry)
    });
    after_release.recv().unwrap();
    assert_eq!(registry.state.lock().active, 0);
    assert!(shared.upgrade().is_none());
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
fn queued_foreign_task_disposal_is_contained_at_shutdown() {
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
        assert!(matches!(
            futures::executor::block_on(handle),
            Err(Error::Closed)
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn startup_failure_survives_rejected_payload_destructor_panic() {
    let drops = Arc::new(AtomicUsize::new(0));
    let observed = drops.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(config().with_catch_panics(false)).start(|context| async move {
            let payload = RejectedPayload {
                registry: context.shared.workers.clone(),
                drops,
                panic_on_drop: true,
            };
            context.shared.fail_startup.store(true, Ordering::Relaxed);
            drop(
                context
                    .child("failed_launch")
                    .shared(true)
                    .spawn(move |_| payload),
            );
            futures::future::pending::<()>().await;
        });
    }));
    let panic = result.expect_err("native startup failure must fail the runner");
    assert!(
        extract_panic_message(&*panic).contains("injected native worker initialization failure")
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[test]
fn creation_failure_in_caught_task_leaves_runner_usable() {
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
                    context.shared.fail_launch.store(true, Ordering::Relaxed);
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
fn ready_future_destructor_closes_handle_and_leaves_runner_usable() {
    struct ReadyDrop {
        polls: Arc<AtomicUsize>,
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
fn callback_generated_work_prevents_parking() {
    enum Work {
        Wake(Waker, Arc<AtomicBool>),
        Spawn(Context, oneshot::Sender<()>),
    }

    struct Callback {
        remaining: usize,
        work: Option<Work>,
    }

    // The destructor performs the callback, which Waker::noop cannot model.
    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for Callback {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for Callback {
        fn drop(&mut self) {
            let work = self.work.take().unwrap();
            if self.remaining != 0 {
                current()
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
                        let (sender, mut receiver) = oneshot::channel();
                        let mut sender = Some(sender);
                        let ready = Arc::new(AtomicBool::new(false));
                        let mut queued = false;
                        futures::future::poll_fn(|cx| {
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
                                let local = current().unwrap();
                                let mut local = local.borrow_mut();
                                local.forbid_park = true;
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
