//! Controlled checks of worker admission, cleanup, and failure publication.

use super::*;
use crate::{Blob as _, Runner as _, Storage as _, WriteOptions, utils::extract_panic_message};
use futures::FutureExt;
use std::{
    fs::{self, File},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn config() -> Config {
    Config::new().with_idle_spinner(SpinnerConfig::disabled())
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
                let _ = context.shared.launch(Task::boxed(payload));
            }));
            assert!(result.is_err());
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(context.shared.workers.state.lock().active, 0);
        });
    }
}

#[test]
fn transfer_failure_destroys_payload_before_releasing_tracking() {
    for panic_on_drop in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_catch_panics(true)).start(|context| async move {
                let drops = Arc::new(AtomicUsize::new(0));
                let payload = RejectedPayload {
                    registry: context.shared.workers.clone(),
                    drops: drops.clone(),
                    panic_on_drop,
                };
                context.shared.fail_transfer.store(true, Ordering::Relaxed);
                let rejected = catch_unwind(AssertUnwindSafe(|| {
                    assert!(context.shared.launch(Task::boxed(payload)).is_ok());
                }));
                assert_eq!(rejected.is_err(), panic_on_drop);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(context.shared.workers.state.lock().active, 0);
            });
        }));
        let panic = result.expect_err("transfer failure must remain runner-fatal");
        assert_eq!(
            extract_panic_message(&*panic),
            "io_uring worker payload transfer failed"
        );
    }
}

struct FailingOutput(Arc<AtomicBool>);

impl Drop for FailingOutput {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        panic!("secondary output destruction failure");
    }
}

struct RootWithLatePublisher {
    dropped: Option<mpsc::Sender<()>>,
    fail: bool,
    output_dropped: Arc<AtomicBool>,
}

impl Future for RootWithLatePublisher {
    type Output = FailingOutput;

    fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Self::Output> {
        assert!(!self.fail, "primary root failure");
        Poll::Ready(FailingOutput(self.output_dropped.clone()))
    }
}

impl Drop for RootWithLatePublisher {
    fn drop(&mut self) {
        self.dropped.take().unwrap().send(()).unwrap();
    }
}

#[test]
fn shutdown_waits_for_delayed_failure_and_preserves_primary_panic() {
    for root_fails in [false, true] {
        let (metadata, received) = mpsc::channel();
        let (publishing, publication) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let output_dropped = Arc::new(AtomicBool::new(false));
        let observed_output = output_dropped.clone();
        let runner = thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_catch_panics(true)).start(move |context| {
                    let registry = context.shared.workers.clone();
                    let active = registry.admit().unwrap();
                    let panicker = context.shared.panicker.clone();
                    let (dropped, root_dropped) = mpsc::channel();
                    let publisher = thread::spawn(move || {
                        // Root destruction follows admission closure and precedes
                        // the shutdown wait, when its interrupt waker is inert.
                        root_dropped.recv().unwrap();
                        publishing.send(()).unwrap();
                        released.recv().unwrap();
                        panicker.notify_fatal(Box::new("delayed worker failure"));
                        drop(active);
                    });
                    metadata.send((registry, publisher)).unwrap();
                    RootWithLatePublisher {
                        dropped: Some(dropped),
                        fail: root_fails,
                        output_dropped,
                    }
                });
            }));
            match result {
                Ok(_) => panic!("delayed worker failure must fail the runner"),
                Err(panic) => extract_panic_message(&*panic),
            }
        });
        let (registry, publisher) = received.recv().unwrap();
        publication.recv().unwrap();
        assert!(registry.state.lock().closed);
        assert_eq!(registry.state.lock().active, 1);
        assert!(!runner.is_finished());
        release.send(()).unwrap();
        publisher.join().unwrap();
        assert_eq!(
            runner.join().unwrap(),
            if root_fails {
                "primary root failure"
            } else {
                "delayed worker failure"
            }
        );
        assert_eq!(observed_output.load(Ordering::SeqCst), !root_fails);
        assert_eq!(registry.state.lock().active, 0);
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
            // Joining only the publisher leaves its accepted cell in the
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
        Runner::new(config().with_catch_panics(true)).start(|context| async move {
            let payload = RejectedPayload {
                registry: context.shared.workers.clone(),
                drops,
                panic_on_drop: true,
            };
            context.shared.fail_startup.store(true, Ordering::Relaxed);
            assert!(context.shared.launch(Task::boxed(payload)).is_ok());
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
fn ready_future_destructor_uses_selected_worker_poll_panic_policy() {
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
            let result = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(config().with_catch_panics(catch)).start(|context| async move {
                    let child = context.child("ready_drop");
                    let child = if dedicated { child.dedicated() } else { child };
                    // The selected-worker async wrapper destroys this completed
                    // future inside its poll, where user panic policy applies.
                    let result = child.spawn(move |_| future).await;
                    if catch {
                        assert!(matches!(result, Err(Error::Exited)));
                        context.child("survivor").spawn(|_| async {}).await.unwrap();
                    } else {
                        futures::future::pending::<()>().await;
                    }
                });
            }));
            if catch {
                assert!(result.is_ok());
            } else {
                let panic = result.expect_err("uncaught poll failure must fail the runner");
                assert_eq!(
                    extract_panic_message(&*panic),
                    "ready future destructor failed"
                );
            }
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
