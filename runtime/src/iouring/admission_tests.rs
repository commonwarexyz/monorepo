//! Factory construction and publication across admission closure.

use super::*;
use crate::Runner as _;
use futures::FutureExt;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};

fn config() -> Config {
    Config::new().with_idle_spinner(SpinnerConfig::disabled())
}

struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn aborted_context_skips_factories_for_every_placement() {
    Runner::new(config()).start(|context| async move {
        context.tree.abort();
        for execution in [
            Execution::default(),
            Execution::Shared(false),
            Execution::Dedicated,
            Execution::Shared(true),
        ] {
            let mut rejected = context.child("rejected");
            rejected.execution = execution;
            let handle = rejected.spawn(|_| -> std::future::Ready<()> {
                panic!("an aborted context must not invoke its factory");
            });
            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }
        assert_eq!(context.shared.workers.state.lock().active, 0);
    });
}

#[test]
fn closed_origin_skips_local_and_foreign_factories() {
    for foreign in [false, true] {
        Runner::new(config()).start(|context| async move {
            if foreign {
                let mailbox = context.origin.upgrade().unwrap();
                drop(mailbox.close());
            } else {
                // The local admission check must see closure without consulting
                // the mailbox, which remains open until worker shutdown.
                current().unwrap().borrow_mut().closing = true;
            }
            let spawn = move || {
                context.spawn(|_| -> std::future::Ready<()> {
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
fn closed_registry_skips_one_off_factories() {
    Runner::new(config()).start(|context| async move {
        context.shared.workers.close();
        for execution in [Execution::Dedicated, Execution::Shared(true)] {
            let mut rejected = context.child("rejected");
            rejected.execution = execution;
            let handle = rejected.spawn(|_| -> std::future::Ready<()> {
                panic!("a closed registry must not invoke its factory");
            });
            assert!(matches!(handle.now_or_never(), Some(Err(Error::Closed))));
        }
        assert_eq!(context.shared.workers.state.lock().active, 0);
    });
}

#[test]
fn shutdown_does_not_wait_for_an_unpublished_ordinary_factory() {
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
                released.recv().unwrap();
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
fn one_off_admission_covers_factory_construction_through_shutdown() {
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
                        futures::future::pending::<()>().await;
                    });
                let registry = context.shared.workers.clone();
                let (entered, entering) = oneshot::channel();
                let mut child = context.child("foreign");
                child.execution = execution;
                let publisher = thread::spawn(move || {
                    child.spawn(move |_| {
                        entered.send(()).unwrap();
                        released.recv().unwrap();
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
        let (registry, publisher) = received.recv().unwrap();
        closed.recv().unwrap();
        assert!(registry.state.lock().closed);
        assert_eq!(registry.state.lock().active, 1);
        assert!(!runner.is_finished());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
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
fn one_off_factory_panic_releases_admission() {
    for catch in [false, true] {
        Runner::new(config().with_catch_panics(catch)).start(|context| async move {
            for execution in [Execution::Dedicated, Execution::Shared(true)] {
                let registry = context.shared.workers.clone();
                let mut child = context.child("panicking_factory");
                child.execution = execution;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    child.spawn(move |_| -> std::future::Ready<()> {
                        // Factory execution holds the count but not its lock.
                        assert_eq!(registry.state.lock().active, 1);
                        panic!("factory failed");
                    })
                }));
                assert!(result.is_err());
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
