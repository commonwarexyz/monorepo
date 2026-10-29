use super::ThreadPool;
use crate::rayon::{ThreadPoolBuilder, sleep::with_sleep_notification};
use commonware_utils::sync::Mutex;
use futures::{channel::oneshot, future::poll_fn};
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    sync::{Arc, mpsc},
    task::Poll,
    thread,
    time::Duration,
};

fn with_pool<T>(threads: usize, run: impl FnOnce(&Arc<ThreadPool>) -> T) -> T {
    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap(),
    );
    let registry = Arc::clone(&pool.registry);
    let result = catch_unwind(AssertUnwindSafe(|| run(&pool)));
    drop(pool);
    registry.wait_until_stopped();
    result.unwrap_or_else(|panic| resume_unwind(panic))
}

#[allow(
    clippy::disallowed_types,
    reason = "Exercise the channel used by Strategy::spawn."
)]
fn sleeping_receiver(
    release: impl FnOnce(&Arc<ThreadPool>, oneshot::Sender<u32>),
) -> Result<u32, oneshot::Canceled> {
    with_pool(1, |pool| {
        let (tx, mut rx) = oneshot::channel();
        let (asleep_tx, asleep_rx) = mpsc::channel();
        thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                pool.install(|| {
                    with_sleep_notification(asleep_tx, || {
                        pool.block_on_worker(Pin::new(&mut rx)).unwrap()
                    })
                })
            });
            asleep_rx.recv().unwrap();
            release(pool, tx);
            waiter.join().unwrap()
        })
    })
}

#[commonware_macros::test_group("miri")]
#[test]
fn result_wakes_sleeping_worker() {
    assert_eq!(sleeping_receiver(|_, tx| tx.send(42).unwrap()), Ok(42));
}

#[commonware_macros::test_group("miri")]
#[test]
fn canceled_sender_wakes_sleeping_worker() {
    assert!(sleeping_receiver(|_, tx| drop(tx)).is_err());
}

#[commonware_macros::test_group("miri")]
#[test]
fn queued_work_wakes_sleeping_worker() {
    assert_eq!(
        sleeping_receiver(|pool, tx| pool.spawn(move || tx.send(42).unwrap())),
        Ok(42)
    );
}

#[commonware_macros::test_group("miri")]
#[test]
fn outside_and_foreign_workers_do_not_poll() {
    with_pool(1, |pool| {
        let mut future = poll_fn(|_| -> Poll<()> { panic!("future must not be polled") });
        assert!(pool.block_on_worker(Pin::new(&mut future)).is_none());
        with_pool(1, |other| {
            other.install(|| {
                assert!(pool.block_on_worker(Pin::new(&mut future)).is_none());
            });
        });
    });
}

#[commonware_macros::test_group("miri")]
#[test]
fn duplicate_wakes_during_poll_are_retained() {
    with_pool(1, |pool| {
        pool.install(|| {
            let mut polls = 0;
            let mut future = poll_fn(|cx| {
                polls += 1;
                if polls == 1 {
                    cx.waker().wake_by_ref();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(42)
                }
            });
            assert_eq!(pool.block_on_worker(Pin::new(&mut future)), Some(42));
            assert_eq!(polls, 2);
        });
    });
}

#[commonware_macros::test_group("miri")]
#[test]
fn retained_wakers_outlive_ready_panic_and_pool() {
    let wakers = with_pool(1, |pool| {
        pool.install(|| {
            let mut ready_wakers = Vec::new();
            let mut ready = poll_fn(|cx| {
                ready_wakers.push(cx.waker().clone());
                if ready_wakers.len() == 1 {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            });
            assert_eq!(pool.block_on_worker(Pin::new(&mut ready)), Some(()));

            let mut panic_waker = None;
            let mut panicking = poll_fn(|cx| -> Poll<()> {
                panic_waker = Some(cx.waker().clone());
                panic!("future poll panicked");
            });
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    pool.block_on_worker(Pin::new(&mut panicking));
                }))
                .is_err()
            );
            ready_wakers.push(panic_waker.unwrap());
            ready_wakers
        })
    });
    for waker in wakers {
        waker.wake_by_ref();
        waker.wake_by_ref();
        waker.wake();
    }
}

#[commonware_macros::test_group("miri")]
#[test]
fn nested_waits_service_later_work() {
    with_pool(1, |pool| {
        let (outer_tx, mut outer_rx) = oneshot::channel();
        let (inner_tx, mut inner_rx) = oneshot::channel();
        let (outer_asleep_tx, outer_asleep_rx) = mpsc::channel();
        let (inner_asleep_tx, inner_asleep_rx) = mpsc::channel();
        thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                pool.install(|| {
                    with_sleep_notification(outer_asleep_tx, || {
                        pool.block_on_worker(Pin::new(&mut outer_rx)).unwrap()
                    })
                })
            });
            outer_asleep_rx.recv().unwrap();
            let inner_pool = Arc::clone(pool);
            pool.spawn(move || {
                let value = with_sleep_notification(inner_asleep_tx, || {
                    inner_pool
                        .block_on_worker(Pin::new(&mut inner_rx))
                        .unwrap()
                        .unwrap()
                });
                outer_tx.send(value).unwrap();
            });
            inner_asleep_rx.recv().unwrap();
            pool.spawn(move || inner_tx.send(42).unwrap());
            assert_eq!(waiter.join().unwrap(), Ok(42));
        });
    });
}

#[commonware_macros::test_group("miri")]
#[test]
fn workers_wait_independently() {
    with_pool(2, |pool| {
        let (asleep_tx, asleep_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..2)
            .map(|_| {
                let (tx, rx) = oneshot::channel();
                (tx, Mutex::new(Some(rx)))
            })
            .unzip();
        let waiting_pool = Arc::clone(pool);
        pool.spawn_broadcast(move |context| {
            let mut rx = receivers[context.index()].lock().take().unwrap();
            let result = with_sleep_notification(asleep_tx.clone(), || {
                waiting_pool.block_on_worker(Pin::new(&mut rx)).unwrap()
            });
            done_tx.send(result.unwrap()).unwrap();
        });
        asleep_rx.recv().unwrap();
        asleep_rx.recv().unwrap();
        let mut senders = senders.into_iter();
        let worker0 = senders.next().unwrap();
        let worker1 = senders.next().unwrap();

        // Keep worker 0 blocked so its completion cannot wake worker 1.
        worker1.send(1).unwrap();
        let independent = done_rx.recv_timeout(Duration::from_secs(10)).ok();

        // Let both workers finish before reporting a missed wake.
        worker0.send(0).unwrap();
        let mut values = [
            independent.unwrap_or_else(|| done_rx.recv().unwrap()),
            done_rx.recv().unwrap(),
        ];
        values.sort();
        assert_eq!(values, [0, 1]);
        assert_eq!(
            independent,
            Some(1),
            "worker 1 must finish before worker 0 is released"
        );
    });
}
