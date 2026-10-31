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
};

/// Runs `run` on a pool of `threads` workers split into groups of `width`, where 0 forms one
/// group, then waits for the workers to stop.
fn with_pool<T>(threads: usize, width: usize, run: impl FnOnce(&Arc<ThreadPool>) -> T) -> T {
    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .group_width(width)
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
    with_pool(1, 0, |pool| {
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
    with_pool(1, 0, |pool| {
        let mut future = poll_fn(|_| -> Poll<()> { panic!("future must not be polled") });
        assert!(pool.block_on_worker(Pin::new(&mut future)).is_none());
        with_pool(1, 0, |other| {
            other.install(|| {
                assert!(pool.block_on_worker(Pin::new(&mut future)).is_none());
            });
        });
    });
}

#[commonware_macros::test_group("miri")]
#[test]
fn duplicate_wakes_during_poll_are_retained() {
    with_pool(1, 0, |pool| {
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
    let wakers = with_pool(1, 0, |pool| {
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
    with_pool(1, 0, |pool| {
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

/// Blocks every worker of a pool of `threads` workers, in groups of `width`, on its own result
/// and waits until all of them sleep. `release` then settles the result of worker `target`
/// alone, which only that worker's waker can report, and the outcome the target observes is
/// returned. Every other worker stays blocked until the target has finished, then receives its
/// own index.
#[allow(
    clippy::disallowed_types,
    reason = "Exercise the channel used by Strategy::spawn."
)]
fn release_one_sleeping_worker(
    threads: usize,
    width: usize,
    target: usize,
    release: impl FnOnce(&Arc<ThreadPool>, oneshot::Sender<u32>),
) -> Result<u32, oneshot::Canceled> {
    with_pool(threads, width, |pool| {
        let (asleep_tx, asleep_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let (mut senders, receivers): (Vec<_>, Vec<_>) = (0..threads)
            .map(|_| {
                let (tx, rx) = oneshot::channel();
                (Some(tx), Mutex::new(Some(rx)))
            })
            .unzip();
        let waiting_pool = Arc::clone(pool);
        pool.spawn_broadcast(move |context| {
            let index = context.index();
            let mut rx = receivers[index].lock().take().unwrap();
            let result = with_sleep_notification(asleep_tx.clone(), || {
                waiting_pool.block_on_worker(Pin::new(&mut rx)).unwrap()
            });
            done_tx.send((index, result)).unwrap();
        });

        // Each worker reports its first sleep inside its wait, but a worker woken while another
        // takes its job can still be awake afterwards. With no work left, a pool whose workers
        // all sleep stays asleep, so only the target's waker can wake the target.
        for _ in 0..threads {
            asleep_rx.recv().unwrap();
        }
        while pool.sleeping_workers() < threads {
            thread::yield_now();
        }

        release(pool, senders[target].take().unwrap());
        let (index, result) = done_rx.recv().unwrap();
        assert_eq!(index, target);

        for (index, tx) in senders.into_iter().enumerate() {
            if let Some(tx) = tx {
                tx.send(u32::try_from(index).unwrap()).unwrap();
            }
        }
        for _ in 1..threads {
            let (index, other) = done_rx.recv().unwrap();
            assert_eq!(other, Ok(u32::try_from(index).unwrap()));
        }
        result
    })
}

#[commonware_macros::test_group("miri")]
#[test]
fn workers_wait_independently() {
    assert_eq!(
        release_one_sleeping_worker(2, 0, 1, |_, tx| tx.send(42).unwrap()),
        Ok(42)
    );
}

/// Worker 3 of four in groups of two is the second worker of the second group, so its waker must
/// reach the exact group and offset where it sleeps.
#[commonware_macros::test_group("miri")]
#[test]
fn result_wakes_a_sleeping_worker_of_a_later_group() {
    assert_eq!(
        release_one_sleeping_worker(4, 2, 3, |_, tx| tx.send(42).unwrap()),
        Ok(42)
    );
}

#[commonware_macros::test_group("miri")]
#[test]
fn canceled_sender_wakes_a_sleeping_worker_of_a_later_group() {
    assert!(release_one_sleeping_worker(4, 2, 3, |_, tx| drop(tx)).is_err());
}

#[commonware_macros::test_group("miri")]
#[test]
fn queued_work_wakes_a_sleeping_worker_of_a_later_group() {
    assert_eq!(
        release_one_sleeping_worker(4, 2, 3, |pool, tx| pool.spawn(move || tx.send(42).unwrap())),
        Ok(42)
    );
}
