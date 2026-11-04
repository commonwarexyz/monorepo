use super::ThreadPool;
use crate::rayon::{
    ThreadPoolBuilder, join, registry::Placement, sleep::with_sleep_notification, unwind, yield_now,
};
use commonware_utils::sync::Mutex;
use futures::{channel::oneshot, future::poll_fn};
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::Poll,
    thread, time,
};

#[test]
#[should_panic(expected = "Hello, world!")]
fn panic_propagate() {
    let thread_pool = ThreadPoolBuilder::new().build().unwrap();
    thread_pool.install(|| {
        panic!("Hello, world!");
    });
}

#[test]
fn workers_stop() {
    let registry;

    {
        // once we exit this block, thread pool will be dropped
        let thread_pool = ThreadPoolBuilder::new().num_threads(22).build().unwrap();
        registry = thread_pool.install(|| {
            // do some work on these threads
            join_a_lot(22);

            Arc::clone(&thread_pool.registry)
        });
        assert_eq!(registry.num_threads(), 22);
    }

    // once thread pool is dropped, registry should terminate, which
    // should lead to worker threads stopping
    registry.wait_until_stopped();
}

fn join_a_lot(n: usize) {
    if n > 0 {
        join(|| join_a_lot(n - 1), || join_a_lot(n - 1));
    }
}

#[test]
fn sleeper_stop() {
    let registry;

    {
        // once we exit this block, thread pool will be dropped
        let thread_pool = ThreadPoolBuilder::new().num_threads(22).build().unwrap();
        registry = Arc::clone(&thread_pool.registry);

        // Give time for at least some of the thread pool to fall asleep.
        thread::sleep(time::Duration::from_secs(1));
    }

    // once thread pool is dropped, registry should terminate, which
    // should lead to worker threads stopping
    registry.wait_until_stopped();
}

/// Creates a start handler that increments an atomic counter.
fn count_handler() -> (Arc<AtomicUsize>, impl Fn(usize)) {
    let count = Arc::new(AtomicUsize::new(0));
    (Arc::clone(&count), move |_| {
        count.fetch_add(1, Ordering::SeqCst);
    })
}

/// Wait until a counter is no longer shared, then return its value. The registry owns the start
/// handler's copy, so this also waits until every thread the pool started has exited.
fn wait_for_counter(mut counter: Arc<AtomicUsize>) -> usize {
    for _ in 0..60 {
        counter = match Arc::try_unwrap(counter) {
            Ok(counter) => return counter.into_inner(),
            Err(counter) => {
                thread::sleep(time::Duration::from_secs(1));
                counter
            }
        };
    }

    // That's too long!
    panic!("Counter is still shared!");
}

#[test]
fn failed_thread_stack() {
    // Note: we first tried to force failure with a `usize::MAX` stack, but
    // macOS and Windows weren't fazed, or at least didn't fail the way we want.
    // They work with `isize::MAX`, but 32-bit platforms may feasibly allocate a
    // 2GB stack, so it might not fail until the second thread.
    let stack_size = isize::MAX as usize;

    let (start_count, start_handler) = count_handler();
    let builder = ThreadPoolBuilder::new()
        .num_threads(10)
        .stack_size(stack_size)
        .start_handler(start_handler);

    let pool = builder.build();
    assert!(pool.is_err(), "thread stack should have failed!");

    // With such a huge stack, 64-bit will probably fail on the first thread;
    // 32-bit might manage the first 2GB, but certainly fail the second.
    let start_count = wait_for_counter(start_count);
    assert!(start_count <= 1);
}

#[test]
fn panic_thread_name() {
    let (start_count, start_handler) = count_handler();
    let builder = ThreadPoolBuilder::new()
        .num_threads(10)
        .start_handler(start_handler)
        .thread_name(|i| {
            if i >= 5 {
                panic!();
            }
            format!("panic_thread_name#{i}")
        });

    let pool = unwind::halt_unwinding(|| builder.build());
    assert!(pool.is_err(), "thread-name panic should propagate!");

    // Assuming they're created in order, threads 0 through 4 should have
    // been started already, and then terminated by the panic.
    assert_eq!(5, wait_for_counter(start_count));
}

#[test]
fn self_install() {
    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    // If the inner `install` blocks, then nothing will actually run it!
    assert!(pool.install(|| pool.install(|| true)));
}

#[test]
fn mutual_install() {
    let pool1 = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool2 = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    let ok = pool1.install(|| {
        // This creates a dependency from `pool1` -> `pool2`
        pool2.install(|| {
            // This creates a dependency from `pool2` -> `pool1`
            pool1.install(|| {
                // If they blocked on inter-pool installs, there would be no
                // threads left to run this!
                true
            })
        })
    });
    assert!(ok);
}

#[test]
fn mutual_install_sleepy() {
    let pool1 = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool2 = ThreadPoolBuilder::new().num_threads(1).build().unwrap();

    let ok = pool1.install(|| {
        // This creates a dependency from `pool1` -> `pool2`
        pool2.install(|| {
            // Give `pool1` time to fall asleep.
            thread::sleep(time::Duration::from_secs(1));

            // This creates a dependency from `pool2` -> `pool1`
            pool1.install(|| {
                // Give `pool2` time to fall asleep.
                thread::sleep(time::Duration::from_secs(1));

                // If they blocked on inter-pool installs, there would be no
                // threads left to run this!
                true
            })
        })
    });
    assert!(ok);
}

#[test]
fn spawn_lifo_order() {
    let builder = ThreadPoolBuilder::new().num_threads(1);
    let pool = &builder.build().unwrap();
    let (tx, rx) = mpsc::channel();
    pool.install(move || {
        for i in 0..10 {
            let tx = tx.clone();
            pool.spawn(move || {
                tx.send(i).unwrap();
            });
        }
    });
    let vec = rx.iter().collect::<Vec<i32>>();
    let expected: Vec<i32> = (0..10).rev().collect(); // LIFO -> reversed
    assert_eq!(vec, expected);
}

#[test]
fn yield_now_to_spawn() {
    let (tx, rx) = mpsc::channel();
    let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();

    // Queue a regular spawn.
    pool.spawn(move || tx.send(22).unwrap());

    // A worker that yields runs the spawn if no other worker took it first.
    pool.install(move || {
        yield_now();
    });

    // The spawn **must** have started by now, but we still might have to wait
    // for it to finish if a different thread stole it first.
    assert_eq!(22, rx.recv().unwrap());
}

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

/// Blocks the only worker of a pool on a oneshot result until it sleeps, lets `release` act on
/// the pool and the sender, and returns what the worker observed.
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

/// A result sent to a sleeping worker wakes it with the value.
#[commonware_macros::test_group("miri")]
#[test]
fn result_wakes_sleeping_worker() {
    assert_eq!(sleeping_receiver(|_, tx| tx.send(42).unwrap()), Ok(42));
}

/// Dropping the sender wakes the sleeping worker, which observes the cancellation.
#[commonware_macros::test_group("miri")]
#[test]
fn canceled_sender_wakes_sleeping_worker() {
    assert!(sleeping_receiver(|_, tx| drop(tx)).is_err());
}

/// Work queued on the pool wakes its only worker, which runs the job and then receives the result
/// it sent.
#[commonware_macros::test_group("miri")]
#[test]
fn queued_work_wakes_sleeping_worker() {
    assert_eq!(
        sleeping_receiver(|pool, tx| pool.spawn(move || tx.send(42).unwrap())),
        Ok(42)
    );
}

/// A thread outside the pool, or a worker of another pool, gets `None` without the future being
/// polled.
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

/// Wakes issued during a poll are kept, so a pending future is polled again, and only once.
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

/// Wakers retained past a completed poll or a panicking poll remain safe to wake after the pool
/// is gone.
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

/// A worker waiting on one result runs a job that waits on another, and work queued later
/// resolves both.
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
fn release_sleeping_worker(
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

/// Of two workers blocked on their own results, settling one wakes that worker alone.
#[commonware_macros::test_group("miri")]
#[test]
fn workers_wait_independently() {
    assert_eq!(
        release_sleeping_worker(2, 0, 1, |_, tx| tx.send(42).unwrap()),
        Ok(42)
    );
}

/// Worker 3 of four in groups of two is the second worker of the second group, so its waker must
/// reach the exact group and offset where it sleeps.
#[commonware_macros::test_group("miri")]
#[test]
fn result_wakes_later_group_worker() {
    assert_eq!(
        release_sleeping_worker(4, 2, 3, |_, tx| tx.send(42).unwrap()),
        Ok(42)
    );
}

/// Dropping the sender of the result that a sleeping worker of a later group awaits wakes that
/// worker, which observes the cancellation.
#[commonware_macros::test_group("miri")]
#[test]
fn canceled_sender_wakes_later_group_worker() {
    assert!(release_sleeping_worker(4, 2, 3, |_, tx| drop(tx)).is_err());
}

/// A queued producer in another group wakes only the worker waiting for its result.
#[commonware_macros::test_group("miri")]
#[test]
fn queued_work_wakes_later_group_worker() {
    for cancel in [false, true] {
        let result = release_sleeping_worker(4, 2, 3, |pool, tx| {
            // Keep the producer in another group until the waiting workers are asleep.
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            pool.spawn_in(Placement::Local(0), move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                if !cancel {
                    tx.send(42).unwrap();
                }
            });
            started_rx.recv().unwrap();

            // Let incidental wakeups settle so only the result can wake the waiting worker.
            while pool.sleeping_workers() < 3 {
                thread::yield_now();
            }
            release_tx.send(()).unwrap();
        });

        // Both completion and cancellation must reach the same waiting worker.
        if cancel {
            assert!(result.is_err());
        } else {
            assert_eq!(result, Ok(42));
        }
    }
}
