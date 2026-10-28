use crate::rayon::{Placement, ThreadPoolBuilder, current_thread_index, unwind};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::channel,
    },
    thread, time,
};

#[test]
fn broadcast_self() {
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let v = pool.install_in(Placement::Wide { near: 0 }, || {
        pool.broadcast_in(0, || current_thread_index().unwrap())
    });
    assert!(v.into_iter().eq(0..7));
}

#[test]
fn broadcast_panic_one() {
    let count = AtomicUsize::new(0);
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let result = unwind::halt_unwinding(|| {
        pool.broadcast_in(0, || {
            count.fetch_add(1, Ordering::Relaxed);
            if current_thread_index() == Some(3) {
                panic!("Hello, world!");
            }
        })
    });
    assert_eq!(count.into_inner(), 7);
    assert!(result.is_err(), "broadcast panic should propagate!");
}

#[test]
fn broadcast_panic_many() {
    let count = AtomicUsize::new(0);
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let result = unwind::halt_unwinding(|| {
        pool.broadcast_in(0, || {
            count.fetch_add(1, Ordering::Relaxed);
            if current_thread_index().unwrap().is_multiple_of(2) {
                panic!("Hello, world!");
            }
        })
    });
    assert_eq!(count.into_inner(), 7);
    assert!(result.is_err(), "broadcast panic should propagate!");
}

#[test]
fn broadcast_sleep_race() {
    let test_duration = time::Duration::from_secs(1);
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let start = time::Instant::now();
    while start.elapsed() < test_duration {
        pool.broadcast_in(0, || {
            // A slight spread of sleep duration increases the chance that one
            // of the threads will race in the pool's idle sleep afterward.
            thread::sleep(time::Duration::from_micros(
                current_thread_index().unwrap() as u64
            ));
        });
    }
}

#[test]
fn broadcast_after_spawn_broadcast() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();

    // Queue a non-blocking spawn_broadcast_in.
    pool.spawn_broadcast_in(0, move || tx.send(current_thread_index().unwrap()).unwrap());

    // This blocking broadcast runs after all prior broadcasts.
    pool.broadcast_in(0, || {});

    // The spawned broadcast **must** have run by now on all threads.
    let mut v: Vec<_> = rx.try_iter().collect();
    v.sort_unstable();
    assert!(v.into_iter().eq(0..pool.current_num_threads()));
}

#[test]
fn broadcast_after_spawn() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();

    // Queue a regular spawn on a thread-local deque.
    pool.install_in(Placement::Wide { near: 0 }, || {
        pool.spawn_in(Placement::Wide { near: 0 }, move || tx.send(22).unwrap())
    });

    // Broadcast runs after the local deque is empty.
    pool.broadcast_in(0, || {});

    // The spawn **must** have run by now.
    assert_eq!(22, rx.try_recv().unwrap());
}
