use crate::scheduler::{ThreadPoolBuilder, unwind};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::channel,
    },
    thread, time,
};

#[test]
fn broadcast_pool() {
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let v = pool.broadcast(|ctx| ctx.index());
    assert!(v.into_iter().eq(0..7));
}

#[test]
fn spawn_broadcast_pool() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    pool.spawn_broadcast(move |ctx| tx.send(ctx.index()).unwrap());

    let mut v: Vec<_> = rx.into_iter().collect();
    v.sort_unstable();
    assert!(v.into_iter().eq(0..7));
}

#[test]
fn broadcast_self() {
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let v = pool.install(|| pool.broadcast(|ctx| ctx.index()));
    assert!(v.into_iter().eq(0..7));
}

#[test]
fn spawn_broadcast_self() {
    let (tx, rx) = channel();
    let pool = Arc::new(ThreadPoolBuilder::new().num_threads(7).build().unwrap());
    pool.spawn({
        let pool = Arc::clone(&pool);
        move || pool.spawn_broadcast(move |ctx| tx.send(ctx.index()).unwrap())
    });

    let mut v: Vec<_> = rx.into_iter().collect();
    v.sort_unstable();
    assert!(v.into_iter().eq(0..7));
}

#[test]
fn broadcast_mutual() {
    let count = AtomicUsize::new(0);
    let pool1 = ThreadPoolBuilder::new().num_threads(3).build().unwrap();
    let pool2 = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    pool1.install(|| {
        pool2.broadcast(|_| {
            pool1.broadcast(|_| {
                count.fetch_add(1, Ordering::Relaxed);
            })
        })
    });
    assert_eq!(count.into_inner(), 3 * 7);
}

#[test]
fn spawn_broadcast_mutual() {
    let (tx, rx) = channel();
    let pool1 = Arc::new(ThreadPoolBuilder::new().num_threads(3).build().unwrap());
    let pool2 = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    pool1.spawn({
        let pool1 = Arc::clone(&pool1);
        move || {
            pool2.spawn_broadcast(move |_| {
                let tx = tx.clone();
                pool1.spawn_broadcast(move |_| tx.send(()).unwrap())
            })
        }
    });
    assert_eq!(rx.into_iter().count(), 3 * 7);
}

#[test]
fn broadcast_mutual_sleepy() {
    let count = AtomicUsize::new(0);
    let pool1 = ThreadPoolBuilder::new().num_threads(3).build().unwrap();
    let pool2 = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    pool1.install(|| {
        thread::sleep(time::Duration::from_secs(1));
        pool2.broadcast(|_| {
            thread::sleep(time::Duration::from_secs(1));
            pool1.broadcast(|_| {
                thread::sleep(time::Duration::from_millis(100));
                count.fetch_add(1, Ordering::Relaxed);
            })
        })
    });
    assert_eq!(count.into_inner(), 3 * 7);
}

#[test]
fn spawn_broadcast_mutual_sleepy() {
    let (tx, rx) = channel();
    let pool1 = Arc::new(ThreadPoolBuilder::new().num_threads(3).build().unwrap());
    let pool2 = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    pool1.spawn({
        let pool1 = Arc::clone(&pool1);
        move || {
            thread::sleep(time::Duration::from_secs(1));
            pool2.spawn_broadcast(move |_| {
                let tx = tx.clone();
                thread::sleep(time::Duration::from_secs(1));
                pool1.spawn_broadcast(move |_| {
                    thread::sleep(time::Duration::from_millis(100));
                    tx.send(()).unwrap();
                })
            })
        }
    });
    assert_eq!(rx.into_iter().count(), 3 * 7);
}

#[test]
fn broadcast_panic_one() {
    let count = AtomicUsize::new(0);
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();
    let result = unwind::halt_unwinding(|| {
        pool.broadcast(|ctx| {
            count.fetch_add(1, Ordering::Relaxed);
            if ctx.index() == 3 {
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
        pool.broadcast(|ctx| {
            count.fetch_add(1, Ordering::Relaxed);
            if ctx.index() % 2 == 0 {
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
        pool.broadcast(|ctx| {
            // A slight spread of sleep duration increases the chance that one
            // of the threads will race in the pool's idle sleep afterward.
            thread::sleep(time::Duration::from_micros(ctx.index() as u64));
        });
    }
}

#[test]
fn broadcast_after_spawn_broadcast() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();

    // Queue a non-blocking spawn_broadcast.
    pool.spawn_broadcast(move |ctx| tx.send(ctx.index()).unwrap());

    // This blocking broadcast runs after all prior broadcasts.
    pool.broadcast(|_| {});

    // The spawn_broadcast **must** have run by now on all threads.
    let mut v: Vec<_> = rx.try_iter().collect();
    v.sort_unstable();
    assert!(v.into_iter().eq(0..pool.current_num_threads()));
}

#[test]
fn broadcast_after_spawn() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(7).build().unwrap();

    // Queue a regular spawn on a thread-local deque.
    pool.install(|| pool.spawn(move || tx.send(22).unwrap()));

    // Broadcast runs after the local deque is empty.
    pool.broadcast(|_| {});

    // The spawn **must** have run by now.
    assert_eq!(22, rx.try_recv().unwrap());
}
