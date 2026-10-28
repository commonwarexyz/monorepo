use super::spawn_in;
use crate::rayon::{Placement, ThreadPoolBuilder, registry::WorkerThread};
use std::sync::{Arc, mpsc::channel};

/// Spawns `func` into the pool of the calling worker, under the placement of the job it runs.
fn spawn<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let worker = unsafe { WorkerThread::current().as_ref() }.expect("must run on a worker");
    let registry = Arc::clone(worker.registry());
    // SAFETY: the calling worker runs a job of the pool, which keeps the registry from
    // terminating.
    unsafe { spawn_in(func, &registry, worker.placement()) }
}

#[test]
fn spawn_then_join_in_worker() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    pool.install_in(Placement::Wide { near: 0 }, move || {
        spawn(move || tx.send(22).unwrap());
    });
    assert_eq!(22, rx.recv().unwrap());
}

#[test]
fn spawn_then_join_outside_worker() {
    let (tx, rx) = channel();
    let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    pool.spawn_in(Placement::Wide { near: 0 }, move || tx.send(22).unwrap());
    assert_eq!(22, rx.recv().unwrap());
}

/// Test what happens when the thread pool is dropped but there are
/// still active asynchronous tasks. We expect the thread pool to stay
/// alive and executing until those threads are complete.
#[test]
fn termination_while_things_are_executing() {
    let (tx0, rx0) = channel();
    let (tx1, rx1) = channel();

    // Create a thread pool and spawn some code in it, but then drop
    // our reference to it.
    {
        let thread_pool = ThreadPoolBuilder::new().build().unwrap();
        thread_pool.spawn_in(Placement::Wide { near: 0 }, move || {
            let data = rx0.recv().unwrap();

            // At this point, we know the "main" reference to the
            // `ThreadPool` has been dropped, but there are still
            // active threads. Launch one more.
            spawn(move || {
                tx1.send(data).unwrap();
            });
        });
    }

    tx0.send(22).unwrap();
    let v = rx1.recv().unwrap();
    assert_eq!(v, 22);
}

macro_rules! test_order {
    ($outer_spawn:ident, $inner_spawn:ident) => {{
        let builder = ThreadPoolBuilder::new().num_threads(1);
        let pool = builder.build().unwrap();
        let (tx, rx) = channel();
        pool.install_in(Placement::Wide { near: 0 }, move || {
            for i in 0..10 {
                let tx = tx.clone();
                $outer_spawn(move || {
                    for j in 0..10 {
                        let tx = tx.clone();
                        $inner_spawn(move || {
                            tx.send(i * 10 + j).unwrap();
                        });
                    }
                });
            }
        });
        rx.iter().collect::<Vec<i32>>()
    }};
}

#[test]
fn lifo_order() {
    // In the absence of stealing, `spawn()` jobs on a thread will run in LIFO order.
    let vec = test_order!(spawn, spawn);
    let expected: Vec<i32> = (0..100).rev().collect(); // LIFO -> reversed
    assert_eq!(vec, expected);
}
