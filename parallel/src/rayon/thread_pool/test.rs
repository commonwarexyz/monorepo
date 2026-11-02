use crate::rayon::{ThreadPoolBuilder, join, unwind, yield_now};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::channel,
    },
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
    let (tx, rx) = channel();
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
    let (tx, rx) = channel();
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
