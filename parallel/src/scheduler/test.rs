use super::{ThreadPoolBuildError, ThreadPoolBuilder, current_num_threads, join, scope};
use std::{
    panic,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc::channel,
    },
    time::Duration,
};

#[test]
fn worker_thread_index() {
    let pool = ThreadPoolBuilder::new().num_threads(22).build().unwrap();
    assert_eq!(pool.current_num_threads(), 22);
    assert_eq!(pool.current_thread_index(), None);
    let index = pool.install(|| pool.current_thread_index().unwrap());
    assert!(index < 22);
}

#[test]
fn start_callback_called() {
    let n_threads = 16;
    let n_called = Arc::new(AtomicUsize::new(0));
    // Wait for all the threads in the pool plus the one running tests.
    let barrier = Arc::new(Barrier::new(n_threads + 1));

    let b = Arc::clone(&barrier);
    let nc = Arc::clone(&n_called);
    let start_handler = move |_| {
        nc.fetch_add(1, Ordering::SeqCst);
        b.wait();
    };

    let conf = ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .start_handler(start_handler);
    let _ = conf.build().unwrap();

    // Wait for all the threads to have been scheduled to run.
    barrier.wait();

    // The handler must have been called on every started thread.
    assert_eq!(n_called.load(Ordering::SeqCst), n_threads);
}

#[test]
fn check_config_build() {
    let pool = ThreadPoolBuilder::new().num_threads(22).build().unwrap();
    assert_eq!(pool.current_num_threads(), 22);
}

/// Helper used by check_error_send_sync to ensure ThreadPoolBuildError is Send + Sync
const fn _send_sync<T: Send + Sync>() {}

#[test]
fn check_error_send_sync() {
    _send_sync::<ThreadPoolBuildError>();
}

#[test]
fn default_pool() {
    ThreadPoolBuilder::default().build().unwrap();
}

/// Without a global pool to fall back on, the operations that run on the caller's pool refuse a
/// caller outside every pool.
#[test]
fn pool_operations_require_a_worker() {
    let operations: [fn(); 3] = [
        || {
            let _ = join(|| (), || ());
        },
        || scope(|_| ()),
        || {
            let _ = current_num_threads();
        },
    ];
    for operation in operations {
        let payload = panic::catch_unwind(operation).unwrap_err();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied());
        assert_eq!(
            message,
            Some("the calling thread must be a worker of a thread pool")
        );
    }
}

/// A thread that is a worker of one pool cannot be taken over by another.
#[test]
fn use_current_thread_rejects_a_worker() {
    let first = ThreadPoolBuilder::new()
        .num_threads(1)
        .use_current_thread()
        .build()
        .unwrap();
    assert_eq!(first.current_thread_index(), Some(0));
    let second = ThreadPoolBuilder::new()
        .num_threads(1)
        .use_current_thread()
        .build();
    assert!(second.is_err());
}

/// A pool whose workers never started holds queued jobs until a taken-over thread yields to it.
#[test]
fn unstarted_workers_run_nothing_until_the_current_thread_yields() {
    let pool = ThreadPoolBuilder::new()
        .num_threads(2)
        .use_current_thread()
        .unstarted_workers()
        .build()
        .unwrap();
    let (tx, rx) = channel();
    pool.spawn(move || tx.send(22).unwrap());
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(pool.yield_now(), Some(super::Yield::Executed));
    assert_eq!(rx.try_recv(), Ok(22));
    assert_eq!(pool.yield_now(), Some(super::Yield::Idle));
}
