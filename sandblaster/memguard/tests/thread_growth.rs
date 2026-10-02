//! The per-thread count of the counting allocator ([`thread_allocated`],
//! [`thread_growth`]): a thread's own allocations and frees move it, other
//! threads' allocations do not (while the process-wide [`allocated`] sees
//! them), and a block freed by another thread lowers the freeing thread's
//! count. The counters are process-wide state, so this binary has exactly
//! one test.

use std::hint::black_box;
use std::sync::Barrier;

use sandblaster_memguard::{THREAD_STOCK, allocated, thread_allocated, thread_growth};

const MIB: usize = 1 << 20;

#[test]
fn a_threads_count_is_its_own_allocations() {
    // first spawns initialize lazy runtime state
    std::thread::spawn(|| black_box(vec![0u8; 100])).join().unwrap();

    // own allocations, small (the stock path) and large (the direct path),
    // and their frees
    let t0 = thread_allocated();
    let small: Vec<Vec<u8>> = (0..1000).map(|i| black_box(vec![1u8; 1 + i % 200])).collect();
    let large = black_box(vec![0u8; 8 * MIB]);
    let grown = thread_growth(t0);
    assert!(grown >= (8 * MIB + 1000) as isize && grown < (9 * MIB) as isize, "growth {grown}");
    drop(small);
    drop(large);
    let left = thread_growth(t0);
    assert!(left.unsigned_abs() < THREAD_STOCK, "after the frees: {left}");

    // another thread's allocation: the process-wide counter moves, this
    // thread's count does not
    let (go, done) = (Barrier::new(2), Barrier::new(2));
    std::thread::scope(|s| {
        let t1 = thread_allocated();
        let a1 = allocated();
        s.spawn(|| {
            go.wait();
            let v = black_box(vec![0u8; 64 * MIB]);
            done.wait();
            // held until this thread has measured
            go.wait();
            drop(v);
        });
        go.wait();
        done.wait();
        assert!(allocated() >= a1 + 64 * MIB, "the process-wide count sees the other thread");
        assert!(thread_growth(t1).unsigned_abs() < THREAD_STOCK, "another thread's allocation moved this thread's count: {}", thread_growth(t1));
        go.wait();
    });

    // a block allocated here and freed by another thread: this thread's
    // count stays up, the freeing thread's goes down (wrapping below its
    // start, read as a negative growth)
    let t2 = thread_allocated();
    let v = black_box(vec![0u8; 16 * MIB]);
    let freed_there = std::thread::spawn(move || {
        let f0 = thread_allocated();
        drop(v);
        thread_growth(f0)
    })
    .join()
    .unwrap();
    assert!(thread_growth(t2) >= (16 * MIB - THREAD_STOCK) as isize, "{}", thread_growth(t2));
    assert!(freed_there <= -((16 * MIB) as isize), "{freed_there}");
}
