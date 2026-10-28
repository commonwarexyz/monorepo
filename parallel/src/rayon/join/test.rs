//! Tests for the join code.

use super::*;
use crate::rayon::{Placement, ThreadPoolBuilder, unwind};
use commonware_utils::test_rng;
use rand::Rng as _;
use std::sync::Barrier;

fn quick_sort<T: PartialOrd + Send>(v: &mut [T]) {
    if v.len() <= 1 {
        return;
    }

    let mid = partition(v);
    let (lo, hi) = v.split_at_mut(mid);
    join(|| quick_sort(lo), || quick_sort(hi));
}

fn partition<T: PartialOrd + Send>(v: &mut [T]) -> usize {
    let pivot = v.len() - 1;
    let mut i = 0;
    for j in 0..pivot {
        if v[j] <= v[pivot] {
            v.swap(i, j);
            i += 1;
        }
    }
    v.swap(i, pivot);
    i
}

fn random_data(len: usize) -> Vec<u32> {
    let mut rng = test_rng();
    (0..len).map(|_| rng.next_u32()).collect()
}

/// Runs `op` on a worker of a new pool.
fn in_pool<R: Send>(op: impl FnOnce() -> R + Send) -> R {
    ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap()
        .install_in(Placement::Wide { near: 0 }, op)
}

#[test]
fn sort() {
    let mut data = random_data(6 * 1024);
    let mut sorted_data = data.clone();
    sorted_data.sort();
    in_pool(|| quick_sort(&mut data));
    assert_eq!(data, sorted_data);
}

#[test]
fn sort_in_pool() {
    let mut data = random_data(12 * 1024);

    let pool = ThreadPoolBuilder::new().build().unwrap();
    let mut sorted_data = data.clone();
    sorted_data.sort();
    pool.install_in(Placement::Wide { near: 0 }, || quick_sort(&mut data));
    assert_eq!(data, sorted_data);
}

#[test]
#[should_panic(expected = "Hello, world!")]
fn panic_propagate_a() {
    in_pool(|| join(|| panic!("Hello, world!"), || ()));
}

#[test]
#[should_panic(expected = "Hello, world!")]
fn panic_propagate_b() {
    in_pool(|| join(|| (), || panic!("Hello, world!")));
}

#[test]
#[should_panic(expected = "Hello, world!")]
fn panic_propagate_both() {
    in_pool(|| join(|| panic!("Hello, world!"), || panic!("Goodbye, world!")));
}

#[test]
fn panic_b_still_executes() {
    let mut x = false;
    match unwind::halt_unwinding(|| in_pool(|| join(|| panic!("Hello, world!"), || x = true))) {
        Ok(_) => panic!("failed to propagate panic from closure A,"),
        Err(_) => assert!(x, "closure b failed to execute"),
    }
}

#[test]
fn join_context_neither() {
    // If we're already in a 1-thread pool, neither job should be stolen.
    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let (a_migrated, b_migrated) = pool.install_in(Placement::Wide { near: 0 }, || {
        join_context(|migrated| migrated, |migrated| migrated)
    });
    assert!(!a_migrated);
    assert!(!b_migrated);
}

#[test]
fn join_context_second() {
    // If we're already in a 2-thread pool, the second job should be stolen.
    let barrier = Barrier::new(2);
    let pool = ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    let (a_migrated, b_migrated) = pool.install_in(Placement::Wide { near: 0 }, || {
        join_context(
            |migrated| {
                barrier.wait();
                migrated
            },
            |migrated| {
                barrier.wait();
                migrated
            },
        )
    });
    assert!(!a_migrated);
    assert!(b_migrated);
}

#[test]
fn join_counter_overflow() {
    const MAX: u32 = 500_000;

    let mut i = 0;
    let mut j = 0;
    let pool = ThreadPoolBuilder::new().num_threads(2).build().unwrap();

    // Hammer on join a bunch of times -- used to hit overflow debug-assertions
    // in JEC on 32-bit targets: https://github.com/rayon-rs/rayon/issues/797
    for _ in 0..MAX {
        pool.install_in(Placement::Wide { near: 0 }, || join(|| i += 1, || j += 1));
    }

    assert_eq!(i, MAX);
    assert_eq!(j, MAX);
}
