//! Allocation budgets of the Multimmit machine's hot paths.
//!
//! Counting needs a global allocator, which would tax every unit test in the library binary, so
//! these tests run in their own binary.

use commonware_consensus::multimmit::test_utils::benchmarks::HotPathOperations;
use core::{alloc::GlobalAlloc, cell::Cell};
use std::alloc::{Layout, System};

thread_local! {
    static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: Every method forwards the caller's exact pointer and layout contract to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        let allocation = unsafe { System.alloc(layout) };
        count_allocation(allocation);
        allocation
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        let allocation = unsafe { System.alloc_zeroed(layout) };
        count_allocation(allocation);
        allocation
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` came from the corresponding system allocation.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: The pointer, layout, and requested size are forwarded unchanged.
        let allocation = unsafe { System.realloc(ptr, layout, new_size) };
        count_allocation(allocation);
        allocation
    }
}

fn count_allocation(allocation: *mut u8) {
    if allocation.is_null() {
        return;
    }
    COUNT_ALLOCATIONS.with(|enabled| {
        if enabled.get() {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
    });
}

fn count_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            COUNT_ALLOCATIONS.with(|enabled| enabled.set(false));
        }
    }

    COUNT_ALLOCATIONS.with(|enabled| {
        assert!(
            !enabled.replace(true),
            "allocation counters cannot be nested"
        );
    });
    ALLOCATIONS.with(|count| count.set(0));
    let reset = Reset;
    let result = operation();
    let allocations = ALLOCATIONS.with(Cell::get);
    drop(reset);
    (result, allocations)
}

#[test]
fn hot_path_allocation_budgets_are_stable() {
    let mut operations = HotPathOperations::new();
    let (_, header) = count_allocations(|| operations.duplicate_header());
    let (_, vqc) = count_allocations(|| operations.duplicate_vqc());
    let (idle, poll) = count_allocations(|| operations.idle_poll());

    assert!(idle);
    // Each duplicate count includes building, classifying, and settling its one-artifact cohort.
    // Debug builds authenticate the supplied artifact ID again before classifying a duplicate.
    // An idle poll allocates nothing.
    let debug = usize::from(cfg!(debug_assertions));
    assert_eq!([header, vqc, poll], [8 + debug, 15 + debug, 0]);
}
