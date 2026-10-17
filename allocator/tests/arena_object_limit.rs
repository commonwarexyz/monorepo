//! Placement of huge objects under the default arena object-size limit.
//!
//! The probes map and unmap hundreds of mebibytes and compare process-wide
//! statistics around each, so they run in a process of their own, in one
//! test, with no other allocator user in flight. Every probe allocation
//! passes through `black_box`: the optimizer may otherwise drop an
//! allocation whose result is only compared and assume it succeeded.

#![cfg(feature = "mimalloc")]

use commonware_allocator::mimalloc::{
    ARENA_CHUNK_SIZE, ARENA_MAX_OBJECT_SIZE, ARENA_SLICE_SIZE, Config, Effective, MiMalloc, Stats,
};
use std::{
    alloc::{Layout, alloc, dealloc},
    hint::black_box,
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config::DEFAULT);

fn stats() -> Stats {
    Stats::read().expect("stats must be available")
}

#[test]
fn huge_objects_are_placed_as_documented() {
    assert_eq!(
        Effective::read().arena_max_object_size,
        ARENA_MAX_OBJECT_SIZE
    );

    // The largest page an arena can hold is carved from one, reserving a new
    // arena when the existing ones have no room, and returned to it on free
    // rather than unmapped.
    let before = stats();
    let page = black_box(Vec::<u8>::with_capacity(ARENA_MAX_OBJECT_SIZE));
    let held = stats();
    drop(page);
    let after = stats();
    assert_eq!(held.huge_allocations, before.huge_allocations + 1);
    assert!(held.mmap_calls == before.mmap_calls || held.arenas > before.arenas);
    assert_eq!(after.reserved_bytes, held.reserved_bytes);

    // One slice more goes straight to the operating system, without an
    // arena reservation on the way, and is unmapped on free. mimalloc keeps
    // the page-map entry for a newly used address range, so reservations do
    // not return exactly to their starting point.
    let size = ARENA_MAX_OBJECT_SIZE + ARENA_SLICE_SIZE;
    let before = stats();
    let page = black_box(Vec::<u8>::with_capacity(size));
    let held = stats();
    drop(page);
    let after = stats();
    assert_eq!(held.huge_allocations, before.huge_allocations + 1);
    assert_eq!(held.arenas, before.arenas);
    assert!(held.mmap_calls > before.mmap_calls);
    assert!(held.reserved_bytes >= before.reserved_bytes + size as u64);
    assert!(held.reserved_bytes >= after.reserved_bytes + size as u64);

    // An alignment beyond a slice is served by a fresh mapping as well; one
    // of a whole metadata group or more is refused.
    let aligned = Layout::from_size_align(64, 2 * ARENA_SLICE_SIZE).expect("layout must be valid");
    let before = stats();
    // SAFETY: a valid non-zero layout; the block is released below.
    let block = black_box(unsafe { alloc(aligned) });
    assert!(!block.is_null() && block.addr().is_multiple_of(aligned.align()));
    let held = stats();
    // SAFETY: allocated above with this layout and not used afterwards.
    unsafe { dealloc(block, aligned) };
    let after = stats();
    assert!(held.mmap_calls > before.mmap_calls);
    assert!(held.reserved_bytes >= after.reserved_bytes + ARENA_SLICE_SIZE as u64);
    let group = size_of::<usize>() * ARENA_CHUNK_SIZE;
    let refused = Layout::from_size_align(64, group).expect("layout must be valid");
    // SAFETY: a valid non-zero layout; null is the expected result.
    assert!(black_box(unsafe { alloc(refused) }).is_null());
}
