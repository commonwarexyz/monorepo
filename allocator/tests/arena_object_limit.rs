//! Placement of huge objects under the default arena object-size limit.
//!
//! The probes compare process-wide statistics around allocations of hundreds
//! of MiB, so they run as one test in a process of their own. Every probe
//! passes through `black_box` so the optimizer cannot elide the allocation.

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

    // The largest page an arena can hold comes from an arena and stays
    // reserved after free.
    let before = stats();
    let page = black_box(Vec::<u8>::with_capacity(ARENA_MAX_OBJECT_SIZE));
    let held = stats();
    drop(page);
    let after = stats();
    assert_eq!(held.huge_allocations, before.huge_allocations + 1);
    assert_eq!(after.reserved_bytes, held.reserved_bytes);

    // One slice more is mapped from the operating system without reserving
    // an arena, and is unmapped on free. mimalloc keeps page-map entries for
    // newly used addresses, so reservations do not return exactly to their
    // starting point.
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

    // An alignment beyond a slice is also served by a fresh mapping. An
    // alignment of a whole metadata group is refused.
    let aligned = Layout::from_size_align(64, 2 * ARENA_SLICE_SIZE).expect("layout must be valid");
    let before = stats();
    // SAFETY: a valid non-zero layout, and the block is released below.
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
    // SAFETY: a valid non-zero layout, and null is expected.
    assert!(black_box(unsafe { alloc(refused) }).is_null());
}
