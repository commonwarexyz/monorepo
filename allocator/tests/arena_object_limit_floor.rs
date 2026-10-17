//! The arena object-size limit at its floor.

#![cfg(feature = "mimalloc")]

use commonware_allocator::mimalloc::{ARENA_SLICE_SIZE, Config, Effective, MiMalloc};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config {
    arena_max_object_size: Some(0),
    ..Config::DEFAULT
});

#[test]
fn arena_object_limit_is_at_least_a_slice() {
    assert_eq!(Effective::read().arena_max_object_size, ARENA_SLICE_SIZE);
}
