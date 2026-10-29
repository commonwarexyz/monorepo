//! [`Config::DEFAULT`] against the option values mimalloc starts with.

#![cfg(feature = "mimalloc")]

use commonware_allocator::mimalloc::{
    ARENA_MAX_OBJECT_SIZE, Config, EagerCommit, Effective, Purge, is_global_allocator,
};

/// With the system allocator as the global allocator, no [`Config`] is ever
/// applied, so [`Effective`] reports the values mimalloc starts with.
#[test]
fn default_config_matches_mimalloc_defaults() {
    assert!(!is_global_allocator());
    let builtin = Effective::read();
    let default = Config::DEFAULT;

    let Purge::After(delay) = default.purge else {
        panic!("the default must purge after a delay");
    };
    assert_eq!(builtin.purge, Some(delay));
    assert_eq!(default.reserve, None);
    assert_eq!(builtin.allow_large_os_pages, default.allow_large_os_pages);
    assert_eq!(
        builtin.transparent_huge_pages,
        default.transparent_huge_pages
    );
    let eager_commit = match default.arena_eager_commit {
        EagerCommit::Never => 0,
        EagerCommit::Always => 1,
        EagerCommit::IfOvercommit => 2,
    };
    assert_eq!(builtin.arena_eager_commit, eager_commit);
    assert_eq!(builtin.arena_reserve, default.arena_reserve);
    assert_eq!(builtin.stats_merge_threshold, default.stats_merge_threshold);

    // mimalloc's own ceiling admits pages no arena can hold, so the default
    // caps the arena object-size limit below it.
    assert_eq!(default.arena_max_object_size, ARENA_MAX_OBJECT_SIZE);
    assert!(builtin.arena_max_object_size >= ARENA_MAX_OBJECT_SIZE);
}
