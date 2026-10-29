//! Nondefault process-wide configuration.

#![cfg(feature = "mimalloc")]

use commonware_allocator::mimalloc::{
    ARENA_CHUNK_SIZE, Config, EagerCommit, Effective, MiMalloc, Purge, Reserve, ReserveOutcome,
    Stats, Status, is_global_allocator,
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config {
    purge: Purge::Never,
    reserve: Some(Reserve::unpinned(ARENA_CHUNK_SIZE + 1)),
    allow_large_os_pages: true,
    arena_eager_commit: EagerCommit::Never,
    arena_reserve: ARENA_CHUNK_SIZE + 1,
    ..Config::DEFAULT
});

#[test]
fn configured_options_are_effective() {
    assert!(is_global_allocator());
    let status = Status::read();
    assert!(status.configured);
    assert_eq!(status.reserve, ReserveOutcome::Reserved);
    let stats = Stats::read().expect("stats must be available");
    assert!(stats.reserved_bytes >= ARENA_CHUNK_SIZE as u64);
    let effective = Effective::read();
    assert_eq!(effective.purge, None);
    assert_eq!(effective.arena_eager_commit, 0);
    assert!(effective.allow_large_os_pages);
    assert_eq!(effective.arena_reserve, ARENA_CHUNK_SIZE + 1024);
}
