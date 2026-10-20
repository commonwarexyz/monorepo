//! Huge page advice on an unpinned reservation (Linux).

#![cfg(all(feature = "mimalloc", target_os = "linux"))]

mod smaps;

use commonware_allocator::mimalloc::{
    ARENA_CHUNK_SIZE, Config, MiMalloc, Reserve, ReserveOutcome, Status,
};
use std::hint::black_box;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config {
    reserve: Some(Reserve::unpinned(2 * ARENA_CHUNK_SIZE)),
    transparent_huge_pages: Some(true),
    ..Config::DEFAULT
});

#[test]
fn unpinned_reservation_is_advised_huge_pages() {
    if !smaps::kernel_grants_huge_pages() {
        return;
    }
    assert_eq!(Status::read().reserve, ReserveOutcome::Reserved);

    // A multi-mebibyte page is carved from the only arena, the reservation,
    // so its address lies in that mapping.
    let page = black_box(Vec::<u8>::with_capacity(4 << 20));
    let flags = smaps::vm_flags(page.as_ptr().addr());
    assert!(
        flags.iter().any(|flag| flag == "hg"),
        "the unpinned reservation must carry the huge page advice: {flags:?}"
    );
}
