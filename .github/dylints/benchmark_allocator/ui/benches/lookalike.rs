// aux-build:commonware_allocator.rs
// compile-flags: --edition=2021

extern crate commonware_allocator;

#[global_allocator]
static GLOBAL: commonware_allocator::MiMalloc = commonware_allocator::MiMalloc;

static UNUSED: commonware_allocator::mimalloc::MiMalloc = commonware_allocator::mimalloc::MiMalloc;

fn main() {
    let _ = &UNUSED;
}
