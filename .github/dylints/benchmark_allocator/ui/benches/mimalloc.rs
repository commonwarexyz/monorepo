// aux-build:commonware_allocator.rs
// compile-flags: --edition=2021

extern crate commonware_allocator;

use commonware_allocator::mimalloc;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {}
