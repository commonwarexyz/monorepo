// compile-flags: --edition=2021

use std::alloc::System;

#[global_allocator]
static GLOBAL: System = System;

fn main() {}
