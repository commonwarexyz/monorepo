// Lives in `ui/benches` because the lint only checks binaries in a `benches` directory.

use std::alloc::System;

#[global_allocator]
static GLOBAL: System = System;

fn main() {}
