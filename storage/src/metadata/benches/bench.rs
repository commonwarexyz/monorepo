use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod overwrite;
mod restart;
mod sync;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(sync::benches, overwrite::benches, restart::benches);
