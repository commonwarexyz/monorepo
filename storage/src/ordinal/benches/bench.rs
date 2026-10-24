use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod get;
mod put;
mod restart;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(get::benches, put::benches, restart::benches);
