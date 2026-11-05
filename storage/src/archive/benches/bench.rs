use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod get;
mod put;
mod restart;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(put::benches, get::benches, restart::benches);

/// Whether `just test-benches` requested the smallest inputs.
fn smoke() -> bool {
    std::env::var_os("COMMONWARE_BENCH_SMOKE").is_some()
}
