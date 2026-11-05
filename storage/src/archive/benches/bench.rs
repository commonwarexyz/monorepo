use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod get;
mod put;
mod restart;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

/// Whether to run benchmarks with their smallest inputs.
fn smoke() -> bool {
    std::env::var_os("COMMONWARE_BENCH_SMOKE").is_some()
}

criterion_main!(put::benches, get::benches, restart::benches);
