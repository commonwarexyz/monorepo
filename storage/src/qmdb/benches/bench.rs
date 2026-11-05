//! Benchmark entry point for all QMDB benchmarks.

use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod apply_batch;
mod chained_growth;
mod common;
mod generate;
mod init;
mod merkleize;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    apply_batch::benches,
    chained_growth::benches,
    generate::benches,
    init::benches,
    merkleize::benches
);

/// Whether `just test-benches` requested the smallest inputs.
fn smoke() -> bool {
    std::env::var_os("COMMONWARE_BENCH_SMOKE").is_some()
}
