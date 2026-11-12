use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod log2_ceil;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(log2_ceil::benches);
