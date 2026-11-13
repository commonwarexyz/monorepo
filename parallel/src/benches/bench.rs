use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod sort;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(sort::benches);
