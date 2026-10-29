use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod seal_open;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(seal_open::benches);
