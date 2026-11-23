use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod decode;
mod display;
mod encode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(encode::benches, decode::benches, display::benches);
