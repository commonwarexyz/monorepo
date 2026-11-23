use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod sake;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(sake::benches);
