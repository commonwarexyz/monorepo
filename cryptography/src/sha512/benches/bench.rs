use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod hash_many;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(hash_many::benches);
