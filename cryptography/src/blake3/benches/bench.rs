use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod hash_message;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(hash_message::benches);
