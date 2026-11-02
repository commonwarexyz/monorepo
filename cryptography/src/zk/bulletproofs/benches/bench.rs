use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod ipa;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(ipa::benches);
