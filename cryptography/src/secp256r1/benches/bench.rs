use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod signature_generation;
mod signature_verification;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    signature_generation::benches,
    signature_verification::benches
);
