use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod batch_verify;
mod batch_verify_same_message;
mod batch_verify_same_signer;
mod signature_generation;
mod signature_verification;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_message::benches,
    batch_verify_same_signer::benches,
    batch_verify::benches,
);
