use criterion::criterion_main;

mod batch_verify_same_message;
mod batch_verify_same_signer;
mod signature_generation;
mod signature_verification;

criterion_main!(
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_message::benches,
    batch_verify_same_signer::benches,
);
