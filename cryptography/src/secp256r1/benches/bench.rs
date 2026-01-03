use criterion::criterion_main;

mod batch_verify_multiple_messages;
mod batch_verify_multiple_public_keys;
mod batch_vs_individual;
mod signature_generation;
mod signature_verification;

criterion_main!(
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_multiple_public_keys::benches,
    batch_verify_multiple_messages::benches,
    batch_vs_individual::benches,
);
