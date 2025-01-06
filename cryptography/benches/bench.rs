use criterion::criterion_main;

mod ed25519_batch_verify_multiple_messages;
mod ed25519_batch_verify_multiple_public_keys;
mod ed25519_signature_verification;

criterion_main!(
    ed25519_signature_verification::ed25519_benches,
    ed25519_batch_verify_multiple_public_keys::ed25519_benches,
    ed25519_batch_verify_multiple_messages::ed25519_benches,
);
