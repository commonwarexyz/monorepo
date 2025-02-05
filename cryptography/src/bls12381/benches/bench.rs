use criterion::criterion_main;

mod aggregate_public_keys;
mod aggregate_signatures;
mod aggregate_verify_multiple_messages;
mod aggregate_verify_multiple_public_keys;
mod dkg_recovery;
mod dkg_reshare_recovery;
mod signature_generation;
mod signature_verification;
mod threshold_signature_recover;

criterion_main!(
    signature_generation::benches,
    signature_verification::benches,
);
