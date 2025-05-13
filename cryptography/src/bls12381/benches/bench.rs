use criterion::criterion_main;

mod aggregate_public_keys;
mod aggregate_signatures;
mod aggregate_verify_multiple_messages;
mod aggregate_verify_multiple_public_keys;
mod batch_verify_multiple_messages;
mod batch_verify_multiple_public_keys;
mod dkg_recovery;
mod dkg_reshare_recovery;
mod signature_generation;
mod signature_verification;
mod threshold_signature_recover;

criterion_main!(
    dkg_recovery::benches,
    dkg_reshare_recovery::benches,
    threshold_signature_recover::benches,
    aggregate_public_keys::benches,
    aggregate_signatures::benches,
    signature_generation::benches,
    signature_verification::benches,
    aggregate_verify_multiple_messages::benches,
    aggregate_verify_multiple_public_keys::benches,
    batch_verify_multiple_messages::benches,
    batch_verify_multiple_public_keys::benches,
);
