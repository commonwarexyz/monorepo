use criterion::criterion_main;

mod dkg_recovery;
mod dkg_reshare_recovery;
mod partial_signature_aggregation;
mod signature_aggregation;
mod signature_generation;
mod signature_verification;
mod signature_verify_aggregation;

criterion_main!(
    dkg_recovery::benches,
    dkg_reshare_recovery::benches,
    partial_signature_aggregation::benches,
    signature_aggregation::benches,
    signature_generation::benches,
    signature_verification::benches,
    signature_verify_aggregation::benches,
);
