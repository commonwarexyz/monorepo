use criterion::criterion_main;

mod aggregate_public_keys;
mod aggregate_signatures;
mod aggregate_verify_multiple_messages;
mod aggregate_verify_multiple_public_keys;
mod batch_verify_multiple_messages;
mod dkg;
mod evaluate_point;
mod scheme_verify_multiple_messages;
mod scheme_verify_multiple_public_keys;
mod signature_generation;
mod signature_verification;
mod threshold_recover;
mod threshold_verify_multiple_public_keys;
mod threshold_verify_multiple_public_keys_precomputed;
mod tle_decrypt;
mod tle_encrypt;

criterion_main!(
    dkg::benches,
    threshold_recover::benches,
    aggregate_public_keys::benches,
    aggregate_signatures::benches,
    aggregate_verify_multiple_messages::benches,
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_multiple_messages::benches,
    aggregate_verify_multiple_public_keys::benches,
    scheme_verify_multiple_messages::benches,
    scheme_verify_multiple_public_keys::benches,
    evaluate_point::benches,
    threshold_verify_multiple_public_keys::benches,
    threshold_verify_multiple_public_keys_precomputed::benches,
    tle_encrypt::benches,
    tle_decrypt::benches,
);
