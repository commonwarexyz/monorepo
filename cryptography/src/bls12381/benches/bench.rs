use criterion::criterion_main;

mod aggregate_verify_same_message;
mod aggregate_verify_same_signer;
mod batch_verify_same_signer;
mod combine_public_keys;
mod combine_signatures;
mod dkg;
mod evaluate_point;
mod scheme_batch_verify_multiple_messages;
mod scheme_batch_verify_multiple_public_keys;
mod signature_generation;
mod signature_verification;
mod threshold_batch_verify_same_message;
mod threshold_batch_verify_same_message_precomputed;
mod threshold_recover;
mod tle_decrypt;
mod tle_encrypt;

criterion_main!(
    dkg::benches,
    threshold_recover::benches,
    combine_public_keys::benches,
    combine_signatures::benches,
    aggregate_verify_same_signer::benches,
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_signer::benches,
    aggregate_verify_same_message::benches,
    scheme_batch_verify_multiple_messages::benches,
    scheme_batch_verify_multiple_public_keys::benches,
    evaluate_point::benches,
    threshold_batch_verify_same_message::benches,
    threshold_batch_verify_same_message_precomputed::benches,
    tle_encrypt::benches,
    tle_decrypt::benches,
);
