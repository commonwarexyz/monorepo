use criterion::criterion_main;

mod aggregate_verify_same_message;
mod aggregate_verify_same_signer;
mod batch_to_affine;
mod batch_verify_same_signer;
mod check_subgroup;
mod combine_public_keys;
mod combine_signatures;
mod dkg;
mod evaluate_point;
mod hash_to_curve;
mod msm;
mod scheme_batch_verify_same_message;
mod scheme_batch_verify_same_signer;
mod signature_generation;
mod signature_verification;
mod threshold_batch_verify_same_message;
mod threshold_batch_verify_same_message_precomputed;
mod threshold_recover;
mod tle_decrypt;
mod tle_encrypt;

criterion_main!(
    batch_to_affine::benches,
    check_subgroup::benches,
    dkg::benches,
    hash_to_curve::benches,
    threshold_recover::benches,
    combine_public_keys::benches,
    combine_signatures::benches,
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_signer::benches,
    aggregate_verify_same_message::benches,
    aggregate_verify_same_signer::benches,
    scheme_batch_verify_same_signer::benches,
    scheme_batch_verify_same_message::benches,
    evaluate_point::benches,
    msm::benches,
    threshold_batch_verify_same_message::benches,
    threshold_batch_verify_same_message_precomputed::benches,
    tle_encrypt::benches,
    tle_decrypt::benches,
);
