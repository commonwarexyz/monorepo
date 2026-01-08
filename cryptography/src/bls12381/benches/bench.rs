use criterion::criterion_main;

mod aggregate_verify_same_message;
mod aggregate_verify_same_signer;
mod batch_to_affine;
mod batch_verify_same_message;
mod batch_verify_same_signer;
mod combine_public_keys;
mod combine_signatures;
mod dkg;
mod evaluate_point;
mod msm;
mod msm_affine;
mod pairing_verify;
mod scheme_batch_verify_same_message;
mod scheme_batch_verify_same_signer;
mod signature_generation;
mod signature_verification;
mod threshold_batch_verify_same_message;
mod threshold_batch_verify_same_message_precomputed;
mod threshold_recover;
mod tle_decrypt;
mod tle_encrypt;
mod verify_same_message_msm;

criterion_main!(
    dkg::benches,
    threshold_recover::benches,
    combine_public_keys::benches,
    combine_signatures::benches,
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_message::benches,
    batch_verify_same_signer::benches,
    aggregate_verify_same_message::benches,
    aggregate_verify_same_signer::benches,
    scheme_batch_verify_same_signer::benches,
    scheme_batch_verify_same_message::benches,
    evaluate_point::benches,
    threshold_batch_verify_same_message::benches,
    threshold_batch_verify_same_message_precomputed::benches,
    tle_encrypt::benches,
    tle_decrypt::benches,
    batch_to_affine::benches,
    msm::benches,
    msm_affine::benches,
    pairing_verify::benches,
    verify_same_message_msm::benches,
);
