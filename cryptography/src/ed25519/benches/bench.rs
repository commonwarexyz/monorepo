use commonware_cryptography::transcript;
use criterion::criterion_main;

// Compile the existing verifier directly so comparisons need no public backend override.
#[allow(dead_code, unused_imports)]
#[path = "../core/mod.rs"]
mod dalek;

mod batch_verify;
mod batch_verify_same_message;
mod batch_verify_same_signer;
mod signature_generation;
mod signature_verification;

criterion_main!(
    batch_verify::benches,
    signature_generation::benches,
    signature_verification::benches,
    batch_verify_same_message::benches,
    batch_verify_same_signer::benches,
);
