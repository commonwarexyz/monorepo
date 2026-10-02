use criterion::criterion_main;

mod public_key_cmp;
mod signature_generation;
mod signature_verification;

criterion_main!(
    public_key_cmp::benches,
    signature_generation::benches,
    signature_verification::benches
);
