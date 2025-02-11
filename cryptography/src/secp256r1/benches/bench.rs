use criterion::criterion_main;

mod signature_generation;
mod signature_verification;

criterion_main!(
    signature_generation::benches,
    signature_verification::benches
);
