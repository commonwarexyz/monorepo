use criterion::criterion_main;

mod signature_verification;

criterion_main!(signature_verification::benches);
