use criterion::criterion_main;

mod build;
mod generate_proof;
mod prove_multi;
mod prove_range;
mod prove_single;

criterion_main!(
    build::benches,
    generate_proof::benches,
    prove_single::benches,
    prove_multi::benches,
    prove_range::benches
);
