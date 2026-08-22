use criterion::criterion_main;

mod build;
mod build_streaming;
mod prove_multi;
mod prove_range;
mod prove_single;

criterion_main!(
    build::benches,
    build_streaming::benches,
    prove_single::benches,
    prove_multi::benches,
    prove_range::benches,
);
