use criterion::criterion_main;

mod build;
mod prove_range;
mod prove_single;

criterion_main!(build::benches, prove_single::benches, prove_range::benches);
