use criterion::criterion_main;

mod build;
mod prove_range;
mod prove_single_element;

criterion_main!(
    build::benches,
    prove_single_element::benches,
    prove_range::benches
);
