use criterion::criterion_main;

mod build;
mod prove_element_range;
mod prove_single_element;

criterion_main!(
    build::benches,
    prove_element_range::benches,
    prove_single_element::benches,
);
