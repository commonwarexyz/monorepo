use criterion::criterion_main;

mod build;
mod build_additional;
mod prove_many_elements;
mod prove_single_element;

criterion_main!(
    build::benches,
    build_additional::benches,
    prove_many_elements::benches,
    prove_single_element::benches,
);
