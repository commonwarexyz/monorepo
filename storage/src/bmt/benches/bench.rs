use criterion::criterion_main;

mod build;
mod prove_single_element;

criterion_main!(build::benches, prove_single_element::benches);
