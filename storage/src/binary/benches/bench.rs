use criterion::criterion_main;

mod new;
mod prove_single_element;

criterion_main!(new::benches, prove_single_element::benches);
