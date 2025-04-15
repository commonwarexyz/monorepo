use criterion::criterion_main;

mod append;
mod append_additional;
mod bitmap;
mod prove_many_elements;
mod prove_single_element;

criterion_main!(
    //bitmap::benches,
    append::benches,
    append_additional::benches,
    prove_many_elements::benches,
    prove_single_element::benches,
);
