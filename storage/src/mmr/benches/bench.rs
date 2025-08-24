use criterion::criterion_main;

mod append;
mod append_additional;
mod leaf_pos_to_num;
mod prove_many_elements;
mod prove_single_element;
mod update;

criterion_main!(
    append::benches,
    append_additional::benches,
    prove_many_elements::benches,
    prove_single_element::benches,
    leaf_pos_to_num::benches,
    update::benches,
);
