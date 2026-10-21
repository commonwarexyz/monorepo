use criterion::criterion_main;

mod append;
mod append_additional;
mod common;
mod flush;
mod position_to_location;
mod proof;
mod range_proof;
mod update;
mod verify_many_elements;
mod verify_single_element;

criterion_main!(
    append::benches,
    append_additional::benches,
    flush::benches,
    position_to_location::benches,
    proof::benches,
    range_proof::benches,
    verify_single_element::benches,
    verify_many_elements::benches,
    update::benches,
);
