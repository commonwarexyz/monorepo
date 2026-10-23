use criterion::criterion_main;

mod add_many;
mod append;
mod append_additional;
mod common;
mod flush;
mod multi_proof;
mod position_to_location;
mod proof;
mod range_proof;
mod update;
mod verify_many_elements;
mod verify_multi;
mod verify_single_element;

criterion_main!(
    add_many::benches,
    add_many::skewed,
    append::benches,
    append_additional::benches,
    flush::benches,
    multi_proof::benches,
    position_to_location::benches,
    proof::benches,
    range_proof::benches,
    verify_single_element::benches,
    verify_many_elements::benches,
    verify_multi::benches,
    update::benches,
);
