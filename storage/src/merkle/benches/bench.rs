use commonware_allocator::mimalloc;
use criterion::criterion_main;

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

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
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
