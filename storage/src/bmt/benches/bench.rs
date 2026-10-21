use criterion::criterion_main;

mod build;
mod multi_proof;
mod proof;
mod range_proof;
mod verify_multi;
mod verify_range;
mod verify_single;

criterion_main!(
    build::benches,
    proof::benches,
    multi_proof::benches,
    range_proof::benches,
    verify_single::benches,
    verify_multi::benches,
    verify_range::benches
);
