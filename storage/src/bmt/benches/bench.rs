use criterion::criterion_main;

mod build;
mod build_streaming;
mod prove_multi;
mod prove_range;
mod prove_single;
mod range_update_fixtures;
mod range_update_proofs;
mod update;
mod verify_range_update;

criterion_main!(
    build::benches,
    build_streaming::benches,
    prove_single::benches,
    prove_multi::benches,
    prove_range::benches,
    update::benches,
    range_update_proofs::benches,
    verify_range_update::benches,
);
