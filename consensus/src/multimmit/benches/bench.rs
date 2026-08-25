use criterion::criterion_main;

mod aggregate;
mod common;
mod engine;
mod journal;
mod machine;
mod ordinary;
mod recover;
mod shares;

criterion_main!(
    ordinary::benches,
    shares::benches,
    recover::benches,
    aggregate::benches,
    machine::benches,
    journal::benches,
    engine::benches,
);
