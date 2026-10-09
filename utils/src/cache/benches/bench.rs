use criterion::criterion_main;

mod get;
mod insert;
mod mixed;
mod refill;
mod remove;

criterion_main!(
    get::benches,
    insert::benches,
    mixed::benches,
    refill::benches,
    remove::benches
);
