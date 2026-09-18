use criterion::criterion_main;

mod get;
mod insert;
mod mixed;
mod refill;

criterion_main!(
    get::benches,
    insert::benches,
    mixed::benches,
    refill::benches
);
