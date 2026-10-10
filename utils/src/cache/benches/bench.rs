use criterion::criterion_main;

mod displace;
mod get;
mod insert;
mod mixed;
mod refill;
mod remove;

criterion_main!(
    displace::benches,
    get::benches,
    insert::benches,
    mixed::benches,
    refill::benches,
    remove::benches
);
