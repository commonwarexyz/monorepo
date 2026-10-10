use criterion::criterion_main;

mod displace;
mod get;
mod insert;
mod mixed;
mod refill;

criterion_main!(
    displace::benches,
    get::benches,
    insert::benches,
    mixed::benches,
    refill::benches
);
