use criterion::criterion_main;

mod get;
mod get_large;
mod get_pressure;
mod put;
mod restart;
mod utils;

criterion_main!(
    put::benches,
    get::benches,
    get_large::benches,
    get_pressure::benches,
    restart::benches
);
