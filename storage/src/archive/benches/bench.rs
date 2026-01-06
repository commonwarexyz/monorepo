use criterion::criterion_main;

mod get;
mod get_large;
mod put;
mod restart;
mod utils;

criterion_main!(put::benches, get::benches, get_large::benches, restart::benches);
