use criterion::criterion_main;

mod get;
mod put;
mod restart;
mod utils;

criterion_main!(put::benches, get::benches, restart::benches);
