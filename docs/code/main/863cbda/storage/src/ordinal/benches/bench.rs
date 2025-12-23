use criterion::criterion_main;

mod get;
mod put;
mod restart;
mod utils;

criterion_main!(get::benches, put::benches, restart::benches);
