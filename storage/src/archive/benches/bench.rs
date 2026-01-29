use criterion::criterion_main;

mod get;
mod index_of;
mod put;
mod restart;
mod utils;

criterion_main!(put::benches, get::benches, index_of::benches, restart::benches);
