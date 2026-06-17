use criterion::criterion_main;

mod get;
mod insert;

criterion_main!(get::benches, insert::benches);
