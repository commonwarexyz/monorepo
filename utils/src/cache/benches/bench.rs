use criterion::criterion_main;

mod get;
mod insert;
mod mixed;

criterion_main!(get::benches, insert::benches, mixed::benches);
