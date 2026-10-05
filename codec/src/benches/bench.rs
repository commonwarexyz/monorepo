use criterion::criterion_main;

mod encode;
mod tx;
mod varint;

criterion_main!(encode::benches, varint::benches);
