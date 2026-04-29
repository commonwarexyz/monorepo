use criterion::criterion_main;

mod decode;
mod encode;

criterion_main!(encode::benches, decode::benches);
