use criterion::criterion_main;

mod decode;
mod decode_formatted;
mod encode;

criterion_main!(encode::benches, decode::benches, decode_formatted::benches);
