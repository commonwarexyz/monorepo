use criterion::criterion_main;

mod encode_decode;

criterion_main!(encode_decode::benches);
