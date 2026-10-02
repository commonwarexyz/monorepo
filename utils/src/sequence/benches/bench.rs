use criterion::criterion_main;

mod cmp_bytes;

criterion_main!(cmp_bytes::benches);
