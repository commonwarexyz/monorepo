use criterion::criterion_main;

mod throughput;

criterion_main!(throughput::benches);
