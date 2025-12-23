use criterion::criterion_main;

mod insert;

criterion_main!(insert::benches);
