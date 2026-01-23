use criterion::criterion_main;

mod contains;
mod insert;

criterion_main!(insert::benches, contains::benches);
