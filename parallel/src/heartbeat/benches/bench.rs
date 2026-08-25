use criterion::criterion_main;

mod fold;

criterion_main!(fold::benches);
