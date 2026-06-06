use criterion::criterion_main;

mod finalize;

criterion_main!(finalize::benches);
