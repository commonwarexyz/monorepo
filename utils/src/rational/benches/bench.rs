use criterion::criterion_main;

mod log2_ceil;

criterion_main!(log2_ceil::benches);
