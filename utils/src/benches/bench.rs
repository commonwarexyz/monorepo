mod log2_ceil;
mod roaring;

criterion::criterion_main!(log2_ceil::benches, roaring::benches);
