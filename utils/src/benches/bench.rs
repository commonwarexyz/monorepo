mod bitmap;
mod log2_ceil;

criterion::criterion_main!(bitmap::benches, log2_ceil::benches);
