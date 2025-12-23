use criterion::criterion_main;

mod restart;
mod sync;
mod utils;

criterion_main!(sync::benches, restart::benches);
