use criterion::criterion_main;

mod overwrite;
mod restart;
mod sync;
mod utils;

criterion_main!(sync::benches, overwrite::benches, restart::benches);
