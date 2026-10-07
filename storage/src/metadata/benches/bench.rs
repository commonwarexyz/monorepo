use criterion::criterion_main;

mod restart;
mod sync;
mod sync_small;
mod utils;

criterion_main!(sync::benches, sync_small::benches, restart::benches);
