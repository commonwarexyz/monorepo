//! Benchmarks for the stream crate.

use criterion::criterion_main;

mod send_frame;

criterion_main!(send_frame::benches);
