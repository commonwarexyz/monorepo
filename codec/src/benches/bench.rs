use criterion::criterion_main;

mod lazy;
mod utils;

criterion_main!(lazy::benches);
