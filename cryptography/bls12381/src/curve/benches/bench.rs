use criterion::criterion_main;

mod g1;
mod utils;

criterion_main!(g1::benches);
