use criterion::criterion_main;

mod g1;
mod g2;
mod utils;

criterion_main!(g1::benches, g2::benches);
