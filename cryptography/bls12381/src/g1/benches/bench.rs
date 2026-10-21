use criterion::criterion_main;

mod add;
mod mul;
mod sum;
mod utils;

criterion_main!(add::benches, mul::benches, sum::benches);
