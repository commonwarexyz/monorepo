use criterion::criterion_main;

mod add;
mod decode;
mod mul;
mod sum;
mod utils;

criterion_main!(add::benches, decode::benches, mul::benches, sum::benches);
