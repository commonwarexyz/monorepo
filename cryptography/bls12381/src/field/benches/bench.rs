use criterion::criterion_main;

mod convert;
mod mul;
mod utils;

criterion_main!(convert::benches, mul::benches);
