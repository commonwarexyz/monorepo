use criterion::criterion_main;

mod convert;
mod fp12;
mod fp2;
mod mul;
mod utils;

criterion_main!(convert::benches, fp12::benches, fp2::benches, mul::benches);
