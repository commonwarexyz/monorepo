use criterion::criterion_main;

mod add;
mod decode;
mod hash;
mod msm;
mod mul;
mod sum;
mod utils;

criterion_main!(
    add::benches,
    decode::benches,
    hash::benches,
    msm::benches,
    mul::benches,
    sum::benches
);
