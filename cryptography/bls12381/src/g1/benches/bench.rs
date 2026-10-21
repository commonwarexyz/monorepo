use criterion::criterion_main;

mod add;
mod decode;
mod msm;
mod mul;
mod sum;
mod utils;

criterion_main!(
    add::benches,
    decode::benches,
    msm::benches,
    mul::benches,
    sum::benches
);
