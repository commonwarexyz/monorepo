use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod add;
mod double;
mod msm;
mod mul;
mod multi_pairing;
mod pairing;
mod sum;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    add::benches,
    double::benches,
    msm::benches,
    mul::benches,
    multi_pairing::benches,
    pairing::benches,
    sum::benches
);
