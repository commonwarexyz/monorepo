use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod final_exponentiation;
mod miller_loop;
mod pairing;
mod pairing_check;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    final_exponentiation::benches,
    miller_loop::benches,
    pairing::benches,
    pairing_check::benches
);
