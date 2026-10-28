use criterion::criterion_main;

mod final_exponentiation;
mod miller_loop;
mod multi_pairing;
mod pairing;
mod pairing_check;
mod utils;

criterion_main!(
    final_exponentiation::benches,
    miller_loop::benches,
    multi_pairing::benches,
    pairing::benches,
    pairing_check::benches
);
