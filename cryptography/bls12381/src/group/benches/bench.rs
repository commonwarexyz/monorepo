//! Benchmarks of the group operations.
//!
//! The benchmarks compare the public API with blst on the same inputs: addition, doubling,
//! multiplication by a scalar, sums, and multi-scalar multiplications in G1 and G2, and single
//! and multiple pairings.

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
