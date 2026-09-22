//! Benchmark private decode experiments without generating unrelated unit tests.

// Shared modules retain public API conventions and unused unit-test helpers.
#![allow(
    dead_code,
    unused_imports,
    unused_macros,
    clippy::wrong_self_convention
)]

extern crate alloc;

mod banderwagon;
mod bls12381;
mod fuzz;
mod hash;
mod test;

fn main() {
    bls12381::group::subgroup::decompression::receive::benchmark_wire_to_points();
}
