//! tests/lift_opt.rs: a host crate whose `src/bits.rs` is lifted in place, with the alternatives `opt.rs` (compiled as `mod opt`, `--inject`).
#![allow(dead_code)]
mod bits;
pub fn f(x: u8) -> bool { bits::at_most_one_bit(x) }
