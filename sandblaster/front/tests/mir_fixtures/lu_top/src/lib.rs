//! tests/lowered_use.rs: `src/bits.rs` lifted in place at the top level, with the alternatives `opt.rs`.
#![allow(dead_code)]
pub mod bits;
pub fn f(x: u8) -> bool { bits::at_most_one_bit(x) }
