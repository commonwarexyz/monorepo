//! tests/lowered_use.rs: `bits.rs` with an out-of-line test module.
#![allow(dead_code)]
mod outer;
pub fn f(x: u8) -> bool { outer::bits::at_most_one_bit(x) }
