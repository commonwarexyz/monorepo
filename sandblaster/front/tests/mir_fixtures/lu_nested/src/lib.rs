//! tests/lowered_use.rs: `src/outer/bits.rs` lifted in place as a child of `outer`, with the alternatives `opt.rs`.
#![allow(dead_code)]
mod outer;
pub fn f(x: u8) -> bool { outer::bits::at_most_one_bit(x) }
