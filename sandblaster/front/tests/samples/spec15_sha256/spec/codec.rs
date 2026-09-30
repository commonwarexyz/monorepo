//! The reference of the big-endian `u32` reader, over unbounded sequences
//! and natural numbers: the value `b0·2^24 + b1·2^16 + b2·2^8 + b3` of the
//! first four bytes, and the rest.

#[example(read_u32_be(seq![1u8, 2u8, 3u8, 4u8, 5u8]) == Some((16909060, seq![5u8])))]
#[example(read_u32_be(seq![0xffu8, 0xffu8, 0xffu8, 0xffu8]) == Some((4294967295, seq![])))]
#[example(read_u32_be(seq![1u8, 2u8, 3u8]) == None)]
pub fn read_u32_be(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    if xs.len() < 4 {
        None
    } else {
        Some(((xs[0] as Nat) * 16777216 + (xs[1] as Nat) * 65536 + (xs[2] as Nat) * 256 + (xs[3] as Nat), xs.skip(4)))
    }
}
