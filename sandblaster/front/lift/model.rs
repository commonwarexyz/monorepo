//! The lift prelude, model part (`crate::__lift_model`, a ghost `#[spec]`
//! module; SEMANTICS.md §19): the meaning of the `bytes` buffer calls that
//! lifted code makes. A `&mut impl BufMut` is the sequence of bytes put so far,
//! a `&mut impl Buf` the sequence of bytes not yet read; lifted functions take
//! them by value and return them (state passing).
//!
//! Host assumption (TCB): the caller's `Buf`/`BufMut` behave as these
//! sequences (true of `Vec<u8>`, `BytesMut`, `Bytes`, `&[u8]` adapters and
//! chains of them). A `BufMut` that panics when it runs out of capacity
//! panics in host code before the call returns; that panic is outside the
//! model.

use sandblaster::prelude::*;
use crate::__lift::{Result, TryGetError, I16, I32, I64};

/// `BufMut::put_u8(n)`: appends `n`.
#[example(bufmut_put_u8(seq![1u8], 2u8) == seq![1u8, 2u8])]
pub fn bufmut_put_u8(buf: Seq<u8>, n: u8) -> Seq<u8> {
    seq![..buf, n]
}

/// `BufMut::put_slice(src)`: appends `src`.
#[example(bufmut_put_slice(seq![1u8], &[2u8, 3u8]) == seq![1u8, 2u8, 3u8])]
pub fn bufmut_put_slice(buf: Seq<u8>, src: &[u8]) -> Seq<u8> {
    seq![..buf, ..src]
}

/// `Buf::try_get_u8()`: the first byte, consumed; an error that consumes
/// nothing when the buffer is empty.
#[example(buf_try_get_u8(seq![7u8, 8u8]) == (seq![8u8], Result::Ok(7u8)))]
#[example(buf_try_get_u8(seq![]) == (seq![], Result::Err(TryGetError)))]
pub fn buf_try_get_u8(buf: Seq<u8>) -> (Seq<u8>, Result<u8, TryGetError>) {
    match buf {
        [h, t @ ..] => (t, Result::Ok(h)),
        [] => (buf, Result::Err(TryGetError)),
    }
}

/// The value of the `i16` whose two's complement bits are `x.0` (what lifted
/// ghost code means by `x as Int` for a signed `x`). These conversions are
/// opaque in proofs (their uses stay folded; a proof unfolds them by name).
#[opaque]
#[example(int_of_i16(I16(0u16)) == 0 && int_of_i16(I16(5u16)) == 5 && int_of_i16(I16(32767u16)) == 32767)]
#[example(int_of_i16(I16(32768u16)) == -32768 && int_of_i16(I16(65535u16)) == -1)]
pub fn int_of_i16(x: I16) -> Int {
    if x.0 < 32768u16 { x.0 as Int } else { (x.0 as Int) - 65536 }
}

/// The value of the `i32` whose two's complement bits are `x.0`.
#[opaque]
#[example(int_of_i32(I32(0u32)) == 0 && int_of_i32(I32(5u32)) == 5 && int_of_i32(I32(2147483647u32)) == 2147483647)]
#[example(int_of_i32(I32(2147483648u32)) == -2147483648 && int_of_i32(I32(4294967295u32)) == -1)]
pub fn int_of_i32(x: I32) -> Int {
    if x.0 < 2147483648u32 { x.0 as Int } else { (x.0 as Int) - 4294967296 }
}

/// The value of the `i64` whose two's complement bits are `x.0`.
#[opaque]
#[example(int_of_i64(I64(0u64)) == 0 && int_of_i64(I64(5u64)) == 5 && int_of_i64(I64(9223372036854775807u64)) == 9223372036854775807)]
#[example(int_of_i64(I64(9223372036854775808u64)) == -9223372036854775808 && int_of_i64(I64(18446744073709551615u64)) == -1)]
pub fn int_of_i64(x: I64) -> Int {
    if x.0 < 9223372036854775808u64 { x.0 as Int } else { (x.0 as Int) - 18446744073709551616 }
}

/// The `i16` whose value is congruent to `i` modulo 2^16 (what lifted ghost
/// code means by `i as i16` for an integer `i`, as Rust's casts).
#[opaque]
#[example(i16_of_int(5) == I16(5u16) && i16_of_int(-1) == I16(65535u16) && i16_of_int(-32768) == I16(32768u16))]
#[example(i16_of_int(65536) == I16(0u16) && i16_of_int(-65536) == I16(0u16) && i16_of_int(32767) == I16(32767u16))]
pub fn i16_of_int(i: Int) -> I16 {
    if i >= 0 { I16((i as Nat) as u16) } else { I16((65536 - ((-i) as Nat) % 65536) as u16) }
}

/// The `i32` whose value is congruent to `i` modulo 2^32.
#[opaque]
#[example(i32_of_int(5) == I32(5u32) && i32_of_int(-1) == I32(4294967295u32) && i32_of_int(-2147483648) == I32(2147483648u32))]
#[example(i32_of_int(4294967296) == I32(0u32) && i32_of_int(-4294967296) == I32(0u32) && i32_of_int(2147483647) == I32(2147483647u32))]
pub fn i32_of_int(i: Int) -> I32 {
    if i >= 0 { I32((i as Nat) as u32) } else { I32((4294967296 - ((-i) as Nat) % 4294967296) as u32) }
}

/// The `i64` whose value is congruent to `i` modulo 2^64.
#[opaque]
#[example(i64_of_int(5) == I64(5u64) && i64_of_int(-1) == I64(18446744073709551615u64) && i64_of_int(-9223372036854775808) == I64(9223372036854775808u64))]
#[example(i64_of_int(18446744073709551616) == I64(0u64) && i64_of_int(-18446744073709551616) == I64(0u64) && i64_of_int(9223372036854775807) == I64(9223372036854775807u64))]
pub fn i64_of_int(i: Int) -> I64 {
    if i >= 0 { I64((i as Nat) as u64) } else { I64((18446744073709551616 - ((-i) as Nat) % 18446744073709551616) as u64) }
}
