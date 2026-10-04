//! Ordinary code the MIR reading takes since the reader widening: core's
//! slice iterator, nested loops, a loop test of two conditions, signed
//! comparisons, wrapping and sign extension, `?` on `Option`, byte
//! conversions, rotations, a slice's `get` by a range and a call into
//! another file of the crate, a match through a shared reference.
//! `tests/reader_widen.rs` lifts it in place.

/// The wrapping sum of the bytes (`for &b in data`).
pub fn sum_bytes(data: &[u8]) -> u64 {
    let mut s = 0u64;
    for &b in data {
        s = s.wrapping_add(b as u64);
    }
    s
}

/// The number of zero bytes, wrapping (`data.iter()`, a test in the body).
pub fn count_zeros(data: &[u8]) -> u32 {
    let mut n = 0u32;
    for b in data.iter() {
        if *b == 0 {
            n = n.wrapping_add(1);
        }
    }
    n
}

/// Nested loops over ranges.
pub fn mix_grid(n: u32) -> u32 {
    let mut s = 0u32;
    for i in 0..4u32 {
        for j in 0..3u32 {
            s = s.wrapping_mul(31).wrapping_add(i ^ j ^ n);
        }
    }
    s
}

/// A loop test of two conditions, counting both values down.
pub fn steps(mut a: u32, mut b: u32) -> u32 {
    let mut n = 0u32;
    while a > 0 || b > 0 {
        if a > 0 {
            a -= 1;
        } else {
            b -= 1;
        }
        n = n.wrapping_add(1);
    }
    n
}

/// Signed comparisons: the larger of two `i32`s.
pub fn smax(a: i32, b: i32) -> i32 {
    if a < b { b } else { a }
}

/// Signed `<=` and `>` with a wrapping sum of `i64`s.
pub fn sclass(a: i64, b: i64) -> u8 {
    if a <= b {
        0
    } else if a > b.wrapping_add(10) {
        2
    } else {
        1
    }
}

/// Sign extension: `i16` to `i64`, and to `u32`.
pub fn widen(a: i16) -> i64 {
    a as i64
}

/// Sign extension to an unsigned type.
pub fn widen_bits(a: i16) -> u32 {
    a as u32
}

/// `?` on `Option`.
pub fn plus4(x: usize) -> Option<usize> {
    let y = x.checked_add(4)?;
    Some(y)
}

/// Bytes to words and back (`transmute` in core's conversions).
pub fn le32(b: [u8; 4]) -> u32 {
    u32::from_le_bytes(b)
}

/// Big-endian bytes to a word (a byte swap after the conversion).
pub fn be32(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

/// A word to its little-endian bytes.
pub fn le_bytes(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

/// Rotations.
pub fn rot(x: u32, n: u32) -> u32 {
    x.rotate_left(n) ^ x.rotate_right(3)
}

/// A slice's `get` by a range.
pub fn window(data: &[u8], i: usize, j: usize) -> usize {
    match data.get(i..j) {
        Some(s) => s.len(),
        None => usize::MAX,
    }
}

/// A call into another file of the crate.
pub fn low_sum(x: u64, y: u64) -> u64 {
    crate::b::low(x).wrapping_add(crate::b::low(y))
}

/// A signed range: `for _ in 0..8` (an `i32` range) with rotations.
pub fn spin(x: u32) -> u32 {
    let mut out = 0u32;
    for _ in 0..8 {
        out = out.rotate_left(5) ^ x;
    }
    out
}

/// A slice iterator with its index (`enumerate`): the first byte at or above `0x20`.
pub fn first_printable(data: &[u8]) -> Option<usize> {
    for (i, &b) in data.iter().enumerate() {
        if b >= 0x20 {
            return Some(i);
        }
    }
    None
}

/// Bit-by-bit CRC-8 (polynomial 0x07): a range loop inside a slice loop.
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8u32 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Equality of two options (core's `Option::eq`: a match on `*self`, then on
/// `*other`, through shared references).
pub fn same(a: Option<u8>, b: Option<u8>) -> bool {
    a == b
}
