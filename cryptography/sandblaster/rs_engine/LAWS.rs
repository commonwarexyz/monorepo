//! What Reed–Solomon's engine multiply computes, for the NEON engine and the
//! scalar engine of commonware-cryptography as written
//! (`src/reed_solomon/engine/engine_neon.rs`, `engine_scalar.rs`), and the
//! claim that they compute the same.
//!
//! Reading the statements. A field element of GF(2^16) is two bytes: in a
//! 64-byte chunk, element `i < 32` keeps its low byte at `i` and its high
//! byte at `32 + i` (`Engine::mul`'s layout). Multiplying an element by the
//! multiplier with logarithm `log_m` looks up its four nibbles in tables: the
//! NEON engine's row `Multiply128lutT` holds, for each nibble position `i`,
//! the sixteen low product bytes in `lo[i]` and the sixteen high ones in
//! `hi[i]`, each a `u128` read as its sixteen little-endian bytes
//! (`row_bytes`); the scalar engine's row `[[u16; 16]; 4]` holds the 16-bit
//! products themselves. A `u128` is read as the pair of its 64-bit words,
//! low word first (`t.0`, `t.1`; docs/DESIGN-UNSAFE-SIMD.md §2.2). A vector
//! (`uint8x16_t`) is the array of its sixteen lanes, lane 0 first. In
//! `{ let mut a = x; n.mul(&mut a, log_m); a }`, `a` is the slice of chunks
//! after the call. `n.mul128[log_m as usize]` is the engine's table row
//! for the multiplier (the tables the constructors build, `tables.rs`, stay
//! host code: the claim that the two engines agree takes their relation,
//! `is_split_of`, as its hypothesis).
use sandblaster::prelude::*;
use core::arch::aarch64::*;
use crate::reed_solomon::engine::engine_neon::Neon;
use crate::reed_solomon::engine::engine_scalar::Scalar;
use crate::reed_solomon::engine::tables::Multiply128lutT;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// The sixteen bytes of a 128-bit table row `t`: its little-endian bytes, the
/// low word's first (`t.to_ne_bytes()` on these little-endian targets).
#[spec]
#[example(row_bytes((0x0807060504030201u64, 0x100f0e0d0c0b0a09u64)) == [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])]
pub fn row_bytes(t: u128) -> [u8; 16] {
    [t.0.to_le_bytes()[0],
        t.0.to_le_bytes()[1],
        t.0.to_le_bytes()[2],
        t.0.to_le_bytes()[3],
        t.0.to_le_bytes()[4],
        t.0.to_le_bytes()[5],
        t.0.to_le_bytes()[6],
        t.0.to_le_bytes()[7],
        t.1.to_le_bytes()[0],
        t.1.to_le_bytes()[1],
        t.1.to_le_bytes()[2],
        t.1.to_le_bytes()[3],
        t.1.to_le_bytes()[4],
        t.1.to_le_bytes()[5],
        t.1.to_le_bytes()[6],
        t.1.to_le_bytes()[7]]
}

/// The table row of the multiplier one: nibble `x` at position `i` times one
/// is `x << (4 * i)`, its low byte in `lo[i]` (positions 0 and 1), its high
/// byte in `hi[i]` (positions 2 and 3). A known answer for the examples.
pub const LUT_ONE: Multiply128lutT = Multiply128lutT {
    lo: [(0x0706050403020100u64, 0x0f0e0d0c0b0a0908u64), (0x7060504030201000u64, 0xf0e0d0c0b0a09080u64), (0u64, 0u64), (0u64, 0u64)],
    hi: [(0u64, 0u64), (0u64, 0u64), (0x0706050403020100u64, 0x0f0e0d0c0b0a0908u64), (0x7060504030201000u64, 0xf0e0d0c0b0a09080u64)],
};

/// The low byte of the product of one element (low byte `lo`, high byte `hi`)
/// by the multiplier of `lut`: its four nibbles' entries in the rows of the
/// product's low bytes, combined by xor.
#[spec]
#[example(mul_lo_byte(LUT_ONE, 0x5au8, 0xa5u8) == 0x5au8)]
#[example(mul_lo_byte(LUT_ONE, 0xffu8, 0x00u8) == 0xffu8)]
pub fn mul_lo_byte(lut: Multiply128lutT, lo: u8, hi: u8) -> u8 {
    row_bytes(lut.lo[0])[(lo & 15u8) as usize] ^ row_bytes(lut.lo[1])[(lo >> 4u32) as usize] ^ row_bytes(lut.lo[2])[(hi & 15u8) as usize] ^ row_bytes(lut.lo[3])[(hi >> 4u32) as usize]
}

/// The high byte of the same product.
#[spec]
#[example(mul_hi_byte(LUT_ONE, 0x5au8, 0xa5u8) == 0xa5u8)]
#[example(mul_hi_byte(LUT_ONE, 0xffu8, 0x00u8) == 0x00u8)]
pub fn mul_hi_byte(lut: Multiply128lutT, lo: u8, hi: u8) -> u8 {
    row_bytes(lut.hi[0])[(lo & 15u8) as usize] ^ row_bytes(lut.hi[1])[(lo >> 4u32) as usize] ^ row_bytes(lut.hi[2])[(hi & 15u8) as usize] ^ row_bytes(lut.hi[3])[(hi >> 4u32) as usize]
}

/// The low product bytes of sixteen elements (their low bytes in `vlo`, their
/// high bytes in `vhi`), lane 0 first.
#[spec]
#[example(mul_lo_lanes(LUT_ONE, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255], [9u8; 16]) == [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255])]
pub fn mul_lo_lanes(lut: Multiply128lutT, vlo: [u8; 16], vhi: [u8; 16]) -> [u8; 16] {
    [mul_lo_byte(lut, vlo[0], vhi[0]),
        mul_lo_byte(lut, vlo[1], vhi[1]),
        mul_lo_byte(lut, vlo[2], vhi[2]),
        mul_lo_byte(lut, vlo[3], vhi[3]),
        mul_lo_byte(lut, vlo[4], vhi[4]),
        mul_lo_byte(lut, vlo[5], vhi[5]),
        mul_lo_byte(lut, vlo[6], vhi[6]),
        mul_lo_byte(lut, vlo[7], vhi[7]),
        mul_lo_byte(lut, vlo[8], vhi[8]),
        mul_lo_byte(lut, vlo[9], vhi[9]),
        mul_lo_byte(lut, vlo[10], vhi[10]),
        mul_lo_byte(lut, vlo[11], vhi[11]),
        mul_lo_byte(lut, vlo[12], vhi[12]),
        mul_lo_byte(lut, vlo[13], vhi[13]),
        mul_lo_byte(lut, vlo[14], vhi[14]),
        mul_lo_byte(lut, vlo[15], vhi[15])]
}

/// Their high product bytes.
#[spec]
#[example(mul_hi_lanes(LUT_ONE, [9u8; 16], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]) == [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255])]
pub fn mul_hi_lanes(lut: Multiply128lutT, vlo: [u8; 16], vhi: [u8; 16]) -> [u8; 16] {
    [mul_hi_byte(lut, vlo[0], vhi[0]),
        mul_hi_byte(lut, vlo[1], vhi[1]),
        mul_hi_byte(lut, vlo[2], vhi[2]),
        mul_hi_byte(lut, vlo[3], vhi[3]),
        mul_hi_byte(lut, vlo[4], vhi[4]),
        mul_hi_byte(lut, vlo[5], vhi[5]),
        mul_hi_byte(lut, vlo[6], vhi[6]),
        mul_hi_byte(lut, vlo[7], vhi[7]),
        mul_hi_byte(lut, vlo[8], vhi[8]),
        mul_hi_byte(lut, vlo[9], vhi[9]),
        mul_hi_byte(lut, vlo[10], vhi[10]),
        mul_hi_byte(lut, vlo[11], vhi[11]),
        mul_hi_byte(lut, vlo[12], vhi[12]),
        mul_hi_byte(lut, vlo[13], vhi[13]),
        mul_hi_byte(lut, vlo[14], vhi[14]),
        mul_hi_byte(lut, vlo[15], vhi[15])]
}

/// A 64-byte chunk with each of its 32 elements multiplied by the multiplier
/// of `lut`: element `i`'s product's low byte at `i`, its high byte at `32 + i`.
#[spec]
#[example(mul_chunk(LUT_ONE, [7u8; 64]) == [7u8; 64])]
pub fn mul_chunk(lut: Multiply128lutT, c: [u8; 64]) -> [u8; 64] {
    [mul_lo_byte(lut, c[0], c[32]),
        mul_lo_byte(lut, c[1], c[33]),
        mul_lo_byte(lut, c[2], c[34]),
        mul_lo_byte(lut, c[3], c[35]),
        mul_lo_byte(lut, c[4], c[36]),
        mul_lo_byte(lut, c[5], c[37]),
        mul_lo_byte(lut, c[6], c[38]),
        mul_lo_byte(lut, c[7], c[39]),
        mul_lo_byte(lut, c[8], c[40]),
        mul_lo_byte(lut, c[9], c[41]),
        mul_lo_byte(lut, c[10], c[42]),
        mul_lo_byte(lut, c[11], c[43]),
        mul_lo_byte(lut, c[12], c[44]),
        mul_lo_byte(lut, c[13], c[45]),
        mul_lo_byte(lut, c[14], c[46]),
        mul_lo_byte(lut, c[15], c[47]),
        mul_lo_byte(lut, c[16], c[48]),
        mul_lo_byte(lut, c[17], c[49]),
        mul_lo_byte(lut, c[18], c[50]),
        mul_lo_byte(lut, c[19], c[51]),
        mul_lo_byte(lut, c[20], c[52]),
        mul_lo_byte(lut, c[21], c[53]),
        mul_lo_byte(lut, c[22], c[54]),
        mul_lo_byte(lut, c[23], c[55]),
        mul_lo_byte(lut, c[24], c[56]),
        mul_lo_byte(lut, c[25], c[57]),
        mul_lo_byte(lut, c[26], c[58]),
        mul_lo_byte(lut, c[27], c[59]),
        mul_lo_byte(lut, c[28], c[60]),
        mul_lo_byte(lut, c[29], c[61]),
        mul_lo_byte(lut, c[30], c[62]),
        mul_lo_byte(lut, c[31], c[63]),
        mul_hi_byte(lut, c[0], c[32]),
        mul_hi_byte(lut, c[1], c[33]),
        mul_hi_byte(lut, c[2], c[34]),
        mul_hi_byte(lut, c[3], c[35]),
        mul_hi_byte(lut, c[4], c[36]),
        mul_hi_byte(lut, c[5], c[37]),
        mul_hi_byte(lut, c[6], c[38]),
        mul_hi_byte(lut, c[7], c[39]),
        mul_hi_byte(lut, c[8], c[40]),
        mul_hi_byte(lut, c[9], c[41]),
        mul_hi_byte(lut, c[10], c[42]),
        mul_hi_byte(lut, c[11], c[43]),
        mul_hi_byte(lut, c[12], c[44]),
        mul_hi_byte(lut, c[13], c[45]),
        mul_hi_byte(lut, c[14], c[46]),
        mul_hi_byte(lut, c[15], c[47]),
        mul_hi_byte(lut, c[16], c[48]),
        mul_hi_byte(lut, c[17], c[49]),
        mul_hi_byte(lut, c[18], c[50]),
        mul_hi_byte(lut, c[19], c[51]),
        mul_hi_byte(lut, c[20], c[52]),
        mul_hi_byte(lut, c[21], c[53]),
        mul_hi_byte(lut, c[22], c[54]),
        mul_hi_byte(lut, c[23], c[55]),
        mul_hi_byte(lut, c[24], c[56]),
        mul_hi_byte(lut, c[25], c[57]),
        mul_hi_byte(lut, c[26], c[58]),
        mul_hi_byte(lut, c[27], c[59]),
        mul_hi_byte(lut, c[28], c[60]),
        mul_hi_byte(lut, c[29], c[61]),
        mul_hi_byte(lut, c[30], c[62]),
        mul_hi_byte(lut, c[31], c[63])]
}

/// Sixteen bytes xored lane by lane.
#[spec]
#[example(xor_lanes([1u8; 16], [3u8; 16]) == [2u8; 16])]
pub fn xor_lanes(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3], a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
        a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11], a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15]]
}

/// Every chunk of `s` multiplied by the multiplier of `lut`.
#[spec]
#[example(mul_all(LUT_ONE, seq![[7u8; 64], [9u8; 64]]) == seq![[7u8; 64], [9u8; 64]])]
pub fn mul_all(lut: Multiply128lutT, s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {
    match s {
        [] => Seq::empty(),
        [c, rest @ ..] => Seq::cons(mul_chunk(lut, c), mul_all(lut, rest)),
    }
}

/// Scalar's table row of the multiplier one (`LUT_ONE`'s 16-bit entries):
/// nibble `x` at position `i` times one is `x << (4 * i)`.
pub const LUT16_ONE: [[u16; 16]; 4] = [[0u16, 1u16, 2u16, 3u16, 4u16, 5u16, 6u16, 7u16, 8u16, 9u16, 10u16, 11u16, 12u16, 13u16, 14u16, 15u16],
    [0u16, 16u16, 32u16, 48u16, 64u16, 80u16, 96u16, 112u16, 128u16, 144u16, 160u16, 176u16, 192u16, 208u16, 224u16, 240u16],
    [0u16, 256u16, 512u16, 768u16, 1024u16, 1280u16, 1536u16, 1792u16, 2048u16, 2304u16, 2560u16, 2816u16, 3072u16, 3328u16, 3584u16, 3840u16],
    [0u16, 4096u16, 8192u16, 12288u16, 16384u16, 20480u16, 24576u16, 28672u16, 32768u16, 36864u16, 40960u16, 45056u16, 49152u16, 53248u16, 57344u16, 61440u16]];

/// The product of one element (low byte `lo`, high byte `hi`) by the
/// multiplier of Scalar's row `lut16`: its four nibbles' 16-bit entries,
/// combined by xor.
#[spec]
#[example(mul16(LUT16_ONE, 0x5au8, 0xa5u8) == 0xa55au16)]
#[example(mul16(LUT16_ONE, 0xffu8, 0x00u8) == 0x00ffu16)]
pub fn mul16(lut16: [[u16; 16]; 4], lo: u8, hi: u8) -> u16 {
    lut16[0][(lo & 15u8) as usize] ^ lut16[1][(lo >> 4u32) as usize] ^ lut16[2][(hi & 15u8) as usize] ^ lut16[3][(hi >> 4u32) as usize]
}

/// A 64-byte chunk with each of its 32 elements multiplied by the multiplier
/// of Scalar's row `lut16`: element `i`'s product's low byte at `i`, its high
/// byte at `32 + i`.
#[spec]
#[example(mul_chunk16(LUT16_ONE, [7u8; 64]) == [7u8; 64])]
pub fn mul_chunk16(lut16: [[u16; 16]; 4], c: [u8; 64]) -> [u8; 64] {
    [mul16(lut16, c[0], c[32]) as u8,
        mul16(lut16, c[1], c[33]) as u8,
        mul16(lut16, c[2], c[34]) as u8,
        mul16(lut16, c[3], c[35]) as u8,
        mul16(lut16, c[4], c[36]) as u8,
        mul16(lut16, c[5], c[37]) as u8,
        mul16(lut16, c[6], c[38]) as u8,
        mul16(lut16, c[7], c[39]) as u8,
        mul16(lut16, c[8], c[40]) as u8,
        mul16(lut16, c[9], c[41]) as u8,
        mul16(lut16, c[10], c[42]) as u8,
        mul16(lut16, c[11], c[43]) as u8,
        mul16(lut16, c[12], c[44]) as u8,
        mul16(lut16, c[13], c[45]) as u8,
        mul16(lut16, c[14], c[46]) as u8,
        mul16(lut16, c[15], c[47]) as u8,
        mul16(lut16, c[16], c[48]) as u8,
        mul16(lut16, c[17], c[49]) as u8,
        mul16(lut16, c[18], c[50]) as u8,
        mul16(lut16, c[19], c[51]) as u8,
        mul16(lut16, c[20], c[52]) as u8,
        mul16(lut16, c[21], c[53]) as u8,
        mul16(lut16, c[22], c[54]) as u8,
        mul16(lut16, c[23], c[55]) as u8,
        mul16(lut16, c[24], c[56]) as u8,
        mul16(lut16, c[25], c[57]) as u8,
        mul16(lut16, c[26], c[58]) as u8,
        mul16(lut16, c[27], c[59]) as u8,
        mul16(lut16, c[28], c[60]) as u8,
        mul16(lut16, c[29], c[61]) as u8,
        mul16(lut16, c[30], c[62]) as u8,
        mul16(lut16, c[31], c[63]) as u8,
        (mul16(lut16, c[0], c[32]) >> 8u32) as u8,
        (mul16(lut16, c[1], c[33]) >> 8u32) as u8,
        (mul16(lut16, c[2], c[34]) >> 8u32) as u8,
        (mul16(lut16, c[3], c[35]) >> 8u32) as u8,
        (mul16(lut16, c[4], c[36]) >> 8u32) as u8,
        (mul16(lut16, c[5], c[37]) >> 8u32) as u8,
        (mul16(lut16, c[6], c[38]) >> 8u32) as u8,
        (mul16(lut16, c[7], c[39]) >> 8u32) as u8,
        (mul16(lut16, c[8], c[40]) >> 8u32) as u8,
        (mul16(lut16, c[9], c[41]) >> 8u32) as u8,
        (mul16(lut16, c[10], c[42]) >> 8u32) as u8,
        (mul16(lut16, c[11], c[43]) >> 8u32) as u8,
        (mul16(lut16, c[12], c[44]) >> 8u32) as u8,
        (mul16(lut16, c[13], c[45]) >> 8u32) as u8,
        (mul16(lut16, c[14], c[46]) >> 8u32) as u8,
        (mul16(lut16, c[15], c[47]) >> 8u32) as u8,
        (mul16(lut16, c[16], c[48]) >> 8u32) as u8,
        (mul16(lut16, c[17], c[49]) >> 8u32) as u8,
        (mul16(lut16, c[18], c[50]) >> 8u32) as u8,
        (mul16(lut16, c[19], c[51]) >> 8u32) as u8,
        (mul16(lut16, c[20], c[52]) >> 8u32) as u8,
        (mul16(lut16, c[21], c[53]) >> 8u32) as u8,
        (mul16(lut16, c[22], c[54]) >> 8u32) as u8,
        (mul16(lut16, c[23], c[55]) >> 8u32) as u8,
        (mul16(lut16, c[24], c[56]) >> 8u32) as u8,
        (mul16(lut16, c[25], c[57]) >> 8u32) as u8,
        (mul16(lut16, c[26], c[58]) >> 8u32) as u8,
        (mul16(lut16, c[27], c[59]) >> 8u32) as u8,
        (mul16(lut16, c[28], c[60]) >> 8u32) as u8,
        (mul16(lut16, c[29], c[61]) >> 8u32) as u8,
        (mul16(lut16, c[30], c[62]) >> 8u32) as u8,
        (mul16(lut16, c[31], c[63]) >> 8u32) as u8]
}

/// Every chunk of `s` multiplied by the multiplier of Scalar's row `lut16`.
#[spec]
#[example(mul_all16(LUT16_ONE, seq![[7u8; 64], [9u8; 64]]) == seq![[7u8; 64], [9u8; 64]])]
pub fn mul_all16(lut16: [[u16; 16]; 4], s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {
    match s {
        [] => Seq::empty(),
        [c, rest @ ..] => Seq::cons(mul_chunk16(lut16, c), mul_all16(lut16, rest)),
    }
}

/// The low bytes of sixteen 16-bit entries.
#[spec]
#[example(lo_bytes(LUT16_ONE[2]) == [0u8; 16])]
pub fn lo_bytes(r: [u16; 16]) -> [u8; 16] {
    [r[0] as u8,
        r[1] as u8,
        r[2] as u8,
        r[3] as u8,
        r[4] as u8,
        r[5] as u8,
        r[6] as u8,
        r[7] as u8,
        r[8] as u8,
        r[9] as u8,
        r[10] as u8,
        r[11] as u8,
        r[12] as u8,
        r[13] as u8,
        r[14] as u8,
        r[15] as u8]
}

/// Their high bytes.
#[spec]
#[example(hi_bytes(LUT16_ONE[2]) == [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])]
pub fn hi_bytes(r: [u16; 16]) -> [u8; 16] {
    [(r[0] >> 8u32) as u8,
        (r[1] >> 8u32) as u8,
        (r[2] >> 8u32) as u8,
        (r[3] >> 8u32) as u8,
        (r[4] >> 8u32) as u8,
        (r[5] >> 8u32) as u8,
        (r[6] >> 8u32) as u8,
        (r[7] >> 8u32) as u8,
        (r[8] >> 8u32) as u8,
        (r[9] >> 8u32) as u8,
        (r[10] >> 8u32) as u8,
        (r[11] >> 8u32) as u8,
        (r[12] >> 8u32) as u8,
        (r[13] >> 8u32) as u8,
        (r[14] >> 8u32) as u8,
        (r[15] >> 8u32) as u8]
}

/// NEON's row `lut` is the byte split of Scalar's row `lut16`: for each
/// nibble position `i`, the sixteen bytes of `lut.lo[i]` are the low bytes of
/// `lut16[i]`'s entries and those of `lut.hi[i]` their high bytes (the layout
/// `tables::Multiply128lutT` documents).
#[spec]
#[example(is_split_of(LUT_ONE, LUT16_ONE))]
#[example(!is_split_of(LUT_ONE, [[0u16; 16]; 4]))]
pub fn is_split_of(lut: Multiply128lutT, lut16: [[u16; 16]; 4]) -> bool {
    row_bytes(lut.lo[0]) == lo_bytes(lut16[0]) && row_bytes(lut.hi[0]) == hi_bytes(lut16[0])
        && row_bytes(lut.lo[1]) == lo_bytes(lut16[1]) && row_bytes(lut.hi[1]) == hi_bytes(lut16[1])
        && row_bytes(lut.lo[2]) == lo_bytes(lut16[2]) && row_bytes(lut.hi[2]) == hi_bytes(lut16[2])
        && row_bytes(lut.lo[3]) == lo_bytes(lut16[3]) && row_bytes(lut.hi[3]) == hi_bytes(lut16[3])
}

// ---------------------------------------------------------------------------
// The NEON engine
// ---------------------------------------------------------------------------

/// `muladd_128` adds to sixteen elements (their low bytes in `x_lo`, their
/// high bytes in `x_hi`) the products of sixteen others (`y_lo`, `y_hi`) by
/// the multiplier of `lut`, lane by lane. (Its contract: a private function
/// the engine's transforms call, specified where it is defined.)
#[lift_attach(crate::reed_solomon::engine::engine_neon::Neon::muladd_128)]
fn muladd_128_contract() {
    ensures(|ret: (uint8x16_t, uint8x16_t)| ret == (crate::laws::xor_lanes(x_lo, crate::laws::mul_lo_lanes(*lut, y_lo, y_hi)), crate::laws::xor_lanes(x_hi, crate::laws::mul_hi_lanes(*lut, y_lo, y_hi))));
}

/// `mul` multiplies every element of every chunk by the multiplier with
/// logarithm `log_m`, through the engine's table row for it.
#[law]
fn neon_mul_multiplies_every_chunk(n: Neon, x: &[[u8; 64]], log_m: u16) {
    ensures({ let mut a = x; n.mul(&mut a, log_m); a } == mul_all(n.mul128[log_m as usize], x));
}

// ---------------------------------------------------------------------------
// The scalar engine, and the two engines together
// ---------------------------------------------------------------------------

/// `mul` multiplies every element of every chunk by the multiplier with
/// logarithm `log_m`, through the engine's 16-bit table row for it.
#[law]
fn scalar_mul_multiplies_every_chunk(s: Scalar, x: &[[u8; 64]], log_m: u16) {
    ensures({ let mut b = x; s.mul(&mut b, log_m); b } == mul_all16(s.mul16[log_m as usize], x));
}

/// The NEON engine's `mul` is the scalar engine's `mul`, on every input,
/// whenever the NEON engine's table row for the multiplier is the byte
/// split of the scalar engine's (`is_split_of`; the tables the constructors
/// build, host code, are related by the crate's own test).
#[law]
fn neon_mul_is_scalar_mul(n: Neon, s: Scalar, x: &[[u8; 64]], log_m: u16) {
    requires(is_split_of(n.mul128[log_m as usize], s.mul16[log_m as usize]));
    ensures({ let mut a = x; n.mul(&mut a, log_m); a } == { let mut b = x; s.mul(&mut b, log_m); b });
}

