//! NEON data-movement and integer lane operations (Arm ARM transcriptions).
//!
//! Each model cites the A64 instruction the intrinsic compiles to and the
//! pseudocode of its `Operation` section (Arm Architecture Reference Manual
//! for A-profile, "SIMD&FP instructions"), transcribed at lane level on the
//! representation described in [`crate::aarch64`]. `esize` is the element size,
//! `Elem[V, e, esize]` lane `e`.
#![forbid(unsafe_code)]
// Loops index lanes explicitly to mirror the vendor pseudocode
// (`for e = 0 to elements-1`), including the element-wise loads and stores.
#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

use super::{Uint8x8, Uint8x16, Uint32x4};

/// `vld1q_u8` — `LD1 {Vt.16B}, [Xn]` (no offset).
///
/// ```text
/// for e = 0 to elements-1            // elements = 16, esize = 8
///     Elem[rval, e, esize] = Mem[address + e, 1, AccType_VEC];
/// V[t] = rval;
/// ```
///
/// Model: `r[e] = mem[e]` for `e < 16`.
pub fn vld1q_u8(mem: &[u8; 16]) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = mem[e];
    }
    r
}

/// `vld1q_u32` — `LD1 {Vt.4S}, [Xn]`.
///
/// ```text
/// for e = 0 to elements-1            // elements = 4, esize = 32
///     Elem[rval, e, esize] = Mem[address + 4*e, 4, AccType_VEC];
/// ```
///
/// On a little-endian target `Mem[address + 4e, 4]` of a `[u32; 4]` is its
/// element `e`, so the model is `r[e] = mem[e]`.
pub fn vld1q_u32(mem: &[u32; 4]) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = mem[e];
    }
    r
}

/// `vld1_u8` — `LD1 {Vt.8B}, [Xn]` (64-bit D register).
///
/// ```text
/// for e = 0 to elements-1            // elements = 8, esize = 8
///     Elem[rval, e, esize] = Mem[address + e, 1, AccType_VEC];
/// ```
///
/// Model: `r[e] = mem[e]` for `e < 8`.
pub fn vld1_u8(mem: &[u8; 8]) -> Uint8x8 {
    let mut r = [0u8; 8];
    for e in 0..8 {
        r[e] = mem[e];
    }
    r
}

/// `vst1q_u8` — `ST1 {Vt.16B}, [Xn]`, as a pure function returning the 16
/// bytes written.
///
/// ```text
/// for e = 0 to elements-1
///     Mem[address + e, 1, AccType_VEC] = Elem[V[t], e, esize];
/// ```
pub fn vst1q_u8(a: Uint8x16) -> [u8; 16] {
    let mut mem = [0u8; 16];
    for e in 0..16 {
        mem[e] = a[e];
    }
    mem
}

/// `vst1q_u32` — `ST1 {Vt.4S}, [Xn]`, as a pure function returning the four
/// words written (little-endian: lane `e` is word `e`).
///
/// ```text
/// for e = 0 to elements-1
///     Mem[address + 4*e, 4, AccType_VEC] = Elem[V[t], e, esize];
/// ```
pub fn vst1q_u32(a: Uint32x4) -> [u32; 4] {
    let mut mem = [0u32; 4];
    for e in 0..4 {
        mem[e] = a[e];
    }
    mem
}

/// `vrev32q_u8` — `REV32 Vd.16B, Vn.16B`: reverse the bytes in each 32-bit
/// container.
///
/// ```text
/// container_size = 32; containers = 128 DIV 32; elements_per_container = 32 DIV 8;
/// element = 0;
/// for c = 0 to containers-1
///     rev_element = element + elements_per_container - 1;
///     for e = 0 to elements_per_container-1
///         Elem[result, rev_element, esize] = Elem[operand, element, esize];
///         element = element + 1;
///         rev_element = rev_element - 1;
/// ```
///
/// Model: `r[4c + 3 − e] = a[4c + e]`.
pub fn vrev32q_u8(a: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for c in 0..4 {
        for e in 0..4 {
            r[4 * c + 3 - e] = a[4 * c + e];
        }
    }
    r
}

/// `vreinterpretq_u32_u8` — no instruction; reinterprets the 128 register bits.
///
/// Lane `i` of the `u32` view is bits `<32i+31:32i>`, i.e. bytes `4i..4i+4`
/// little-endian: `r[i] = from_le_bytes(a[4i..4i+4])`.
pub fn vreinterpretq_u32_u8(a: Uint8x16) -> Uint32x4 {
    let mut r = [0u32; 4];
    for i in 0..4 {
        r[i] = u32::from_le_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
    }
    r
}

/// `vreinterpretq_u8_u32` — no instruction; inverse of
/// [`vreinterpretq_u32_u8`]: `r[4i..4i+4] = to_le_bytes(a[i])`.
pub fn vreinterpretq_u8_u32(a: Uint32x4) -> Uint8x16 {
    let mut r = [0u8; 16];
    for i in 0..4 {
        let b = a[i].to_le_bytes();
        r[4 * i] = b[0];
        r[4 * i + 1] = b[1];
        r[4 * i + 2] = b[2];
        r[4 * i + 3] = b[3];
    }
    r
}

/// `vaddq_u32` — `ADD Vd.4S, Vn.4S, Vm.4S`.
///
/// ```text
/// for e = 0 to elements-1
///     element1 = Elem[operand1, e, esize]; element2 = Elem[operand2, e, esize];
///     Elem[result, e, esize] = element1 + element2;      // bits(esize): mod 2^32
/// ```
pub fn vaddq_u32(a: Uint32x4, b: Uint32x4) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = a[e].wrapping_add(b[e]);
    }
    r
}

/// `veorq_u32` — `EOR Vd.16B, Vn.16B, Vm.16B`: `result = operand1 EOR operand2`
/// on 128 bits, which is lane-wise xor on the `u32` view.
pub fn veorq_u32(a: Uint32x4, b: Uint32x4) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = a[e] ^ b[e];
    }
    r
}

/// `vandq_u32` — `AND Vd.16B, Vn.16B, Vm.16B`: `result = operand1 AND operand2`,
/// lane-wise on the `u32` view.
pub fn vandq_u32(a: Uint32x4, b: Uint32x4) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = a[e] & b[e];
    }
    r
}

/// `vorrq_u32` — `ORR Vd.16B, Vn.16B, Vm.16B`: `result = operand1 OR operand2`,
/// lane-wise on the `u32` view.
pub fn vorrq_u32(a: Uint32x4, b: Uint32x4) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = a[e] | b[e];
    }
    r
}

/// `vshlq_n_u32::<N>` — `SHL Vd.4S, Vn.4S, #N`, `0 ≤ N ≤ 31`.
///
/// ```text
/// shift = UInt(immh:immb) - esize;                    // = N
/// for e = 0 to elements-1
///     Elem[result, e, esize] = LSL(Elem[operand, e, esize], shift);
/// ```
///
/// Model: `r[e] = a[e] << n` (bits shifted out are discarded).
pub fn vshlq_n_u32(a: Uint32x4, n: i32) -> Uint32x4 {
    assert!(
        (0..=31).contains(&n),
        "vshlq_n_u32: immediate {n} out of range 0..=31"
    );
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = a[e] << n;
    }
    r
}

/// `vshrq_n_u32::<N>` — `USHR Vd.4S, Vn.4S, #N`, `1 ≤ N ≤ 32`.
///
/// ```text
/// shift = (esize * 2) - UInt(immh:immb);              // = N, 1..32
/// for e = 0 to elements-1
///     element = (UInt(Elem[operand, e, esize]) + round_const) >> shift;   // round_const = 0
///     Elem[result, e, esize] = element<esize-1:0>;
/// ```
///
/// Model: `r[e] = a[e] >> n` for `n < 32` and `0` for `n = 32` (the integer
/// shift of a 32-bit value by 32 is zero).
pub fn vshrq_n_u32(a: Uint32x4, n: i32) -> Uint32x4 {
    assert!(
        (1..=32).contains(&n),
        "vshrq_n_u32: immediate {n} out of range 1..=32"
    );
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = if n == 32 { 0 } else { a[e] >> n };
    }
    r
}

/// `vextq_u32::<N>` — `EXT Vd.16B, Vn.16B, Vm.16B, #(4N)`, `0 ≤ N ≤ 3`.
///
/// ```text
/// position = UInt(imm4) << 3;                         // = 32N
/// bits(256) concat = hi : lo;                         // hi = V[m] = b, lo = V[n] = a
/// V[d] = concat<position+127:position>;
/// ```
///
/// At lane level with `c = [a0, a1, a2, a3, b0, b1, b2, b3]`: `r[i] = c[i + N]`.
pub fn vextq_u32(a: Uint32x4, b: Uint32x4, n: i32) -> Uint32x4 {
    assert!(
        (0..=3).contains(&n),
        "vextq_u32: immediate {n} out of range 0..=3"
    );
    let n = n as usize;
    let mut r = [0u32; 4];
    for i in 0..4 {
        r[i] = if i + n < 4 { a[i + n] } else { b[i + n - 4] };
    }
    r
}

/// `vdupq_n_u32` — `DUP Vd.4S, Wn`.
///
/// ```text
/// element = X[n]<esize-1:0>;
/// for e = 0 to elements-1
///     Elem[result, e, esize] = element;
/// ```
pub fn vdupq_n_u32(value: u32) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = value;
    }
    r
}

/// `vgetq_lane_u32::<LANE>` — `UMOV Wd, Vn.S[LANE]` (`MOV` alias),
/// `0 ≤ LANE ≤ 3`: `X[d] = ZeroExtend(Elem[operand, index, esize])`.
pub fn vgetq_lane_u32(v: Uint32x4, lane: i32) -> u32 {
    assert!(
        (0..=3).contains(&lane),
        "vgetq_lane_u32: lane {lane} out of range 0..=3"
    );
    v[lane as usize]
}

/// `vsetq_lane_u32::<LANE>` — `INS Vd.S[LANE], Wn` (`MOV` alias),
/// `0 ≤ LANE ≤ 3`.
///
/// ```text
/// element = X[n]<esize-1:0>;
/// result = V[d];
/// Elem[result, index, esize] = element;
/// ```
///
/// Note the stdarch argument order: the scalar comes first, the vector second.
pub fn vsetq_lane_u32(a: u32, b: Uint32x4, lane: i32) -> Uint32x4 {
    assert!(
        (0..=3).contains(&lane),
        "vsetq_lane_u32: lane {lane} out of range 0..=3"
    );
    let mut r = b;
    r[lane as usize] = a;
    r
}

/// `vsetq_lane_u8::<LANE>` — `INS Vd.B[LANE], Wn`, `0 ≤ LANE ≤ 15`
/// (same pseudocode as [`vsetq_lane_u32`] with `esize = 8`).
pub fn vsetq_lane_u8(a: u8, b: Uint8x16, lane: i32) -> Uint8x16 {
    assert!(
        (0..=15).contains(&lane),
        "vsetq_lane_u8: lane {lane} out of range 0..=15"
    );
    let mut r = b;
    r[lane as usize] = a;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            vrev32q_u8(bytes),
            [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]
        );
        assert_eq!(
            vreinterpretq_u32_u8(bytes),
            [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c]
        );
        assert_eq!(vreinterpretq_u8_u32(vreinterpretq_u32_u8(bytes)), bytes);
        assert_eq!(vextq_u32([0, 1, 2, 3], [4, 5, 6, 7], 0), [0, 1, 2, 3]);
        assert_eq!(vextq_u32([0, 1, 2, 3], [4, 5, 6, 7], 1), [1, 2, 3, 4]);
        assert_eq!(vextq_u32([0, 1, 2, 3], [4, 5, 6, 7], 3), [3, 4, 5, 6]);
        assert_eq!(vshrq_n_u32([u32::MAX; 4], 32), [0; 4]);
        assert_eq!(vshrq_n_u32([0x8000_0000; 4], 31), [1; 4]);
        assert_eq!(vshlq_n_u32([3; 4], 31), [0x8000_0000; 4]);
        assert_eq!(vaddq_u32([u32::MAX, 1, 2, 3], [1, 1, 1, 1]), [0, 2, 3, 4]);
        assert_eq!(vsetq_lane_u8(0xab, [0; 16], 15)[15], 0xab);
        assert_eq!(vsetq_lane_u32(7, [1, 2, 3, 4], 2), [1, 2, 7, 4]);
        assert_eq!(vgetq_lane_u32([1, 2, 3, 4], 3), 4);
        assert_eq!(vdupq_n_u32(9), [9; 4]);
        // SHA-256 message load: vrev32 + reinterpret = big-endian words.
        let block = *b"abcdefghijklmnop";
        assert_eq!(
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&block)))[0],
            u32::from_be_bytes(*b"abcd")
        );
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn ushr_zero_is_rejected() {
        let _ = vshrq_n_u32([1; 4], 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn ext_four_is_rejected() {
        let _ = vextq_u32([0; 4], [0; 4], 4);
    }
}
