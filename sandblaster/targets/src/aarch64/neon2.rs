//! NEON byte, halfword and doubleword lane operations added by plan O10
//! (design §13.4 "NEON u8/u64/u32×2"): byte logic, compares and table
//! lookups (search, Reed–Solomon), narrowing shifts (the search mask), byte
//! reductions (`seq::eq`), 64-bit adds, shifts and selects, and the widening
//! 32×32→64 multiplies (curve25519 limbs).
//!
//! Each model cites its A64 instruction and transcribes the `Operation`
//! section of the Arm Architecture Reference Manual (DDI 0487, "SIMD&FP
//! instructions") at lane level, on the representation of
//! [`crate::aarch64`]: a vector is the array of its lanes, lane 0 at the
//! lowest address. `Elem[V, e, esize]` is lane `e`.
#![forbid(unsafe_code)]
// Loops index lanes explicitly to mirror the vendor pseudocode.
#![allow(clippy::needless_range_loop)]

use super::{Uint8x8, Uint8x16, Uint16x8, Uint32x2, Uint32x4, Uint64x2};

/// `vld1q_u64` — `LD1 {Vt.2D}, [Xn]`.
///
/// ```text
/// for e = 0 to elements-1            // elements = 2, esize = 64
///     Elem[rval, e, esize] = Mem[address + 8*e, 8, AccType_VEC];
/// ```
///
/// Model: `r[e] = mem[e]` (little-endian: element `e` is word `e`).
pub fn vld1q_u64(mem: &[u64; 2]) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = mem[e];
    }
    r
}

/// `vst1q_u64` — `ST1 {Vt.2D}, [Xn]`, the two words written:
/// `Mem[address + 8e, 8] = Elem[V[t], e, esize]`.
pub fn vst1q_u64(a: Uint64x2) -> [u64; 2] {
    let mut mem = [0u64; 2];
    for e in 0..2 {
        mem[e] = a[e];
    }
    mem
}

/// `veorq_u8` — `EOR Vd.16B, Vn.16B, Vm.16B`: `result = operand1 EOR operand2`.
pub fn veorq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = a[e] ^ b[e];
    }
    r
}

/// `vandq_u8` — `AND Vd.16B, Vn.16B, Vm.16B`: `result = operand1 AND operand2`.
pub fn vandq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = a[e] & b[e];
    }
    r
}

/// `vorrq_u8` — `ORR Vd.16B, Vn.16B, Vm.16B`: `result = operand1 OR operand2`.
pub fn vorrq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = a[e] | b[e];
    }
    r
}

/// `vdupq_n_u8` — `DUP Vd.16B, Wn`: every lane is `X[n]<7:0>`.
pub fn vdupq_n_u8(value: u8) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = value;
    }
    r
}

/// `vshrq_n_u8::<N>` — `USHR Vd.16B, Vn.16B, #N`, `1 ≤ N ≤ 8`.
///
/// ```text
/// shift = (esize * 2) - UInt(immh:immb);              // = N, 1..8
/// for e = 0 to elements-1
///     element = UInt(Elem[operand, e, esize]) >> shift;
///     Elem[result, e, esize] = element<esize-1:0>;
/// ```
///
/// Model: `r[e] = a[e] >> n` for `n < 8`, `0` for `n = 8`.
pub fn vshrq_n_u8(a: Uint8x16, n: i32) -> Uint8x16 {
    assert!((1..=8).contains(&n), "vshrq_n_u8: immediate {n} out of range 1..=8");
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = if n == 8 { 0 } else { a[e] >> n };
    }
    r
}

/// `vcltq_u8(a, b)` — `CMHI Vd.16B, Vm.16B, Vn.16B` with the operands
/// swapped (`b > a`, unsigned):
///
/// ```text
/// element1 = UInt(Elem[operand1, e, esize]); element2 = UInt(Elem[operand2, e, esize]);
/// test_passed = element1 > element2;             // operand1 = b, operand2 = a
/// Elem[result, e, esize] = if test_passed then Ones(esize) else Zeros(esize);
/// ```
///
/// Model: `r[e] = a[e] < b[e] ? 0xff : 0`.
pub fn vcltq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = if a[e] < b[e] { 0xff } else { 0 };
    }
    r
}

/// `vcgeq_u8(a, b)` — `CMHS Vd.16B, Vn.16B, Vm.16B`: `element1 >= element2`
/// unsigned. Model: `r[e] = a[e] ≥ b[e] ? 0xff : 0`.
pub fn vcgeq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = if a[e] >= b[e] { 0xff } else { 0 };
    }
    r
}

/// `vceqq_u8(a, b)` — `CMEQ Vd.16B, Vn.16B, Vm.16B` (register):
/// `test_passed = (element1 == element2)`. Model: `r[e] = a[e] = b[e] ? 0xff : 0`.
pub fn vceqq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = if a[e] == b[e] { 0xff } else { 0 };
    }
    r
}

/// `vqtbl1q_u8(t, idx)` — `TBL Vd.16B, {Vn.16B}, Vm.16B` (one table register).
///
/// ```text
/// table = V[n];                                   // 128 bits, elements = 16
/// for i = 0 to elements-1
///     index = UInt(Elem[indices, i, 8]);
///     if index < 16 then Elem[result, i, 8] = Elem[table, index, 8];
///     else               Elem[result, i, 8] = Zeros(8);     // TBL (not TBX)
/// ```
///
/// Model: `r[i] = idx[i] < 16 ? t[idx[i]] : 0`.
pub fn vqtbl1q_u8(t: Uint8x16, idx: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for i in 0..16 {
        let k = idx[i] as usize;
        r[i] = if k < 16 { t[k] } else { 0 };
    }
    r
}

/// `vcntq_u8` — `CNT Vd.16B, Vn.16B`: `Elem[result, e, 8] = BitCount(Elem[operand, e, 8])`.
pub fn vcntq_u8(a: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        let mut c = 0u8;
        for k in 0..8 {
            c += (a[e] >> k) & 1;
        }
        r[e] = c;
    }
    r
}

/// `vaddvq_u8` — `ADDV Bd, Vn.16B`: `Reduce(ReduceOp_ADD, operand, esize)`,
/// the sum of the 16 lanes mod 2⁸.
pub fn vaddvq_u8(a: Uint8x16) -> u8 {
    let mut s = 0u8;
    for e in 0..16 {
        s = s.wrapping_add(a[e]);
    }
    s
}

/// `vmaxvq_u8` — `UMAXV Bd, Vn.16B`:
///
/// ```text
/// maxmin = UInt(Elem[operand, 0, esize]);
/// for e = 1 to elements-1
///     element = UInt(Elem[operand, e, esize]);
///     maxmin = Max(maxmin, element);
/// V[d] = maxmin<esize-1:0>;
/// ```
pub fn vmaxvq_u8(a: Uint8x16) -> u8 {
    let mut m = a[0];
    for e in 1..16 {
        if a[e] > m {
            m = a[e];
        }
    }
    m
}

/// `vreinterpretq_u16_u8` — no instruction; lane `i` of the `u16` view is
/// bits `<16i+15:16i>`, bytes `2i, 2i+1` little-endian.
pub fn vreinterpretq_u16_u8(a: Uint8x16) -> Uint16x8 {
    let mut r = [0u16; 8];
    for i in 0..8 {
        r[i] = u16::from_le_bytes([a[2 * i], a[2 * i + 1]]);
    }
    r
}

/// `vreinterpretq_u64_u8` — no instruction; lane `i` of the `u64` view is
/// bytes `8i..8i+8` little-endian.
pub fn vreinterpretq_u64_u8(a: Uint8x16) -> Uint64x2 {
    let mut r = [0u64; 2];
    for i in 0..2 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&a[8 * i..8 * i + 8]);
        r[i] = u64::from_le_bytes(b);
    }
    r
}

/// `vcombine_u8(low, high)` — no instruction of its own (`INS`/`MOV` of the
/// high half): the 128-bit vector `high : low`, `low` in lanes 0..8.
pub fn vcombine_u8(low: Uint8x8, high: Uint8x8) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..8 {
        r[e] = low[e];
        r[8 + e] = high[e];
    }
    r
}

/// `vgetq_lane_u64::<LANE>` — `UMOV Xd, Vn.D[LANE]`, `0 ≤ LANE ≤ 1`.
pub fn vgetq_lane_u64(v: Uint64x2, lane: i32) -> u64 {
    assert!((0..=1).contains(&lane), "vgetq_lane_u64: lane {lane} out of range 0..=1");
    v[lane as usize]
}

/// `vshrn_n_u16::<N>` — `SHRN Vd.8B, Vn.8H, #N`, `1 ≤ N ≤ 8`.
///
/// ```text
/// shift = (2 * esize) - UInt(immh:immb);          // esize = 8: N in 1..8
/// for e = 0 to elements-1                         // elements = 8
///     element = (UInt(Elem[operand, e, 2*esize]) + round_const) >> shift;   // round_const = 0
///     Elem[result, e, esize] = element<esize-1:0>;
/// ```
///
/// Model: `r[e] = (a[e] >> n) mod 2⁸`.
pub fn vshrn_n_u16(a: Uint16x8, n: i32) -> Uint8x8 {
    assert!((1..=8).contains(&n), "vshrn_n_u16: immediate {n} out of range 1..=8");
    let mut r = [0u8; 8];
    for e in 0..8 {
        r[e] = (a[e] >> n) as u8;
    }
    r
}

/// `vshrn_n_u64::<N>` — `SHRN Vd.2S, Vn.2D, #N`, `1 ≤ N ≤ 32`: as
/// [`vshrn_n_u16`] with `esize = 32`: `r[e] = (a[e] >> n) mod 2³²`.
pub fn vshrn_n_u64(a: Uint64x2, n: i32) -> Uint32x2 {
    assert!((1..=32).contains(&n), "vshrn_n_u64: immediate {n} out of range 1..=32");
    let mut r = [0u32; 2];
    for e in 0..2 {
        r[e] = (a[e] >> n) as u32;
    }
    r
}

/// `vmovn_u64` — `XTN Vd.2S, Vn.2D`:
/// `Elem[result, e, esize] = Elem[operand, e, 2*esize]<esize-1:0>`.
pub fn vmovn_u64(a: Uint64x2) -> Uint32x2 {
    let mut r = [0u32; 2];
    for e in 0..2 {
        r[e] = a[e] as u32;
    }
    r
}

/// `vaddq_u64` — `ADD Vd.2D, Vn.2D, Vm.2D`: `r[e] = a[e] + b[e] mod 2⁶⁴`.
pub fn vaddq_u64(a: Uint64x2, b: Uint64x2) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = a[e].wrapping_add(b[e]);
    }
    r
}

/// `vsraq_n_u64::<N>(a, b)` — `USRA Vd.2D, Vn.2D, #N`, `1 ≤ N ≤ 64`
/// (`Vd = a` accumulates, `Vn = b` is shifted).
///
/// ```text
/// shift = (esize * 2) - UInt(immh:immb);          // = N, 1..64
/// for e = 0 to elements-1
///     element = (UInt(Elem[operand, e, esize]) + round_const) >> shift;
///     Elem[result, e, esize] = Elem[operand2, e, esize] + element;    // operand2 = V[d]
/// ```
///
/// Model: `r[e] = a[e] + (n = 64 ? 0 : b[e] >> n) mod 2⁶⁴`.
pub fn vsraq_n_u64(a: Uint64x2, b: Uint64x2, n: i32) -> Uint64x2 {
    assert!((1..=64).contains(&n), "vsraq_n_u64: immediate {n} out of range 1..=64");
    let mut r = [0u64; 2];
    for e in 0..2 {
        let s = if n == 64 { 0 } else { b[e] >> n };
        r[e] = a[e].wrapping_add(s);
    }
    r
}

/// `vbslq_u64(a, b, c)` — `BSL Vd.16B, Vn.16B, Vm.16B` with `Vd = a` (the
/// mask), `Vn = b`, `Vm = c`:
///
/// ```text
/// operand1 = V[m]; operand2 = V[n]; operand3 = V[d];      // BSL
/// V[d] = operand1 EOR ((operand1 EOR operand2) AND operand3);
/// ```
///
/// Model: `r[e] = c[e] ⊕ ((c[e] ⊕ b[e]) ∧ a[e])`, i.e. each mask bit picks `b` (1) or `c` (0).
pub fn vbslq_u64(a: Uint64x2, b: Uint64x2, c: Uint64x2) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = c[e] ^ ((c[e] ^ b[e]) & a[e]);
    }
    r
}

/// `vbslq_u32(a, b, c)` — `BSL` on the `u32` view, as [`vbslq_u64`].
pub fn vbslq_u32(a: Uint32x4, b: Uint32x4, c: Uint32x4) -> Uint32x4 {
    let mut r = [0u32; 4];
    for e in 0..4 {
        r[e] = c[e] ^ ((c[e] ^ b[e]) & a[e]);
    }
    r
}

/// `vmull_u32(a, b)` — `UMULL Vd.2D, Vn.2S, Vm.2S`:
///
/// ```text
/// for e = 0 to elements-1                         // elements = 2, esize = 32
///     element1 = UInt(Elem[operand1, e, esize]); element2 = UInt(Elem[operand2, e, esize]);
///     Elem[result, e, 2*esize] = (element1 * element2)<2*esize-1:0>;
/// ```
///
/// Model: `r[e] = a[e] · b[e]` (the exact 64-bit product).
pub fn vmull_u32(a: Uint32x2, b: Uint32x2) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = a[e] as u64 * b[e] as u64;
    }
    r
}

/// `vmlal_u32(a, b, c)` — `UMLAL Vd.2D, Vn.2S, Vm.2S` (`Vd = a` accumulates):
/// `Elem[result, e, 2*esize] = Elem[operand3, e, 2*esize] + element1 * element2`.
///
/// Model: `r[e] = a[e] + b[e] · c[e] mod 2⁶⁴`.
pub fn vmlal_u32(a: Uint64x2, b: Uint32x2, c: Uint32x2) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = a[e].wrapping_add(b[e] as u64 * c[e] as u64);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(vcltq_u8(bytes, vdupq_n_u8(3))[..4], [0xff, 0xff, 0xff, 0]);
        assert_eq!(vcgeq_u8(bytes, vdupq_n_u8(15))[14..], [0, 0xff]);
        assert_eq!(vceqq_u8(bytes, bytes), [0xff; 16]);
        assert_eq!(vqtbl1q_u8(bytes, [15, 16, 0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])[..4], [15, 0, 0, 0]);
        assert_eq!(vcntq_u8([0xff; 16]), [8; 16]);
        assert_eq!(vaddvq_u8([0x20; 16]), 0);
        assert_eq!(vmaxvq_u8(bytes), 15);
        assert_eq!(vreinterpretq_u16_u8(bytes)[1], 0x0302);
        assert_eq!(vreinterpretq_u64_u8(bytes)[1], 0x0f0e_0d0c_0b0a_0908);
        assert_eq!(vshrn_n_u16([0xff00; 8], 4), [0xf0; 8]);
        assert_eq!(vshrn_n_u16([0xffff; 8], 8), [0xff; 8]);
        assert_eq!(vshrq_n_u8([0xff; 16], 8), [0; 16]);
        assert_eq!(vsraq_n_u64([1, 2], [u64::MAX, 8], 64), [1, 2]);
        assert_eq!(vsraq_n_u64([1, 2], [u64::MAX, 8], 3), [1u64.wrapping_add(u64::MAX >> 3), 3]);
        assert_eq!(vmull_u32([u32::MAX, 3], [u32::MAX, 5]), [0xffff_fffe_0000_0001, 15]);
        assert_eq!(vmlal_u32([1, u64::MAX], [2, 1], [3, 1]), [7, 0]);
        assert_eq!(vbslq_u64([0xff00, 0], [0x1234, 1], [0xabcd, 2]), [0x12cd, 2]);
        assert_eq!(vshrn_n_u64([0x1_0000_0002, 0], 1), [0x8000_0001, 0]);
        assert_eq!(vmovn_u64([0x1_0000_0002, u64::MAX]), [2, u32::MAX]);
        // The search mask: the nibble of byte k is 0xf iff byte k < 0x80.
        let mut v = [0x80u8; 16];
        v[5] = 0x11;
        let m = vreinterpretq_u64_u8(vcombine_u8(
            vshrn_n_u16(vreinterpretq_u16_u8(vcltq_u8(v, vdupq_n_u8(0x80))), 4),
            [0; 8],
        ))[0];
        assert_eq!(m, 0xf << 20);
        assert_eq!(m.trailing_zeros() / 4, 5);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn shrn_zero_is_rejected() {
        let _ = vshrn_n_u16([0; 8], 0);
    }
}
