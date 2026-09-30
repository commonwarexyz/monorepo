//! FEAT_SHA3 and FEAT_SHA512 instructions (rustc feature `sha3`): the
//! three-way logic ops (`EOR3`, `BCAX`, `RAX1`, `XAR`, used by Keccak and by
//! bitsliced code) and the SHA-512 round and schedule instructions.
//!
//! Transcriptions of the Arm Architecture Reference Manual (DDI 0487),
//! "SIMD&FP instructions" `Operation` sections, at lane level. For the
//! 128-bit SHA-512 registers, `X<127:64>` is lane 1 and `X<63:0>` lane 0 of
//! the `u64` view.
#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop)]

use super::{Uint8x16, Uint64x2};

/// `veor3q_u8(a, b, c)` — `EOR3 Vd.16B, Vn.16B, Vm.16B, Va.16B`
/// (`Vn = a`, `Vm = b`, `Va = c`): `V[d] = Vm EOR Vn EOR Va`.
pub fn veor3q_u8(a: Uint8x16, b: Uint8x16, c: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = a[e] ^ b[e] ^ c[e];
    }
    r
}

/// `vbcaxq_u8(a, b, c)` — `BCAX Vd.16B, Vn.16B, Vm.16B, Va.16B`
/// (`Vn = a`, `Vm = b`, `Va = c`): `V[d] = Vn EOR (Vm AND NOT(Va))`.
pub fn vbcaxq_u8(a: Uint8x16, b: Uint8x16, c: Uint8x16) -> Uint8x16 {
    let mut r = [0u8; 16];
    for e in 0..16 {
        r[e] = a[e] ^ (b[e] & !c[e]);
    }
    r
}

/// `vrax1q_u64(a, b)` — `RAX1 Vd.2D, Vn.2D, Vm.2D` (`Vn = a`, `Vm = b`):
/// `V[d] = Vn<127:64> EOR ROL(Vm<127:64>, 1) : Vn<63:0> EOR ROL(Vm<63:0>, 1)`.
pub fn vrax1q_u64(a: Uint64x2, b: Uint64x2) -> Uint64x2 {
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = a[e] ^ b[e].rotate_left(1);
    }
    r
}

/// `vxarq_u64::<IMM6>(a, b)` — `XAR Vd.2D, Vn.2D, Vm.2D, #IMM6`, `0 ≤ IMM6 ≤ 63`:
///
/// ```text
/// tmp = Vn EOR Vm;
/// V[d] = ROR(tmp<127:64>, UInt(imm6)) : ROR(tmp<63:0>, UInt(imm6));
/// ```
pub fn vxarq_u64(a: Uint64x2, b: Uint64x2, imm6: i32) -> Uint64x2 {
    assert!((0..=63).contains(&imm6), "vxarq_u64: immediate {imm6} out of range 0..=63");
    let mut r = [0u64; 2];
    for e in 0..2 {
        r[e] = (a[e] ^ b[e]).rotate_right(imm6 as u32);
    }
    r
}

/// SHA-512 Σ1 (`MSigma1` of SHA512H): `ROR 14 ⊕ ROR 18 ⊕ ROR 41`.
pub fn sha512_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// SHA-512 Σ0 (`NSigma0` of SHA512H2): `ROR 28 ⊕ ROR 34 ⊕ ROR 39`.
pub fn sha512_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// `vsha512hq_u64(hash_ed, hash_gf, kwh_kwh2)` — `SHA512H Qd, Qn, Vm.2D`
/// (`Qd = W = hash_ed`, `Qn = X = hash_gf`, `Vm = Y = kwh_kwh2`):
///
/// ```text
/// MSigma1 = ROR(Y<127:64>, 14) EOR ROR(Y<127:64>, 18) EOR ROR(Y<127:64>, 41);
/// Vtmp<127:64> = (Y<127:64> AND X<63:0>) EOR (NOT(Y<127:64>) AND X<127:64>);
/// Vtmp<127:64> = (Vtmp<127:64> + MSigma1 + W<127:64>);
/// tmp = Vtmp<127:64> + Y<63:0>;
/// MSigma1 = ROR(tmp, 14) EOR ROR(tmp, 18) EOR ROR(tmp, 41);
/// Vtmp<63:0> = (tmp AND Y<127:64>) EOR (NOT(tmp) AND X<63:0>);
/// Vtmp<63:0> = (Vtmp<63:0> + MSigma1 + W<63:0>);
/// V[d] = Vtmp;
/// ```
pub fn vsha512hq_u64(hash_ed: Uint64x2, hash_gf: Uint64x2, kwh_kwh2: Uint64x2) -> Uint64x2 {
    let (w, x, y) = (hash_ed, hash_gf, kwh_kwh2);
    let hi = ((y[1] & x[0]) ^ (!y[1] & x[1])).wrapping_add(sha512_sigma1(y[1])).wrapping_add(w[1]);
    let tmp = hi.wrapping_add(y[0]);
    let lo = ((tmp & y[1]) ^ (!tmp & x[0])).wrapping_add(sha512_sigma1(tmp)).wrapping_add(w[0]);
    [lo, hi]
}

/// `vsha512h2q_u64(sum_ab, hash_c_, hash_ab)` — `SHA512H2 Qd, Qn, Vm.2D`
/// (`Qd = W = sum_ab`, `Qn = X = hash_c_`, `Vm = Y = hash_ab`):
///
/// ```text
/// NSigma0 = ROR(Y<63:0>, 28) EOR ROR(Y<63:0>, 34) EOR ROR(Y<63:0>, 39);
/// Vtmp<127:64> = (X<63:0> AND Y<127:64>) EOR (X<63:0> AND Y<63:0>) EOR (Y<127:64> AND Y<63:0>);
/// Vtmp<127:64> = (Vtmp<127:64> + NSigma0 + W<127:64>);
/// NSigma0 = ROR(Vtmp<127:64>, 28) EOR ROR(Vtmp<127:64>, 34) EOR ROR(Vtmp<127:64>, 39);
/// Vtmp<63:0> = (Vtmp<127:64> AND Y<63:0>) EOR (Vtmp<127:64> AND Y<127:64>) EOR (Y<127:64> AND Y<63:0>);
/// Vtmp<63:0> = (Vtmp<63:0> + NSigma0 + W<63:0>);
/// V[d] = Vtmp;
/// ```
pub fn vsha512h2q_u64(sum_ab: Uint64x2, hash_c_: Uint64x2, hash_ab: Uint64x2) -> Uint64x2 {
    let (w, x, y) = (sum_ab, hash_c_, hash_ab);
    let hi = ((x[0] & y[1]) ^ (x[0] & y[0]) ^ (y[1] & y[0])).wrapping_add(sha512_sigma0(y[0])).wrapping_add(w[1]);
    let lo = ((hi & y[0]) ^ (hi & y[1]) ^ (y[1] & y[0])).wrapping_add(sha512_sigma0(hi)).wrapping_add(w[0]);
    [lo, hi]
}

/// `vsha512su0q_u64(w0_1, w2_)` — `SHA512SU0 Vd.2D, Vn.2D` (`Vd = W = w0_1`,
/// `Vn = X = w2_`):
///
/// ```text
/// sig0 = ROR(W<127:64>, 1) EOR ROR(W<127:64>, 8) EOR ('0000000':W<127:71>);
/// Vtmp<63:0> = W<63:0> + sig0;
/// sig0 = ROR(X<63:0>, 1) EOR ROR(X<63:0>, 8) EOR ('0000000':X<63:7>);
/// Vtmp<127:64> = W<127:64> + sig0;
/// V[d] = Vtmp;
/// ```
pub fn vsha512su0q_u64(w0_1: Uint64x2, w2_: Uint64x2) -> Uint64x2 {
    let (w, x) = (w0_1, w2_);
    let s0 = |v: u64| v.rotate_right(1) ^ v.rotate_right(8) ^ (v >> 7);
    [w[0].wrapping_add(s0(w[1])), w[1].wrapping_add(s0(x[0]))]
}

/// `vsha512su1q_u64(s01_s02, w14_15, w9_10)` — `SHA512SU1 Vd.2D, Vn.2D, Vm.2D`
/// (`Vd = W = s01_s02`, `Vn = X = w14_15`, `Vm = Y = w9_10`):
///
/// ```text
/// sig1 = ROR(X<127:64>, 19) EOR ROR(X<127:64>, 61) EOR ('000000':X<127:70>);
/// Vtmp<127:64> = W<127:64> + sig1 + Y<127:64>;
/// sig1 = ROR(X<63:0>, 19) EOR ROR(X<63:0>, 61) EOR ('000000':X<63:6>);
/// Vtmp<63:0> = W<63:0> + sig1 + Y<63:0>;
/// V[d] = Vtmp;
/// ```
pub fn vsha512su1q_u64(s01_s02: Uint64x2, w14_15: Uint64x2, w9_10: Uint64x2) -> Uint64x2 {
    let (w, x, y) = (s01_s02, w14_15, w9_10);
    let s1 = |v: u64| v.rotate_right(19) ^ v.rotate_right(61) ^ (v >> 6);
    [w[0].wrapping_add(s1(x[0])).wrapping_add(y[0]), w[1].wrapping_add(s1(x[1])).wrapping_add(y[1])]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-512 message schedule of the "abc" block through SU0/SU1
    /// (two words per pair) equals FIPS 180-4 §6.4.2.
    #[test]
    fn sha512_schedule_through_the_models() {
        let mut block = [0u8; 128];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[127] = 24;
        let mut w = [0u64; 80];
        for t in 0..16 {
            w[t] = u64::from_be_bytes(block[8 * t..8 * t + 8].try_into().unwrap());
        }
        // Schedule, two words at a time through SU0/SU1: w[t..t+2] from w[t-16..].
        for t in (16..80).step_by(2) {
            let su0 = vsha512su0q_u64([w[t - 16], w[t - 15]], [w[t - 14], 0]);
            let r = vsha512su1q_u64(su0, [w[t - 2], w[t - 1]], [w[t - 7], w[t - 6]]);
            w[t] = r[0];
            w[t + 1] = r[1];
        }
        // The schedule words agree with FIPS 180-4 §6.4.2.
        let sig0 = |x: u64| x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
        let sig1 = |x: u64| x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6);
        for t in 16..80 {
            let want = sig1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(sig0(w[t - 15])).wrapping_add(w[t - 16]);
            assert_eq!(w[t], want, "schedule word {t}");
        }
    }

    #[test]
    fn three_way_ops() {
        assert_eq!(veor3q_u8([1; 16], [2; 16], [4; 16]), [7; 16]);
        assert_eq!(vbcaxq_u8([0xf0; 16], [0xff; 16], [0x0f; 16]), [0x00; 16]);
        assert_eq!(vrax1q_u64([0, 1], [1 << 63, 1]), [1, 3]);
        assert_eq!(vxarq_u64([1, 0], [0, 2], 1), [1 << 63, 1]);
        assert_eq!(vxarq_u64([5, 6], [3, 3], 0), [6, 5]);
    }
}
