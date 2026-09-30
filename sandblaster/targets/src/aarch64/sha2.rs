//! Armv8 SHA2 instructions (FEAT_SHA256): SHA256H, SHA256H2, SHA256SU0,
//! SHA256SU1, transcribed from the Arm ARM pseudocode.
//!
//! The shared pseudocode functions are transcribed one-to-one:
//!
//! ```text
//! bits(32) SHAchoose(bits(32) x, bits(32) y, bits(32) z)
//!     return (((y EOR z) AND x) EOR z);
//! bits(32) SHAmajority(bits(32) x, bits(32) y, bits(32) z)
//!     return ((x AND y) OR ((x OR y) AND z));
//! bits(32) SHAhashSIGMA0(bits(32) x)
//!     return ROR(x, 2) EOR ROR(x, 13) EOR ROR(x, 22);
//! bits(32) SHAhashSIGMA1(bits(32) x)
//!     return ROR(x, 6) EOR ROR(x, 11) EOR ROR(x, 25);
//!
//! bits(128) SHA256hash(bits(128) X, bits(128) Y, bits(128) W, boolean part1)
//!     bits(32) chs, maj, t;
//!     for e = 0 to 3
//!         chs = SHAchoose(Y<31:0>, Y<63:32>, Y<95:64>);
//!         maj = SHAmajority(X<31:0>, X<63:32>, X<95:64>);
//!         t = Y<127:96> + SHAhashSIGMA1(Y<31:0>) + chs + Elem[W, e, 32];
//!         X<127:96> = t + X<127:96>;
//!         Y<127:96> = t + SHAhashSIGMA0(X<31:0>) + maj;
//!         bits(256) yx = ROL(Y : X, 32);
//!         Y = yx<255:128>;
//!         X = yx<127:0>;
//!     return (if part1 then X else Y);
//! ```
//!
//! The kernel has no 256-bit words, so `ROL(Y : X, 32)` is transcribed at lane
//! level (DESIGN.md §9.2): the eight words of `Y : X`, low to high, are
//! `[X0, X1, X2, X3, Y0, Y1, Y2, Y3]`; rotating left by one word gives
//! `[Y3, X0, X1, X2, X3, Y0, Y1, Y2]`, hence
//! `(X', Y') = ([Y3, X0, X1, X2], [X3, Y0, Y1, Y2])`.
#![forbid(unsafe_code)]
// Loops index lanes explicitly to mirror the vendor pseudocode.
#![allow(clippy::needless_range_loop)]

use super::Uint32x4;

/// `SHAchoose(x, y, z) = ((y ⊕ z) ∧ x) ⊕ z`.
pub fn sha_choose(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

/// `SHAmajority(x, y, z) = (x ∧ y) ∨ ((x ∨ y) ∧ z)`.
pub fn sha_majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

/// `SHAhashSIGMA0(x) = ROR(x, 2) ⊕ ROR(x, 13) ⊕ ROR(x, 22)`.
pub fn sha_hash_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// `SHAhashSIGMA1(x) = ROR(x, 6) ⊕ ROR(x, 11) ⊕ ROR(x, 25)`.
pub fn sha_hash_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `SHA256hash(X, Y, W, part1)` at lane level (see the module docs).
///
/// `X` holds `[a, b, c, d]`, `Y` holds `[e, f, g, h]` (lane 0 first); four
/// rounds consume `W[0..4]` (each already `K_t + W_t`).
pub fn sha256hash(x: Uint32x4, y: Uint32x4, w: Uint32x4, part1: bool) -> Uint32x4 {
    let mut x = x;
    let mut y = y;
    for e in 0..4 {
        let chs = sha_choose(y[0], y[1], y[2]);
        let maj = sha_majority(x[0], x[1], x[2]);
        let t = y[3]
            .wrapping_add(sha_hash_sigma1(y[0]))
            .wrapping_add(chs)
            .wrapping_add(w[e]);
        x[3] = t.wrapping_add(x[3]);
        y[3] = t.wrapping_add(sha_hash_sigma0(x[0])).wrapping_add(maj);
        // ROL(Y : X, 32) at lane level.
        let x_next = [y[3], x[0], x[1], x[2]];
        let y_next = [x[3], y[0], y[1], y[2]];
        x = x_next;
        y = y_next;
    }
    if part1 { x } else { y }
}

/// `vsha256hq_u32(hash_abcd, hash_efgh, wk)` — `SHA256H Qd, Qn, Vm.4S` with
/// `Qd = hash_abcd`, `Qn = hash_efgh`, `Vm = wk`:
///
/// ```text
/// result = SHA256hash(V[d], V[n], V[m], TRUE);
/// V[d] = result;
/// ```
///
/// Returns the `abcd` half of the state after four rounds.
pub fn vsha256hq_u32(hash_abcd: Uint32x4, hash_efgh: Uint32x4, wk: Uint32x4) -> Uint32x4 {
    sha256hash(hash_abcd, hash_efgh, wk, true)
}

/// `vsha256h2q_u32(hash_efgh, hash_abcd, wk)` — `SHA256H2 Qd, Qn, Vm.4S` with
/// `Qd = hash_efgh` (first argument), `Qn = hash_abcd`, `Vm = wk`:
///
/// ```text
/// result = SHA256hash(V[n], V[d], V[m], FALSE);
/// V[d] = result;
/// ```
///
/// **Argument order:** the intrinsic's first argument is `Vd` = `efgh`, the
/// second `Vn` = `abcd`, i.e. the *reverse* of `SHA256hash(X, Y, ..)`. (stdarch
/// names the parameters `hash_abcd, hash_efgh` in that position order, which is
/// misleading; ACLE and every real kernel pass `efgh` first.) `hash_abcd` must
/// be the **pre-update** `abcd`: the `sha2` crate saves `abcd_prev` before the
/// `vsha256hq_u32` call and passes it here. Returns the `efgh` half after four
/// rounds.
pub fn vsha256h2q_u32(hash_efgh: Uint32x4, hash_abcd: Uint32x4, wk: Uint32x4) -> Uint32x4 {
    sha256hash(hash_abcd, hash_efgh, wk, false)
}

/// `vsha256su0q_u32(w0_3, w4_7)` — `SHA256SU0 Vd.4S, Vn.4S` with
/// `Vd = w0_3`, `Vn = w4_7`:
///
/// ```text
/// bits(128) operand1 = V[d];
/// bits(128) operand2 = V[n];
/// bits(128) T = operand2<31:0> : operand1<127:32>;
/// for e = 0 to 3
///     elt = Elem[T, e, 32];
///     elt = ROR(elt, 7) EOR ROR(elt, 18) EOR LSR(elt, 3);
///     Elem[result, e, 32] = elt + Elem[operand1, e, 32];
/// V[d] = result;
/// ```
///
/// At lane level `T = [op1_1, op1_2, op1_3, op2_0]`.
pub fn vsha256su0q_u32(w0_3: Uint32x4, w4_7: Uint32x4) -> Uint32x4 {
    let t = [w0_3[1], w0_3[2], w0_3[3], w4_7[0]];
    let mut result = [0u32; 4];
    for e in 0..4 {
        let elt = t[e];
        let elt = elt.rotate_right(7) ^ elt.rotate_right(18) ^ (elt >> 3);
        result[e] = elt.wrapping_add(w0_3[e]);
    }
    result
}

/// `vsha256su1q_u32(tw0_3, w8_11, w12_15)` — `SHA256SU1 Vd.4S, Vn.4S, Vm.4S`
/// with `Vd = tw0_3`, `Vn = w8_11`, `Vm = w12_15`:
///
/// ```text
/// bits(128) operand1 = V[d];
/// bits(128) operand2 = V[n];
/// bits(128) operand3 = V[m];
/// bits(128) T0 = operand3<31:0> : operand2<127:32>;
/// bits(64) T1 = operand3<127:64>;
/// for e = 0 to 1
///     elt = Elem[T1, e, 32];
///     elt = ROR(elt, 17) EOR ROR(elt, 19) EOR LSR(elt, 10);
///     elt = elt + Elem[operand1, e, 32] + Elem[T0, e, 32];
///     Elem[result, e, 32] = elt;
/// T1 = result<63:0>;
/// for e = 2 to 3
///     elt = Elem[T1, e-2, 32];
///     elt = ROR(elt, 17) EOR ROR(elt, 19) EOR LSR(elt, 10);
///     elt = elt + Elem[operand1, e, 32] + Elem[T0, e, 32];
///     Elem[result, e, 32] = elt;
/// V[d] = result;
/// ```
///
/// At lane level `T0 = [op2_1, op2_2, op2_3, op3_0]`, the first `T1 =
/// [op3_2, op3_3]` and the second `T1 = [result_0, result_1]` (the upper
/// half depends on the lower half of the result).
pub fn vsha256su1q_u32(tw0_3: Uint32x4, w8_11: Uint32x4, w12_15: Uint32x4) -> Uint32x4 {
    let t0 = [w8_11[1], w8_11[2], w8_11[3], w12_15[0]];
    let mut result = [0u32; 4];
    let t1 = [w12_15[2], w12_15[3]];
    for e in 0..2 {
        let elt = t1[e];
        let elt = elt.rotate_right(17) ^ elt.rotate_right(19) ^ (elt >> 10);
        result[e] = elt.wrapping_add(tw0_3[e]).wrapping_add(t0[e]);
    }
    let t1 = [result[0], result[1]];
    for e in 2..4 {
        let elt = t1[e - 2];
        let elt = elt.rotate_right(17) ^ elt.rotate_right(19) ^ (elt >> 10);
        result[e] = elt.wrapping_add(tw0_3[e]).wrapping_add(t0[e]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 example "abc" (NIST CSRC SHA256.pdf), rounds t = 0..3.
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const WK_ABC_0_3: [u32; 4] = [
        0x6162_6380u32.wrapping_add(0x428a_2f98),
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
    ];

    #[test]
    fn four_rounds_of_abc() {
        let abcd = [H0[0], H0[1], H0[2], H0[3]];
        let efgh = [H0[4], H0[5], H0[6], H0[7]];
        // After t = 3: a..h = d550f666 c8c347a7 5a6ad9ad 5d6aebcd 24e00850 f92939eb 78ce7989 fa2a4622.
        assert_eq!(
            vsha256hq_u32(abcd, efgh, WK_ABC_0_3),
            [0xd550_f666, 0xc8c3_47a7, 0x5a6a_d9ad, 0x5d6a_ebcd]
        );
        // H2 takes efgh first and the *pre-update* abcd.
        assert_eq!(
            vsha256h2q_u32(efgh, abcd, WK_ABC_0_3),
            [0x24e0_0850, 0xf929_39eb, 0x78ce_7989, 0xfa2a_4622]
        );
        // Feeding H2 the post-update abcd gives a different (wrong) result.
        let abcd_new = vsha256hq_u32(abcd, efgh, WK_ABC_0_3);
        assert_ne!(
            vsha256h2q_u32(efgh, abcd_new, WK_ABC_0_3),
            [0x24e0_0850, 0xf929_39eb, 0x78ce_7989, 0xfa2a_4622]
        );
    }

    #[test]
    fn schedule_known_answers() {
        // σ0(1) = ROR(1,7) ^ ROR(1,18) ^ (1 >> 3) = 0x0200_0000 ^ 0x0000_4000.
        // result[e] = σ0(T[e]) + op1[e] with T = [op1_1, op1_2, op1_3, op2_0].
        assert_eq!(
            vsha256su0q_u32([0, 1, 0, 0], [0; 4]),
            [0x0200_4000, 1, 0, 0]
        );
        assert_eq!(
            vsha256su0q_u32([5, 0, 0, 0], [1, 0, 0, 0]),
            [5, 0, 0, 0x0200_4000]
        );
        // σ1(1) = ROR(1,17) ^ ROR(1,19) ^ (1 >> 10) = 0x0000_8000 ^ 0x0000_2000; lane 2
        // then sees σ1(result lane 0).
        let r = vsha256su1q_u32([0; 4], [0; 4], [0, 0, 1, 0]);
        assert_eq!(r[0], 0x0000_a000);
        assert_eq!(r[1], 0);
        let sigma1 = |x: u32| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
        assert_eq!(r[2], sigma1(0x0000_a000));
        assert_eq!(r[3], 0);
    }
}
