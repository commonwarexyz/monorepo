//! Intel SHA extensions (SHA-NI) for SHA-256: SHA256RNDS2, SHA256MSG1,
//! SHA256MSG2, transcribed from the Intel SDM pseudocode.
//!
//! The SDM defines, for these instructions:
//!
//! ```text
//! Ch(E,F,G)  := (E AND F) XOR ((NOT E) AND G)
//! Maj(A,B,C) := (A AND B) XOR (A AND C) XOR (B AND C)
//! Σ0(A) := ROR(A, 2) XOR ROR(A, 13) XOR ROR(A, 22)
//! Σ1(E) := ROR(E, 6) XOR ROR(E, 11) XOR ROR(E, 25)
//! σ0(W) := ROR(W, 7) XOR ROR(W, 18) XOR SHR(W, 3)
//! σ1(W) := ROR(W, 17) XOR ROR(W, 19) XOR SHR(W, 10)
//! ```
//!
//! All three instructions work on the `u32` view of `__m128i`
//! (`SRC[32i+31:32i]` is lane `i`).
//!
//! **Hardware validation pending:** this machine (Apple M5 Pro, x86_64 only
//! under Rosetta 2) has no SHA-NI. The models are checked for consistency with
//! FIPS 180-4 ([`crate::consistency`]) and the hardware differential tests in
//! [`crate::hw`] run automatically on a CPU that reports `sha`.
#![forbid(unsafe_code)]

use super::{M128i, from_u32x4, view_u32};

/// SDM `Ch(E, F, G) = (E ∧ F) ⊕ (¬E ∧ G)`.
pub fn sdm_ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

/// SDM `Maj(A, B, C) = (A ∧ B) ⊕ (A ∧ C) ⊕ (B ∧ C)`.
pub fn sdm_maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// SDM `Σ0(A) = ROR(A, 2) ⊕ ROR(A, 13) ⊕ ROR(A, 22)`.
pub fn sdm_big_sigma0(a: u32) -> u32 {
    a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
}

/// SDM `Σ1(E) = ROR(E, 6) ⊕ ROR(E, 11) ⊕ ROR(E, 25)`.
pub fn sdm_big_sigma1(e: u32) -> u32 {
    e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
}

/// SDM `σ0(W) = ROR(W, 7) ⊕ ROR(W, 18) ⊕ SHR(W, 3)`.
pub fn sdm_small_sigma0(w: u32) -> u32 {
    w.rotate_right(7) ^ w.rotate_right(18) ^ (w >> 3)
}

/// SDM `σ1(W) = ROR(W, 17) ⊕ ROR(W, 19) ⊕ SHR(W, 10)`.
pub fn sdm_small_sigma1(w: u32) -> u32 {
    w.rotate_right(17) ^ w.rotate_right(19) ^ (w >> 10)
}

/// `_mm_sha256rnds2_epu32(a, b, k)` — `SHA256RNDS2 xmm1, xmm2/m128, <XMM0>`
/// with `SRC1 = xmm1 = a` (the `cdgh` state half), `SRC2 = xmm2 = b` (the
/// `abef` half), `XMM0 = k` (`W + K` for the two rounds, lanes 0 and 1 only).
///
/// ```text
/// A[0] := SRC2[127:96];  B[0] := SRC2[95:64];
/// C[0] := SRC1[127:96];  D[0] := SRC1[95:64];
/// E[0] := SRC2[63:32];   F[0] := SRC2[31:0];
/// G[0] := SRC1[63:32];   H[0] := SRC1[31:0];
/// WK0 := XMM0[31:0];     WK1 := XMM0[63:32];
/// FOR i = 0 to 1
///     A[i+1] := Ch(E[i], F[i], G[i]) + Σ1(E[i]) + WK[i] + H[i] + Maj(A[i], B[i], C[i]) + Σ0(A[i]);
///     B[i+1] := A[i];
///     C[i+1] := B[i];
///     D[i+1] := C[i];
///     E[i+1] := Ch(E[i], F[i], G[i]) + Σ1(E[i]) + WK[i] + H[i] + D[i];
///     F[i+1] := E[i];
///     G[i+1] := F[i];
///     H[i+1] := G[i];
/// ENDFOR
/// DEST[127:96] := A[2];  DEST[95:64] := B[2];
/// DEST[63:32]  := E[2];  DEST[31:0]  := F[2];
/// ```
///
/// Note that the SDM spells the `A` and `E` updates out separately (no shared
/// `T1`); the model keeps that shape.
pub fn _mm_sha256rnds2_epu32(a: M128i, b: M128i, k: M128i) -> M128i {
    let src1 = view_u32(a);
    let src2 = view_u32(b);
    let xmm0 = view_u32(k);
    let mut va = [0u32; 3];
    let mut vb = [0u32; 3];
    let mut vc = [0u32; 3];
    let mut vd = [0u32; 3];
    let mut ve = [0u32; 3];
    let mut vf = [0u32; 3];
    let mut vg = [0u32; 3];
    let mut vh = [0u32; 3];
    va[0] = src2[3];
    vb[0] = src2[2];
    vc[0] = src1[3];
    vd[0] = src1[2];
    ve[0] = src2[1];
    vf[0] = src2[0];
    vg[0] = src1[1];
    vh[0] = src1[0];
    let wk = [xmm0[0], xmm0[1]];
    for i in 0..2 {
        va[i + 1] = sdm_ch(ve[i], vf[i], vg[i])
            .wrapping_add(sdm_big_sigma1(ve[i]))
            .wrapping_add(wk[i])
            .wrapping_add(vh[i])
            .wrapping_add(sdm_maj(va[i], vb[i], vc[i]))
            .wrapping_add(sdm_big_sigma0(va[i]));
        vb[i + 1] = va[i];
        vc[i + 1] = vb[i];
        vd[i + 1] = vc[i];
        ve[i + 1] = sdm_ch(ve[i], vf[i], vg[i])
            .wrapping_add(sdm_big_sigma1(ve[i]))
            .wrapping_add(wk[i])
            .wrapping_add(vh[i])
            .wrapping_add(vd[i]);
        vf[i + 1] = ve[i];
        vg[i + 1] = vf[i];
        vh[i + 1] = vg[i];
    }
    from_u32x4([vf[2], ve[2], vb[2], va[2]])
}

/// `_mm_sha256msg1_epu32(a, b)` — `SHA256MSG1 xmm1, xmm2/m128` with
/// `SRC1 = a`, `SRC2 = b`.
///
/// ```text
/// W4 := SRC2[31:0];
/// W3 := SRC1[127:96];  W2 := SRC1[95:64];  W1 := SRC1[63:32];  W0 := SRC1[31:0];
/// DEST[127:96] := W3 + σ0(W4);
/// DEST[95:64]  := W2 + σ0(W3);
/// DEST[63:32]  := W1 + σ0(W2);
/// DEST[31:0]   := W0 + σ0(W1);
/// ```
pub fn _mm_sha256msg1_epu32(a: M128i, b: M128i) -> M128i {
    let src1 = view_u32(a);
    let src2 = view_u32(b);
    let w4 = src2[0];
    let w3 = src1[3];
    let w2 = src1[2];
    let w1 = src1[1];
    let w0 = src1[0];
    from_u32x4([
        w0.wrapping_add(sdm_small_sigma0(w1)),
        w1.wrapping_add(sdm_small_sigma0(w2)),
        w2.wrapping_add(sdm_small_sigma0(w3)),
        w3.wrapping_add(sdm_small_sigma0(w4)),
    ])
}

/// `_mm_sha256msg2_epu32(a, b)` — `SHA256MSG2 xmm1, xmm2/m128` with
/// `SRC1 = a`, `SRC2 = b`.
///
/// ```text
/// W14 := SRC2[95:64];
/// W15 := SRC2[127:96];
/// W16 := SRC1[31:0]   + σ1(W14);
/// W17 := SRC1[63:32]  + σ1(W15);
/// W18 := SRC1[95:64]  + σ1(W16);
/// W19 := SRC1[127:96] + σ1(W17);
/// DEST[127:96] := W19;  DEST[95:64] := W18;
/// DEST[63:32]  := W17;  DEST[31:0]  := W16;
/// ```
pub fn _mm_sha256msg2_epu32(a: M128i, b: M128i) -> M128i {
    let src1 = view_u32(a);
    let src2 = view_u32(b);
    let w14 = src2[2];
    let w15 = src2[3];
    let w16 = src1[0].wrapping_add(sdm_small_sigma1(w14));
    let w17 = src1[1].wrapping_add(sdm_small_sigma1(w15));
    let w18 = src1[2].wrapping_add(sdm_small_sigma1(w16));
    let w19 = src1[3].wrapping_add(sdm_small_sigma1(w17));
    from_u32x4([w16, w17, w18, w19])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_rounds_of_abc() {
        // FIPS 180-4 "abc": H0 packed as abef = [f, e, b, a], cdgh = [h, g, d, c].
        let abef = from_u32x4([0x9b05688c, 0x510e527f, 0xbb67ae85, 0x6a09e667]);
        let cdgh = from_u32x4([0x5be0cd19, 0x1f83d9ab, 0xa54ff53a, 0x3c6ef372]);
        // K0 + W0, K1 + W1; lanes 2 and 3 are ignored by SHA256RNDS2.
        let wk = from_u32x4([
            0x6162_6380u32.wrapping_add(0x428a_2f98),
            0x7137_4491,
            0xdead_beef,
            0x0bad_f00d,
        ]);
        // After t = 1: a = 5a6ad9ad, b = 5d6aebcd, e = 78ce7989, f = fa2a4622.
        assert_eq!(
            view_u32(_mm_sha256rnds2_epu32(cdgh, abef, wk)),
            [0xfa2a_4622, 0x78ce_7989, 0x5d6a_ebcd, 0x5a6a_d9ad]
        );
    }

    #[test]
    fn schedule_known_answers() {
        // σ0(1) = 0x0200_4000; σ1(1) = 0x0000_a000.
        assert_eq!(
            view_u32(_mm_sha256msg1_epu32(
                from_u32x4([0, 0, 0, 0]),
                from_u32x4([1, 0, 0, 0])
            )),
            [0, 0, 0, 0x0200_4000]
        );
        let r = view_u32(_mm_sha256msg2_epu32(
            from_u32x4([0; 4]),
            from_u32x4([0, 0, 1, 0]),
        ));
        assert_eq!(r[0], 0x0000_a000);
        assert_eq!(r[2], sdm_small_sigma1(0x0000_a000));
    }
}
