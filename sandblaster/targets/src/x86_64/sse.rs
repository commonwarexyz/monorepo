//! SSE2 / SSSE3 / SSE4.1 operations (Intel SDM transcriptions).
//!
//! Each model cites the instruction the intrinsic compiles to and the
//! `Operation` section of its Intel SDM Vol. 2 entry, transcribed at byte or
//! typed-view level on the representation described in [`crate::x86_64`].
//! For two-operand legacy-SSE forms the intrinsic's first argument is `DEST`
//! (xmm1) and the second `SRC` (xmm2/m128).
#![forbid(unsafe_code)]
// Loops index lanes explicitly to mirror the vendor pseudocode
// (`for e = 0 to elements-1`), including the element-wise loads and stores.
#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

use super::{M128i, from_u16x8, from_u32x4, from_u64x2, view_u16, view_u32};

/// `_mm_loadu_si128` — `MOVDQU xmm1, m128`: `DEST[127:0] := SRC[127:0]`
/// (no alignment requirement). Model: `r[i] = mem[i]`.
pub fn _mm_loadu_si128(mem: &[u8; 16]) -> M128i {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = mem[i];
    }
    r
}

/// `_mm_storeu_si128` — `MOVDQU m128, xmm1`: `DEST[127:0] := SRC[127:0]`, as a
/// pure function returning the 16 bytes written.
pub fn _mm_storeu_si128(a: M128i) -> [u8; 16] {
    let mut mem = [0u8; 16];
    for i in 0..16 {
        mem[i] = a[i];
    }
    mem
}

/// `_mm_shuffle_epi8(a, b)` — `PSHUFB xmm1, xmm2/m128` with `DEST = a`,
/// `SRC = b` (the control mask).
///
/// ```text
/// TEMP := DEST
/// for i = 0 to 15 {
///     if (SRC[(i * 8)+7] = 1) then
///         DEST[(i*8)+7..(i*8)+0] := 0;
///     else
///         index[3..0] := SRC[(i*8)+3 .. (i*8)+0];
///         DEST[(i*8)+7..(i*8)+0] := TEMP[(index*8+7)..(index*8+0)];
///     endif
/// }
/// ```
///
/// Model: `r[i] = if b[i] & 0x80 ≠ 0 { 0 } else { a[b[i] & 15] }` (bits 6..4 of
/// the control byte are ignored).
pub fn _mm_shuffle_epi8(a: M128i, b: M128i) -> M128i {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = if b[i] & 0x80 != 0 {
            0
        } else {
            a[(b[i] & 0x0f) as usize]
        };
    }
    r
}

/// `_mm_shuffle_epi32::<IMM8>(a)` — `PSHUFD xmm1, xmm2/m128, imm8`,
/// `0 ≤ IMM8 ≤ 255`.
///
/// ```text
/// DEST[31:0]   := (SRC >> (ORDER[1:0] * 32))[31:0];
/// DEST[63:32]  := (SRC >> (ORDER[3:2] * 32))[31:0];
/// DEST[95:64]  := (SRC >> (ORDER[5:4] * 32))[31:0];
/// DEST[127:96] := (SRC >> (ORDER[7:6] * 32))[31:0];
/// ```
///
/// Model on the `u32` view: `r[i] = a[(imm >> 2i) & 3]`.
pub fn _mm_shuffle_epi32(a: M128i, imm8: i32) -> M128i {
    assert!(
        (0..=255).contains(&imm8),
        "_mm_shuffle_epi32: immediate {imm8} out of range 0..=255"
    );
    let src = view_u32(a);
    let order = imm8 as u32;
    let mut r = [0u32; 4];
    for i in 0..4 {
        r[i] = src[((order >> (2 * i)) & 3) as usize];
    }
    from_u32x4(r)
}

/// `_mm_alignr_epi8::<IMM8>(a, b)` — `PALIGNR xmm1, xmm2/m128, imm8` with
/// `DEST = a` (high half), `SRC = b` (low half), `0 ≤ IMM8 ≤ 255`.
///
/// ```text
/// temp1[255:0] := ((DEST[127:0] << 128) OR SRC[127:0]) >> (imm8*8);
/// DEST[127:0]  := temp1[127:0];
/// ```
///
/// At byte level with `c = b[0..16] ++ a[0..16]` (32 bytes, low first):
/// `r[i] = c[i + imm]` if `i + imm < 32`, else `0` (so `imm ≥ 32` gives 0).
pub fn _mm_alignr_epi8(a: M128i, b: M128i, imm8: i32) -> M128i {
    assert!(
        (0..=255).contains(&imm8),
        "_mm_alignr_epi8: immediate {imm8} out of range 0..=255"
    );
    let shift = imm8 as usize;
    let mut r = [0u8; 16];
    for i in 0..16 {
        let k = i + shift;
        r[i] = if k < 16 {
            b[k]
        } else if k < 32 {
            a[k - 16]
        } else {
            0
        };
    }
    r
}

/// `_mm_blend_epi16::<IMM8>(a, b)` — `PBLENDW xmm1, xmm2/m128, imm8` with
/// `DEST = a`, `SRC = b`, `0 ≤ IMM8 ≤ 255`.
///
/// ```text
/// IF (imm8[0] = 1) THEN DEST[15:0]    := SRC[15:0]
/// ELSE                  DEST[15:0]    := DEST[15:0]
/// ...
/// IF (imm8[7] = 1) THEN DEST[127:112] := SRC[127:112]
/// ELSE                  DEST[127:112] := DEST[127:112]
/// ```
///
/// Model on the `u16` view: `r[i] = if (imm >> i) & 1 = 1 { b[i] } else { a[i] }`.
pub fn _mm_blend_epi16(a: M128i, b: M128i, imm8: i32) -> M128i {
    assert!(
        (0..=255).contains(&imm8),
        "_mm_blend_epi16: immediate {imm8} out of range 0..=255"
    );
    let dest = view_u16(a);
    let src = view_u16(b);
    let mut r = [0u16; 8];
    for i in 0..8 {
        r[i] = if (imm8 >> i) & 1 == 1 {
            src[i]
        } else {
            dest[i]
        };
    }
    from_u16x8(r)
}

/// `_mm_add_epi32(a, b)` — `PADDD xmm1, xmm2/m128`:
/// `DEST[32i+31:32i] := DEST[32i+31:32i] + SRC[32i+31:32i]` for `i = 0..3`
/// (wraparound; carries are discarded). Model on the `u32` view.
pub fn _mm_add_epi32(a: M128i, b: M128i) -> M128i {
    let x = view_u32(a);
    let y = view_u32(b);
    let mut r = [0u32; 4];
    for i in 0..4 {
        r[i] = x[i].wrapping_add(y[i]);
    }
    from_u32x4(r)
}

/// `_mm_set_epi32(e3, e2, e1, e0)` — composite (no single instruction):
/// `dst[31:0] := e0; dst[63:32] := e1; dst[95:64] := e2; dst[127:96] := e3`.
/// The `i32` arguments are reinterpreted as two's-complement `u32`.
pub fn _mm_set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> M128i {
    from_u32x4([e0 as u32, e1 as u32, e2 as u32, e3 as u32])
}

/// `_mm_set_epi64x(e1, e0)` — composite: `dst[63:0] := e0; dst[127:64] := e1`
/// (two's complement).
pub fn _mm_set_epi64x(e1: i64, e0: i64) -> M128i {
    from_u64x2([e0 as u64, e1 as u64])
}

/// `_mm_xor_si128(a, b)` — `PXOR xmm1, xmm2/m128`:
/// `DEST := DEST XOR SRC` (bytewise).
pub fn _mm_xor_si128(a: M128i, b: M128i) -> M128i {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] ^ b[i];
    }
    r
}

/// `_mm_and_si128(a, b)` — `PAND xmm1, xmm2/m128`:
/// `DEST := DEST AND SRC` (bytewise).
pub fn _mm_and_si128(a: M128i, b: M128i) -> M128i {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] & b[i];
    }
    r
}

/// `_mm_or_si128(a, b)` — `POR xmm1, xmm2/m128`:
/// `DEST := DEST OR SRC` (bytewise).
pub fn _mm_or_si128(a: M128i, b: M128i) -> M128i {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] | b[i];
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iota(base: u8) -> M128i {
        core::array::from_fn(|i| base + i as u8)
    }

    #[test]
    fn known_answers() {
        let a = iota(0x10);
        let mut mask = [0u8; 16];
        mask[0] = 0x80; // zero
        mask[1] = 0x0f; // a[15]
        mask[2] = 0x71; // bits 6..4 ignored: a[1]
        mask[3] = 0xff; // zero
        let r = _mm_shuffle_epi8(a, mask);
        assert_eq!(&r[..4], &[0, 0x1f, 0x11, 0]);
        assert_eq!(&r[4..], &[0x10; 12]);
        // PALIGNR: (a:b) >> 8*imm with a high.
        let (hi, lo) = (iota(16), iota(0));
        assert_eq!(_mm_alignr_epi8(hi, lo, 0), lo);
        assert_eq!(_mm_alignr_epi8(hi, lo, 4), iota(4));
        assert_eq!(_mm_alignr_epi8(hi, lo, 16), hi);
        let mut r17 = [0u8; 16];
        r17[..15].copy_from_slice(&iota(17)[..15]);
        assert_eq!(_mm_alignr_epi8(hi, lo, 17), r17);
        assert_eq!(_mm_alignr_epi8(hi, lo, 32), [0; 16]);
        assert_eq!(_mm_alignr_epi8(hi, lo, 255), [0; 16]);
        // PBLENDW 0xF0: words 4..7 from the second operand.
        let blended = view_u32(_mm_blend_epi16(
            from_u32x4([1, 2, 3, 4]),
            from_u32x4([5, 6, 7, 8]),
            0xF0,
        ));
        assert_eq!(blended, [1, 2, 7, 8]);
        assert_eq!(
            view_u32(_mm_shuffle_epi32(from_u32x4([1, 2, 3, 4]), 0x1B)),
            [4, 3, 2, 1]
        );
        assert_eq!(
            view_u32(_mm_shuffle_epi32(from_u32x4([1, 2, 3, 4]), 0xB1)),
            [2, 1, 4, 3]
        );
        assert_eq!(
            view_u32(_mm_shuffle_epi32(from_u32x4([1, 2, 3, 4]), 0x0E)),
            [3, 4, 1, 1]
        );
        assert_eq!(view_u32(_mm_set_epi32(3, 2, 1, -1)), [u32::MAX, 1, 2, 3]);
        assert_eq!(
            _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203),
            [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]
        );
        assert_eq!(
            view_u32(_mm_add_epi32(
                from_u32x4([u32::MAX, 0, 0, 0]),
                from_u32x4([1, 0, 0, 0])
            )),
            [0; 4]
        );
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn imm8_out_of_range_is_rejected() {
        let _ = _mm_shuffle_epi32([0; 16], 256);
    }
}
