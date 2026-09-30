//! VL-generic semantics of the VEX/EVEX integer instructions used by the
//! AVX2 and AVX-512F/BW/VL/DQ models (Intel SDM Vol. 2 transcriptions).
//!
//! One function per SDM instruction page, generic over the vector width `N`
//! in bytes (16, 32 or 64: the SDM's `(KL, VL)` table, `KL = N / element
//! size`), on the representation of [`crate::x86_64::wide`]. Each doc
//! comment quotes the `Operation` section of the EVEX form (the VEX.256 form
//! of the AVX2 instructions computes the same function on 256 bits; where
//! its pseudocode is spelled differently it is quoted as well). The models
//! are the unmasked register forms: `*no writemask*` holds (`k0`) and the
//! second source is a register (`EVEX.b = 0`), so the broadcast and
//! masking branches of the pseudocode are dropped, and the masking
//! instructions (VPBLENDM, VMOVDQA32/64 with a mask, VPCMP into a mask) are
//! modelled with their mask operand. `DEST[MAXVL-1:VL] := 0` concerns
//! register bits above the intrinsic's result type and is not modelled.
//!
//! Operand names follow the SDM (`DEST`, `SRC1`, `SRC2`, …); the intrinsic
//! wrappers in [`super::avx512`] and [`super::avx2`] state which argument is
//! which.
#![forbid(unsafe_code)]
// Loops index elements explicitly to mirror `FOR j := 0 TO KL-1`.
#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

use super::wide::{dword, mask_bit, qword, set_dword, set_qword};

/// `VMOVDQU` / `VMOVDQU32` / `VMOVDQU64` (load or store, no mask):
/// `DEST[VL-1:0] := SRC[VL-1:0]`. Model: `r[i] = src[i]` for every byte.
pub fn vmovdqu<const N: usize>(src: &[u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for i in 0..N {
        dest[i] = src[i];
    }
    dest
}

/// `VPADDD`:
///
/// ```text
/// (KL, VL) = (4, 128), (8, 256), (16, 512)
/// FOR j := 0 TO KL-1
///     i := j * 32
///     DEST[i+31:i] := SRC1[i+31:i] + SRC2[i+31:i]
/// ENDFOR
/// ```
///
/// (VEX.256: `DEST[31:0] := SRC1[31:0] + SRC2[31:0]` … `DEST[255:224] :=
/// SRC1[255:224] + SRC2[255:224]`.) Carries out of each dword are dropped.
pub fn vpaddd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src1, j).wrapping_add(dword(&src2, j)));
    }
    dest
}

/// `VPADDQ`: `(KL, VL) = (2, 128), (4, 256), (8, 512)`; `FOR j := 0 TO KL-1:
/// i := j * 64; DEST[i+63:i] := SRC1[i+63:i] + SRC2[i+63:i]` (mod 2^64).
pub fn vpaddq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, qword(&src1, j).wrapping_add(qword(&src2, j)));
    }
    dest
}

/// `VPSUBD`: `FOR j := 0 TO KL-1: i := j * 32; DEST[i+31:i] := SRC1[i+31:i] -
/// SRC2[i+31:i]` (mod 2^32).
pub fn vpsubd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src1, j).wrapping_sub(dword(&src2, j)));
    }
    dest
}

/// `VPSUBQ`: `FOR j := 0 TO KL-1: i := j * 64; DEST[i+63:i] := SRC1[i+63:i] -
/// SRC2[i+63:i]` (mod 2^64).
pub fn vpsubq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, qword(&src1, j).wrapping_sub(qword(&src2, j)));
    }
    dest
}

/// `VPXORD` (and VEX.256 `VPXOR`: `DEST := SRC1 XOR SRC2`):
/// `FOR j := 0 TO KL-1: i := j * 32; DEST[i+31:i] := SRC1[i+31:i] BITWISE XOR
/// SRC2[i+31:i]`. The operation is bitwise, so the element split only
/// matters for masking; the model uses dwords like the EVEX.W0 form.
pub fn vpxord<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src1, j) ^ dword(&src2, j));
    }
    dest
}

/// `VPANDD` (and VEX.256 `VPAND`): `DEST[i+31:i] := SRC1[i+31:i] BITWISE AND
/// SRC2[i+31:i]` for every dword `j` (`i := j * 32`).
pub fn vpandd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src1, j) & dword(&src2, j));
    }
    dest
}

/// `VPORD` (and VEX.256 `VPOR`): `DEST[i+31:i] := SRC1[i+31:i] BITWISE OR
/// SRC2[i+31:i]` for every dword `j`.
pub fn vpord<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src1, j) | dword(&src2, j));
    }
    dest
}

/// `VPANDND` (and VEX.256 `VPANDN`): `DEST[i+31:i] := ((NOT SRC1[i+31:i]) AND
/// SRC2[i+31:i])` for every dword `j`: the **first** source is inverted.
pub fn vpandnd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, !dword(&src1, j) & dword(&src2, j));
    }
    dest
}

/// `VPTERNLOGD`, `0 ≤ imm8 ≤ 255` (`DEST` is the first source):
///
/// ```text
/// (KL, VL) = (4, 128), (8, 256), (16, 512)
/// FOR j := 0 TO KL-1
///     i := j * 32
///     FOR k := 0 TO 31
///         DEST[j][k] := imm[(DEST[i+k] << 2) + (SRC1[ i+k ] << 1) + SRC2[ i+k ]]
///     ENDFOR
/// ENDFOR
/// ```
///
/// Each result bit is the bit of `imm8` indexed by the three source bits.
pub fn vpternlogd<const N: usize>(dest: [u8; N], src1: [u8; N], src2: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpternlogd: immediate {imm8} out of range 0..=255");
    let imm = imm8 as u32;
    let mut out = [0u8; N];
    for j in 0..N / 4 {
        let (d, s1, s2) = (dword(&dest, j), dword(&src1, j), dword(&src2, j));
        let mut r = 0u32;
        for k in 0..32 {
            let index = (((d >> k) & 1) << 2) + (((s1 >> k) & 1) << 1) + ((s2 >> k) & 1);
            r |= ((imm >> index) & 1) << k;
        }
        set_dword(&mut out, j, r);
    }
    out
}

/// `VPTERNLOGQ`, `0 ≤ imm8 ≤ 255`: as [`vpternlogd`] on qwords
/// (`FOR j := 0 TO KL-1: i := j * 64; FOR k := 0 TO 63: DEST[j][k] :=
/// imm[(DEST[i+k] << 2) + (SRC1[ i+k ] << 1) + SRC2[ i+k ]]`).
pub fn vpternlogq<const N: usize>(dest: [u8; N], src1: [u8; N], src2: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpternlogq: immediate {imm8} out of range 0..=255");
    let imm = imm8 as u64;
    let mut out = [0u8; N];
    for j in 0..N / 8 {
        let (d, s1, s2) = (qword(&dest, j), qword(&src1, j), qword(&src2, j));
        let mut r = 0u64;
        for k in 0..64 {
            let index = (((d >> k) & 1) << 2) + (((s1 >> k) & 1) << 1) + ((s2 >> k) & 1);
            r |= ((imm >> index) & 1) << k;
        }
        set_qword(&mut out, j, r);
    }
    out
}

/// SDM `LEFT_ROTATE_DWORDS(SRC, COUNT_SRC)`:
///
/// ```text
/// COUNT := COUNT_SRC modulo 32;
/// DEST[31:0] := (SRC << COUNT) | (SRC >> (32 - COUNT));
/// ```
///
/// The shifts are on the value widened to 64 bits, so `SRC >> 32` is 0 as in
/// the pseudocode (`COUNT = 0` returns `SRC`); `DEST[31:0]` truncates.
pub fn left_rotate_dwords(src: u32, count_src: u32) -> u32 {
    let count = count_src % 32;
    (((src as u64) << count) | ((src as u64) >> (32 - count))) as u32
}

/// SDM `RIGHT_ROTATE_DWORDS(SRC, COUNT_SRC)`: `COUNT := COUNT_SRC modulo 32;
/// DEST[31:0] := (SRC >> COUNT) | (SRC << (32 - COUNT));` (widened as in
/// [`left_rotate_dwords`]).
pub fn right_rotate_dwords(src: u32, count_src: u32) -> u32 {
    let count = count_src % 32;
    (((src as u64) >> count) | ((src as u64) << (32 - count))) as u32
}

/// SDM `LEFT_ROTATE_QWORDS(SRC, COUNT_SRC)`: `COUNT := COUNT_SRC modulo 64;
/// DEST[63:0] := (SRC << COUNT) | (SRC >> (64 - COUNT));` (widened to 128 bits).
pub fn left_rotate_qwords(src: u64, count_src: u64) -> u64 {
    let count = count_src % 64;
    (((src as u128) << count) | ((src as u128) >> (64 - count))) as u64
}

/// SDM `RIGHT_ROTATE_QWORDS(SRC, COUNT_SRC)`: `COUNT := COUNT_SRC modulo 64;
/// DEST[63:0] := (SRC >> COUNT) | (SRC << (64 - COUNT));` (widened to 128 bits).
pub fn right_rotate_qwords(src: u64, count_src: u64) -> u64 {
    let count = count_src % 64;
    (((src as u128) >> count) | ((src as u128) << (64 - count))) as u64
}

/// `VPROLD` (imm8 form), `0 ≤ imm8 ≤ 255`: `FOR j := 0 TO KL-1: i := j * 32;
/// DEST[i+31:i] := LEFT_ROTATE_DWORDS(SRC1[i+31:i], imm8)`.
pub fn vprold<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vprold: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, left_rotate_dwords(dword(&src1, j), imm8 as u32));
    }
    dest
}

/// `VPRORD` (imm8 form), `0 ≤ imm8 ≤ 255`: `DEST[i+31:i] :=
/// RIGHT_ROTATE_DWORDS(SRC1[i+31:i], imm8)` for every dword.
pub fn vprord<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vprord: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, right_rotate_dwords(dword(&src1, j), imm8 as u32));
    }
    dest
}

/// `VPROLQ` (imm8 form), `0 ≤ imm8 ≤ 255`: `FOR j := 0 TO KL-1: i := j * 64;
/// DEST[i+63:i] := LEFT_ROTATE_QWORDS(SRC1[i+63:i], imm8)`.
pub fn vprolq<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vprolq: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, left_rotate_qwords(qword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPRORQ` (imm8 form), `0 ≤ imm8 ≤ 255`: `DEST[i+63:i] :=
/// RIGHT_ROTATE_QWORDS(SRC1[i+63:i], imm8)` for every qword.
pub fn vprorq<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vprorq: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, right_rotate_qwords(qword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPROLVD`: `FOR j := 0 TO KL-1: i := j * 32; DEST[i+31:i] :=
/// LEFT_ROTATE_DWORDS(SRC1[i+31:i], SRC2[i+31:i])`.
pub fn vprolvd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, left_rotate_dwords(dword(&src1, j), dword(&src2, j)));
    }
    dest
}

/// `VPRORVD`: `DEST[i+31:i] := RIGHT_ROTATE_DWORDS(SRC1[i+31:i], SRC2[i+31:i])`.
pub fn vprorvd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, right_rotate_dwords(dword(&src1, j), dword(&src2, j)));
    }
    dest
}

/// `VPROLVQ`: `FOR j := 0 TO KL-1: i := j * 64; DEST[i+63:i] :=
/// LEFT_ROTATE_QWORDS(SRC1[i+63:i], SRC2[i+63:i])`.
pub fn vprolvq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, left_rotate_qwords(qword(&src1, j), qword(&src2, j)));
    }
    dest
}

/// `VPRORVQ`: `DEST[i+63:i] := RIGHT_ROTATE_QWORDS(SRC1[i+63:i], SRC2[i+63:i])`.
pub fn vprorvq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, right_rotate_qwords(qword(&src1, j), qword(&src2, j)));
    }
    dest
}

/// SDM `LOGICAL_LEFT_SHIFT_DWORDS1(SRC, COUNT)`:
///
/// ```text
/// IF (COUNT > 31)
/// THEN DEST[31:0] := 0
/// ELSE DEST[31:0] := ZeroExtend(SRC[31:0] << COUNT);
/// FI;
/// ```
pub fn logical_left_shift_dwords1(src: u32, count: u64) -> u32 {
    if count > 31 { 0 } else { src << count }
}

/// SDM `LOGICAL_RIGHT_SHIFT_DWORDS1(SRC, COUNT)`: `IF (COUNT > 31) THEN
/// DEST[31:0] := 0 ELSE DEST[31:0] := ZeroExtend(SRC[31:0] >> COUNT); FI;`
pub fn logical_right_shift_dwords1(src: u32, count: u64) -> u32 {
    if count > 31 { 0 } else { src >> count }
}

/// SDM `LOGICAL_LEFT_SHIFT_QWORDS1(SRC, COUNT)`: `IF (COUNT > 63) THEN
/// DEST[63:0] := 0 ELSE DEST[63:0] := ZeroExtend(SRC[63:0] << COUNT); FI;`
pub fn logical_left_shift_qwords1(src: u64, count: u64) -> u64 {
    if count > 63 { 0 } else { src << count }
}

/// SDM `LOGICAL_RIGHT_SHIFT_QWORDS1(SRC, COUNT)`: `IF (COUNT > 63) THEN
/// DEST[63:0] := 0 ELSE DEST[63:0] := ZeroExtend(SRC[63:0] >> COUNT); FI;`
pub fn logical_right_shift_qwords1(src: u64, count: u64) -> u64 {
    if count > 63 { 0 } else { src >> count }
}

/// `VPSLLD` (imm8 form), `0 ≤ imm8 ≤ 255`: `FOR j := 0 TO KL-1: i := j * 32;
/// DEST[i+31:i] := LOGICAL_LEFT_SHIFT_DWORDS1(SRC1[i+31:i], imm8)` (VEX.256:
/// `DEST[255:0] := LOGICAL_LEFT_SHIFT_DWORDS_256b(SRC1, imm8)`, the same
/// per-dword shift with `COUNT > 31` giving 0).
pub fn vpslld_imm<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpslld: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, logical_left_shift_dwords1(dword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPSRLD` (imm8 form), `0 ≤ imm8 ≤ 255`: `DEST[i+31:i] :=
/// LOGICAL_RIGHT_SHIFT_DWORDS1(SRC1[i+31:i], imm8)` for every dword.
pub fn vpsrld_imm<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpsrld: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, logical_right_shift_dwords1(dword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPSLLQ` (imm8 form), `0 ≤ imm8 ≤ 255`: `FOR j := 0 TO KL-1: i := j * 64;
/// DEST[i+63:i] := LOGICAL_LEFT_SHIFT_QWORDS1(SRC1[i+63:i], imm8)`.
pub fn vpsllq_imm<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpsllq: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, logical_left_shift_qwords1(qword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPSRLQ` (imm8 form), `0 ≤ imm8 ≤ 255`: `DEST[i+63:i] :=
/// LOGICAL_RIGHT_SHIFT_QWORDS1(SRC1[i+63:i], imm8)` for every qword.
pub fn vpsrlq_imm<const N: usize>(src1: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpsrlq: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, logical_right_shift_qwords1(qword(&src1, j), imm8 as u64));
    }
    dest
}

/// `VPSLLVQ` (per-element counts):
///
/// ```text
/// FOR j := 0 TO KL-1
///     i := j * 64
///     COUNT := SRC2[i+63:i]
///     IF COUNT < 64
///         THEN DEST[i+63:i] := ZeroExtend(SRC1[i+63:i] << COUNT)
///         ELSE DEST[i+63:i] := 0
/// ENDFOR
/// ```
///
/// (the whole 64-bit count is compared: a count of 64 or more gives 0).
pub fn vpsllvq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let count = qword(&src2, j);
        let r = if count < 64 { qword(&src1, j) << count } else { 0 };
        set_qword(&mut dest, j, r);
    }
    dest
}

/// `VPSRLVQ`: as [`vpsllvq`] with `ZeroExtend(SRC1[i+63:i] >> COUNT)`.
pub fn vpsrlvq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let count = qword(&src2, j);
        let r = if count < 64 { qword(&src1, j) >> count } else { 0 };
        set_qword(&mut dest, j, r);
    }
    dest
}

/// `VPSHUFB` (`SRC1` is the table, `SRC2` the control bytes):
///
/// ```text
/// (KL, VL) = (16, 128), (32, 256), (64, 512)
/// jmask := (KL-1) & ~0xF // 0x00, 0x10, 0x30 depending on the VL
/// FOR j = 0 TO KL-1 // dest
///     index := src.byte[ j ];          -- SRC2 (control)
///     IF index & 0x80
///         Dest.byte[ j ] := 0;
///     ELSE
///         index := (index & 0xF) + (j & jmask); // 16-element in-lane lookup
///         Dest.byte[ j ] := src.byte[ index ];   -- SRC1 (table)
/// ENDFOR
/// ```
///
/// The lookup never crosses a 128-bit lane; bits 6..4 of a control byte are
/// ignored. (VEX.256 spells the same per-lane lookup with `SRC2[128 +
/// (i*8)+7]` for the upper lane.)
pub fn vpshufb<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let jmask = (N - 1) & !0xf;
    let mut dest = [0u8; N];
    for j in 0..N {
        let index = src2[j] as usize;
        dest[j] = if index & 0x80 != 0 { 0 } else { src1[(index & 0xf) + (j & jmask)] };
    }
    dest
}

/// `VPERMD` (EVEX, and VEX.256 `VPERMD ymm1, ymm2, ymm3/m256`); `SRC1` holds
/// the indices, `SRC2` the table:
///
/// ```text
/// (KL, VL) = (8, 256), (16, 512)
/// IF VL = 256 THEN n := 2; FI;
/// IF VL = 512 THEN n := 3; FI;
/// FOR j := 0 TO KL-1
///     i := j * 32
///     id := 32*SRC1[i+n:i]
///     DEST[i+31:i] := SRC2[id+31:id]
/// ENDFOR
/// ```
///
/// (VEX.256: `DEST[31:0] := (SRC2[255:0] >> (SRC1[2:0] * 32))[31:0]` …) The
/// index is the low `n + 1` bits of each dword; the rest are ignored.
pub fn vpermd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let kl = N / 4;
    let mut dest = [0u8; N];
    for j in 0..kl {
        let id = dword(&src1, j) as usize & (kl - 1);
        set_dword(&mut dest, j, dword(&src2, id));
    }
    dest
}

/// `VPERMQ` (EVEX, vector-index form); `SRC1` holds the indices, `SRC2` the
/// table: `(KL, VL) = (4, 256), (8, 512)`; `IF VL = 256 THEN n := 1; IF VL =
/// 512 THEN n := 2; FOR j := 0 TO KL-1: i := j * 64; id := 64*SRC1[i+n:i];
/// DEST[i+63:i] := SRC2[id+63:id]`.
pub fn vpermq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let kl = N / 8;
    let mut dest = [0u8; N];
    for j in 0..kl {
        let id = qword(&src1, j) as usize & (kl - 1);
        set_qword(&mut dest, j, qword(&src2, id));
    }
    dest
}

/// `VPERMI2Q` / `VPERMT2Q` (two-table permute; for VPERMI2Q `DEST` holds the
/// indices, `SRC1` the first table, `SRC2` the second):
///
/// ```text
/// (KL, VL) = (2, 128), (4, 256), (8, 512)
/// IF VL = 128: id := 0
/// IF VL = 256: id := 1
/// IF VL = 512: id := 2
/// FOR j := 0 TO KL-1
///     i := j * 64
///     off := 64*DEST[i+id:i]
///     DEST[i+63:i] := DEST[i+id+1] ? SRC2[off+63:off] : SRC1[off+63:off]
/// ENDFOR
/// ```
///
/// Bit `id + 1` of the index selects the table; the bits above are ignored.
pub fn vpermi2q<const N: usize>(index: [u8; N], src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let kl = N / 8;
    let mut dest = [0u8; N];
    for j in 0..kl {
        let ix = qword(&index, j) as usize;
        let off = ix & (kl - 1);
        let r = if ix & kl != 0 { qword(&src2, off) } else { qword(&src1, off) };
        set_qword(&mut dest, j, r);
    }
    dest
}

/// SDM `Select4(SRC, control)` of VSHUFI32x4/VSHUFI64x2: the 128-bit lane
/// `control[1:0]` of a 512-bit source.
///
/// ```text
/// CASE (control[1:0]) OF
///     0: TMP := SRC[127:0];
///     1: TMP := SRC[255:128];
///     2: TMP := SRC[383:256];
///     3: TMP := SRC[511:384];
/// ESAC;
/// RETURN TMP
/// ```
pub fn select4(src: &[u8; 64], control: u32) -> [u8; 16] {
    let lane = (control & 3) as usize;
    let mut tmp = [0u8; 16];
    for b in 0..16 {
        tmp[b] = src[16 * lane + b];
    }
    tmp
}

/// The 128-bit lanes chosen by VSHUFI32x4/VSHUFI64x2 (512-bit form):
/// `TMP_DEST[127:0] := Select4(SRC1, imm8[1:0]); TMP_DEST[255:128] :=
/// Select4(SRC1, imm8[3:2]); TMP_DEST[383:256] := Select4(SRC2, imm8[5:4]);
/// TMP_DEST[511:384] := Select4(SRC2, imm8[7:6])`.
pub fn vshuf128x4_tmp(src1: &[u8; 64], src2: &[u8; 64], imm8: u32) -> [u8; 64] {
    let lanes = [select4(src1, imm8), select4(src1, imm8 >> 2), select4(src2, imm8 >> 4), select4(src2, imm8 >> 6)];
    let mut tmp_dest = [0u8; 64];
    for l in 0..4 {
        for b in 0..16 {
            tmp_dest[16 * l + b] = lanes[l][b];
        }
    }
    tmp_dest
}

/// `VSHUFI32x4` (EVEX 512-bit version), `0 ≤ imm8 ≤ 255`: `TMP_DEST` as in
/// [`vshuf128x4_tmp`], then `FOR j := 0 TO KL-1: i := j * 32; DEST[i+31:i] :=
/// TMP_DEST[i+31:i]` (`KL = 16`).
pub fn vshufi32x4(src1: [u8; 64], src2: [u8; 64], imm8: i32) -> [u8; 64] {
    assert!((0..=255).contains(&imm8), "vshufi32x4: immediate {imm8} out of range 0..=255");
    let tmp_dest = vshuf128x4_tmp(&src1, &src2, imm8 as u32);
    let mut dest = [0u8; 64];
    for j in 0..16 {
        set_dword(&mut dest, j, dword(&tmp_dest, j));
    }
    dest
}

/// `VSHUFI64x2` (EVEX 512-bit version), `0 ≤ imm8 ≤ 255`: `TMP_DEST` as in
/// [`vshuf128x4_tmp`], then `FOR j := 0 TO KL-1: i := j * 64; DEST[i+63:i] :=
/// TMP_DEST[i+63:i]` (`KL = 8`).
pub fn vshufi64x2(src1: [u8; 64], src2: [u8; 64], imm8: i32) -> [u8; 64] {
    assert!((0..=255).contains(&imm8), "vshufi64x2: immediate {imm8} out of range 0..=255");
    let tmp_dest = vshuf128x4_tmp(&src1, &src2, imm8 as u32);
    let mut dest = [0u8; 64];
    for j in 0..8 {
        set_qword(&mut dest, j, qword(&tmp_dest, j));
    }
    dest
}

/// `VPUNPCKLDQ` (`INTERLEAVE_DWORDS_512b` / `_256b`: per 128-bit lane
/// `INTERLEAVE_DWORDS`):
///
/// ```text
/// INTERLEAVE_DWORDS(SRC1, SRC2)
/// DEST[31:0] := SRC1[31:0]
/// DEST[63:32] := SRC2[31:0]
/// DEST[95:64] := SRC1[63:32]
/// DEST[127:96] := SRC2[63:32]
/// ```
pub fn vpunpckldq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for lane in 0..N / 16 {
        let d = 4 * lane;
        set_dword(&mut dest, d, dword(&src1, d));
        set_dword(&mut dest, d + 1, dword(&src2, d));
        set_dword(&mut dest, d + 2, dword(&src1, d + 1));
        set_dword(&mut dest, d + 3, dword(&src2, d + 1));
    }
    dest
}

/// `VPUNPCKHDQ` (per 128-bit lane `INTERLEAVE_HIGH_DWORDS`): `DEST[31:0] :=
/// SRC1[95:64]; DEST[63:32] := SRC2[95:64]; DEST[95:64] := SRC1[127:96];
/// DEST[127:96] := SRC2[127:96]`.
pub fn vpunpckhdq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for lane in 0..N / 16 {
        let d = 4 * lane;
        set_dword(&mut dest, d, dword(&src1, d + 2));
        set_dword(&mut dest, d + 1, dword(&src2, d + 2));
        set_dword(&mut dest, d + 2, dword(&src1, d + 3));
        set_dword(&mut dest, d + 3, dword(&src2, d + 3));
    }
    dest
}

/// `VPUNPCKLQDQ` (per 128-bit lane `INTERLEAVE_QWORDS`): `DEST[63:0] :=
/// SRC1[63:0]; DEST[127:64] := SRC2[63:0]`.
pub fn vpunpcklqdq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for lane in 0..N / 16 {
        let q = 2 * lane;
        set_qword(&mut dest, q, qword(&src1, q));
        set_qword(&mut dest, q + 1, qword(&src2, q));
    }
    dest
}

/// `VPUNPCKHQDQ` (per 128-bit lane `INTERLEAVE_HIGH_QWORDS`): `DEST[63:0] :=
/// SRC1[127:64]; DEST[127:64] := SRC2[127:64]`.
pub fn vpunpckhqdq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for lane in 0..N / 16 {
        let q = 2 * lane;
        set_qword(&mut dest, q, qword(&src1, q + 1));
        set_qword(&mut dest, q + 1, qword(&src2, q + 1));
    }
    dest
}

/// `VPBROADCASTD` (from a general-purpose register or memory): `FOR j := 0 TO
/// KL-1: i := j * 32; DEST[i+31:i] := SRC[31:0]`.
pub fn vpbroadcastd<const N: usize>(src: u32) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, src);
    }
    dest
}

/// `VPBROADCASTQ`: `FOR j := 0 TO KL-1: i := j * 64; DEST[i+63:i] := SRC[63:0]`.
pub fn vpbroadcastq<const N: usize>(src: u64) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, src);
    }
    dest
}

/// `VPBLENDMD` (merging form, `k1` the control mask):
///
/// ```text
/// FOR j := 0 TO KL-1
///     i := j * 32
///     IF k1[j] OR *no controlmask*
///         THEN DEST[i+31:i] := SRC2[i+31:i]
///         ELSE DEST[i+31:i] := SRC1[i+31:i]       ; merging-masking
/// ENDFOR
/// ```
pub fn vpblendmd<const N: usize>(k1: u64, src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        let r = if mask_bit(k1, j) { dword(&src2, j) } else { dword(&src1, j) };
        set_dword(&mut dest, j, r);
    }
    dest
}

/// `VPBLENDMQ`: as [`vpblendmd`] on qwords (`i := j * 64`).
pub fn vpblendmq<const N: usize>(k1: u64, src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let r = if mask_bit(k1, j) { qword(&src2, j) } else { qword(&src1, j) };
        set_qword(&mut dest, j, r);
    }
    dest
}

/// `VMOVDQA32` register copy with a writemask (`src` is the merge source):
///
/// ```text
/// FOR j := 0 TO KL-1
///     i := j * 32
///     IF k1[j] OR *no writemask*
///         THEN DEST[i+31:i] := SRC[i+31:i]
///         ELSE
///             IF *merging-masking*
///                 THEN *DEST[i+31:i] remains unchanged*
///                 ELSE DEST[i+31:i] := 0 ; zeroing-masking
///             FI
///     FI;
/// ENDFOR
/// ```
///
/// `merge = Some(old DEST)` is merging-masking, `None` zeroing-masking.
pub fn vmovdqa32_masked<const N: usize>(merge: Option<[u8; N]>, k1: u64, src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        let r = if mask_bit(k1, j) {
            dword(&src, j)
        } else {
            match &merge {
                Some(old) => dword(old, j),
                None => 0,
            }
        };
        set_dword(&mut dest, j, r);
    }
    dest
}

/// `VMOVDQA64` register copy with a writemask: as [`vmovdqa32_masked`] on
/// qwords.
pub fn vmovdqa64_masked<const N: usize>(merge: Option<[u8; N]>, k1: u64, src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let r = if mask_bit(k1, j) {
            qword(&src, j)
        } else {
            match &merge {
                Some(old) => qword(old, j),
                None => 0,
            }
        };
        set_qword(&mut dest, j, r);
    }
    dest
}

/// `VPCMPUQ` with predicate 1 (`LT`, unsigned) into a mask, no `k2`:
///
/// ```text
/// FOR j := 0 TO KL-1
///     i := j * 64
///     CMP := SRC1[i+63:i] OP SRC2[i+63:i];        -- OP = LT (unsigned)
///     IF CMP = TRUE THEN DEST[j] := 1; ELSE DEST[j] := 0; FI;
/// ENDFOR
/// DEST[MAX_KL-1:KL] := 0
/// ```
pub fn vpcmpuq_lt<const N: usize>(src1: [u8; N], src2: [u8; N]) -> u64 {
    let mut dest = 0u64;
    for j in 0..N / 8 {
        if qword(&src1, j) < qword(&src2, j) {
            dest |= 1 << j;
        }
    }
    dest
}

/// `VPCMPEQQ` (EVEX, into a mask): `FOR j := 0 TO KL-1: i := j * 64; CMP :=
/// SRC1[i+63:i] = SRC2[i+63:i]; IF CMP = TRUE THEN DEST[j] := 1; ELSE
/// DEST[j] := 0; FI; ENDFOR; DEST[MAX_KL-1:KL] := 0`.
pub fn vpcmpeqq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> u64 {
    let mut dest = 0u64;
    for j in 0..N / 8 {
        if qword(&src1, j) == qword(&src2, j) {
            dest |= 1 << j;
        }
    }
    dest
}

/// `VPCMPEQD` (EVEX, into a mask): as [`vpcmpeqq`] on dwords (`i := j * 32`).
pub fn vpcmpeqd<const N: usize>(src1: [u8; N], src2: [u8; N]) -> u64 {
    let mut dest = 0u64;
    for j in 0..N / 4 {
        if dword(&src1, j) == dword(&src2, j) {
            dest |= 1 << j;
        }
    }
    dest
}

/// `VPMULLQ` (AVX512DQ):
///
/// ```text
/// FOR j := 0 TO KL-1
///     i := j * 64
///     Temp[127:0] := SRC1[i+63:i] * SRC2[i+63:i]
///     DEST[i+63:i] := Temp[63:0]
/// ENDFOR
/// ```
pub fn vpmullq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let temp = (qword(&src1, j) as u128) * (qword(&src2, j) as u128);
        set_qword(&mut dest, j, temp as u64);
    }
    dest
}

/// `VPMULUDQ`: `FOR j := 0 TO KL-1: i := j * 64; DEST[i+63:i] :=
/// ZeroExtend64( SRC1[i+31:i]) * ZeroExtend64( SRC2[i+31:i] )` (the low
/// dword of each qword; the product fits in 64 bits).
pub fn vpmuludq<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let a = dword(&src1, 2 * j) as u64;
        let b = dword(&src2, 2 * j) as u64;
        set_qword(&mut dest, j, a * b);
    }
    dest
}

/// `VPBLENDD` (AVX2, VEX.256), `0 ≤ imm8 ≤ 255`:
///
/// ```text
/// IF (imm8[0] == 1) THEN DEST[31:0] := SRC2[31:0] ELSE DEST[31:0] := SRC1[31:0]
/// ...
/// IF (imm8[7] == 1) THEN DEST[255:224] := SRC2[255:224] ELSE DEST[255:224] := SRC1[255:224]
/// ```
pub fn vpblendd(src1: [u8; 32], src2: [u8; 32], imm8: i32) -> [u8; 32] {
    assert!((0..=255).contains(&imm8), "vpblendd: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; 32];
    for j in 0..8 {
        let r = if (imm8 >> j) & 1 == 1 { dword(&src2, j) } else { dword(&src1, j) };
        set_dword(&mut dest, j, r);
    }
    dest
}

/// `VPALIGNR` (AVX2, VEX.256), `0 ≤ imm8 ≤ 255`, per 128-bit lane:
///
/// ```text
/// temp1[255:0] := ((SRC1[127:0] << 128) OR SRC2[127:0])>>(imm8*8);
/// DEST[127:0] := temp1[127:0]
/// temp1[255:0] := ((SRC1[255:128] << 128) OR SRC2[255:128])>>(imm8*8);
/// DEST[255:128] := temp1[127:0]
/// ```
///
/// At byte level, lane `L` with `c = SRC2 lane L ++ SRC1 lane L` (32 bytes,
/// `SRC2` low): `r[16L + i] = c[i + imm8]` if `i + imm8 < 32`, else 0.
pub fn vpalignr256(src1: [u8; 32], src2: [u8; 32], imm8: i32) -> [u8; 32] {
    assert!((0..=255).contains(&imm8), "vpalignr: immediate {imm8} out of range 0..=255");
    let shift = imm8 as usize;
    let mut dest = [0u8; 32];
    for lane in 0..2 {
        for i in 0..16 {
            let k = i + shift;
            dest[16 * lane + i] = if k < 16 {
                src2[16 * lane + k]
            } else if k < 32 {
                src1[16 * lane + k - 16]
            } else {
                0
            };
        }
    }
    dest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_and_shifts_at_the_edges() {
        assert_eq!(left_rotate_dwords(0x8000_0001, 0), 0x8000_0001);
        assert_eq!(left_rotate_dwords(0x8000_0001, 1), 0x0000_0003);
        assert_eq!(left_rotate_dwords(0x8000_0001, 33), 0x0000_0003);
        assert_eq!(right_rotate_dwords(0x8000_0001, 1), 0xc000_0000);
        assert_eq!(right_rotate_dwords(1, 32), 1);
        assert_eq!(left_rotate_qwords(1 << 63, 1), 1);
        assert_eq!(right_rotate_qwords(1, 65), 1 << 63);
        assert_eq!(logical_left_shift_dwords1(1, 31), 1 << 31);
        assert_eq!(logical_left_shift_dwords1(1, 32), 0);
        assert_eq!(logical_right_shift_qwords1(u64::MAX, 63), 1);
        assert_eq!(logical_right_shift_qwords1(u64::MAX, 64), 0);
    }

    #[test]
    fn ternlog_known_functions() {
        let a: [u8; 16] = core::array::from_fn(|i| (i * 17) as u8);
        let b: [u8; 16] = core::array::from_fn(|i| (i * 29 + 3) as u8);
        let c: [u8; 16] = core::array::from_fn(|i| (i * 71 + 5) as u8);
        let xor3: [u8; 16] = core::array::from_fn(|i| a[i] ^ b[i] ^ c[i]);
        let ch: [u8; 16] = core::array::from_fn(|i| (a[i] & b[i]) ^ (!a[i] & c[i]));
        let maj: [u8; 16] = core::array::from_fn(|i| (a[i] & b[i]) ^ (a[i] & c[i]) ^ (b[i] & c[i]));
        for f in [vpternlogd::<16>, vpternlogq::<16>] {
            assert_eq!(f(a, b, c, 0x96), xor3);
            assert_eq!(f(a, b, c, 0xca), ch);
            assert_eq!(f(a, b, c, 0xe8), maj);
            assert_eq!(f(a, b, c, 0xf0), a);
            assert_eq!(f(a, b, c, 0xcc), b);
            assert_eq!(f(a, b, c, 0xaa), c);
            assert_eq!(f(a, b, c, 0x00), [0; 16]);
            assert_eq!(f(a, b, c, 0xff), [0xff; 16]);
        }
    }

    #[test]
    fn permutes_and_shuffles() {
        let t: [u8; 64] = core::array::from_fn(|i| i as u8);
        // VPERMD with index j ^ 15 reverses the dwords; bits above 3 ignored.
        let mut idx = [0u8; 64];
        for j in 0..16 {
            set_dword(&mut idx, j, (j as u32 ^ 15) | 0xffff_fff0);
        }
        let r = vpermd(idx, t);
        for j in 0..16 {
            assert_eq!(dword(&r, j), dword(&t, 15 - j));
        }
        // VPSHUFB stays in its 128-bit lane.
        let ctl: [u8; 64] = core::array::from_fn(|j| if j % 16 == 0 { 0x80 } else { 0x7f });
        let r = vpshufb(t, ctl);
        for j in 0..64 {
            assert_eq!(r[j], if j % 16 == 0 { 0 } else { (j & !15) as u8 + 15 });
        }
        // VSHUFI64x2 0x1B reverses the four 128-bit lanes of (src1, src1).
        let r = vshufi64x2(t, t, 0x1b);
        for l in 0..4 {
            assert_eq!(r[16 * l], (16 * (3 - l)) as u8);
        }
        // VPERMI2Q: bit 3 of the index selects the second table.
        let s2: [u8; 64] = core::array::from_fn(|i| 0x80 | i as u8);
        let mut idx = [0u8; 64];
        for j in 0..8 {
            set_qword(&mut idx, j, (j as u64) | if j % 2 == 1 { 8 } else { 0 } | 0xf0);
        }
        let r = vpermi2q(idx, t, s2);
        for j in 0..8 {
            assert_eq!(qword(&r, j), qword(if j % 2 == 1 { &s2 } else { &t }, j));
        }
    }
}
