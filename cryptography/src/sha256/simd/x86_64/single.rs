//! Single-message SHA-NI kernels for the merkle shapes, each loading its
//! message parts directly into vector registers and returning the chaining
//! state in registers.

use super::{
    super::{BMT_LEAF_LEN, BMT_POSITION_LEN, MMR_LEAF_LEN, POSITION_LEN},
    Align16, K,
    pair::{BYTE_SWAP_MASK, FINAL_64_WK, FINAL_72_LENGTH, TAIL_8_PAD},
};
use crate::sha256::{DIGEST_LENGTH, Digest, IV};
use core::arch::x86_64::{
    __m128i, _mm_alignr_epi8, _mm_blend_epi16, _mm_load_si128, _mm_shuffle_epi8, _mm_shuffle_epi32,
    _mm_storeu_si128,
};

/// The `0x80` terminator following the message's last 4 bytes in a vector.
static TAIL_4_PAD: Align16<[u32; 4]> = Align16([0, 0x80000000, 0, 0]);

/// The message bit length in the final words of the MMR leaf's block.
static FINAL_40_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, (MMR_LEAF_LEN * 8) as u32]);

/// The message bit length in the final words of the BMT leaf's block.
static FINAL_36_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, (BMT_LEAF_LEN * 8) as u32]);

/// Serialize the chaining state a kernel returns, as its `ABEF` and `CDGH`
/// words, into a digest.
///
/// The digest is stored here so that the compiler sees the stores and can
/// place them where the caller reads the digest.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
#[inline]
unsafe fn serialize(abef: __m128i, cdgh: __m128i) -> Digest {
    let mut output = [0u8; DIGEST_LENGTH];
    // SAFETY: The mask is 16-byte aligned and both stores stay within `output`.
    unsafe {
        let mask = _mm_load_si128(BYTE_SWAP_MASK.0.as_ptr().cast());
        let feba = _mm_shuffle_epi32(abef, 27);
        let dchg = _mm_shuffle_epi32(cdgh, 177);
        let dcba = _mm_blend_epi16(feba, dchg, 240);
        let hgfe = _mm_alignr_epi8(dchg, feba, 8);
        _mm_storeu_si128(output.as_mut_ptr().cast(), _mm_shuffle_epi8(dcba, mask));
        _mm_storeu_si128(
            output.as_mut_ptr().add(16).cast(),
            _mm_shuffle_epi8(hgfe, mask),
        );
    }
    Digest(output)
}

/// Hash one MMR node-shaped message (`position || left || right`, 72 bytes)
/// with SHA-NI instructions, as one full block plus a fixed-layout padding
/// block.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_72(
    pos: &[u8; POSITION_LEN],
    left: &[u8; DIGEST_LENGTH],
    right: &[u8; DIGEST_LENGTH],
) -> Digest {
    let abef: __m128i;
    let cdgh: __m128i;
    // SAFETY: The inputs are properly sized buffers, the caller guarantees
    // every instruction used here is available, and all registers written by
    // the asm are listed as outputs. Every table read with an aligned load is
    // 16-byte aligned, every load stays in bounds, and the asm neither uses
    // the stack nor writes memory.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_single_macros.asm"),
            // See `hash_pair_72` for why the upper halves are cleared.
            "vzeroupper",
            include_str!("sha256_single_72.asm"),
            include_str!("sha256_single_finish.asm"),
            pos = in(reg) pos.as_ptr(),
            left = in(reg) left.as_ptr(),
            right = in(reg) right.as_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            pad = in(reg) TAIL_8_PAD.0.as_ptr(),
            len = in(reg) FINAL_72_LENGTH.0.as_ptr(),
            out("xmm0") _, out("xmm1") abef, out("xmm2") cdgh, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
    // SAFETY: The caller guarantees the target features.
    unsafe { serialize(abef, cdgh) }
}

/// Hash one BMT node-shaped message (`left || right`, 64 bytes) with SHA-NI
/// instructions, as one full block plus a compile-time constant padding block.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_64(
    left: &[u8; DIGEST_LENGTH],
    right: &[u8; DIGEST_LENGTH],
) -> Digest {
    let abef: __m128i;
    let cdgh: __m128i;
    // SAFETY: The inputs are properly sized buffers, the caller guarantees
    // every instruction used here is available, and all registers written by
    // the asm are listed as outputs. Every table read with an aligned load is
    // 16-byte aligned, every load stays in bounds, and the asm neither uses
    // the stack nor writes memory.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_single_macros.asm"),
            // See `hash_pair_72` for why the upper halves are cleared.
            "vzeroupper",
            include_str!("sha256_single_64.asm"),
            include_str!("sha256_single_finish.asm"),
            left = in(reg) left.as_ptr(),
            right = in(reg) right.as_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            fixed_wk = in(reg) FINAL_64_WK.0.as_ptr(),
            out("xmm0") _, out("xmm1") abef, out("xmm2") cdgh, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
    // SAFETY: The caller guarantees the target features.
    unsafe { serialize(abef, cdgh) }
}

/// Hash one MMR leaf-shaped message (`position || digest`, 40 bytes) with
/// SHA-NI instructions, as a single block that ends in fixed-layout padding.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_40(
    pos: &[u8; POSITION_LEN],
    digest: &[u8; DIGEST_LENGTH],
) -> Digest {
    let abef: __m128i;
    let cdgh: __m128i;
    // SAFETY: The inputs are properly sized buffers, the caller guarantees
    // every instruction used here is available, and all registers written by
    // the asm are listed as outputs. Every table read with an aligned load is
    // 16-byte aligned, every load stays in bounds, and the asm neither uses
    // the stack nor writes memory.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_single_macros.asm"),
            // See `hash_pair_72` for why the upper halves are cleared.
            "vzeroupper",
            include_str!("sha256_single_40.asm"),
            include_str!("sha256_single_finish.asm"),
            pos = in(reg) pos.as_ptr(),
            digest = in(reg) digest.as_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            pad = in(reg) TAIL_8_PAD.0.as_ptr(),
            len = in(reg) FINAL_40_LENGTH.0.as_ptr(),
            out("xmm0") _, out("xmm1") abef, out("xmm2") cdgh, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
    // SAFETY: The caller guarantees the target features.
    unsafe { serialize(abef, cdgh) }
}

/// Hash one BMT leaf-shaped message (`position || digest`, 36 bytes) with
/// SHA-NI instructions, as a single block that ends in fixed-layout padding.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_36(
    pos: &[u8; BMT_POSITION_LEN],
    digest: &[u8; DIGEST_LENGTH],
) -> Digest {
    let abef: __m128i;
    let cdgh: __m128i;
    // SAFETY: The inputs are properly sized buffers, the caller guarantees
    // every instruction used here is available, and all registers written by
    // the asm are listed as outputs. Every table read with an aligned load is
    // 16-byte aligned, every load stays in bounds, and the asm neither uses
    // the stack nor writes memory.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_single_macros.asm"),
            // See `hash_pair_72` for why the upper halves are cleared.
            "vzeroupper",
            include_str!("sha256_single_36.asm"),
            include_str!("sha256_single_finish.asm"),
            pos = in(reg) pos.as_ptr(),
            digest = in(reg) digest.as_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            pad = in(reg) TAIL_4_PAD.0.as_ptr(),
            len = in(reg) FINAL_36_LENGTH.0.as_ptr(),
            out("xmm0") _, out("xmm1") abef, out("xmm2") cdgh, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
    // SAFETY: The caller guarantees the target features.
    unsafe { serialize(abef, cdgh) }
}
