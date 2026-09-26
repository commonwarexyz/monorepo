use super::{
    super::{
        super::{BLOCK_LENGTH, DIGEST_LENGTH, Digest, IV},
        blocks::Blocks,
    },
    K,
    pair::BYTE_SWAP_MASK,
};
use core::{
    arch::{
        asm,
        x86_64::{
            __m128i, _mm_alignr_epi8, _mm_blend_epi16, _mm_load_si128, _mm_loadu_si128,
            _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128,
        },
    },
    mem::MaybeUninit,
};

/// The chaining states of both messages in the SHA-NI register layout: left
/// `abef`, left `cdgh`, right `abef`, right `cdgh`.
type States = [__m128i; 4];

/// Hash two messages of `len` bytes each, given as parts, with interleaved
/// SHA-NI instructions.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
///
/// # Panics
///
/// Panics if either message is shorter than `len` bytes.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_pair_equal(
    left: &[&[u8]],
    right: &[&[u8]],
    len: usize,
) -> (Digest, Digest) {
    let mut left_blocks = Blocks::new(left);
    let mut right_blocks = Blocks::new(right);
    // SAFETY: The caller guarantees every instruction used here is available.
    unsafe {
        let [abef, cdgh] = initial_state();
        let mut states = [abef, cdgh, abef, cdgh];
        for _ in 0..len / BLOCK_LENGTH {
            compress(&mut states, left_blocks.next(), right_blocks.next());
        }
        let (left_padding, blocks) = left_blocks.finish(len);
        let (right_padding, _) = right_blocks.finish(len);
        let left_padding = left_padding.as_chunks::<BLOCK_LENGTH>().0;
        let right_padding = right_padding.as_chunks::<BLOCK_LENGTH>().0;
        compress(&mut states, &left_padding[0], &right_padding[0]);
        if blocks == 2 {
            compress(&mut states, &left_padding[1], &right_padding[1]);
        }
        (store([states[0], states[1]]), store([states[2], states[3]]))
    }
}

/// Compress one block into each message's state.
///
/// The rounds reuse the node kernels' assembly, which schedules them faster
/// than LLVM does for the equivalent intrinsics.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[inline(always)]
unsafe fn compress(states: &mut States, left: &[u8; BLOCK_LENGTH], right: &[u8; BLOCK_LENGTH]) {
    let mut saved = MaybeUninit::<States>::uninit();
    // SAFETY: The caller guarantees every instruction used here is available.
    // The asm reads the two 64-byte blocks, the round-constant table, and the
    // mask, and writes the 16-byte aligned states to `saved` before reading
    // them back. It uses no stack, and every register it writes is declared.
    unsafe {
        asm!(
            include_str!("sha256_pair_macros.asm"),
            "movdqu xmm5, xmmword ptr [{left}]",
            "movdqu xmm6, xmmword ptr [{left} + 16]",
            "movdqu xmm7, xmmword ptr [{left} + 32]",
            "movdqu xmm8, xmmword ptr [{left} + 48]",
            "movdqu xmm9, xmmword ptr [{right}]",
            "movdqu xmm10, xmmword ptr [{right} + 16]",
            "movdqu xmm11, xmmword ptr [{right} + 32]",
            "movdqu xmm12, xmmword ptr [{right} + 48]",
            "pshufb xmm5, xmmword ptr [{mask}]",
            "pshufb xmm6, xmmword ptr [{mask}]",
            "pshufb xmm7, xmmword ptr [{mask}]",
            "pshufb xmm8, xmmword ptr [{mask}]",
            "pshufb xmm9, xmmword ptr [{mask}]",
            "pshufb xmm10, xmmword ptr [{mask}]",
            "pshufb xmm11, xmmword ptr [{mask}]",
            "pshufb xmm12, xmmword ptr [{mask}]",
            "movdqa xmmword ptr [{saved}], xmm1",
            "movdqa xmmword ptr [{saved} + 16], xmm2",
            "movdqa xmmword ptr [{saved} + 32], xmm3",
            "movdqa xmmword ptr [{saved} + 48], xmm4",
            "ROUNDS_64",
            "paddd xmm1, xmmword ptr [{saved}]",
            "paddd xmm2, xmmword ptr [{saved} + 16]",
            "paddd xmm3, xmmword ptr [{saved} + 32]",
            "paddd xmm4, xmmword ptr [{saved} + 48]",
            ".purgem LOAD_STATE",
            ".purgem STORE_DIGEST",
            ".purgem ROUNDS4",
            ".purgem SCHEDULE",
            ".purgem PAIR_ROUNDS4",
            ".purgem ROUNDS_64",
            left = in(reg) left.as_ptr(),
            right = in(reg) right.as_ptr(),
            saved = in(reg) saved.as_mut_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            inout("xmm1") states[0],
            inout("xmm2") states[1],
            inout("xmm3") states[2],
            inout("xmm4") states[3],
            out("xmm0") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _,
            options(nostack),
        );
    }
}

/// Return the initial hash value in the SHA-NI register layout.
///
/// # Safety
///
/// SSSE3 and SSE4.1 must be available.
#[inline(always)]
unsafe fn initial_state() -> [__m128i; 2] {
    // SAFETY: The caller guarantees SSSE3 and SSE4.1 are available, and both
    // loads read within the 8-word initial hash value.
    unsafe {
        let badc = _mm_shuffle_epi32(_mm_loadu_si128(IV.as_ptr().cast()), 0xb1);
        let hgfe = _mm_shuffle_epi32(_mm_loadu_si128(IV.as_ptr().add(4).cast()), 0x1b);
        [
            _mm_alignr_epi8(badc, hgfe, 8),
            _mm_blend_epi16(hgfe, badc, 0xf0),
        ]
    }
}

/// Serialize a state from the SHA-NI register layout as its big-endian
/// digest.
///
/// # Safety
///
/// SSSE3 and SSE4.1 must be available.
#[inline(always)]
unsafe fn store(state: [__m128i; 2]) -> Digest {
    let mut digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The caller guarantees SSSE3 and SSE4.1 are available, the mask
    // table is 16-byte aligned, and both stores write within the 32-byte
    // digest with no alignment requirement.
    unsafe {
        let mask = _mm_load_si128(BYTE_SWAP_MASK.0.as_ptr().cast());
        let abef = _mm_shuffle_epi32(state[0], 0x1b);
        let ghcd = _mm_shuffle_epi32(state[1], 0xb1);
        let abcd = _mm_blend_epi16(abef, ghcd, 0xf0);
        let efgh = _mm_alignr_epi8(ghcd, abef, 8);
        _mm_storeu_si128(digest.as_mut_ptr().cast(), _mm_shuffle_epi8(abcd, mask));
        _mm_storeu_si128(
            digest.as_mut_ptr().add(16).cast(),
            _mm_shuffle_epi8(efgh, mask),
        );
    }
    Digest(digest)
}
