//! Four short messages, one per 128-bit group of a 512-bit state row.

use super::{
    input::{Input, load_contiguous},
    row,
};
use crate::blake3::simd::{CHUNK_END, CHUNK_START, IV, ROOT};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::x86_64::*;

/// Hash four equal-length 40-, 64-, or 72-byte messages.
///
/// # Safety
///
/// The caller must establish AVX-512F availability, and the first input must
/// be 40, 64, or 72 bytes long.
#[target_feature(enable = "avx512f")]
pub(super) unsafe fn hash(inputs: [&[u8]; 4]) -> [[u8; OUT_LEN]; 4] {
    let len = inputs[0].len();
    assert!(
        inputs.iter().all(|input| input.len() == len),
        "BLAKE3 lane inputs must have equal lengths"
    );

    // SAFETY: AVX-512F is enabled and each equal-length input is supported.
    unsafe { hash_inner(len, inputs) }
}

/// Hash four validated messages with the same supported length.
///
/// # Safety
///
/// The caller must establish AVX-512F availability and equal input lengths.
#[target_feature(enable = "avx512f")]
pub(super) unsafe fn hash_parts(inputs: [&Input<'_>; 4]) -> [[u8; OUT_LEN]; 4] {
    // SAFETY: AVX-512F is enabled, Input validates each fragment extent,
    // and the caller establishes equal lengths.
    unsafe { hash_inner(inputs[0].len(), inputs) }
}

/// Four messages whose loads preserve their 128-bit groups.
trait Inputs {
    unsafe fn load(&self, offset: usize) -> __m512i;
}

impl Inputs for [&[u8]; 4] {
    #[inline(always)]
    unsafe fn load(&self, offset: usize) -> __m512i {
        // SAFETY: The caller establishes AVX-512F and supported extents.
        unsafe {
            let row = _mm512_castsi128_si512(load_contiguous(self[0], offset));
            let row = _mm512_inserti32x4::<1>(row, load_contiguous(self[1], offset));
            let row = _mm512_inserti32x4::<2>(row, load_contiguous(self[2], offset));
            _mm512_inserti32x4::<3>(row, load_contiguous(self[3], offset))
        }
    }
}

impl Inputs for [&Input<'_>; 4] {
    #[inline(always)]
    unsafe fn load(&self, offset: usize) -> __m512i {
        // SAFETY: The caller establishes AVX-512F and Input owns fragment extents.
        unsafe {
            let row = _mm512_castsi128_si512(self[0].load(offset));
            let row = _mm512_inserti32x4::<1>(row, self[1].load(offset));
            let row = _mm512_inserti32x4::<2>(row, self[2].load(offset));
            _mm512_inserti32x4::<3>(row, self[3].load(offset))
        }
    }
}

/// Compress and serialize four messages through a validated quarter loader.
#[inline(always)]
unsafe fn hash_inner<I: Inputs>(len: usize, inputs: I) -> [[u8; OUT_LEN]; 4] {
    // SAFETY: The caller establishes AVX-512F and provides a loader valid
    // for every 16-byte quarter in the supported message.
    unsafe {
        let mut cv = [
            _mm512_broadcast_i32x4(_mm_loadu_si128(IV.as_ptr().cast())),
            _mm512_broadcast_i32x4(_mm_loadu_si128(IV.as_ptr().add(4).cast())),
        ];
        let flags = CHUNK_START
            | if len <= BLOCK_LEN {
                CHUNK_END | ROOT
            } else {
                0
            };
        let message = [
            inputs.load(0),
            inputs.load(16),
            inputs.load(32),
            inputs.load(48),
        ];
        row::compress::<_, true>(&mut cv, message, len.min(BLOCK_LEN), flags);
        if len == 72 {
            let tail = _mm512_unpacklo_epi64(inputs.load(BLOCK_LEN), _mm512_setzero_si512());
            row::compress::<_, true>(
                &mut cv,
                [
                    tail,
                    _mm512_setzero_si512(),
                    _mm512_setzero_si512(),
                    _mm512_setzero_si512(),
                ],
                8,
                CHUNK_END | ROOT,
            );
        }
        let mut outputs = [[0; OUT_LEN]; 4];
        macro_rules! store {
            ($lane:literal) => {
                _mm_storeu_si128(
                    outputs[$lane].as_mut_ptr().cast(),
                    _mm512_extracti32x4_epi32::<$lane>(cv[0]),
                );
                _mm_storeu_si128(
                    outputs[$lane].as_mut_ptr().add(16).cast(),
                    _mm512_extracti32x4_epi32::<$lane>(cv[1]),
                );
            };
        }
        store!(0);
        store!(1);
        store!(2);
        store!(3);
        outputs
    }
}
