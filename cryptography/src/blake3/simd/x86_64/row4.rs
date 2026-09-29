//! Four short messages, one per 128-bit group of a 512-bit state row.

use super::{input::load_contiguous, row};
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
    let blocks = len.div_ceil(BLOCK_LEN);

    // SAFETY: AVX-512F is enabled. Input lengths are multiples of 8 and every
    // load offset is a multiple of 16. The loader reads only complete extents.
    unsafe {
        let mut cv = [
            _mm512_broadcast_i32x4(_mm_loadu_si128(IV.as_ptr().cast())),
            _mm512_broadcast_i32x4(_mm_loadu_si128(IV.as_ptr().add(4).cast())),
        ];
        for block in 0..blocks {
            let offset = block * BLOCK_LEN;
            let flags = if block == 0 { CHUNK_START } else { 0 }
                | if block + 1 == blocks {
                    CHUNK_END | ROOT
                } else {
                    0
                };
            let message = core::array::from_fn(|quarter| {
                let offset = offset + 16 * quarter;
                let row = _mm512_castsi128_si512(load_contiguous(inputs[0], offset));
                let row = _mm512_inserti32x4::<1>(row, load_contiguous(inputs[1], offset));
                let row = _mm512_inserti32x4::<2>(row, load_contiguous(inputs[2], offset));
                _mm512_inserti32x4::<3>(row, load_contiguous(inputs[3], offset))
            });
            row::compress::<_, true>(&mut cv, message, (len - offset).min(BLOCK_LEN), flags);
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
