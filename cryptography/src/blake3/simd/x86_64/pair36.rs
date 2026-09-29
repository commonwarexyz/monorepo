//! Direct pair loading for a four-byte position followed by a digest.

use super::row;
use crate::blake3::simd::{CHUNK_END, CHUNK_START, IV, ROOT};
use blake3::OUT_LEN;
use core::arch::x86_64::*;

/// Validated fragments of one 36-byte message.
pub(super) struct Input<'a> {
    position: &'a [u8; 4],
    digest: &'a [u8; 32],
}

impl<'a> Input<'a> {
    #[inline]
    pub(super) fn new(parts: &[&'a [u8]]) -> Option<Self> {
        let (position, digest) = match parts {
            [message] if message.len() == 36 => message.split_at(4),
            [position, digest] => (*position, *digest),
            _ => return None,
        };
        Some(Self {
            position: position.try_into().ok()?,
            digest: digest.try_into().ok()?,
        })
    }

    /// Load the message into three zero-padded rows.
    #[inline(always)]
    fn rows(&self) -> [__m128i; 3] {
        // SAFETY: SSE2 is available on x86-64. The scalar loads read the
        // four-byte position and digest bytes 28..32. The vector loads read
        // digest bytes 0..16 and 12..28, all within validated arrays.
        unsafe {
            [
                _mm_or_si128(
                    _mm_cvtsi32_si128(self.position.as_ptr().cast::<i32>().read_unaligned()),
                    _mm_slli_si128::<4>(_mm_loadu_si128(self.digest.as_ptr().cast())),
                ),
                _mm_loadu_si128(self.digest.as_ptr().add(12).cast()),
                _mm_cvtsi32_si128(self.digest.as_ptr().add(28).cast::<i32>().read_unaligned()),
            ]
        }
    }
}

/// Hash two validated 36-byte messages with native packed rotates.
///
/// # Safety
///
/// The caller must establish AVX2, AVX-512F, and AVX-512VL availability.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
pub(super) unsafe fn hash(left: &Input<'_>, right: &Input<'_>) -> [[u8; OUT_LEN]; 2] {
    let left = left.rows();
    let right = right.rows();

    // SAFETY: The required features are enabled. The IV loads each read four
    // words of its eight-word array, and each output store fills 32 bytes.
    unsafe {
        let mut cv = [
            _mm256_broadcastsi128_si256(_mm_loadu_si128(IV.as_ptr().cast())),
            _mm256_broadcastsi128_si256(_mm_loadu_si128(IV.as_ptr().add(4).cast())),
        ];
        let message = [
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(left[0]), right[0]),
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(left[1]), right[1]),
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(left[2]), right[2]),
            _mm256_setzero_si256(),
        ];
        row::compress::<_, true>(&mut cv, message, 36, CHUNK_START | CHUNK_END | ROOT);
        let mut outputs = [[0; OUT_LEN]; 2];
        _mm256_storeu_si256(
            outputs[0].as_mut_ptr().cast(),
            _mm256_permute2x128_si256::<0x20>(cv[0], cv[1]),
        );
        _mm256_storeu_si256(
            outputs[1].as_mut_ptr().cast(),
            _mm256_permute2x128_si256::<0x31>(cv[0], cv[1]),
        );
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(len: usize, offset: usize, seed: u8) -> Box<[u8]> {
        (0..len + offset)
            .map(|i| seed.wrapping_add((i as u8).wrapping_mul(37)))
            .collect()
    }

    #[test]
    fn exact_extents_and_alignment() {
        for position_offset in 0..32 {
            for digest_offset in 0..32 {
                let position = bytes(4, position_offset, 19);
                let digest = bytes(32, digest_offset, 83);
                let position = &position[position_offset..];
                let digest = &digest[digest_offset..];
                let input = Input::new(&[position, digest]).unwrap();
                let mut actual = [0u8; 48];
                for (i, row) in input.rows().into_iter().enumerate() {
                    // SAFETY: SSE2 is available and each store fills its
                    // distinct 16-byte section of the output array.
                    unsafe { _mm_storeu_si128(actual.as_mut_ptr().add(i * 16).cast(), row) };
                }
                assert_eq!(&actual[..4], position);
                assert_eq!(&actual[4..36], digest);
                assert_eq!(&actual[36..], &[0; 12]);
            }
        }
        for len in 0..=129 {
            let message = bytes(len, 0, 41);
            assert_eq!(Input::new(&[&message]).is_some(), len == 36);
            for split in 0..=len {
                assert_eq!(
                    Input::new(&[&message[..split], &message[split..]]).is_some(),
                    len == 36 && split == 4
                );
            }
        }
        assert!(Input::new(&[]).is_none());
        assert!(Input::new(&[&[0; 4], &[], &[0; 32]]).is_none());
    }

    #[test]
    fn direct_pair_oracle() {
        let available = std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512vl");
        if cfg!(miri) {
            assert!(available, "enable AVX2/F/VL so Miri executes the pair body");
        }
        if !available {
            return;
        }
        for offset in 0..32 {
            let contiguous = bytes(36, offset, 3);
            let position = bytes(4, 31 - offset, 103);
            let digest = bytes(32, offset, 149);
            let contiguous = &contiguous[offset..];
            let position = &position[31 - offset..];
            let digest = &digest[offset..];
            let formats: [&[&[u8]]; 3] = [
                &[contiguous],
                &[position, digest],
                &[&contiguous[..4], &contiguous[4..]],
            ];
            for left in formats {
                for right in formats {
                    let expected = [left, right].map(|parts| {
                        let mut hasher = ::blake3::Hasher::new();
                        for part in parts {
                            hasher.update(part);
                        }
                        *hasher.finalize().as_bytes()
                    });
                    let left = Input::new(left).unwrap();
                    let right = Input::new(right).unwrap();
                    // SAFETY: The required features were checked above.
                    assert_eq!(unsafe { hash(&left, &right) }, expected);
                }
            }
        }
    }
}
