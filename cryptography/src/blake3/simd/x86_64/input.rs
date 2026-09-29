//! Direct loads for short messages and merkle-node fragments.

use core::arch::x86_64::*;

/// A message whose shape establishes the extents used by its direct loads.
pub(super) struct Input<'a>(Shape<'a>);

enum Shape<'a> {
    Contiguous(&'a [u8]),
    Bmt(&'a [u8], &'a [u8]),
    Leaf(&'a [u8], &'a [u8]),
    Mmr(&'a [u8], &'a [u8], &'a [u8]),
}

impl<'a> Input<'a> {
    /// Message lengths supported by the direct kernels.
    pub(super) const fn supports_len(len: usize) -> bool {
        matches!(len, 40 | 64 | 72)
    }

    /// Recognize contiguous messages or canonical merkle-node fragments.
    pub(super) const fn new(parts: &[&'a [u8]]) -> Option<Self> {
        let shape = match parts {
            [message] if Self::supports_len(message.len()) => Shape::Contiguous(message),
            [a, b] if a.len() == 32 && b.len() == 32 => Shape::Bmt(a, b),
            [position, digest] if position.len() == 8 && digest.len() == 32 => {
                Shape::Leaf(position, digest)
            }
            [position, left, right]
                if position.len() == 8 && left.len() == 32 && right.len() == 32 =>
            {
                Shape::Mmr(position, left, right)
            }
            _ => return None,
        };
        Some(Self(shape))
    }

    pub(super) const fn len(&self) -> usize {
        match self.0 {
            Shape::Contiguous(bytes) => bytes.len(),
            Shape::Bmt(..) => 64,
            Shape::Leaf(..) => 40,
            Shape::Mmr(..) => 72,
        }
    }

    /// Load one 16-byte quarter, zero-padded at the end of the message.
    ///
    /// # Safety
    ///
    /// `offset` must be a multiple of 16.
    #[inline(always)]
    pub(super) unsafe fn load(&self, offset: usize) -> __m128i {
        // SAFETY: Construction validates all fragment extents. Each full load
        // fits its fragment; 8-byte loads zero their upper halves. SSE2 is
        // available on x86_64.
        unsafe {
            match self.0 {
                Shape::Contiguous(input) => load_contiguous(input, offset),
                Shape::Bmt(a, b) => match offset {
                    0 => _mm_loadu_si128(a.as_ptr().cast()),
                    16 => _mm_loadu_si128(a.as_ptr().add(16).cast()),
                    32 => _mm_loadu_si128(b.as_ptr().cast()),
                    48 => _mm_loadu_si128(b.as_ptr().add(16).cast()),
                    _ => _mm_setzero_si128(),
                },
                Shape::Leaf(position, digest) => match offset {
                    0 => _mm_unpacklo_epi64(
                        _mm_loadl_epi64(position.as_ptr().cast()),
                        _mm_loadl_epi64(digest.as_ptr().cast()),
                    ),
                    16 => _mm_loadu_si128(digest.as_ptr().add(8).cast()),
                    32 => _mm_loadl_epi64(digest.as_ptr().add(24).cast()),
                    _ => _mm_setzero_si128(),
                },
                Shape::Mmr(position, left, right) => match offset {
                    0 => _mm_unpacklo_epi64(
                        _mm_loadl_epi64(position.as_ptr().cast()),
                        _mm_loadl_epi64(left.as_ptr().cast()),
                    ),
                    16 => _mm_loadu_si128(left.as_ptr().add(8).cast()),
                    32 => _mm_unpacklo_epi64(
                        _mm_loadl_epi64(left.as_ptr().add(24).cast()),
                        _mm_loadl_epi64(right.as_ptr().cast()),
                    ),
                    48 => _mm_loadu_si128(right.as_ptr().add(8).cast()),
                    64 => _mm_loadl_epi64(right.as_ptr().add(24).cast()),
                    _ => _mm_setzero_si128(),
                },
            }
        }
    }
}

/// Load a 16-byte quarter, zero-padded at the end of a whole-word message.
///
/// # Safety
///
/// The input length must be a multiple of 8, and `offset` a multiple of 16.
#[inline(always)]
pub(super) unsafe fn load_contiguous(input: &[u8], offset: usize) -> __m128i {
    // SAFETY: The remaining length is a multiple of 8. Pointer arithmetic and
    // loads occur only when at least their full width remains in the input.
    unsafe {
        let remaining = input.len().saturating_sub(offset);
        if remaining >= 16 {
            _mm_loadu_si128(input.as_ptr().add(offset).cast())
        } else if remaining >= 8 {
            _mm_loadl_epi64(input.as_ptr().add(offset).cast())
        } else {
            _mm_setzero_si128()
        }
    }
}
