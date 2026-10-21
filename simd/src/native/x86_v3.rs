//! Native implementation of the common instructions with x86-64-v3 (AVX2).

use super::{
    partial::{load_below_8, store_below_8},
    x86_u32x4,
};
use crate::{Operation, Simd};
use core::arch::x86_64::*;

/// Native x86-64-v3 execution token with 32 byte, eight u32, and four u64 lanes.
///
/// Implements only the common [`Simd`] instructions with 256-bit AVX2 vectors and
/// exposes no instruction profile: [`Simd::execute`] runs [`Operation::portable`]
/// within an AVX2 target-feature scope. Construction checks AVX2, which implies the
/// SSE levels used by the fixed four-word instructions; it does not check the other
/// x86-64-v3 features. Copies preserve the feature guarantee. No CPU vendor or model
/// is required.
#[derive(Clone, Copy, Debug)]
pub struct NativeX86V3(());

impl NativeX86V3 {
    /// Returns a token if AVX2 is available.
    ///
    /// With `std`, checks the current CPU and operating system's vector support.
    /// Without `std`, requires AVX2 to be enabled at compile time.
    pub fn new() -> Option<Self> {
        #[cfg(feature = "std")]
        let supported = std::arch::is_x86_feature_detected!("avx2");
        #[cfg(not(feature = "std"))]
        let supported = cfg!(target_feature = "avx2");
        supported.then_some(Self(()))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn execute_x86_v3<O: Operation<Self>>(self, operation: O) -> O::Output {
        operation.portable(self)
    }
}

const _: () = crate::core::assert_lane_relation::<NativeX86V3>();

impl Simd for NativeX86V3 {
    type U32x4 = __m128i;

    #[inline]
    fn u32x4_load(self, input: &[u32]) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::load(input) }
    }

    #[inline]
    fn u32x4_store(self, value: __m128i, output: &mut [u32]) {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::store(value, output) }
    }

    #[inline]
    fn u32x4_add(self, a: __m128i, b: __m128i) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::add(a, b) }
    }

    #[inline]
    fn u32x4_shuffle<const MASK: i32>(self, value: __m128i) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::shuffle::<MASK>(value) }
    }

    #[inline]
    fn u32x4_load_be(self, input: &[u8]) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::load_be(input) }
    }

    #[inline]
    fn u32x4_load_be2(self, input: &[u8]) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::load_be2(input) }
    }

    #[inline]
    fn u32x4_store_be(self, value: __m128i, output: &mut [u8]) {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::store_be(value, output) }
    }

    #[inline]
    fn u32x4_align<const N: i32>(self, a: __m128i, b: __m128i) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::align::<N>(a, b) }
    }

    #[inline]
    fn u32x4_blend<const MASK: i32>(self, a: __m128i, b: __m128i) -> __m128i {
        // SAFETY: Token construction established the entry's required features.
        unsafe { x86_u32x4::blend::<MASK>(a, b) }
    }

    type U8 = __m256i;
    type U32 = __m256i;
    type U64 = __m256i;
    const U8_LANES: usize = 32;
    const U32_LANES: usize = 8;
    const U64_LANES: usize = 4;

    #[inline]
    fn u8_load(self, input: &[u8]) -> __m256i {
        assert!(input.len() >= 32);
        // SAFETY: The token guarantees AVX2 and the slice has 32 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm256_loadu_si256(input.as_ptr().cast()) }
    }

    #[inline]
    fn u8_store(self, value: __m256i, output: &mut [u8]) {
        assert!(output.len() >= 32);
        // SAFETY: The token guarantees AVX2 and the slice has 32 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm256_storeu_si256(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u8_splat(self, value: u8) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_set1_epi8(value as i8) }
    }

    #[inline]
    fn u8_xor(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_xor_si256(a, b) }
    }

    #[inline]
    fn u8_load_partial(self, input: &[u8]) -> __m256i {
        assert!(input.len() <= 32);
        if let Some(full) = input.first_chunk::<32>() {
            // SAFETY: The token guarantees AVX2, and the chunk has 32 readable bytes.
            // The load accepts unaligned memory.
            return unsafe { _mm256_loadu_si256(full.as_ptr().cast()) };
        }
        // Bits 3 and 4 of the length select the whole little-endian words, and bits 0
        // to 2 select the exact reads assembling the next word. Each byte is read once.
        let (words, tail) = input.as_chunks::<8>();
        let tail = load_below_8(tail);
        let (w0, w1, w2, w3) = match *words {
            [] => (tail, 0, 0, 0),
            [a] => (u64::from_le_bytes(a), tail, 0, 0),
            [a, b] => (u64::from_le_bytes(a), u64::from_le_bytes(b), tail, 0),
            [a, b, c] => (
                u64::from_le_bytes(a),
                u64::from_le_bytes(b),
                u64::from_le_bytes(c),
                tail,
            ),
            _ => unreachable!("fewer than 32 bytes form at most three whole words"),
        };
        // Byte k of little-endian word j becomes byte lane 8*j+k.
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_set_epi64x(w3 as i64, w2 as i64, w1 as i64, w0 as i64) }
    }

    #[inline]
    fn u8_store_partial(self, value: __m256i, output: &mut [u8]) {
        assert!(output.len() <= 32);
        if let Some(full) = output.first_chunk_mut::<32>() {
            // SAFETY: The token guarantees AVX2, and the chunk has 32 writable bytes.
            // The store accepts unaligned memory.
            unsafe { _mm256_storeu_si256(full.as_mut_ptr().cast(), value) };
            return;
        }
        // Byte lane 8*j+k becomes byte k of little-endian word j.
        // SAFETY: Token construction established AVX2 support.
        let (w0, w1, w2, w3) = unsafe {
            (
                _mm256_extract_epi64::<0>(value) as u64,
                _mm256_extract_epi64::<1>(value) as u64,
                _mm256_extract_epi64::<2>(value) as u64,
                _mm256_extract_epi64::<3>(value) as u64,
            )
        };
        // Whole words and the exact tail writes cover the output once, and nothing beyond it.
        let (words, tail) = output.as_chunks_mut::<8>();
        match words {
            [] => store_below_8(w0, tail),
            [a] => {
                *a = w0.to_le_bytes();
                store_below_8(w1, tail);
            }
            [a, b] => {
                *a = w0.to_le_bytes();
                *b = w1.to_le_bytes();
                store_below_8(w2, tail);
            }
            [a, b, c] => {
                *a = w0.to_le_bytes();
                *b = w1.to_le_bytes();
                *c = w2.to_le_bytes();
                store_below_8(w3, tail);
            }
            _ => unreachable!("fewer than 32 bytes form at most three whole words"),
        }
    }

    #[inline]
    fn u8_and(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_and_si256(a, b) }
    }

    type U8Table = __m256i;

    #[inline]
    fn u8_table_load(self, table: &[u8; 16]) -> __m256i {
        // SAFETY: The token guarantees AVX2. The table holds 16 readable bytes, and the
        // load accepts unaligned memory. The broadcast copies it into both 128-bit lanes.
        unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(table.as_ptr().cast())) }
    }

    #[inline]
    fn u8_table_lookup(self, table: __m256i, indices: __m256i) -> __m256i {
        // Saturating addition of 0x70 maps indices 0..16 to 0x70..0x80, preserving the low
        // nibble with the top bit clear, and maps 16..256 to 0x80..=0xff, which VPSHUFB zeroes.
        // Both 128-bit lanes hold the full table, so the lane-local shuffle is a full lookup.
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_shuffle_epi8(table, _mm256_adds_epu8(indices, _mm256_set1_epi8(0x70))) }
    }

    #[inline]
    fn u8_or(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_or_si256(a, b) }
    }

    #[inline]
    fn u8_add(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_add_epi8(a, b) }
    }

    #[inline]
    fn u8_sub(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_sub_epi8(a, b) }
    }

    #[inline]
    fn u8_add_saturating(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_adds_epu8(a, b) }
    }

    #[inline]
    fn u8_sub_saturating(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_subs_epu8(a, b) }
    }

    #[inline]
    fn u8_min(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_min_epu8(a, b) }
    }

    #[inline]
    fn u8_max(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_max_epu8(a, b) }
    }

    #[inline]
    fn u8_eq(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_cmpeq_epi8(a, b) }
    }

    #[inline]
    fn u8_gt(self, a: __m256i, b: __m256i) -> __m256i {
        // AVX2 compares bytes as signed values only. min(a, b) = a exactly when a <= b,
        // so the complement of that unsigned comparison is a > b.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_xor_si256(
                _mm256_cmpeq_epi8(_mm256_min_epu8(a, b), a),
                _mm256_set1_epi8(-1),
            )
        }
    }

    #[inline]
    fn u8_movemask(self, value: __m256i) -> u64 {
        // VPMOVMSKB sets bit i of the 32-bit result to bit 7 of byte i; the upper bits are zero.
        // SAFETY: Token construction established AVX2 support.
        unsafe { u64::from(_mm256_movemask_epi8(value) as u32) }
    }

    #[inline]
    fn u8_any(self, value: __m256i) -> bool {
        // SAFETY: Token construction established AVX2 support, which implies AVX.
        unsafe { _mm256_testz_si256(value, value) == 0 }
    }

    #[inline]
    fn u8_all(self, value: __m256i) -> bool {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_movemask_epi8(_mm256_cmpeq_epi8(value, _mm256_setzero_si256())) == 0 }
    }

    // Split z into 16-byte chunks z[16*k..16*k+16] = Zk. VPUNPCKLBW interleaves the low
    // halves of each 128-bit lane, yielding [Z0, Z2], and VPUNPCKHBW the high halves,
    // yielding [Z1, Z3]. VPERM2I128 then selects zip_lo = [Z0, Z1] as lane 0 of each
    // (immediate 0x20) and zip_hi = [Z2, Z3] as lane 1 of each (immediate 0x31).
    #[inline]
    fn u8_zip_lo(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_permute2x128_si256::<0x20>(
                _mm256_unpacklo_epi8(a, b),
                _mm256_unpackhi_epi8(a, b),
            )
        }
    }

    #[inline]
    fn u8_zip_hi(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_permute2x128_si256::<0x31>(
                _mm256_unpacklo_epi8(a, b),
                _mm256_unpackhi_epi8(a, b),
            )
        }
    }

    // Byte 2k of a vector is the low byte of word k and byte 2k+1 is its high byte. After
    // isolating the selected byte in each word, VPACKUSWB packs 128-bit lane g of a into
    // qword 2g and lane g of b into qword 2g+1; values below 256 are unchanged by
    // saturation. The packed qwords are [a0, b0, a1, b1], and the output needs
    // [a0, a1, b0, b1], so output qword k is packed qword [0, 2, 1, 3][k]: VPERMQ with
    // immediate 0 | 2 << 2 | 1 << 4 | 3 << 6 = 0xd8.
    #[inline]
    fn u8_unzip_even(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            let low = _mm256_set1_epi16(0x00ff);
            _mm256_permute4x64_epi64::<0xd8>(_mm256_packus_epi16(
                _mm256_and_si256(a, low),
                _mm256_and_si256(b, low),
            ))
        }
    }

    #[inline]
    fn u8_unzip_odd(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_permute4x64_epi64::<0xd8>(_mm256_packus_epi16(
                _mm256_srli_epi16::<8>(a),
                _mm256_srli_epi16::<8>(b),
            ))
        }
    }

    #[inline]
    fn u8_shl<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 8);
        // Word shifts move bits across the byte boundary; the mask clears them.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_and_si256(
                _mm256_sll_epi16(value, _mm_cvtsi32_si128(N as i32)),
                _mm256_set1_epi8((0xffu8 << N) as i8),
            )
        }
    }

    #[inline]
    fn u8_shr<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 8);
        // Word shifts move bits across the byte boundary; the mask clears them.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_and_si256(
                _mm256_srl_epi16(value, _mm_cvtsi32_si128(N as i32)),
                _mm256_set1_epi8((0xffu8 >> N) as i8),
            )
        }
    }

    #[inline]
    fn u8_xor_fold(self, value: __m256i) -> u8 {
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            let value = _mm_xor_si128(
                _mm256_castsi256_si128(value),
                _mm256_extracti128_si256::<1>(value),
            );
            let value = _mm_xor_si128(value, _mm_srli_si128::<8>(value));
            let value = _mm_xor_si128(value, _mm_srli_si128::<4>(value));
            let value = _mm_xor_si128(value, _mm_srli_si128::<2>(value));
            let value = _mm_xor_si128(value, _mm_srli_si128::<1>(value));
            _mm_cvtsi128_si32(value) as u8
        }
    }

    #[inline]
    fn u32_load(self, input: &[u32]) -> __m256i {
        assert!(input.len() >= 8);
        // SAFETY: The token guarantees AVX2 and the slice has 32 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm256_loadu_si256(input.as_ptr().cast()) }
    }

    #[inline]
    fn u32_store(self, value: __m256i, output: &mut [u32]) {
        assert!(output.len() >= 8);
        // SAFETY: The token guarantees AVX2 and the slice has 32 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm256_storeu_si256(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u32_splat(self, value: u32) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_set1_epi32(value as i32) }
    }

    #[inline]
    fn u32_xor(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_xor_si256(a, b) }
    }

    #[inline]
    fn u32_add(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline]
    fn u32_rotate_right<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 32);
        // VPSLLVD zeroes lanes whose count exceeds 31, so N = 0 leaves the value unchanged.
        // LLVM folds the constant counts into immediate shifts.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_or_si256(
                _mm256_srlv_epi32(value, _mm256_set1_epi32(N as i32)),
                _mm256_sllv_epi32(value, _mm256_set1_epi32((32 - N) as i32)),
            )
        }
    }

    #[inline]
    fn u32_sub(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_sub_epi32(a, b) }
    }

    #[inline]
    fn u32_and(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_and_si256(a, b) }
    }

    #[inline]
    fn u32_or(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_or_si256(a, b) }
    }

    #[inline]
    fn u32_shl<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 32);
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_sllv_epi32(value, _mm256_set1_epi32(N as i32)) }
    }

    #[inline]
    fn u32_shr<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 32);
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_srlv_epi32(value, _mm256_set1_epi32(N as i32)) }
    }

    #[inline]
    fn u32_select(self, mask: __m256i, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_or_si256(_mm256_and_si256(mask, a), _mm256_andnot_si256(mask, b)) }
    }

    #[inline]
    fn u32_permute(self, value: __m256i, indices: __m256i) -> __m256i {
        // SAFETY: The token guarantees AVX2. VPERMD reads only the low 3 bits of each
        // index lane, which reduces it modulo 8.
        unsafe { _mm256_permutevar8x32_epi32(value, indices) }
    }

    #[inline]
    fn u32_permute2(self, a: __m256i, b: __m256i, indices: __m256i) -> __m256i {
        // Each VPERMD reads the low 3 bits of an index. Bit 3 then selects b, which with
        // the ignored higher bits reduces the index modulo 16. Shifting bit 3 to bit 31 and
        // arithmetically back fills its lane with the selection mask for VPBLENDVB.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            let select_b = _mm256_srai_epi32::<31>(_mm256_slli_epi32::<28>(indices));
            _mm256_blendv_epi8(
                _mm256_permutevar8x32_epi32(a, indices),
                _mm256_permutevar8x32_epi32(b, indices),
                select_b,
            )
        }
    }

    #[inline]
    fn u64_load(self, input: &[u64]) -> __m256i {
        assert!(input.len() >= 4);
        // SAFETY: The token guarantees AVX2 and the slice has 32 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm256_loadu_si256(input.as_ptr().cast()) }
    }

    #[inline]
    fn u64_store(self, value: __m256i, output: &mut [u64]) {
        assert!(output.len() >= 4);
        // SAFETY: The token guarantees AVX2 and the slice has 32 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm256_storeu_si256(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u64_splat(self, value: u64) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_set1_epi64x(value as i64) }
    }

    #[inline]
    fn u64_add(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_add_epi64(a, b) }
    }

    #[inline]
    fn u64_shl<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 64);
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_sllv_epi64(value, _mm256_set1_epi64x(N as i64)) }
    }

    #[inline]
    fn u64_shr<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 64);
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_srlv_epi64(value, _mm256_set1_epi64x(N as i64)) }
    }

    #[inline]
    fn u64_and(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_and_si256(a, b) }
    }

    #[inline]
    fn u64_or(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_or_si256(a, b) }
    }

    #[inline]
    fn u64_sub(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_sub_epi64(a, b) }
    }

    #[inline]
    fn u64_xor(self, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_xor_si256(a, b) }
    }

    #[inline]
    fn u64_rotate_left<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 64);
        // VPSRLVQ zeroes lanes whose count exceeds 63, so N = 0 leaves the value unchanged.
        // LLVM folds the constant counts into immediate shifts.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_or_si256(
                _mm256_sllv_epi64(value, _mm256_set1_epi64x(N as i64)),
                _mm256_srlv_epi64(value, _mm256_set1_epi64x((64 - N) as i64)),
            )
        }
    }

    #[inline]
    fn u64_rotate_right<const N: u32>(self, value: __m256i) -> __m256i {
        assert!(N < 64);
        // VPSLLVQ zeroes lanes whose count exceeds 63, so N = 0 leaves the value unchanged.
        // LLVM folds the constant counts into immediate shifts.
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            _mm256_or_si256(
                _mm256_srlv_epi64(value, _mm256_set1_epi64x(N as i64)),
                _mm256_sllv_epi64(value, _mm256_set1_epi64x((64 - N) as i64)),
            )
        }
    }

    #[inline]
    fn u64_andnot(self, a: __m256i, b: __m256i) -> __m256i {
        // VPANDN complements its first operand.
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_andnot_si256(b, a) }
    }

    #[inline]
    fn u64_xor3(self, a: __m256i, b: __m256i, c: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_xor_si256(_mm256_xor_si256(a, b), c) }
    }

    #[inline]
    fn u64_select(self, mask: __m256i, a: __m256i, b: __m256i) -> __m256i {
        // SAFETY: Token construction established AVX2 support.
        unsafe { _mm256_or_si256(_mm256_and_si256(mask, a), _mm256_andnot_si256(mask, b)) }
    }

    #[inline]
    fn u64_extract<const N: usize>(self, value: __m256i) -> u64 {
        assert!(N < 4);
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            match N {
                0 => _mm256_extract_epi64::<0>(value) as u64,
                1 => _mm256_extract_epi64::<1>(value) as u64,
                2 => _mm256_extract_epi64::<2>(value) as u64,
                3 => _mm256_extract_epi64::<3>(value) as u64,
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    fn u64_insert<const N: usize>(self, value: __m256i, lane: u64) -> __m256i {
        assert!(N < 4);
        let lane = lane as i64;
        // SAFETY: Token construction established AVX2 support.
        unsafe {
            match N {
                0 => _mm256_insert_epi64::<0>(value, lane),
                1 => _mm256_insert_epi64::<1>(value, lane),
                2 => _mm256_insert_epi64::<2>(value, lane),
                3 => _mm256_insert_epi64::<3>(value, lane),
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    fn u8_as_u32(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn u32_as_u8(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn u8_as_u64(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn u64_as_u8(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn u32_as_u64(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn u64_as_u32(self, value: __m256i) -> __m256i {
        value
    }

    #[inline]
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output {
        // SAFETY: Token construction established every feature enabled by this entry.
        unsafe { self.execute_x86_v3(operation) }
    }
}

#[cfg(test)]
mod tests {
    use super::NativeX86V3;
    use crate::Simd;

    #[test]
    fn test_partial_every_alignment_and_length() {
        let Some(native) = NativeX86V3::new() else {
            std::eprintln!("skipping native x86-64-v3 partial: AVX2 is unavailable");
            return;
        };
        let source: [u8; 32] = core::array::from_fn(|i| (i as u8 + 1).wrapping_mul(0x1d) ^ 0x80);
        let value = native.u8_load(&source);
        for start in 0..32 {
            for len in 0..=32 {
                // Nonzero sentinels expose any read or write outside the slice.
                let mut memory = [0xa5u8; 96];
                memory[start..start + len].copy_from_slice(&source[..len]);
                let loaded = native.u8_load_partial(&memory[start..start + len]);
                let mut lanes = [0xffu8; 32];
                native.u8_store(loaded, &mut lanes);
                let mut expected = [0u8; 32];
                expected[..len].copy_from_slice(&source[..len]);
                assert_eq!(lanes, expected, "load start={start} len={len}");

                let mut stored = [0xa5u8; 96];
                native.u8_store_partial(value, &mut stored[start..start + len]);
                let mut expected = [0xa5u8; 96];
                expected[start..start + len].copy_from_slice(&source[..len]);
                assert_eq!(stored, expected, "store start={start} len={len}");
            }
        }
    }
}
