//! Native implementation of the x86v4c instruction profile.

use super::x86_u32x4;
use crate::{Operation, Simd, X86V4C};
use core::arch::x86_64::*;

/// Native x86v4c execution token with 64 byte, 16 u32, and eight u64 lanes.
///
/// Construction checks AVX-512F, AVX-512BW, GFNI, AVX-512IFMA, and SHA. AVX-512BW
/// supplies byte-masked memory operations, byte shuffles, and word shifts used
/// to implement independent byte shifts. Copies preserve the feature guarantee.
/// No CPU vendor or model is required.
#[derive(Clone, Copy, Debug)]
pub struct NativeX86V4C(());

impl NativeX86V4C {
    /// Returns a token if all required instruction features are available.
    ///
    /// With `std`, checks the current CPU and operating system's vector support.
    /// Without `std`, requires all features to be enabled at compile time.
    pub fn new() -> Option<Self> {
        #[cfg(feature = "std")]
        let supported = std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("gfni")
            && std::arch::is_x86_feature_detected!("avx512ifma")
            && std::arch::is_x86_feature_detected!("sha");
        #[cfg(not(feature = "std"))]
        let supported = cfg!(target_feature = "avx512f")
            && cfg!(target_feature = "avx512bw")
            && cfg!(target_feature = "gfni")
            && cfg!(target_feature = "avx512ifma")
            && cfg!(target_feature = "sha");
        supported.then_some(Self(()))
    }

    #[inline]
    #[target_feature(enable = "avx512f,avx512bw,gfni,avx512ifma,sha")]
    unsafe fn execute_x86_v4c<O: Operation<Self>>(self, operation: O) -> O::Output {
        operation.x86_v4c(self)
    }
}

const _: () = crate::core::assert_lane_relation::<NativeX86V4C>();

impl Simd for NativeX86V4C {
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

    type U8 = __m512i;
    type U32 = __m512i;
    type U64 = __m512i;
    const U8_LANES: usize = 64;
    const U32_LANES: usize = 16;
    const U64_LANES: usize = 8;

    #[inline]
    fn u8_load(self, input: &[u8]) -> __m512i {
        assert!(input.len() >= 64);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm512_loadu_si512(input.as_ptr().cast()) }
    }

    #[inline]
    fn u8_store(self, value: __m512i, output: &mut [u8]) {
        assert!(output.len() >= 64);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm512_storeu_si512(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u8_splat(self, value: u8) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_set1_epi8(value as i8) }
    }

    #[inline]
    fn u8_xor(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_xor_si512(a, b) }
    }

    #[inline]
    fn u8_and(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_and_si512(a, b) }
    }

    type U8Table = __m512i;

    #[inline]
    fn u8_table_load(self, table: &[u8; 16]) -> __m512i {
        // SAFETY: The token guarantees AVX-512F. The table holds 16 readable bytes, and the
        // load accepts unaligned memory. The broadcast copies it into every 128-bit group.
        unsafe { _mm512_broadcast_i32x4(_mm_loadu_si128(table.as_ptr().cast())) }
    }

    #[inline]
    fn u8_table_lookup(self, table: __m512i, indices: __m512i) -> __m512i {
        // Saturating addition of 0x70 maps indices 0..16 to 0x70..0x80, preserving the low
        // nibble with the top bit clear, and maps 16..256 to 0x80..=0xff, which VPSHUFB zeroes.
        // Every group holds the full table, so the group-local shuffle is a full lookup.
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_shuffle_epi8(table, _mm512_adds_epu8(indices, _mm512_set1_epi8(0x70))) }
    }

    #[inline]
    fn u8_or(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_or_si512(a, b) }
    }

    #[inline]
    fn u8_add(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_add_epi8(a, b) }
    }

    #[inline]
    fn u8_sub(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_sub_epi8(a, b) }
    }

    #[inline]
    fn u8_add_saturating(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_adds_epu8(a, b) }
    }

    #[inline]
    fn u8_sub_saturating(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_subs_epu8(a, b) }
    }

    #[inline]
    fn u8_min(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_min_epu8(a, b) }
    }

    #[inline]
    fn u8_max(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_max_epu8(a, b) }
    }

    #[inline]
    fn u8_eq(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_movm_epi8(_mm512_cmpeq_epi8_mask(a, b)) }
    }

    #[inline]
    fn u8_gt(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_movm_epi8(_mm512_cmpgt_epu8_mask(a, b)) }
    }

    #[inline]
    fn u8_movemask(self, value: __m512i) -> u64 {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_movepi8_mask(value) }
    }

    #[inline]
    fn u8_any(self, value: __m512i) -> bool {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_test_epi8_mask(value, value) != 0 }
    }

    #[inline]
    fn u8_all(self, value: __m512i) -> bool {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_cmpeq_epi8_mask(value, _mm512_setzero_si512()) == 0 }
    }

    // Split z into 16-byte chunks z[16*k..16*k+16] = Zk. Per 128-bit group g, VPUNPCKLBW
    // yields Z(2g) and VPUNPCKHBW yields Z(2g+1), each occupying qwords 2g and 2g+1. With the
    // low result as qwords 0..8 and the high result as qwords 8..16, the output qwords are
    // zip_lo = [Z0, Z1, Z2, Z3] = [0, 1, 8, 9, 2, 3, 10, 11] and
    // zip_hi = [Z4, Z5, Z6, Z7] = [4, 5, 12, 13, 6, 7, 14, 15].
    #[inline]
    fn u8_zip_lo(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512F and AVX-512BW support.
        unsafe {
            _mm512_permutex2var_epi64(
                _mm512_unpacklo_epi8(a, b),
                _mm512_set_epi64(11, 10, 3, 2, 9, 8, 1, 0),
                _mm512_unpackhi_epi8(a, b),
            )
        }
    }

    #[inline]
    fn u8_zip_hi(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512F and AVX-512BW support.
        unsafe {
            _mm512_permutex2var_epi64(
                _mm512_unpacklo_epi8(a, b),
                _mm512_set_epi64(15, 14, 7, 6, 13, 12, 5, 4),
                _mm512_unpackhi_epi8(a, b),
            )
        }
    }

    // Byte 2k of a vector is the low byte of word k and byte 2k+1 is its high byte. After
    // isolating the selected byte in each word, VPACKUSWB packs group g of a into qword 2g
    // (r[8g..8g+8]) and group g of b into qword 2g+1 (r[32+8g..32+8g+8]); values below
    // 256 are unchanged by saturation. Output qword k is then packed qword 2k for k < 4 and
    // 2(k-4)+1 otherwise: [0, 2, 4, 6, 1, 3, 5, 7].
    #[inline]
    fn u8_unzip_even(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512F and AVX-512BW support.
        unsafe {
            let low = _mm512_set1_epi16(0x00ff);
            _mm512_permutexvar_epi64(
                _mm512_set_epi64(7, 5, 3, 1, 6, 4, 2, 0),
                _mm512_packus_epi16(_mm512_and_si512(a, low), _mm512_and_si512(b, low)),
            )
        }
    }

    #[inline]
    fn u8_unzip_odd(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512F and AVX-512BW support.
        unsafe {
            _mm512_permutexvar_epi64(
                _mm512_set_epi64(7, 5, 3, 1, 6, 4, 2, 0),
                _mm512_packus_epi16(_mm512_srli_epi16::<8>(a), _mm512_srli_epi16::<8>(b)),
            )
        }
    }

    #[inline]
    fn u32_load(self, input: &[u32]) -> __m512i {
        assert!(input.len() >= 16);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm512_loadu_si512(input.as_ptr().cast()) }
    }

    #[inline]
    fn u32_store(self, value: __m512i, output: &mut [u32]) {
        assert!(output.len() >= 16);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm512_storeu_si512(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u32_splat(self, value: u32) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_set1_epi32(value as i32) }
    }

    #[inline]
    fn u32_xor(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_xor_si512(a, b) }
    }

    #[inline]
    fn u32_and(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_and_si512(a, b) }
    }

    #[inline]
    fn u64_load(self, input: &[u64]) -> __m512i {
        assert!(input.len() >= 8);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 readable bytes.
        // The load accepts unaligned memory.
        unsafe { _mm512_loadu_si512(input.as_ptr().cast()) }
    }

    #[inline]
    fn u64_store(self, value: __m512i, output: &mut [u64]) {
        assert!(output.len() >= 8);
        // SAFETY: The token guarantees AVX-512F and the slice has 64 writable bytes.
        // The store accepts unaligned memory.
        unsafe { _mm512_storeu_si512(output.as_mut_ptr().cast(), value) };
    }

    #[inline]
    fn u64_splat(self, value: u64) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_set1_epi64(value as i64) }
    }

    #[inline]
    fn u64_xor(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_xor_si512(a, b) }
    }

    #[inline]
    fn u64_rotate_left<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 64);
        // LLVM folds the constant count into a VPROLQ immediate.
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_rolv_epi64(value, _mm512_set1_epi64(N as i64)) }
    }

    #[inline]
    fn u64_rotate_right<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 64);
        // LLVM folds the constant count into a VPRORQ immediate.
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_rorv_epi64(value, _mm512_set1_epi64(N as i64)) }
    }

    #[inline]
    fn u64_andnot(self, a: __m512i, b: __m512i) -> __m512i {
        // VPANDNQ complements its first operand.
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_andnot_si512(b, a) }
    }

    #[inline]
    fn u64_xor3(self, a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_ternarylogic_epi64::<0x96>(a, b, c) }
    }

    #[inline]
    fn u64_and(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_and_si512(a, b) }
    }

    #[inline]
    fn u8_load_partial(self, input: &[u8]) -> __m512i {
        assert!(input.len() <= 64);
        let mask = u64::MAX.checked_shr((64 - input.len()) as u32).unwrap_or(0);
        // SAFETY: The token guarantees AVX-512F/BW. Only the first input.len()
        // bytes are enabled, and masked-off lanes do not access memory.
        unsafe { _mm512_maskz_loadu_epi8(mask, input.as_ptr().cast()) }
    }

    #[inline]
    fn u8_store_partial(self, value: __m512i, output: &mut [u8]) {
        assert!(output.len() <= 64);
        let mask = u64::MAX
            .checked_shr((64 - output.len()) as u32)
            .unwrap_or(0);
        // SAFETY: The token guarantees AVX-512F/BW. Only the first output.len()
        // bytes are enabled, and masked-off lanes do not access memory.
        unsafe { _mm512_mask_storeu_epi8(output.as_mut_ptr().cast(), mask, value) };
    }

    #[inline]
    fn u8_shl<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 8);
        // SAFETY: Token construction established all required instruction features.
        unsafe {
            _mm512_and_si512(
                _mm512_sllv_epi16(value, _mm512_set1_epi16(N as i16)),
                _mm512_set1_epi8((0xffu8 << N) as i8),
            )
        }
    }

    #[inline]
    fn u8_shr<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 8);
        // SAFETY: Token construction established all required instruction features.
        unsafe {
            _mm512_and_si512(
                _mm512_srlv_epi16(value, _mm512_set1_epi16(N as i16)),
                _mm512_set1_epi8((0xffu8 >> N) as i8),
            )
        }
    }

    #[inline]
    fn u8_xor_fold(self, value: __m512i) -> u8 {
        let mut lanes = [0; 64];
        self.u8_store(value, &mut lanes);
        lanes.into_iter().fold(0, |acc, lane| acc ^ lane)
    }

    #[inline]
    fn u32_add(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_add_epi32(a, b) }
    }

    #[inline]
    fn u32_sub(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_sub_epi32(a, b) }
    }

    #[inline]
    fn u32_or(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_or_si512(a, b) }
    }

    #[inline]
    fn u32_shl<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 32);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_sllv_epi32(value, _mm512_set1_epi32(N as i32)) }
    }

    #[inline]
    fn u32_shr<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 32);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_srlv_epi32(value, _mm512_set1_epi32(N as i32)) }
    }

    #[inline]
    fn u32_select(self, mask: __m512i, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_or_si512(_mm512_and_si512(mask, a), _mm512_andnot_si512(mask, b)) }
    }

    #[inline]
    fn u64_add(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_add_epi64(a, b) }
    }

    #[inline]
    fn u64_sub(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_sub_epi64(a, b) }
    }

    #[inline]
    fn u64_or(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_or_si512(a, b) }
    }

    #[inline]
    fn u64_shl<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 64);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_sllv_epi64(value, _mm512_set1_epi64(N as i64)) }
    }

    #[inline]
    fn u64_shr<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 64);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_srlv_epi64(value, _mm512_set1_epi64(N as i64)) }
    }

    #[inline]
    fn u64_select(self, mask: __m512i, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_or_si512(_mm512_and_si512(mask, a), _mm512_andnot_si512(mask, b)) }
    }

    #[inline]
    fn u32_rotate_right<const N: u32>(self, value: __m512i) -> __m512i {
        assert!(N < 32);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_rorv_epi32(value, _mm512_set1_epi32(N as i32)) }
    }

    #[inline]
    fn u32_permute(self, value: __m512i, indices: __m512i) -> __m512i {
        // SAFETY: The token guarantees AVX-512F. `_mm512_permutexvar_epi32` reads only the
        // low 4 bits of each index lane, which reduces it modulo 16.
        unsafe { _mm512_permutexvar_epi32(indices, value) }
    }

    #[inline]
    fn u32_permute2(self, a: __m512i, b: __m512i, indices: __m512i) -> __m512i {
        // SAFETY: The token guarantees AVX-512F. `_mm512_permutex2var_epi32` reads only the
        // low 5 bits of each index lane: 4 bits select the lane and bit 4 selects `b`,
        // which reduces the index modulo 32.
        unsafe { _mm512_permutex2var_epi32(a, indices, b) }
    }

    #[inline]
    fn u64_extract<const N: usize>(self, value: __m512i) -> u64 {
        assert!(N < 8);
        let mut lanes = [0; 8];
        self.u64_store(value, &mut lanes);
        lanes[N]
    }

    #[inline]
    fn u64_insert<const N: usize>(self, value: __m512i, lane: u64) -> __m512i {
        assert!(N < 8);
        let mut lanes = [0; 8];
        self.u64_store(value, &mut lanes);
        lanes[N] = lane;
        self.u64_load(&lanes)
    }

    #[inline]
    fn u8_as_u32(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn u32_as_u8(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn u8_as_u64(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn u64_as_u8(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn u32_as_u64(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn u64_as_u32(self, value: __m512i) -> __m512i {
        value
    }

    #[inline]
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output {
        // SAFETY: Token construction established every feature enabled by this entry.
        unsafe { self.execute_x86_v4c(operation) }
    }
}

impl X86V4C for NativeX86V4C {
    #[inline]
    fn u32_load_be(self, input: &[u8]) -> __m512i {
        assert!(input.len() >= 64);
        // SAFETY: The token guarantees AVX-512F/BW and the slice has 64 readable bytes.
        // The load accepts unaligned memory; the shuffle reverses each four-byte word.
        unsafe {
            let value = _mm512_loadu_si512(input.as_ptr().cast());
            let mask = _mm512_set4_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
            _mm512_shuffle_epi8(value, mask)
        }
    }

    #[inline]
    fn sha256_rounds2(self, a: __m128i, b: __m128i, k: __m128i) -> __m128i {
        // SAFETY: Token construction established SHA support.
        unsafe { _mm_sha256rnds2_epu32(a, b, k) }
    }

    #[inline]
    fn sha256_msg1(self, a: __m128i, b: __m128i) -> __m128i {
        // SAFETY: Token construction established SHA support.
        unsafe { _mm_sha256msg1_epu32(a, b) }
    }

    #[inline]
    fn sha256_msg2(self, a: __m128i, b: __m128i) -> __m128i {
        // SAFETY: Token construction established SHA support.
        unsafe { _mm_sha256msg2_epu32(a, b) }
    }

    #[inline]
    fn u32_ternary<const MASK: i32>(self, a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        assert!((0..256).contains(&MASK));
        // SAFETY: Token construction established AVX-512F support.
        unsafe { _mm512_ternarylogic_epi32::<MASK>(a, b, c) }
    }

    #[inline]
    fn u64_ternary<const MASK: i32>(self, a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        assert!((0..256).contains(&MASK));
        // SAFETY: Token construction established AVX-512F support.
        unsafe { _mm512_ternarylogic_epi64::<MASK>(a, b, c) }
    }

    #[inline]
    fn u8_shuffle128(self, value: __m512i, indices: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512BW support.
        unsafe { _mm512_shuffle_epi8(value, indices) }
    }

    #[inline]
    fn u32_shuffle_groups<const MASK: i32>(self, a: __m512i, b: __m512i) -> __m512i {
        assert!((0..256).contains(&MASK));
        // SAFETY: Token construction established AVX-512F support.
        unsafe { _mm512_shuffle_i32x4::<MASK>(a, b) }
    }

    #[inline]
    fn u32_unpackhi64(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established AVX-512F support.
        unsafe { _mm512_unpackhi_epi64(a, b) }
    }

    #[inline]
    fn u8_gf_mul(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_gf2p8mul_epi8(a, b) }
    }

    #[inline]
    fn u64_madd52lo(self, acc: __m512i, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_madd52lo_epu64(acc, a, b) }
    }

    #[inline]
    fn u64_madd52hi(self, acc: __m512i, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_madd52hi_epu64(acc, a, b) }
    }

    #[inline]
    fn u32_shuffle128<const MASK: i32>(self, value: __m512i) -> __m512i {
        assert!((0..256).contains(&MASK));
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_shuffle_epi32::<MASK>(value) }
    }

    #[inline]
    fn u32_shuffle2_128<const MASK: i32>(self, a: __m512i, b: __m512i) -> __m512i {
        assert!((0..256).contains(&MASK));
        // SAFETY: Token construction established all required instruction features.
        unsafe {
            _mm512_castps_si512(_mm512_shuffle_ps::<MASK>(
                _mm512_castsi512_ps(a),
                _mm512_castsi512_ps(b),
            ))
        }
    }

    #[inline]
    fn u32_blend128<const MASK: i32>(self, a: __m512i, b: __m512i) -> __m512i {
        assert!(MASK >= 0 && MASK < 16);
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_mask_blend_epi32((MASK as u16) * 0x1111, a, b) }
    }

    #[inline]
    fn u32_unpacklo32(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_unpacklo_epi32(a, b) }
    }

    #[inline]
    fn u32_unpackhi32(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_unpackhi_epi32(a, b) }
    }

    #[inline]
    fn u32_unpacklo64(self, a: __m512i, b: __m512i) -> __m512i {
        // SAFETY: Token construction established all required instruction features.
        unsafe { _mm512_unpacklo_epi64(a, b) }
    }
}
