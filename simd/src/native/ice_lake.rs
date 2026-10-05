//! Native implementation of the Ice Lake instruction profile.

use crate::{IceLake, Operation, Simd};
use core::arch::x86_64::*;

/// Native Ice Lake execution token with 64 byte, 16 u32, and eight u64 lanes.
///
/// Construction checks AVX-512F, AVX-512BW, GFNI, and AVX-512IFMA. AVX-512BW
/// supplies byte-masked memory operations, byte broadcasts, and word shifts used
/// to implement independent byte shifts. Copies preserve the feature guarantee.
/// No CPU vendor or model is required.
#[derive(Clone, Copy, Debug)]
pub struct NativeIceLake(());

impl NativeIceLake {
    /// Returns a token if all required instruction features are available.
    ///
    /// With `std`, checks the current CPU and operating system's vector support.
    /// Without `std`, requires all features to be enabled at compile time.
    pub fn new() -> Option<Self> {
        #[cfg(feature = "std")]
        let supported = std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("gfni")
            && std::arch::is_x86_feature_detected!("avx512ifma");
        #[cfg(not(feature = "std"))]
        let supported = cfg!(target_feature = "avx512f")
            && cfg!(target_feature = "avx512bw")
            && cfg!(target_feature = "gfni")
            && cfg!(target_feature = "avx512ifma");
        supported.then_some(Self(()))
    }

    #[inline]
    #[target_feature(enable = "avx512f,avx512bw,gfni,avx512ifma")]
    unsafe fn execute_ice_lake<O: Operation>(self, operation: O) -> O::Output {
        operation.ice_lake(self)
    }
}

impl Simd for NativeIceLake {
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
    fn u32_permute(self, value: __m512i, indices: &[usize]) -> __m512i {
        assert!(indices.len() >= 16);
        let mut lanes = [0u32; 16];
        for (lane, &index) in lanes.iter_mut().zip(indices) {
            assert!(index < 16);
            *lane = index as u32;
        }
        let indices = self.u32_load(&lanes);
        // SAFETY: The token guarantees AVX-512F; all active indices were validated.
        unsafe { _mm512_permutexvar_epi32(indices, value) }
    }

    #[inline]
    fn u32_permute2(self, a: __m512i, b: __m512i, indices: &[usize]) -> __m512i {
        assert!(indices.len() >= 16);
        let mut lanes = [0u32; 16];
        for (lane, &index) in lanes.iter_mut().zip(indices) {
            assert!(index < 32);
            *lane = index as u32;
        }
        let indices = self.u32_load(&lanes);
        // SAFETY: The token guarantees AVX-512F; all active indices were validated.
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
    fn execute<O: Operation>(self, operation: O) -> O::Output {
        // SAFETY: Token construction established every feature enabled by this entry.
        unsafe { self.execute_ice_lake(operation) }
    }
}

impl IceLake for NativeIceLake {
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
