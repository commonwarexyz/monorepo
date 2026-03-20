use super::elem::BinaryElem32;
use super::poly::{BinaryPoly128, BinaryPoly256, BinaryPoly64};

// 64x64 -> 128 bit carryless multiplication
pub fn carryless_mul_64(a: BinaryPoly64, b: BinaryPoly64) -> BinaryPoly128 {
    // x86_64 with PCLMULQDQ
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        use core::arch::x86_64::*;

        // SAFETY: The cfg gate guarantees pclmulqdq is available. The intrinsics
        // operate on stack-local __m128i values with no pointer dereferences.
        unsafe {
            let a_vec = _mm_set_epi64x(0, a.value() as i64);
            let b_vec = _mm_set_epi64x(0, b.value() as i64);

            let result = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);

            let lo = _mm_extract_epi64(result, 0) as u64;
            let hi = _mm_extract_epi64(result, 1) as u64;

            return BinaryPoly128::new(((hi as u128) << 64) | (lo as u128));
        }
    }

    // WASM with SIMD128
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        return carryless_mul_64_wasm_simd(a, b);
    }

    // Software fallback for other platforms
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "pclmulqdq"),
        all(target_arch = "wasm32", target_feature = "simd128")
    )))]
    {
        // software fallback
        carryless_mul_64_soft(a, b)
    }
}

// software implementation for 64x64 using lookup tables
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
fn carryless_mul_64_soft(a: BinaryPoly64, b: BinaryPoly64) -> BinaryPoly128 {
    let a_val = a.value();
    let b_val = b.value();

    // Split into 32-bit halves for Karatsuba
    let a_lo = (a_val & 0xFFFFFFFF) as u32;
    let a_hi = (a_val >> 32) as u32;
    let b_lo = (b_val & 0xFFFFFFFF) as u32;
    let b_hi = (b_val >> 32) as u32;

    // Karatsuba multiplication with lookup tables
    let z0 = mul_32x32_to_64_lut(a_lo, b_lo);
    let z2 = mul_32x32_to_64_lut(a_hi, b_hi);
    let z1 = mul_32x32_to_64_lut(a_lo ^ a_hi, b_lo ^ b_hi);

    // Karatsuba combination
    let middle = z1 ^ z0 ^ z2;
    let result_lo = z0 ^ (middle << 32);
    let result_hi = (middle >> 32) ^ z2;

    BinaryPoly128::new(((result_hi as u128) << 64) | (result_lo as u128))
}

// WASM SIMD128 optimized implementation using Karatsuba decomposition
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
fn carryless_mul_64_wasm_simd(a: BinaryPoly64, b: BinaryPoly64) -> BinaryPoly128 {
    // SAFETY: The cfg gate guarantees wasm32 simd128 is available. The called
    // mul_32x32_to_64_simd is an unsafe fn that requires simd128, which is
    // guaranteed by the same cfg gate.
    unsafe {
        let a_val = a.value();
        let b_val = b.value();

        // Split into 32-bit halves for Karatsuba
        let a_lo = (a_val & 0xFFFFFFFF) as u32;
        let a_hi = (a_val >> 32) as u32;
        let b_lo = (b_val & 0xFFFFFFFF) as u32;
        let b_hi = (b_val >> 32) as u32;

        // Use SIMD for parallel 32x32 multiplications
        let z0 = mul_32x32_to_64_simd(a_lo, b_lo);
        let z2 = mul_32x32_to_64_simd(a_hi, b_hi);
        let z1 = mul_32x32_to_64_simd(a_lo ^ a_hi, b_lo ^ b_hi);

        // Karatsuba combination: z1 = z1 ^ z0 ^ z2
        let middle = z1 ^ z0 ^ z2;

        // Combine: result = z0 + (middle << 32) + (z2 << 64)
        let result_lo = z0 ^ (middle << 32);
        let result_hi = (middle >> 32) ^ z2;

        BinaryPoly128::new(((result_hi as u128) << 64) | (result_lo as u128))
    }
}

// 4-bit x 4-bit carryless multiplication lookup table
// Entry [a][b] = a * b in GF(2) polynomial multiplication (no reduction)
// This is the core building block for branchless carryless multiply
#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
static CLMUL_4X4: [[u8; 16]; 16] = {
    let mut table = [[0u8; 16]; 16];
    let mut a = 0usize;
    while a < 16 {
        let mut b = 0usize;
        while b < 16 {
            // Compute a * b carryless (no branches)
            let mut result = 0u8;
            let mut i = 0;
            while i < 4 {
                // If bit i of b is set, XOR a << i into result
                let mask = ((b >> i) & 1) as u8;
                result ^= ((a as u8) << i) * mask;
                i += 1;
            }
            table[a][b] = result;
            b += 1;
        }
        a += 1;
    }
    table
};

// 32x32 -> 64 carryless multiplication using WASM SIMD128 i8x16_swizzle
// Uses swizzle for parallel 16-way table lookups - 4x faster than scalar
// SAFETY: Caller must ensure wasm32 simd128 target feature is available.
// The function reads from the static CLMUL_4X4 table via v128_load, which
// is safe because each row is exactly 16 bytes (matching v128 size).
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
unsafe fn mul_32x32_to_64_simd(a: u32, b: u32) -> u64 {
    use core::arch::wasm32::*;

    // Extract 4-bit nibbles from both operands
    let a_nibbles: [usize; 8] = [
        (a & 0xF) as usize,
        ((a >> 4) & 0xF) as usize,
        ((a >> 8) & 0xF) as usize,
        ((a >> 12) & 0xF) as usize,
        ((a >> 16) & 0xF) as usize,
        ((a >> 20) & 0xF) as usize,
        ((a >> 24) & 0xF) as usize,
        ((a >> 28) & 0xF) as usize,
    ];

    // Create b_nibbles index vector for swizzle (replicate to fill 16 lanes)
    let b0 = (b & 0xF) as u8;
    let b1 = ((b >> 4) & 0xF) as u8;
    let b2 = ((b >> 8) & 0xF) as u8;
    let b3 = ((b >> 12) & 0xF) as u8;
    let b4 = ((b >> 16) & 0xF) as u8;
    let b5 = ((b >> 20) & 0xF) as u8;
    let b6 = ((b >> 24) & 0xF) as u8;
    let b7 = ((b >> 28) & 0xF) as u8;

    // Index vector: b_nibbles[0..7] in first 8 lanes, zeros in upper 8 (unused)
    let b_indices = u8x16(b0, b1, b2, b3, b4, b5, b6, b7, 0, 0, 0, 0, 0, 0, 0, 0);

    let mut result = 0u64;

    // For each a_nibble, load its CLMUL_4X4 row and swizzle with b_indices
    // This computes all 8 products a_nibble[i] * b_nibble[j] in parallel
    for i in 0..8 {
        // Load the 16-byte lookup table row for this a_nibble
        let table_row = v128_load(CLMUL_4X4[a_nibbles[i]].as_ptr() as *const v128);

        // Swizzle: products[j] = CLMUL_4X4[a_nibbles[i]][b_nibbles[j]]
        let products = i8x16_swizzle(table_row, b_indices);

        // Extract the 8 products and accumulate with proper shifts
        // Each product at position j contributes at bit position (i+j)*4
        let p0 = u8x16_extract_lane::<0>(products) as u64;
        let p1 = u8x16_extract_lane::<1>(products) as u64;
        let p2 = u8x16_extract_lane::<2>(products) as u64;
        let p3 = u8x16_extract_lane::<3>(products) as u64;
        let p4 = u8x16_extract_lane::<4>(products) as u64;
        let p5 = u8x16_extract_lane::<5>(products) as u64;
        let p6 = u8x16_extract_lane::<6>(products) as u64;
        let p7 = u8x16_extract_lane::<7>(products) as u64;

        let base_shift = i * 4;
        result ^= p0 << base_shift;
        result ^= p1 << (base_shift + 4);
        result ^= p2 << (base_shift + 8);
        result ^= p3 << (base_shift + 12);
        result ^= p4 << (base_shift + 16);
        result ^= p5 << (base_shift + 20);
        result ^= p6 << (base_shift + 24);
        result ^= p7 << (base_shift + 28);
    }

    result
}

// Lookup table based 32x32 carryless multiply (also used as software fallback)
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
#[inline(always)]
fn mul_32x32_to_64_lut(a: u32, b: u32) -> u64 {
    // Split a and b into 4-bit nibbles
    let a_nibbles: [usize; 8] = [
        (a & 0xF) as usize,
        ((a >> 4) & 0xF) as usize,
        ((a >> 8) & 0xF) as usize,
        ((a >> 12) & 0xF) as usize,
        ((a >> 16) & 0xF) as usize,
        ((a >> 20) & 0xF) as usize,
        ((a >> 24) & 0xF) as usize,
        ((a >> 28) & 0xF) as usize,
    ];

    let b_nibbles: [usize; 8] = [
        (b & 0xF) as usize,
        ((b >> 4) & 0xF) as usize,
        ((b >> 8) & 0xF) as usize,
        ((b >> 12) & 0xF) as usize,
        ((b >> 16) & 0xF) as usize,
        ((b >> 20) & 0xF) as usize,
        ((b >> 24) & 0xF) as usize,
        ((b >> 28) & 0xF) as usize,
    ];

    // Schoolbook multiplication with 4-bit chunks
    // Each a_nibble[i] * b_nibble[j] contributes at bit position (i+j)*4
    let mut result = 0u64;

    // Unrolled for performance
    for i in 0..8 {
        for j in 0..8 {
            let prod = CLMUL_4X4[a_nibbles[i]][b_nibbles[j]] as u64;
            result ^= prod << ((i + j) * 4);
        }
    }

    result
}

// 128x128 -> 128 bit carryless multiplication (truncated)
pub fn carryless_mul_128(a: BinaryPoly128, b: BinaryPoly128) -> BinaryPoly128 {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        use core::arch::x86_64::*;

        // SAFETY: The cfg gate guarantees pclmulqdq is available. All intrinsics
        // operate on stack-local __m128i values with no pointer dereferences.
        unsafe {
            // split inputs into 64-bit halves
            let a_lo = a.value() as u64;
            let a_hi = (a.value() >> 64) as u64;
            let b_lo = b.value() as u64;
            let b_hi = (b.value() >> 64) as u64;

            // perform 3 64x64->128 bit multiplications (skip hi*hi for truncated result)
            let lo_lo = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_lo as i64),
                _mm_set_epi64x(0, b_lo as i64),
                0x00,
            );

            let lo_hi = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_lo as i64),
                _mm_set_epi64x(0, b_hi as i64),
                0x00,
            );

            let hi_lo = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_hi as i64),
                _mm_set_epi64x(0, b_lo as i64),
                0x00,
            );

            // extract 128-bit results - fix the overflow by casting to u128 first
            let r0 = (_mm_extract_epi64(lo_lo, 0) as u64) as u128
                | ((_mm_extract_epi64(lo_lo, 1) as u64) as u128) << 64;
            let r1 = (_mm_extract_epi64(lo_hi, 0) as u64) as u128
                | ((_mm_extract_epi64(lo_hi, 1) as u64) as u128) << 64;
            let r2 = (_mm_extract_epi64(hi_lo, 0) as u64) as u128
                | ((_mm_extract_epi64(hi_lo, 1) as u64) as u128) << 64;

            // combine: result = r0 + (r1 << 64) + (r2 << 64)
            let result = r0 ^ (r1 << 64) ^ (r2 << 64);

            return BinaryPoly128::new(result);
        }
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
    {
        // software fallback
        carryless_mul_128_soft(a, b)
    }
}

// software implementation for 128x128 truncated
#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
fn carryless_mul_128_soft(a: BinaryPoly128, b: BinaryPoly128) -> BinaryPoly128 {
    let a_lo = a.value() as u64;
    let a_hi = (a.value() >> 64) as u64;
    let b_lo = b.value() as u64;
    let b_hi = (b.value() >> 64) as u64;

    let z0 = mul_64x64_to_128(a_lo, b_lo);
    let z1 = mul_64x64_to_128(a_lo ^ a_hi, b_lo ^ b_hi);
    let z2 = mul_64x64_to_128(a_hi, b_hi);

    // karatsuba combination (truncated)
    let result = z0 ^ (z1 << 64) ^ (z0 << 64) ^ (z2 << 64);
    BinaryPoly128::new(result)
}

// 128x128 -> 256 bit full multiplication
pub fn carryless_mul_128_full(a: BinaryPoly128, b: BinaryPoly128) -> BinaryPoly256 {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        use core::arch::x86_64::*;

        // SAFETY: The cfg gate guarantees pclmulqdq is available. All intrinsics
        // operate on stack-local __m128i values with no pointer dereferences.
        unsafe {
            let a_lo = a.value() as u64;
            let a_hi = (a.value() >> 64) as u64;
            let b_lo = b.value() as u64;
            let b_hi = (b.value() >> 64) as u64;

            // 4 multiplications
            let lo_lo = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_lo as i64),
                _mm_set_epi64x(0, b_lo as i64),
                0x00,
            );

            let lo_hi = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_lo as i64),
                _mm_set_epi64x(0, b_hi as i64),
                0x00,
            );

            let hi_lo = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_hi as i64),
                _mm_set_epi64x(0, b_lo as i64),
                0x00,
            );

            let hi_hi = _mm_clmulepi64_si128(
                _mm_set_epi64x(0, a_hi as i64),
                _mm_set_epi64x(0, b_hi as i64),
                0x00,
            );

            // extract and combine
            let r0_lo = _mm_extract_epi64(lo_lo, 0) as u64;
            let r0_hi = _mm_extract_epi64(lo_lo, 1) as u64;
            let r1_lo = _mm_extract_epi64(lo_hi, 0) as u64;
            let r1_hi = _mm_extract_epi64(lo_hi, 1) as u64;
            let r2_lo = _mm_extract_epi64(hi_lo, 0) as u64;
            let r2_hi = _mm_extract_epi64(hi_lo, 1) as u64;
            let r3_lo = _mm_extract_epi64(hi_hi, 0) as u64;
            let r3_hi = _mm_extract_epi64(hi_hi, 1) as u64;

            // build 256-bit result
            let mut lo = r0_lo as u128 | ((r0_hi as u128) << 64);
            let mut hi = 0u128;

            // add r1 << 64
            lo ^= (r1_lo as u128) << 64;
            hi ^= (r1_lo as u128) >> 64;
            hi ^= r1_hi as u128;

            // add r2 << 64
            lo ^= (r2_lo as u128) << 64;
            hi ^= (r2_lo as u128) >> 64;
            hi ^= r2_hi as u128;

            // add r3 << 128
            hi ^= r3_lo as u128 | ((r3_hi as u128) << 64);

            return BinaryPoly256::from_parts(hi, lo);
        }
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
    {
        // software fallback
        carryless_mul_128_full_soft(a, b)
    }
}

// software implementation for 128x128 full
#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
fn carryless_mul_128_full_soft(a: BinaryPoly128, b: BinaryPoly128) -> BinaryPoly256 {
    let a_lo = a.value() as u64;
    let a_hi = (a.value() >> 64) as u64;
    let b_lo = b.value() as u64;
    let b_hi = (b.value() >> 64) as u64;

    let z0 = mul_64x64_to_128(a_lo, b_lo);
    let z2 = mul_64x64_to_128(a_hi, b_hi);
    let z1 = mul_64x64_to_128(a_lo ^ a_hi, b_lo ^ b_hi) ^ z0 ^ z2;

    // combine: result = z0 + (z1 << 64) + (z2 << 128)
    let mut lo = z0;
    let mut hi = 0u128;

    // add z1 << 64
    lo ^= z1 << 64;
    hi ^= z1 >> 64;

    // add z2 << 128
    hi ^= z2;

    BinaryPoly256::from_parts(hi, lo)
}

// helper: constant-time 64x64 -> 128
#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
#[inline(always)]
fn mul_64x64_to_128(a: u64, b: u64) -> u128 {
    let mut result = 0u128;
    let mut a_shifted = a as u128;

    for i in 0..64 {
        let mask = 0u128.wrapping_sub(((b >> i) & 1) as u128);
        result ^= a_shifted & mask;
        a_shifted <<= 1;
    }

    result
}

// batch field operations

use super::elem::BinaryElem128;
use super::BinaryFieldElement;

/// batch multiply gf(2^128) elements with two-tier dispatch:
/// hardware-accel → pclmulqdq, else → scalar
pub fn batch_mul_gf128(a: &[BinaryElem128], b: &[BinaryElem128], out: &mut [BinaryElem128]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());

    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        return batch_mul_gf128_hw(a, b, out);
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
    {
        // scalar fallback
        for i in 0..a.len() {
            out[i] = a[i].mul(&b[i]);
        }
    }
}

/// batch add gf(2^128) elements (xor in gf(2^n))
pub fn batch_add_gf128(a: &[BinaryElem128], b: &[BinaryElem128], out: &mut [BinaryElem128]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());

    // scalar fallback (XOR is already very fast)
    for i in 0..a.len() {
        out[i] = a[i].add(&b[i]);
    }
}

// pclmulqdq-based batch multiply for x86_64
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
fn batch_mul_gf128_hw(a: &[BinaryElem128], b: &[BinaryElem128], out: &mut [BinaryElem128]) {
    for i in 0..a.len() {
        let a_poly = a[i].poly();
        let b_poly = b[i].poly();
        let product = carryless_mul_128_full(a_poly, b_poly);
        let reduced = reduce_gf128(product);
        out[i] = BinaryElem128::from_value(reduced.value());
    }
}

/// reduce 256-bit product modulo GF(2^128) irreducible polynomial
/// irreducible: x^128 + x^7 + x^2 + x + 1 (0x87 = 0b10000111)
/// matches the @generated mod_irreducible pattern
#[inline(always)]
pub fn reduce_gf128(product: BinaryPoly256) -> BinaryPoly128 {
    let (hi, lo) = product.split();
    let high = hi.value();
    let low = lo.value();

    // Compute tmp for irreducible 0b10000111 (bits 0,1,2,7):
    // for each set bit i in irreducible: tmp ^= hi >> (128 - i)
    // bits set: 0, 1, 2, 7 -> shifts: 128, 127, 126, 121
    let tmp = high ^ (high >> 127) ^ (high >> 126) ^ (high >> 121);

    // Compute res:
    // for each set bit i in irreducible: res ^= tmp << i
    // bits set: 0, 1, 2, 7 -> shifts: 0, 1, 2, 7
    let res = low ^ tmp ^ (tmp << 1) ^ (tmp << 2) ^ (tmp << 7);

    BinaryPoly128::new(res)
}

// =========================================================================
// BinaryElem32 batch operations - FFT optimization
// =========================================================================

/// Vectorized FFT butterfly for GF(2^32) with tiered fallback
/// Tries: AVX-512 (8 elements) -> AVX2 (4 elements) -> SSE (2 elements) -> scalar
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
pub fn fft_butterfly_gf32_avx512(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    #[cfg(target_arch = "x86_64")]
    {
        // Tier 1: Try AVX-512 with 512-bit VPCLMULQDQ (8 elements at once)
        if is_x86_feature_detected!("vpclmulqdq") && is_x86_feature_detected!("avx512f") {
            // SAFETY: we just checked the CPU supports these features
            unsafe { fft_butterfly_gf32_avx512_impl(u, w, lambda) };
            return;
        }

        // Tier 2: Try AVX2 with 256-bit VPCLMULQDQ (4 elements at once)
        if is_x86_feature_detected!("vpclmulqdq") && is_x86_feature_detected!("avx2") {
            // SAFETY: we just checked the CPU supports these features
            unsafe { fft_butterfly_gf32_avx2_impl(u, w, lambda) };
            return;
        }

        // Tier 3: Fall back to SSE with 128-bit PCLMULQDQ (2 elements at once)
        return fft_butterfly_gf32_sse(u, w, lambda);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        fft_butterfly_gf32_scalar(u, w, lambda)
    }
}

/// Vectorized GF(2^32) reduction on 8 x 64-bit products in a __m512i.
///
/// Each 64-bit lane holds a 63-bit carry-less product. The high 32 bits
/// are reduced modulo x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1 using
/// shifts and XORs, all in-register.
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[target_feature(enable = "avx512f")]
#[inline]
unsafe fn reduce_gf32_avx512(p: core::arch::x86_64::__m512i) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::*;

    // hi = p >> 32 (high 32 bits of each 64-bit lane)
    let hi = _mm512_srli_epi64(p, 32);
    // lo = p & 0xFFFFFFFF
    let mask32 = _mm512_set1_epi64(0xFFFFFFFFi64);
    let lo = _mm512_and_si512(p, mask32);

    // tmp = hi ^ (hi >> 17) ^ (hi >> 23) ^ (hi >> 25) ^ (hi >> 28) ^ (hi >> 29)
    let tmp = _mm512_xor_si512(
        _mm512_xor_si512(
            _mm512_xor_si512(hi, _mm512_srli_epi64(hi, 17)),
            _mm512_xor_si512(_mm512_srli_epi64(hi, 23), _mm512_srli_epi64(hi, 25)),
        ),
        _mm512_xor_si512(_mm512_srli_epi64(hi, 28), _mm512_srli_epi64(hi, 29)),
    );

    // res = lo ^ tmp ^ (tmp << 3) ^ (tmp << 4) ^ (tmp << 7) ^ (tmp << 9) ^ (tmp << 15)
    let res = _mm512_xor_si512(
        _mm512_xor_si512(
            _mm512_xor_si512(lo, tmp),
            _mm512_xor_si512(_mm512_slli_epi64(tmp, 3), _mm512_slli_epi64(tmp, 4)),
        ),
        _mm512_xor_si512(
            _mm512_xor_si512(_mm512_slli_epi64(tmp, 7), _mm512_slli_epi64(tmp, 9)),
            _mm512_slli_epi64(tmp, 15),
        ),
    );

    // Mask to 32 bits
    _mm512_and_si512(res, mask32)
}

/// AVX-512 FFT butterfly: fully vectorized multiply, reduce, and XOR.
///
/// Processes 16 elements per iteration (two rounds of 8-wide VPCLMULQDQ).
/// Multiply, reduce, and butterfly XOR all stay in 512-bit registers.
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[target_feature(enable = "avx512f,vpclmulqdq")]
unsafe fn fft_butterfly_gf32_avx512_impl(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    use core::arch::x86_64::*;

    assert_eq!(u.len(), w.len());
    let len = u.len();

    let lambda_val = lambda.poly().value() as u64;
    let lambda_512 = _mm512_set1_epi64(lambda_val as i64);

    // SAFETY: BinaryElem32 is repr(transparent) over a u32 wrapper.
    // Interpreting &[BinaryElem32] as &[u32] is sound for aligned SIMD loads.
    let u_ptr = u.as_mut_ptr() as *mut u32;
    let w_ptr = w.as_mut_ptr() as *mut u32;

    let mut i = 0;

    // Process 16 elements per iteration: two batches of 8
    while i + 16 <= len {
        for batch in 0..2 {
            let off = i + batch * 8;

            // Load 8 x u32 from w, zero-extend to 8 x u64 in __m512i
            // SAFETY: we checked i + 16 <= len, so off + 7 < len
            let w_256 = _mm256_loadu_si256(w_ptr.add(off) as *const __m256i);
            let w_512 = _mm512_cvtepu32_epi64(w_256);

            // VPCLMULQDQ: 4 clmuls per instruction, 2 instructions = 8 products
            // Selector 0x00: low*low of each 128-bit lane (even indices)
            // Selector 0x01: low*high of each 128-bit lane (odd indices)
            let prod_even = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x00);
            let prod_odd = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x01);

            // Interleave even/odd products back to original order:
            // prod_even has results in lanes [0,_,2,_,4,_,6,_]
            // prod_odd has results in lanes  [_,1,_,3,_,5,_,7]
            // Merge: take even from prod_even, odd from prod_odd
            let merge_idx = _mm512_set_epi64(15, 6, 13, 4, 11, 2, 9, 0);
            let products = _mm512_permutex2var_epi64(prod_even, merge_idx, prod_odd);

            // Reduce all 8 products in-register
            let reduced = reduce_gf32_avx512(products);

            // Load 8 x u32 from u, zero-extend to 8 x u64
            let u_256 = _mm256_loadu_si256(u_ptr.add(off) as *const __m256i);
            let u_512 = _mm512_cvtepu32_epi64(u_256);

            // u' = u ^ lambda_w
            let u_new = _mm512_xor_si512(u_512, reduced);

            // w' = w ^ u' (original w XOR new u)
            let w_new = _mm512_xor_si512(w_512, u_new);

            // Truncate 64->32 and store back
            let u_out = _mm512_cvtepi64_epi32(u_new);
            let w_out = _mm512_cvtepi64_epi32(w_new);

            _mm256_storeu_si256(u_ptr.add(off) as *mut __m256i, u_out);
            _mm256_storeu_si256(w_ptr.add(off) as *mut __m256i, w_out);
        }

        i += 16;
    }

    // Handle remaining 8 elements
    if i + 8 <= len {
        let w_256 = _mm256_loadu_si256(w_ptr.add(i) as *const __m256i);
        let w_512 = _mm512_cvtepu32_epi64(w_256);

        let prod_even = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x00);
        let prod_odd = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x01);

        let merge_idx = _mm512_set_epi64(15, 6, 13, 4, 11, 2, 9, 0);
        let products = _mm512_permutex2var_epi64(prod_even, merge_idx, prod_odd);

        let reduced = reduce_gf32_avx512(products);

        let u_256 = _mm256_loadu_si256(u_ptr.add(i) as *const __m256i);
        let u_512 = _mm512_cvtepu32_epi64(u_256);

        let u_new = _mm512_xor_si512(u_512, reduced);
        let w_new = _mm512_xor_si512(w_512, u_new);

        let u_out = _mm512_cvtepi64_epi32(u_new);
        let w_out = _mm512_cvtepi64_epi32(w_new);

        _mm256_storeu_si256(u_ptr.add(i) as *mut __m256i, u_out);
        _mm256_storeu_si256(w_ptr.add(i) as *mut __m256i, w_out);

        i += 8;
    }

    // Scalar tail
    while i < len {
        let lambda_w = lambda.mul(&w[i]);
        u[i] = u[i].add(&lambda_w);
        w[i] = w[i].add(&u[i]);
        i += 1;
    }
}

/// Inline reduction for GF(2^32) - branchless
#[inline(always)]
fn reduce_gf32_inline(p: u64) -> u64 {
    let hi = p >> 32;
    let lo = p & 0xFFFFFFFF;

    // Irreducible: x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1
    // Compute reduction using shift pattern
    let tmp = hi ^ (hi >> 17) ^ (hi >> 23) ^ (hi >> 25) ^ (hi >> 28) ^ (hi >> 29);
    lo ^ tmp ^ (tmp << 3) ^ (tmp << 4) ^ (tmp << 7) ^ (tmp << 9) ^ (tmp << 15)
}

/// Vectorized GF(2^32) reduction on 4 x 64-bit products in a __m256i.
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn reduce_gf32_avx2(p: core::arch::x86_64::__m256i) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;

    let hi = _mm256_srli_epi64(p, 32);
    let mask32 = _mm256_set1_epi64x(0xFFFFFFFFi64);
    let lo = _mm256_and_si256(p, mask32);

    let tmp = _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_xor_si256(hi, _mm256_srli_epi64(hi, 17)),
            _mm256_xor_si256(_mm256_srli_epi64(hi, 23), _mm256_srli_epi64(hi, 25)),
        ),
        _mm256_xor_si256(_mm256_srli_epi64(hi, 28), _mm256_srli_epi64(hi, 29)),
    );

    let res = _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_xor_si256(lo, tmp),
            _mm256_xor_si256(_mm256_slli_epi64(tmp, 3), _mm256_slli_epi64(tmp, 4)),
        ),
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_slli_epi64(tmp, 7), _mm256_slli_epi64(tmp, 9)),
            _mm256_slli_epi64(tmp, 15),
        ),
    );

    _mm256_and_si256(res, mask32)
}

/// AVX2 FFT butterfly: fully vectorized multiply, reduce, and XOR.
///
/// Processes 4 elements per iteration using 256-bit VPCLMULQDQ.
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn fft_butterfly_gf32_avx2_impl(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    use core::arch::x86_64::*;

    assert_eq!(u.len(), w.len());
    let len = u.len();

    let lambda_val = lambda.poly().value() as u64;
    let lambda_256 = _mm256_set1_epi64x(lambda_val as i64);

    // SAFETY: BinaryElem32 is repr(transparent) over a u32 wrapper.
    let u_ptr = u.as_mut_ptr() as *mut u32;
    let w_ptr = w.as_mut_ptr() as *mut u32;

    let mut i = 0;

    while i + 4 <= len {
        // Load 4 x u32 from w, zero-extend to 4 x u64
        let w_128 = _mm_loadu_si128(w_ptr.add(i) as *const __m128i);
        let w_256 = _mm256_cvtepu32_epi64(w_128);

        // 2 VPCLMULQDQ: even lanes (0x00) and odd lanes (0x01)
        let prod_even = _mm256_clmulepi64_epi128(lambda_256, w_256, 0x00);
        let prod_odd = _mm256_clmulepi64_epi128(lambda_256, w_256, 0x01);

        // Interleave: prod_even has [p0, _, p2, _], prod_odd has [_, p1, _, p3]
        // Blend: take even lanes from prod_even, odd lanes from prod_odd
        let products = _mm256_blend_epi32(prod_even, prod_odd, 0b11001100);

        // Reduce in-register
        let reduced = reduce_gf32_avx2(products);

        // Load 4 x u32 from u, zero-extend
        let u_128 = _mm_loadu_si128(u_ptr.add(i) as *const __m128i);
        let u_256 = _mm256_cvtepu32_epi64(u_128);

        // u' = u ^ reduced, w' = w ^ u'
        let u_new = _mm256_xor_si256(u_256, reduced);
        let w_new = _mm256_xor_si256(w_256, u_new);

        // Truncate 64->32 and store (pack with shuffle)
        // Extract lower 32 bits of each 64-bit lane
        let u_packed = _mm256_shuffle_epi8(
            u_new,
            _mm256_set_epi8(
                -1, -1, -1, -1, -1, -1, -1, -1, 28, 24, 20, 16, -1, -1, -1, -1,
                -1, -1, -1, -1, 12, 8, 4, 0, -1, -1, -1, -1, -1, -1, -1, -1,
            ),
        );
        let u_lo = _mm256_extracti128_si256::<0>(u_packed);
        let u_hi = _mm256_extracti128_si256::<1>(u_packed);
        let u_out = _mm_or_si128(u_lo, u_hi);

        let w_packed = _mm256_shuffle_epi8(
            w_new,
            _mm256_set_epi8(
                -1, -1, -1, -1, -1, -1, -1, -1, 28, 24, 20, 16, -1, -1, -1, -1,
                -1, -1, -1, -1, 12, 8, 4, 0, -1, -1, -1, -1, -1, -1, -1, -1,
            ),
        );
        let w_lo = _mm256_extracti128_si256::<0>(w_packed);
        let w_hi = _mm256_extracti128_si256::<1>(w_packed);
        let w_out = _mm_or_si128(w_lo, w_hi);

        _mm_storeu_si128(u_ptr.add(i) as *mut __m128i, u_out);
        _mm_storeu_si128(w_ptr.add(i) as *mut __m128i, w_out);

        i += 4;
    }

    // Scalar tail
    while i < len {
        let lambda_w = lambda.mul(&w[i]);
        u[i] = u[i].add(&lambda_w);
        w[i] = w[i].add(&u[i]);
        i += 1;
    }
}

/// Force AVX-512 path (for benchmarking)
/// Panics if AVX-512 + VPCLMULQDQ not available
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
pub fn fft_butterfly_gf32_avx512_only(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    assert!(
        is_x86_feature_detected!("vpclmulqdq") && is_x86_feature_detected!("avx512f"),
        "AVX-512 + VPCLMULQDQ required"
    );
    // SAFETY: The assert above verified the CPU supports avx512f and vpclmulqdq.
    unsafe { fft_butterfly_gf32_avx512_impl(u, w, lambda) };
}

/// Force AVX2 path (for benchmarking)
/// Panics if AVX2 + VPCLMULQDQ not available
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
pub fn fft_butterfly_gf32_avx2_only(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    assert!(
        is_x86_feature_detected!("vpclmulqdq") && is_x86_feature_detected!("avx2"),
        "AVX2 + VPCLMULQDQ required"
    );
    // SAFETY: The assert above verified the CPU supports avx2 and vpclmulqdq.
    unsafe { fft_butterfly_gf32_avx2_impl(u, w, lambda) };
}

/// SSE vectorized FFT butterfly operation for GF(2^32)
/// computes: u[i] = u[i] + lambda*w[i]; w[i] = w[i] + u[i]
/// processes 2 elements at a time using SSE/AVX
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
pub fn fft_butterfly_gf32_sse(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    use core::arch::x86_64::*;

    assert_eq!(u.len(), w.len());
    let len = u.len();

    // irreducible polynomial for GF(2^32):
    // x^32 + x^7 + x^9 + x^15 + x^3 + 1
    const IRREDUCIBLE_32: u64 = (1u64 << 32) | 0b11001 | (1 << 7) | (1 << 9) | (1 << 15);

    // SAFETY: The cfg gate guarantees pclmulqdq is available. All intrinsics
    // operate on stack-local __m128i values with no pointer dereferences.
    unsafe {
        let lambda_val = lambda.poly().value() as u64;
        let lambda_vec = _mm_set1_epi64x(lambda_val as i64);

        let mut i = 0;

        // process 2 elements at once (2x32-bit = 64 bits, fits in one lane)
        while i + 2 <= len {
            // load w[i] and w[i+1] into 64-bit lanes
            let w0 = w[i].poly().value() as u64;
            let w1 = w[i + 1].poly().value() as u64;
            let w_vec = _mm_set_epi64x(w1 as i64, w0 as i64);

            // carryless multiply: lambda * w[i]
            let prod_lo = _mm_clmulepi64_si128(lambda_vec, w_vec, 0x00); // lambda * w0
            let prod_hi = _mm_clmulepi64_si128(lambda_vec, w_vec, 0x11); // lambda * w1

            // reduce modulo irreducible
            let p0 = _mm_extract_epi64(prod_lo, 0) as u64;
            let p1 = _mm_extract_epi64(prod_hi, 0) as u64;

            let lambda_w0 = reduce_gf32(p0, IRREDUCIBLE_32);
            let lambda_w1 = reduce_gf32(p1, IRREDUCIBLE_32);

            // u[i] = u[i] XOR lambda_w[i]
            let u0 = u[i].poly().value() ^ (lambda_w0 as u32);
            let u1 = u[i + 1].poly().value() ^ (lambda_w1 as u32);

            // w[i] = w[i] XOR u[i] (using updated u)
            let w0_new = w[i].poly().value() ^ u0;
            let w1_new = w[i + 1].poly().value() ^ u1;

            u[i] = BinaryElem32::from(u0);
            u[i + 1] = BinaryElem32::from(u1);
            w[i] = BinaryElem32::from(w0_new);
            w[i + 1] = BinaryElem32::from(w1_new);

            i += 2;
        }

        // handle remaining element
        if i < len {
            let lambda_w = lambda.mul(&w[i]);
            u[i] = u[i].add(&lambda_w);
            w[i] = w[i].add(&u[i]);
        }
    }
}

/// reduce 64-bit product modulo GF(2^32) irreducible
/// optimized branchless reduction for GF(2^32)
#[inline(always)]
fn reduce_gf32(p: u64, _irr: u64) -> u64 {
    // for 32x32 -> 64 multiplication, we need to reduce bits [63:32]
    // unrolled reduction: process high 32 bits in chunks

    let hi = p >> 32;
    let lo = p & 0xFFFFFFFF;

    // compute tmp by shifting high bits down
    // for irreducible 0b1_0000_1000_1001_1000_1001 (x^32 + x^15 + x^9 + x^7 + x^3 + 1)
    // bits set at positions: 0,3,7,9,15 -> shifts needed: 32,29,25,23,17
    let tmp = hi
        ^ (hi >> 29)  // bit 15: shift by (32-3)
        ^ (hi >> 25)  // bit 9: shift by (32-7)
        ^ (hi >> 23)  // bit 7: shift by (32-9)
        ^ (hi >> 17); // bit 3: shift by (32-15)

    // XOR with low bits and shifted tmp
    lo ^ tmp ^ (tmp << 3) ^ (tmp << 7) ^ (tmp << 9) ^ (tmp << 15)
}

/// scalar fallback for FFT butterfly
pub fn fft_butterfly_gf32_scalar(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    assert_eq!(u.len(), w.len());

    for i in 0..u.len() {
        let lambda_w = lambda.mul(&w[i]);
        u[i] = u[i].add(&lambda_w);
        w[i] = w[i].add(&u[i]);
    }
}

/// dispatch FFT butterfly to best available SIMD version
pub fn fft_butterfly_gf32(u: &mut [BinaryElem32], w: &mut [BinaryElem32], lambda: BinaryElem32) {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        // Try AVX-512 first (runtime detection), fallback to SSE
        return fft_butterfly_gf32_avx512(u, w, lambda);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        return fft_butterfly_gf32_wasm_simd(u, w, lambda);
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "pclmulqdq"),
        all(target_arch = "wasm32", target_feature = "simd128")
    )))]
    {
        fft_butterfly_gf32_scalar(u, w, lambda)
    }
}

/// WASM SIMD128 optimized FFT butterfly
/// Uses v128_xor for additions and swizzle-based table lookups for multiplication
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
pub fn fft_butterfly_gf32_wasm_simd(
    u: &mut [BinaryElem32],
    w: &mut [BinaryElem32],
    lambda: BinaryElem32,
) {
    use core::arch::wasm32::*;

    assert_eq!(u.len(), w.len());
    let len = u.len();

    // GF(2^32) irreducible: x^32 + x^7 + x^9 + x^15 + x^3 + 1
    const IRR: u64 = 0x100008299;

    // Process 4 elements at once using v128
    let mut i = 0;
    while i + 4 <= len {
        // SAFETY: The cfg gate guarantees wasm32 simd128 is available. The pointer
        // arithmetic is in bounds because the loop condition ensures i + 4 <= len.
        // The slices are contiguous and properly aligned for v128 loads/stores
        // because BinaryElem32 is repr(transparent) over a u32.
        unsafe {
            let u_vec = v128_load(u.as_ptr().add(i) as *const v128);
            let w_vec = v128_load(w.as_ptr().add(i) as *const v128);

            // Compute lambda * w[i..i+4] using swizzle-based multiply
            let w0 = w[i].poly().value();
            let w1 = w[i + 1].poly().value();
            let w2 = w[i + 2].poly().value();
            let w3 = w[i + 3].poly().value();
            let lambda_val = lambda.poly().value();

            // Multiply and reduce each element
            let p0 = mul_32x32_to_64_simd(lambda_val, w0);
            let p1 = mul_32x32_to_64_simd(lambda_val, w1);
            let p2 = mul_32x32_to_64_simd(lambda_val, w2);
            let p3 = mul_32x32_to_64_simd(lambda_val, w3);

            // Reduce mod irreducible polynomial
            let r0 = reduce_gf32_wasm(p0, IRR) as u32;
            let r1 = reduce_gf32_wasm(p1, IRR) as u32;
            let r2 = reduce_gf32_wasm(p2, IRR) as u32;
            let r3 = reduce_gf32_wasm(p3, IRR) as u32;

            // Create lambda*w vector
            let lambda_w = u32x4(r0, r1, r2, r3);

            // u[i] = u[i] ^ lambda*w[i] (GF addition is XOR)
            let new_u = v128_xor(u_vec, lambda_w);

            // w[i] = w[i] ^ new_u[i]
            let new_w = v128_xor(w_vec, new_u);

            // Store results
            v128_store(u.as_mut_ptr().add(i) as *mut v128, new_u);
            v128_store(w.as_mut_ptr().add(i) as *mut v128, new_w);
        }

        i += 4;
    }

    // Handle remaining elements
    while i < len {
        let lambda_w = lambda.mul(&w[i]);
        u[i] = u[i].add(&lambda_w);
        w[i] = w[i].add(&u[i]);
        i += 1;
    }
}

/// GF(2^32) reduction for WASM (branchless)
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
fn reduce_gf32_wasm(p: u64, _irr: u64) -> u64 {
    // Reduction for x^32 + x^7 + x^9 + x^15 + x^3 + 1
    let hi = p >> 32;
    let lo = p & 0xFFFFFFFF;
    let tmp = hi ^ (hi >> 17) ^ (hi >> 23) ^ (hi >> 25) ^ (hi >> 28) ^ (hi >> 29);
    lo ^ tmp ^ (tmp << 3) ^ (tmp << 4) ^ (tmp << 7) ^ (tmp << 9) ^ (tmp << 15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_butterfly_gf32() {
        // test SIMD vs scalar butterfly give same results
        let mut u_simd = vec![
            BinaryElem32::from(1),
            BinaryElem32::from(2),
            BinaryElem32::from(3),
            BinaryElem32::from(4),
        ];
        let mut w_simd = vec![
            BinaryElem32::from(5),
            BinaryElem32::from(6),
            BinaryElem32::from(7),
            BinaryElem32::from(8),
        ];
        let lambda = BinaryElem32::from(3);

        let mut u_scalar = u_simd.clone();
        let mut w_scalar = w_simd.clone();

        fft_butterfly_gf32(&mut u_simd, &mut w_simd, lambda);
        fft_butterfly_gf32_scalar(&mut u_scalar, &mut w_scalar, lambda);

        for i in 0..u_simd.len() {
            assert_eq!(u_simd[i], u_scalar[i], "u mismatch at index {}", i);
            assert_eq!(w_simd[i], w_scalar[i], "w mismatch at index {}", i);
        }
    }

    #[test]
    fn test_batch_add() {
        let a = vec![
            BinaryElem128::from(1),
            BinaryElem128::from(2),
            BinaryElem128::from(3),
        ];
        let b = vec![
            BinaryElem128::from(4),
            BinaryElem128::from(5),
            BinaryElem128::from(6),
        ];
        let mut out = vec![BinaryElem128::zero(); 3];

        batch_add_gf128(&a, &b, &mut out);

        for i in 0..3 {
            assert_eq!(out[i], a[i].add(&b[i]));
        }
    }

    #[test]
    fn test_batch_mul() {
        let a = vec![
            BinaryElem128::from(7),
            BinaryElem128::from(11),
            BinaryElem128::from(13),
        ];
        let b = vec![
            BinaryElem128::from(3),
            BinaryElem128::from(5),
            BinaryElem128::from(7),
        ];
        let mut out = vec![BinaryElem128::zero(); 3];

        batch_mul_gf128(&a, &b, &mut out);

        for i in 0..3 {
            assert_eq!(out[i], a[i].mul(&b[i]));
        }
    }

    #[test]
    fn test_batch_mul_large() {
        // test with larger field elements
        let a = vec![
            BinaryElem128::from(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0),
            BinaryElem128::from(u128::MAX),
        ];
        let b = vec![
            BinaryElem128::from(0x123456789ABCDEF0123456789ABCDEF0),
            BinaryElem128::from(0x8000000000000000_0000000000000000),
        ];
        let mut out = vec![BinaryElem128::zero(); 2];

        batch_mul_gf128(&a, &b, &mut out);

        for i in 0..2 {
            assert_eq!(out[i], a[i].mul(&b[i]));
        }
    }
}
