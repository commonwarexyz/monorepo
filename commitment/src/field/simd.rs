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

/// AVX-512 implementation using 512-bit VPCLMULQDQ
/// Processes 8 elements at once using full 512-bit vectors
/// Requires Rust 1.89+ for _mm512_extracti64x4_epi64
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
    // Broadcast lambda to all 8 lanes of 512-bit vector
    let lambda_512 = _mm512_set1_epi64(lambda_val as i64);

    let mut i = 0;

    // Process 8 elements at once using 512-bit vectors
    // VPCLMULQDQ on 512-bit does 4 clmuls per instruction (one per 128-bit lane)
    // We pack elements: [w0, w1] [w2, w3] [w4, w5] [w6, w7] in 4 x 128-bit lanes
    while i + 8 <= len {
        // Load 8 w elements into 512-bit vector
        // Each 128-bit lane holds 2 elements for clmul
        let w_512 = _mm512_set_epi64(
            w[i + 7].poly().value() as i64,
            w[i + 6].poly().value() as i64,
            w[i + 5].poly().value() as i64,
            w[i + 4].poly().value() as i64,
            w[i + 3].poly().value() as i64,
            w[i + 2].poly().value() as i64,
            w[i + 1].poly().value() as i64,
            w[i].poly().value() as i64,
        );

        // VPCLMULQDQ selector 0x00: multiply low 64-bits of each 128-bit lane
        // This gives us: lambda*w[0], lambda*w[2], lambda*w[4], lambda*w[6]
        let prod_even = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x00);

        // VPCLMULQDQ selector 0x01: multiply low of first operand with high of second
        // This gives us: lambda*w[1], lambda*w[3], lambda*w[5], lambda*w[7]
        let prod_odd = _mm512_clmulepi64_epi128(lambda_512, w_512, 0x01);

        // Extract 256-bit halves using _mm512_extracti64x4_epi64 (Rust 1.89+)
        let prod_even_lo: __m256i = _mm512_extracti64x4_epi64::<0>(prod_even);
        let prod_even_hi: __m256i = _mm512_extracti64x4_epi64::<1>(prod_even);
        let prod_odd_lo: __m256i = _mm512_extracti64x4_epi64::<0>(prod_odd);
        let prod_odd_hi: __m256i = _mm512_extracti64x4_epi64::<1>(prod_odd);

        // Extract individual 64-bit products
        let p0 = _mm256_extract_epi64::<0>(prod_even_lo) as u64; // lambda * w[0]
        let p2 = _mm256_extract_epi64::<2>(prod_even_lo) as u64; // lambda * w[2]
        let p4 = _mm256_extract_epi64::<0>(prod_even_hi) as u64; // lambda * w[4]
        let p6 = _mm256_extract_epi64::<2>(prod_even_hi) as u64; // lambda * w[6]

        let p1 = _mm256_extract_epi64::<0>(prod_odd_lo) as u64; // lambda * w[1]
        let p3 = _mm256_extract_epi64::<2>(prod_odd_lo) as u64; // lambda * w[3]
        let p5 = _mm256_extract_epi64::<0>(prod_odd_hi) as u64; // lambda * w[5]
        let p7 = _mm256_extract_epi64::<2>(prod_odd_hi) as u64; // lambda * w[7]

        // Reduce all 8 products
        let lw = [
            reduce_gf32_inline(p0) as u32,
            reduce_gf32_inline(p1) as u32,
            reduce_gf32_inline(p2) as u32,
            reduce_gf32_inline(p3) as u32,
            reduce_gf32_inline(p4) as u32,
            reduce_gf32_inline(p5) as u32,
            reduce_gf32_inline(p6) as u32,
            reduce_gf32_inline(p7) as u32,
        ];

        // u[i] = u[i] XOR lambda_w[i], then w[i] = w[i] XOR u[i]
        for j in 0..8 {
            let u_val = u[i + j].poly().value() ^ lw[j];
            let w_val = w[i + j].poly().value() ^ u_val;
            u[i + j] = BinaryElem32::from(u_val);
            w[i + j] = BinaryElem32::from(w_val);
        }

        i += 8;
    }

    // Handle remaining elements with scalar
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

/// AVX2 vectorized FFT butterfly operation for GF(2^32)
/// Processes 4 elements at once using 256-bit VPCLMULQDQ
/// For CPUs with AVX2 but not AVX-512
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
    // Broadcast lambda to both 128-bit lanes
    let lambda_256 = _mm256_set1_epi64x(lambda_val as i64);

    let mut i = 0;

    // Process 4 elements at once using 256-bit vectors
    // VPCLMULQDQ on 256-bit does 2 clmuls per instruction (one per 128-bit lane)
    while i + 4 <= len {
        // Load 4 w elements: [w0, w1] in low lane, [w2, w3] in high lane
        let w_256 = _mm256_set_epi64x(
            w[i + 3].poly().value() as i64,
            w[i + 2].poly().value() as i64,
            w[i + 1].poly().value() as i64,
            w[i].poly().value() as i64,
        );

        // Selector 0x00: multiply low 64-bits of each 128-bit lane
        // Gives: lambda*w[0], lambda*w[2]
        let prod_even = _mm256_clmulepi64_epi128(lambda_256, w_256, 0x00);

        // Selector 0x01: multiply low of first with high of second
        // Gives: lambda*w[1], lambda*w[3]
        let prod_odd = _mm256_clmulepi64_epi128(lambda_256, w_256, 0x01);

        // Extract products
        let p0 = _mm256_extract_epi64::<0>(prod_even) as u64;
        let p2 = _mm256_extract_epi64::<2>(prod_even) as u64;
        let p1 = _mm256_extract_epi64::<0>(prod_odd) as u64;
        let p3 = _mm256_extract_epi64::<2>(prod_odd) as u64;

        // Reduce all 4 products
        let lw = [
            reduce_gf32_inline(p0) as u32,
            reduce_gf32_inline(p1) as u32,
            reduce_gf32_inline(p2) as u32,
            reduce_gf32_inline(p3) as u32,
        ];

        // u[i] = u[i] XOR lambda_w[i], then w[i] = w[i] XOR u[i]
        for j in 0..4 {
            let u_val = u[i + j].poly().value() ^ lw[j];
            let w_val = w[i + j].poly().value() ^ u_val;
            u[i + j] = BinaryElem32::from(u_val);
            w[i + j] = BinaryElem32::from(w_val);
        }

        i += 4;
    }

    // Handle remaining elements with scalar
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
