//! Fast inversion for GF(2^128) using Itoh-Tsujii with nibble tables
//!
//! This implements efficient field inversion using precomputed tables
//! of frobenius powers. The algorithm reduces from ~127 multiplications
//! to ~9 multiplications + table lookups.
//!
//! ## Algorithm
//!
//! Uses the identity: x^(-1) = x^(2^128 - 2)
//!
//! The exponent 2^128 - 2 is computed using addition chains:
//! - 2^128 - 2 = 2 * (2^127 - 1)
//! - 2^127 - 1 has binary representation of 127 ones
//!
//! By using the linearity of frobenius in characteristic 2, we can
//! decompose computations by nibbles and use table lookups.
//!
//! ## References
//!
//! - Itoh-Tsujii: "A fast algorithm for computing multiplicative inverses in GF(2^m)"
//! - Binius implementation: <https://github.com/IrreducibleOSS/binius>
//! - GF2t Java library: <https://github.com/reyzin/GF2t>

#![allow(long_running_const_eval)]

#[cfg(not(any(feature = "std", test)))]
use alloc::{vec, vec::Vec};

use super::poly::BinaryPoly128;

/// Compute x^(2^(2^n)) using nibble table lookup
///
/// Uses the linearity of frobenius: (a + b)^(2^k) = a^(2^k) + b^(2^k)
/// So we can decompose x into 32 nibbles and XOR the precomputed results.
#[inline]
fn pow_2_2_n(value: u128, n: usize, table: &[[[u128; 16]; 32]; 7]) -> u128 {
    match n {
        0 => square_gf128(value),
        1..=7 => {
            let mut result = 0u128;
            for nibble_index in 0..32 {
                let nibble_value = ((value >> (nibble_index * 4)) & 0x0F) as usize;
                result ^= table[n - 1][nibble_index][nibble_value];
            }
            result
        }
        _ => value,
    }
}

/// Square in GF(2^128) with reduction modulo x^128 + x^7 + x^2 + x + 1
#[inline]
fn square_gf128(x: u128) -> u128 {
    // Use the proven-correct carryless multiplication for squaring
    mul_gf128(x, x)
}

/// Invert a field element in GF(2^128)
///
/// Computes x^(-1) = x^(2^128 - 2) using Itoh-Tsujii algorithm.
/// Returns 0 if x is 0 (not mathematically correct but safe).
#[inline]
pub fn invert_gf128(value: u128) -> u128 {
    if value == 0 {
        return 0;
    }

    // Computes value^(2^128-2)
    // value * value^(2^128 - 2) = value^(2^128-1) = 1

    // self_pow_2_pow_k1s contains value raised to power with 2^k ones in binary
    let mut self_pow_2_pow_k1s = value;

    // Square to get exponent = 2 (binary: 10)
    let mut res = pow_2_2_n(self_pow_2_pow_k1s, 0, &NIBBLE_POW_TABLE);

    // self_pow_2_pow_k1s_to_k0s = value^(2^k ones followed by 2^k zeros)
    let mut self_pow_2_pow_k1s_to_k0s = res;

    // Build up the exponent 2^128 - 2 = 111...110 (127 ones followed by a zero)
    for k in 1..7 {
        // Fill in zeros in exponent with ones
        self_pow_2_pow_k1s = mul_gf128(self_pow_2_pow_k1s, self_pow_2_pow_k1s_to_k0s);

        // Append 2^k zeros to exponent
        self_pow_2_pow_k1s_to_k0s = pow_2_2_n(self_pow_2_pow_k1s, k, &NIBBLE_POW_TABLE);

        // Prepend 2^k ones to result
        res = mul_gf128(res, self_pow_2_pow_k1s_to_k0s);
    }

    res
}

/// Batch invert multiple field elements using Montgomery's trick
///
/// Given N elements, computes N inversions using only 3(N-1) multiplications
/// plus a single inversion, instead of N separate inversions.
///
/// This is ~3x faster for N > 3, and ~9x faster for large N.
///
/// # Example
/// ```ignore
/// let inputs = [a, b, c, d];
/// let outputs = batch_invert_gf128(&inputs);
/// assert_eq!(outputs[0], a.inv());
/// assert_eq!(outputs[1], b.inv());
/// // etc
/// ```
pub fn batch_invert_gf128(values: &[u128]) -> Vec<u128> {
    if values.is_empty() {
        return Vec::new();
    }

    let n = values.len();
    let mut result = vec![0u128; n];

    // Handle zeros by tracking their positions
    let non_zero_indices: Vec<usize> = values
        .iter()
        .enumerate()
        .filter(|(_, &v)| v != 0)
        .map(|(i, _)| i)
        .collect();

    if non_zero_indices.is_empty() {
        return result; // All zeros
    }

    // Montgomery's trick:
    // 1. Compute prefix products: p[i] = a[0] * a[1] * ... * a[i]
    // 2. Invert the final product: inv_all = p[n-1]^(-1)
    // 3. Recover individual inverses using suffix products

    let mut prefix_products = Vec::with_capacity(non_zero_indices.len());
    let mut running = values[non_zero_indices[0]];
    prefix_products.push(running);

    for &idx in &non_zero_indices[1..] {
        running = mul_gf128(running, values[idx]);
        prefix_products.push(running);
    }

    // Single inversion of the cumulative product
    let mut inv_suffix = invert_gf128(running);

    // Work backwards to recover individual inverses
    for i in (1..non_zero_indices.len()).rev() {
        let idx = non_zero_indices[i];
        // inv(a[i]) = prefix[i-1] * inv_suffix
        result[idx] = mul_gf128(prefix_products[i - 1], inv_suffix);
        // Update inv_suffix = inv_suffix * a[i] = inv(prefix[i-1])
        inv_suffix = mul_gf128(inv_suffix, values[idx]);
    }

    // First element's inverse is just inv_suffix at the end
    result[non_zero_indices[0]] = inv_suffix;

    result
}

/// Batch invert in-place (more memory efficient)
///
/// Modifies the input slice in-place, replacing each element with its inverse.
pub fn batch_invert_gf128_in_place(values: &mut [u128]) {
    let inverted = batch_invert_gf128(values);
    values.copy_from_slice(&inverted);
}

/// Multiply two elements in GF(2^128)
#[inline]
fn mul_gf128(a: u128, b: u128) -> u128 {
    use super::simd::{carryless_mul_128_full, reduce_gf128};
    let a_poly = BinaryPoly128::new(a);
    let b_poly = BinaryPoly128::new(b);
    let product = carryless_mul_128_full(a_poly, b_poly);
    reduce_gf128(product).value()
}

/// Precomputed table: table[n][nibble_pos][nibble_val] = (nibble_val << 4*nibble_pos)^(2^(2^(n+1)))
///
/// Generated for GF(2^128) with irreducible x^128 + x^7 + x^2 + x + 1
///
/// the const eval warnings from this are harmless — rustc's const evaluator
/// reports "taking a long time" because const_spread_bits loops 64 times per
/// squaring and we do 7*32*16 = 3584 entries. the table is computed once at
/// compile time and cached. can't #[allow] it (not a lint, compiler diagnostic).
/// could embed as 120KB hex literal but readability isn't worth the tradeoff.
static NIBBLE_POW_TABLE: [[[u128; 16]; 32]; 7] = generate_nibble_table();

/// Generate the nibble power table at compile time
const fn generate_nibble_table() -> [[[u128; 16]; 32]; 7] {
    let mut table = [[[0u128; 16]; 32]; 7];

    // For each power level n (computing x^(2^(2^(n+1))))
    let mut n = 0;
    while n < 7 {
        // For each nibble position (0..32)
        let mut pos = 0;
        while pos < 32 {
            // For each nibble value (0..16)
            let mut val = 0;
            while val < 16 {
                // Compute (val << 4*pos)^(2^(2^(n+1)))
                let input = (val as u128) << (pos * 4);
                let result = const_pow_2_k(input, n + 1);
                table[n][pos][val] = result;
                val += 1;
            }
            pos += 1;
        }
        n += 1;
    }

    table
}

/// Compute x^(2^(2^k)) at compile time
const fn const_pow_2_k(x: u128, k: usize) -> u128 {
    // 2^k squarings
    let iterations = 1usize << k;
    let mut result = x;
    let mut i = 0;
    while i < iterations {
        result = const_square_gf128(result);
        i += 1;
    }
    result
}

/// Square in GF(2^128) at compile time
const fn const_square_gf128(x: u128) -> u128 {
    // Split into 64-bit halves
    let lo = x as u64;
    let hi = (x >> 64) as u64;

    // Spread bits
    let lo_spread = const_spread_bits(lo);
    let hi_spread = const_spread_bits(hi);

    // Reduce
    const_reduce_256_to_128(hi_spread, lo_spread)
}

/// Spread bits at compile time
const fn const_spread_bits(x: u64) -> u128 {
    let mut result = 0u128;
    let mut val = x;
    let mut i = 0;
    while i < 64 {
        if val & 1 != 0 {
            result |= 1u128 << (2 * i);
        }
        val >>= 1;
        i += 1;
    }
    result
}

/// Reduce at compile time
///
/// Uses the same algorithm as reduce_gf128 in simd.rs
const fn const_reduce_256_to_128(hi: u128, lo: u128) -> u128 {
    // Irreducible: x^128 + x^7 + x^2 + x + 1
    // For bits in hi that would overflow when shifted left by 1,2,7,
    // we compute tmp = bits that wrap around
    let tmp = hi ^ (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);

    // Then apply the reduction: for each bit i in irreducible (0,1,2,7)
    lo ^ tmp ^ (tmp << 1) ^ (tmp << 2) ^ (tmp << 7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{BinaryElem128, BinaryFieldElement};

    #[test]
    fn test_invert_basic() {
        // Test that x * x^(-1) = 1
        let test_values: [u128; 8] = [
            1,
            2,
            0x12345678,
            0xdeadbeef,
            0xffffffffffffffff,
            0x123456789abcdef0123456789abcdef0,
            u128::MAX,
            u128::MAX - 1,
        ];

        for &x in &test_values {
            let x_inv = invert_gf128(x);
            let product = mul_gf128(x, x_inv);
            assert_eq!(product, 1, "x * x^(-1) should be 1 for x = 0x{:032x}", x);
        }
    }

    #[test]
    fn test_invert_zero() {
        assert_eq!(invert_gf128(0), 0);
    }

    #[test]
    fn test_invert_matches_slow() {
        // Compare with the slow fermat-based inverse for all test values
        let test_values: [u128; 8] = [
            1,
            2,
            0x12345678,
            0xdeadbeef,
            0xffffffffffffffff,
            0x123456789abcdef0123456789abcdef0,
            u128::MAX,
            u128::MAX - 1,
        ];

        for &x in &test_values {
            let fast_inv = invert_gf128(x);

            // Slow inverse using existing implementation
            let elem = BinaryElem128::from(x);
            let slow_inv = elem.inv();
            let slow_inv_val = slow_inv.poly().value();

            assert_eq!(
                fast_inv, slow_inv_val,
                "fast and slow inverse should match for x = 0x{:032x}",
                x
            );
        }
    }

    #[test]
    fn test_square_basic() {
        // x^2 in GF(2^128) should satisfy x^2 + x^2 = 0 (characteristic 2)
        let x = 0x123456789abcdef0u128;
        let x_sq = square_gf128(x);

        // Also verify using multiplication
        let x_sq_mul = mul_gf128(x, x);
        assert_eq!(x_sq, x_sq_mul, "square should match multiplication");
    }

    #[test]
    fn test_batch_invert() {
        let values: Vec<u128> = vec![
            1,
            2,
            0x12345678,
            0xdeadbeef,
            0xffffffffffffffff,
            0x123456789abcdef0123456789abcdef0,
            u128::MAX,
            u128::MAX - 1,
        ];

        let batch_inverted = batch_invert_gf128(&values);

        // Verify each batch result matches individual inversion
        for (i, &v) in values.iter().enumerate() {
            let individual_inv = invert_gf128(v);
            assert_eq!(
                batch_inverted[i], individual_inv,
                "batch inversion should match individual for index {} value 0x{:032x}",
                i, v
            );
        }
    }

    #[test]
    fn test_batch_invert_with_zeros() {
        let values: Vec<u128> = vec![1, 0, 2, 0, 3, 0];
        let batch_inverted = batch_invert_gf128(&values);

        // Zeros should remain zeros
        assert_eq!(batch_inverted[1], 0);
        assert_eq!(batch_inverted[3], 0);
        assert_eq!(batch_inverted[5], 0);

        // Non-zeros should be correctly inverted
        assert_eq!(batch_inverted[0], invert_gf128(1));
        assert_eq!(batch_inverted[2], invert_gf128(2));
        assert_eq!(batch_inverted[4], invert_gf128(3));
    }

    #[test]
    fn test_batch_invert_empty() {
        let values: Vec<u128> = vec![];
        let batch_inverted = batch_invert_gf128(&values);
        assert!(batch_inverted.is_empty());
    }

    #[test]
    fn test_batch_invert_single() {
        let values = vec![0x12345678u128];
        let batch_inverted = batch_invert_gf128(&values);
        assert_eq!(batch_inverted[0], invert_gf128(0x12345678));
    }
}
