//! GF(2^8) field arithmetic using the AES irreducible polynomial.
//!
//! This module provides GF(2^8) multiplication and inversion via precomputed
//! log/exp tables. The AES polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B) is
//! used to match hardware GFNI instructions, ensuring scalar and SIMD paths
//! produce identical results.

/// Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1.
const POLYNOMIAL: u16 = 0x11B;

/// Primitive element (generator of the multiplicative group).
/// 3 (= x + 1) is a generator for GF(2^8) with the AES polynomial 0x11B.
/// It has multiplicative order 255 = 2^8 - 1.
#[cfg(test)]
const GENERATOR: u8 = 0x03;

/// `EXP[i] = GENERATOR^i mod POLYNOMIAL`.
///
/// Extended to 512 entries so that `EXP[LOG[a] + LOG[b]]` never requires
/// modular reduction -- the sum of two log values is at most 254 + 254 = 508.
const EXP: [u8; 512] = {
    let mut table = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0;
    while i < 255 {
        table[i] = val as u8;
        // Multiply by GENERATOR (0x03 = x + 1) in GF(2^8):
        // val * 3 = val * 2 XOR val = (val << 1) XOR val, with reduction
        let shifted = val << 1;
        val = if shifted & 0x100 != 0 {
            (shifted ^ POLYNOMIAL) ^ (val)
        } else {
            shifted ^ val
        };
        i += 1;
    }
    // EXP[255] should wrap to EXP[0] = 1
    // Fill 255..512 with the cyclic extension
    let mut i = 255;
    while i < 512 {
        table[i] = table[i - 255];
        i += 1;
    }
    table
};

/// `LOG[x]` = discrete log base `GENERATOR` of `x`.
///
/// `LOG[0]` is set to 0 as a sentinel (never used in valid multiplication).
const LOG: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0u16;
    while i < 255 {
        table[EXP[i as usize] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Multiply two GF(2^8) elements using log/exp tables.
#[inline(always)]
pub const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[(LOG[a as usize] as usize) + (LOG[b as usize] as usize)]
}

/// Multiplicative inverse in GF(2^8).
///
/// Returns 0 for input 0 (by convention).
#[inline(always)]
pub const fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    EXP[255 - LOG[a as usize] as usize]
}

/// Precompute the split-nibble lookup tables for multiplying by constant `c`.
///
/// Returns `(low_table, high_table)`, each 16 bytes, such that:
/// ```text
/// mul(c, x) == low_table[x & 0x0F] ^ high_table[x >> 4]
/// ```
///
/// This identity holds because GF(2^8) multiplication distributes over XOR
/// (addition in the field).
#[inline]
pub fn init_mul_table(c: u8) -> ([u8; 16], [u8; 16]) {
    let mut low = [0u8; 16];
    let mut high = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        low[i] = mul(c, i as u8);
        high[i] = mul(c, (i as u8) << 4);
        i += 1;
    }
    (low, high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_table_starts_at_one() {
        assert_eq!(EXP[0], 1, "EXP[0] should be 1 (GENERATOR^0)");
    }

    #[test]
    fn test_exp_table_generator() {
        assert_eq!(EXP[1], GENERATOR, "EXP[1] should be GENERATOR");
    }

    #[test]
    fn test_exp_table_cyclic() {
        for i in 0..255 {
            assert_eq!(EXP[i], EXP[i + 255], "EXP not cyclic at {i}");
        }
    }

    #[test]
    fn test_log_exp_roundtrip() {
        for x in 1..=255u8 {
            assert_eq!(EXP[LOG[x as usize] as usize], x, "log/exp roundtrip failed for {x}");
        }
    }

    #[test]
    fn test_mul_zero() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
        }
    }

    #[test]
    fn test_mul_one() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
        }
    }

    #[test]
    fn test_all_inverses() {
        for a in 1..=255u8 {
            let a_inv = inv(a);
            assert_eq!(mul(a, a_inv), 1, "inv({a}) = {a_inv}, but a * inv(a) != 1");
        }
    }

    #[test]
    fn test_inv_zero() {
        assert_eq!(inv(0), 0);
    }

    #[test]
    fn test_mul_commutative() {
        for a in 0..=255u16 {
            for b in 0..=255u16 {
                assert_eq!(
                    mul(a as u8, b as u8),
                    mul(b as u8, a as u8),
                    "commutativity failed for ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_mul_associative() {
        for a in (0..=255u16).step_by(7) {
            for b in (0..=255u16).step_by(11) {
                for c in (0..=255u16).step_by(13) {
                    let (a, b, c) = (a as u8, b as u8, c as u8);
                    assert_eq!(
                        mul(mul(a, b), c),
                        mul(a, mul(b, c)),
                        "associativity failed for ({a}, {b}, {c})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_mul_distributes_over_xor() {
        for a in (0..=255u16).step_by(3) {
            for b in (0..=255u16).step_by(5) {
                for c in (0..=255u16).step_by(7) {
                    let (a, b, c) = (a as u8, b as u8, c as u8);
                    assert_eq!(
                        mul(a, b ^ c),
                        mul(a, b) ^ mul(a, c),
                        "distributivity failed for ({a}, {b}, {c})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_generator_order() {
        let mut val = GENERATOR;
        for i in 1..255u32 {
            assert_ne!(val, 1, "generator has order {i}, expected 255");
            val = mul(val, GENERATOR);
        }
        assert_eq!(val, 1, "generator does not have order 255");
    }

    #[test]
    fn test_init_mul_table() {
        // Verify split-nibble tables produce correct results for all inputs
        for c in 0..=255u8 {
            let (low, high) = init_mul_table(c);
            for x in 0..=255u8 {
                let expected = mul(c, x);
                let got = low[(x & 0x0F) as usize] ^ high[(x >> 4) as usize];
                assert_eq!(got, expected, "split-nibble mismatch for c={c}, x={x}");
            }
        }
    }

    #[test]
    fn test_known_values() {
        // Cross-check a few known GF(2^8) products with AES polynomial
        assert_eq!(mul(0x53, 0xCA), 0x01); // from AES spec
        assert_eq!(mul(2, 0x80), 0x1B); // 2 * 0x80 = x * x^7 = x^8 = x^4+x^3+x+1 = 0x1B
    }
}
