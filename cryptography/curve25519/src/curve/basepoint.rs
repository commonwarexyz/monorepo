//! Precomputed multiples of the Ed25519 basepoint.
//!
//! Multiplication by a secret scalar is constant time and uses the fixed-base method of
//! [Ed25519, section 4]. The scalar is recoded into 64 signed radix-16 digits `e[i]` in
//! `[-8, 8]`, and `sum e[i] * 16^i * B` is accumulated from a precomputed table holding
//! `k * 256^j * B` for `1 <= k <= 8` and `0 <= j < 32`. The odd digits are added first, the sum
//! is multiplied by 16 with four doublings, and the even digits are added last.
//!
//! Verification splits a public scalar at bit 128 and multiplies `B` by the low half and
//! `2^128 * B` by the high half, looking up the non-adjacent-form digits of each half in
//! [`ODD_MULTIPLES`].
//!
//! [Ed25519, section 4]: https://ed25519.cr.yp.to/ed25519-20110926.pdf

use super::{Backend, F, G, GAffine, Niels, WithBackend, with_backend};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// `TABLE[j][k]` is `(k + 1) * 256^j * B` for the Ed25519 basepoint `B`.
pub(super) static TABLE: [[Niels; 8]; 32] = table();

/// Width of the non-adjacent forms whose digits select entries of [`ODD_MULTIPLES`].
pub const ODD_MULTIPLES_NAF_WIDTH: usize = 8;

/// The number of odd multiples a width-[`ODD_MULTIPLES_NAF_WIDTH`] digit can select.
const ODD_MULTIPLES_LEN: usize = 1 << (ODD_MULTIPLES_NAF_WIDTH - 2);

/// `ODD_MULTIPLES[j][k]` is `(2k + 1) * 2^(128j) * B` for the Ed25519 basepoint `B`, so a
/// nonzero digit `d` selects `|d| * 2^(128j) * B` at index `|d| / 2`.
pub static ODD_MULTIPLES: [[Niels; ODD_MULTIPLES_LEN]; 2] = odd_multiples();

impl ConditionallySelectable for Niels {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            sum: F::conditional_select(&a.sum, &b.sum, choice),
            diff: F::conditional_select(&a.diff, &b.diff, choice),
            t2d: F::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

impl G {
    /// Multiplies the Ed25519 basepoint by a secret little-endian scalar.
    ///
    /// Bit 255 of `scalar` must be clear. Every scalar performs the same table reads and point
    /// operations, selecting table entries with masks rather than secret-dependent branches or
    /// indexing.
    #[inline(never)]
    pub fn mul_base_secret(scalar: &[u8; 32]) -> Self {
        with_backend(MulBase(scalar))
    }
}

/// A secret scalar for [`G::mul_base_secret`], multiplied with the selected backend's
/// single-point operations.
struct MulBase<'a>(&'a [u8; 32]);

impl WithBackend for MulBase<'_> {
    type Output = G;

    // Inlined so the algorithm compiles inside the backend's target-feature entry, where its
    // point operations can inline.
    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> G {
        mul_base(backend, &Zeroizing::new(digits(self.0)))
    }
}

/// Returns `sum e[i] * 16^i * B` for the radix-16 digits `e` of [`digits`].
///
/// Pair `j` holds digits `e[2j]` and `e[2j+1]`, both read from row `j`. Adding the odd digits,
/// multiplying by 16 with four doublings, and then adding the even digits gives
/// `sum (16 * e[2j+1] + e[2j]) * 256^j * B`. Every digit costs one constant-time
/// [`Backend::add_selected`].
#[inline(always)]
fn mul_base<B: Backend>(backend: B, digits: &[i8; 64]) -> G {
    let pairs = digits.as_chunks::<2>().0;
    let mut result = backend.identity();
    for (row, pair) in TABLE.iter().zip(pairs) {
        result = backend.to_extended(backend.add_selected(result, row, pair[1]));
    }

    // Only the last doubling feeds an addition, which reads `T`.
    let mut multiple = backend.project(result);
    for _ in 0..3 {
        multiple = backend.to_projective(backend.double(multiple));
    }
    result = backend.to_extended(backend.double(multiple));

    for (row, pair) in TABLE.iter().zip(pairs) {
        result = backend.to_extended(backend.add_selected(result, row, pair[0]));
    }
    backend.store(result)
}

/// Recodes a scalar below `2^255` as `sum e[i] * 16^i`, with `e[i]` in `[-8, 7]` for `i < 63`
/// and `e[63]` in `[0, 8]`.
#[inline]
fn digits(scalar: &[u8; 32]) -> [i8; 64] {
    debug_assert!(scalar[31] >> 7 == 0);
    let mut digits = [0i8; 64];
    for (pair, byte) in digits.as_chunks_mut::<2>().0.iter_mut().zip(scalar) {
        *pair = [(byte & 15) as i8, (byte >> 4) as i8];
    }

    // Wrapping operations keep overflow checks, which would branch on the digits, out of the
    // recoding. Each digit is in [0, 16] after absorbing the previous carry, so none of them
    // wraps and the carry is 0 or 1.
    let mut carry = 0i8;
    for digit in &mut digits[..63] {
        let value = digit.wrapping_add(carry);
        carry = value.wrapping_add(8) >> 4;
        *digit = value.wrapping_sub(carry << 4);
    }
    digits[63] = digits[63].wrapping_add(carry);
    digits
}

/// Returns `digit * P` from `row[k] = (k + 1) * P`, for `digit` in `[-8, 8]`.
///
/// Every entry is read and combined with a mask, so neither the access pattern nor the control
/// flow depends on `digit`.
#[inline]
pub(super) fn select(row: &[Niels; 8], digit: i8) -> Niels {
    // The sign bit, and `|digit|` computed with the two's complement identity.
    let negative = (digit as u8) >> 7;
    let magnitude = ((digit as u8) ^ 0u8.wrapping_sub(negative)).wrapping_add(negative);
    let mut point = Niels::IDENTITY;
    for (k, entry) in (1u8..).zip(row) {
        point.conditional_assign(entry, magnitude.ct_eq(&k));
    }
    let negated = Niels {
        sum: point.diff,
        diff: point.sum,
        t2d: point.t2d.neg(),
    };
    Niels::conditional_select(&point, &negated, Choice::from(negative))
}

/// Builds [`TABLE`] at compile time from [`GAffine::BASEPOINT`].
const fn table() -> [[Niels; 8]; 32] {
    // `points[8 * j + k]` is `(k + 1) * p` for `p = 256^j * B`, built by repeated addition.
    let mut p = GAffine::BASEPOINT.to_extended();
    let mut points = [G::IDENTITY; 256];
    let mut j = 0;
    while j < 32 {
        let mut multiple = p;
        let mut k = 0;
        while k < 8 {
            points[8 * j + k] = multiple;
            multiple = multiple.add(p);
            k += 1;
        }

        // `256 * p = 32 * (8 * p)`.
        p = points[8 * j + 7];
        let mut doubling = 0;
        while doubling < 5 {
            p = p.add(p);
            doubling += 1;
        }
        j += 1;
    }

    let niels = to_niels(&points);
    let mut table = [[Niels::IDENTITY; 8]; 32];
    let mut i = 0;
    while i < 256 {
        table[i / 8][i % 8] = niels[i];
        i += 1;
    }
    table
}

/// Builds [`ODD_MULTIPLES`] at compile time from [`GAffine::BASEPOINT`].
const fn odd_multiples() -> [[Niels; ODD_MULTIPLES_LEN]; 2] {
    // `points[ODD_MULTIPLES_LEN * j + k]` is `(2k + 1) * p` for `p = 2^(128j) * B`, built by
    // repeatedly adding `2 * p`.
    let mut p = GAffine::BASEPOINT.to_extended();
    let mut points = [G::IDENTITY; 2 * ODD_MULTIPLES_LEN];
    let mut j = 0;
    while j < 2 {
        let double = p.add(p);
        let mut multiple = p;
        let mut k = 0;
        while k < ODD_MULTIPLES_LEN {
            points[ODD_MULTIPLES_LEN * j + k] = multiple;
            multiple = multiple.add(double);
            k += 1;
        }

        let mut doubling = 0;
        while doubling < 128 {
            p = p.add(p);
            doubling += 1;
        }
        j += 1;
    }

    let niels = to_niels(&points);
    let mut table = [[Niels::IDENTITY; ODD_MULTIPLES_LEN]; 2];
    let mut i = 0;
    while i < 2 * ODD_MULTIPLES_LEN {
        table[i / ODD_MULTIPLES_LEN][i % ODD_MULTIPLES_LEN] = niels[i];
        i += 1;
    }
    table
}

/// Normalizes extended points to [`Niels`] form at compile time, inverting every `Z` with one
/// shared inversion.
const fn to_niels<const N: usize>(points: &[G; N]) -> [Niels; N] {
    // `prefix[i]` is the product of the first `i` Z coordinates.
    let mut prefix = [F::ONE; N];
    let mut product = F::ONE;
    let mut i = 0;
    while i < N {
        prefix[i] = product;
        product = product.mul(points[i].z);
        i += 1;
    }

    // On entry to each iteration, `inverse` inverts the product of the first `i` Z coordinates.
    let mut inverse = product.invert();
    let mut niels = [Niels::IDENTITY; N];
    while i > 0 {
        i -= 1;
        let z_inverse = inverse.mul(prefix[i]);
        inverse = inverse.mul(points[i].z);
        let x = points[i].x.mul(z_inverse);
        let y = points[i].y.mul(z_inverse);
        niels[i] = Niels {
            sum: y.add(x),
            diff: y.sub(x),
            t2d: x.mul(y).mul(F::EDWARDS_D2),
        };
    }
    niels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the bits of a little-endian scalar, most significant first.
    fn bits(scalar: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
        (0..256).rev().map(|i| scalar[i / 8] >> (i % 8) & 1 == 1)
    }

    #[test]
    fn table_matches_scalar_multiples() {
        let base = GAffine::BASEPOINT.to_extended();
        for (j, row) in TABLE.iter().enumerate() {
            for (k, entry) in row.iter().enumerate() {
                // `(k + 1) * 256^j` as a little-endian scalar.
                let mut scalar = [0u8; 32];
                scalar[j] = k as u8 + 1;
                assert_niels_eq(entry, base.scalar_mul(bits(&scalar)));
            }
        }
    }

    #[test]
    fn odd_multiples_match_scalar_multiples() {
        let base = GAffine::BASEPOINT.to_extended();
        for (j, row) in ODD_MULTIPLES.iter().enumerate() {
            for (k, entry) in row.iter().enumerate() {
                // `(2k + 1) * 2^(128j)` as a little-endian scalar.
                let mut scalar = [0u8; 32];
                scalar[16 * j] = 2 * k as u8 + 1;
                assert_niels_eq(entry, base.scalar_mul(bits(&scalar)));
            }
        }
    }

    /// Asserts that `entry` is the [`Niels`] form of `expected`.
    fn assert_niels_eq(entry: &Niels, expected: G) {
        let z_inverse = expected.z.invert();
        let x = expected.x.mul(z_inverse);
        let y = expected.y.mul(z_inverse);
        assert!(entry.sum.eq(&y.add(x)));
        assert!(entry.diff.eq(&y.sub(x)));
        assert!(entry.t2d.eq(&x.mul(y).mul(F::EDWARDS_D2)));
    }

    #[test]
    fn digits_recompose_scalar() {
        let scalars = [[0u8; 32], [0x88; 32], [0xff; 32], [0x77; 32]].map(|mut scalar| {
            scalar[31] &= 0x7f;
            scalar
        });
        for scalar in scalars {
            let digits = digits(&scalar);
            assert!(digits[..63].iter().all(|digit| (-8..8).contains(digit)));
            assert!((0..=8).contains(&digits[63]));

            // Recompose `sum e[i] * 16^i` one byte at a time.
            let mut bytes = [0u8; 32];
            let mut carry = 0i32;
            for (byte, pair) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
                let value = carry + i32::from(pair[0]) + 16 * i32::from(pair[1]);
                *byte = value.rem_euclid(256) as u8;
                carry = value.div_euclid(256);
            }
            assert_eq!(carry, 0);
            assert_eq!(bytes, scalar);
        }
    }

    #[test]
    fn mul_base_secret_matches_public() {
        // Zero, small values, every digit at its extremes, the group order, and the maximum.
        let order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut scalars = vec![[0u8; 32], [0x88; 32], [0xff; 32], [0x77; 32], order];
        scalars.extend((1..=17).map(|value| {
            let mut scalar = [0u8; 32];
            scalar[0] = value;
            scalar
        }));
        for scalar in &mut scalars {
            scalar[31] &= 0x7f;
        }

        let base = GAffine::BASEPOINT.to_extended();
        for scalar in scalars {
            assert_eq!(
                G::mul_base_secret(&scalar).compress(),
                base.scalar_mul(bits(&scalar)).compress()
            );
        }

        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let mut scalar: [u8; 32] = u.arbitrary()?;
                scalar[31] &= 0x7f;
                assert_eq!(
                    G::mul_base_secret(&scalar).compress(),
                    base.scalar_mul(bits(&scalar)).compress()
                );
                Ok(())
            });
    }
}
