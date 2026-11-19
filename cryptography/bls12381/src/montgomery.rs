//! Arithmetic on canonical multi-word integers.
//!
//! The base and scalar fields share the modular arithmetic and the conversions between
//! big-endian bytes and words. Only the base field inverts with [`invert`]; the scalar field
//! raises to the power `r - 2`. The scalar field splits scalars with [`mul_words`] and
//! [`divide`].
//!
//! Integers are little-endian words. Unless a function states otherwise, it takes integers below
//! the modulus and returns the same. The functions are `const fn` so that field constants can be
//! derived at compile time.

/// Computes `-m^(-1) mod 2^64` for an odd modulus word `m` by Newton iteration.
pub const fn negated_inverse(m: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Returns `a - b` modulo `2^(64 N)` and whether it borrowed.
pub const fn sub_words<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
    let mut difference = [0; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let wide = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow as u128);
        difference[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    (difference, borrow == 1)
}

/// Returns whether `value < modulus`.
pub const fn is_below<const N: usize>(value: &[u64; N], modulus: &[u64; N]) -> bool {
    sub_words(value, modulus).1
}

/// Returns `v mod modulus` for `v = value + carry 2^(64 N) < 2 modulus`.
pub const fn subtract_modulus<const N: usize>(
    value: [u64; N],
    carry: u64,
    modulus: &[u64; N],
) -> [u64; N] {
    let mut reduced = [0; N];
    let mut borrow = 0;
    let mut i = 0;
    while i < N {
        let wide = (value[i] as u128)
            .wrapping_sub(modulus[i] as u128)
            .wrapping_sub(borrow as u128);
        reduced[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    // Keep the subtraction exactly when it did not underflow the extended value.
    let underflow = carry.wrapping_sub(borrow) >> 63;
    let mask = underflow.wrapping_neg();
    let mut i = 0;
    while i < N {
        reduced[i] = (reduced[i] & !mask) | (value[i] & mask);
        i += 1;
    }
    reduced
}

/// Returns the product of two little-endian integers, in `N = A + B` words.
pub const fn mul_words<const A: usize, const B: usize, const N: usize>(
    a: &[u64; A],
    b: &[u64; B],
) -> [u64; N] {
    const { assert!(N == A + B) };
    let mut product = [0; N];
    let mut i = 0;
    while i < A {
        let mut carry = 0u64;
        let mut j = 0;
        while j < B {
            // A product of words plus a word and a carry is below 2^128.
            let wide = product[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry as u128;
            product[i + j] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        product[i + B] = carry;
        i += 1;
    }
    product
}

/// Returns `value / divisor` and `value mod divisor` for a value of `N = 2 D` words whose
/// quotient fits in `D` words, given `reciprocal = floor(2^(64 N) / divisor)` in `R = D + 1`
/// words, without branching on the value.
///
/// The quotient estimated from the reciprocal falls short by at most one, since
/// `value * reciprocal / 2^(64 N)` is at least `value / divisor - value / 2^(64 N)`, so one
/// conditional subtraction of the divisor corrects the remainder.
pub const fn divide<const N: usize, const D: usize, const R: usize, const W: usize>(
    value: &[u64; N],
    divisor: &[u64; D],
    reciprocal: &[u64; R],
) -> ([u64; D], [u64; D]) {
    const { assert!(N == 2 * D && R == D + 1 && W == N + R) };
    let wide: [u64; W] = mul_words(value, reciprocal);
    let mut quotient = [0; D];
    let mut i = 0;
    while i < D {
        quotient[i] = wide[N + i];
        i += 1;
    }
    let product: [u64; N] = mul_words(&quotient, divisor);
    let (remainder, _) = sub_words(value, &product);
    let mut extended = [0; N];
    let mut i = 0;
    while i < D {
        extended[i] = divisor[i];
        i += 1;
    }
    let (reduced, borrow) = sub_words(&remainder, &extended);
    // Keep the remainder when it is below the divisor, and otherwise take the reduced one and
    // add one to the quotient.
    let keep = (borrow as u64).wrapping_neg();
    let mut corrected = [0; D];
    let mut carry = !keep & 1;
    let mut i = 0;
    while i < D {
        corrected[i] = (remainder[i] & keep) | (reduced[i] & !keep);
        let (sum, overflow) = quotient[i].overflowing_add(carry);
        quotient[i] = sum;
        carry = overflow as u64;
        i += 1;
    }
    (quotient, corrected)
}

/// Returns the little-endian words of the big-endian integer `bytes`, for `B = 8 N`.
pub const fn words_from_be_bytes<const N: usize, const B: usize>(bytes: &[u8; B]) -> [u64; N] {
    const { assert!(B == 8 * N) };
    let chunks = bytes.as_chunks::<8>().0;
    let mut words = [0; N];
    let mut i = 0;
    while i < N {
        words[i] = u64::from_be_bytes(chunks[N - 1 - i]);
        i += 1;
    }
    words
}

/// Returns the big-endian encoding of the little-endian words `words`, for `B = 8 N`.
pub const fn be_bytes_from_words<const N: usize, const B: usize>(words: &[u64; N]) -> [u8; B] {
    const { assert!(B == 8 * N) };
    let mut bytes = [0; B];
    let mut i = 0;
    while i < N {
        let chunk = words[N - 1 - i].to_be_bytes();
        let mut j = 0;
        while j < 8 {
            bytes[8 * i + j] = chunk[j];
            j += 1;
        }
        i += 1;
    }
    bytes
}

/// Returns `a + b mod modulus`.
pub const fn add<const N: usize>(a: &[u64; N], b: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut sum = [0; N];
    let mut carry = 0;
    let mut i = 0;
    while i < N {
        let wide = a[i] as u128 + b[i] as u128 + carry as u128;
        sum[i] = wide as u64;
        carry = (wide >> 64) as u64;
        i += 1;
    }
    subtract_modulus(sum, carry, modulus)
}

/// Returns `modulus - a`, mapping zero to zero.
pub const fn neg<const N: usize>(a: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut value = [0; N];
    let mut borrow = 0;
    let mut nonzero = 0;
    let mut i = 0;
    while i < N {
        let wide = (modulus[i] as u128)
            .wrapping_sub(a[i] as u128)
            .wrapping_sub(borrow as u128);
        value[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        nonzero |= a[i];
        i += 1;
    }
    // A zero input yields the modulus; mask it back to zero.
    let mask = ((nonzero | nonzero.wrapping_neg()) >> 63).wrapping_neg();
    let mut i = 0;
    while i < N {
        value[i] &= mask;
        i += 1;
    }
    value
}

/// Returns `2^k mod modulus` by repeated doubling.
pub const fn power_of_two<const N: usize>(k: u32, modulus: &[u64; N]) -> [u64; N] {
    let mut value = [0; N];
    value[0] = 1;
    let mut i = 0;
    while i < k {
        value = add(&value, &value, modulus);
        i += 1;
    }
    value
}

/// Returns `a * b / 2^(64 N) mod modulus` (CIOS Montgomery multiplication) for an odd modulus
/// below `2^(64 N - 1)`, given `inv = -modulus^(-1) mod 2^64`.
///
/// `a` may be any integer below `2^(64 N)`; `b` must be below the modulus.
pub const fn mul<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    modulus: &[u64; N],
    inv: u64,
) -> [u64; N] {
    let mut t = [0u64; N];
    let mut high = 0u64;
    let mut i = 0;
    while i < N {
        // t += a * b[i], with the carry out going to high.
        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let wide = t[j] as u128 + a[j] as u128 * b[i] as u128 + carry as u128;
            t[j] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = high as u128 + carry as u128;
        high = wide as u64;
        let top = (wide >> 64) as u64;

        // t += m * modulus, then drop the low word, which is now zero.
        let m = t[0].wrapping_mul(inv);
        let wide = t[0] as u128 + m as u128 * modulus[0] as u128;
        let mut carry = (wide >> 64) as u64;
        let mut j = 1;
        while j < N {
            let wide = t[j] as u128 + m as u128 * modulus[j] as u128 + carry as u128;
            t[j - 1] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = high as u128 + carry as u128;
        t[N - 1] = wide as u64;
        high = top + (wide >> 64) as u64;
        i += 1;
    }
    subtract_modulus(t, high, modulus)
}

/// Bits of a limb of the signed representation of [`invert`].
const LIMB: u32 = 62;

/// Mask of the low [`LIMB`] bits of a word.
const LIMB_MASK: u64 = (1 << LIMB) - 1;

/// Division steps one batch of [`invert`] takes: the transition matrix of a batch starts
/// scaled by `8`, so it ends scaled by `2^62`, its entries stay within `2^62` in magnitude,
/// and its determinant is `2^65`.
const STEPS: u32 = 59;

/// Returns `m^(-1) mod 2^62` for an odd modulus word `m`.
pub const fn inverse_mod_limb(m: u64) -> u64 {
    negated_inverse(m).wrapping_neg() & LIMB_MASK
}

/// Returns the signed limbs of a nonnegative integer below `2^(62 L - 2)`.
const fn to_limbs<const N: usize, const L: usize>(words: &[u64; N]) -> [i64; L] {
    let mut limbs = [0i64; L];
    let mut bit = 0;
    let mut i = 0;
    while i < L {
        let (word, offset) = (bit / 64, bit % 64);
        let mut limb = 0;
        if word < N {
            limb = words[word] >> offset;
            if offset > 64 - LIMB as usize && word + 1 < N {
                limb |= words[word + 1] << (64 - offset);
            }
        }
        limbs[i] = (limb & LIMB_MASK) as i64;
        bit += LIMB as usize;
        i += 1;
    }
    limbs
}

/// Returns the words of a nonnegative integer with normalized limbs below `2^(64 N)`.
const fn from_limbs<const N: usize, const L: usize>(limbs: &[i64; L]) -> [u64; N] {
    let mut words = [0u64; N];
    let mut bit = 0;
    let mut i = 0;
    while i < L {
        let (word, offset) = (bit / 64, bit % 64);
        let limb = limbs[i] as u64;
        if word < N {
            words[word] |= limb << offset;
            if offset > 64 - LIMB as usize && word + 1 < N {
                words[word + 1] |= limb >> (64 - offset);
            }
        }
        bit += LIMB as usize;
        i += 1;
    }
    words
}

/// Runs [`STEPS`] division steps on the low limbs `f0` and `g0` in constant time, returning the
/// updated `zeta` and the transition matrix `[u, v, q, r]` that maps `(f, g)` to
/// `(u f + v g, q f + r g) / 2^62`.
///
/// `zeta` is `-(delta + 1/2)` for the `delta` of Bernstein and Yang's division steps.
const fn divsteps(mut zeta: i64, f0: u64, g0: u64) -> (i64, [i64; 4]) {
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    let mut i = 0;
    while i < STEPS {
        // Masks for zeta < 0 and for g odd.
        let c1 = (zeta >> 63) as u64;
        let c2 = (g & 1).wrapping_neg();
        // f, u, v negated when zeta < 0.
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        // Add them to g, q, r when g is odd.
        g = g.wrapping_add(x & c2);
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        // When both, swap by adding g, q, r to f, u, v and flip zeta to -zeta - 2;
        // otherwise zeta decreases by one.
        let c1 = c1 & c2;
        zeta = (zeta ^ c1 as i64).wrapping_sub(1);
        f = f.wrapping_add(g & c1);
        u = u.wrapping_add(q & c1);
        v = v.wrapping_add(r & c1);
        g >>= 1;
        u <<= 1;
        v <<= 1;
        i += 1;
    }
    (zeta, [u as i64, v as i64, q as i64, r as i64])
}

/// Sets `(f, g)` to `(u f + v g, q f + r g) / 2^62` for the transition matrix `[u, v, q, r]`,
/// whose numerators [`divsteps`] makes divisible by `2^62`.
const fn update_fg<const L: usize>(f: &mut [i64; L], g: &mut [i64; L], [u, v, q, r]: [i64; 4]) {
    let mut cf = u as i128 * f[0] as i128 + v as i128 * g[0] as i128;
    let mut cg = q as i128 * f[0] as i128 + r as i128 * g[0] as i128;
    debug_assert!(cf as u64 & LIMB_MASK == 0 && cg as u64 & LIMB_MASK == 0);
    cf >>= LIMB;
    cg >>= LIMB;
    let mut i = 1;
    while i < L {
        cf += u as i128 * f[i] as i128 + v as i128 * g[i] as i128;
        cg += q as i128 * f[i] as i128 + r as i128 * g[i] as i128;
        f[i - 1] = (cf as u64 & LIMB_MASK) as i64;
        g[i - 1] = (cg as u64 & LIMB_MASK) as i64;
        cf >>= LIMB;
        cg >>= LIMB;
        i += 1;
    }
    f[L - 1] = cf as i64;
    g[L - 1] = cg as i64;
}

/// Applies the transition matrix to `(d, e)` modulo the modulus and divides by `2^62`, adding the
/// multiples of the modulus that clear the low 62 bits, given `inverse = modulus^(-1) mod 2^62`.
///
/// Keeps `d` and `e` within `(-2 modulus, modulus)`.
const fn update_de<const L: usize>(
    d: &mut [i64; L],
    e: &mut [i64; L],
    [u, v, q, r]: [i64; 4],
    modulus: &[i64; L],
    inverse: u64,
) {
    // Start the multiples at u, q for a negative d and v, r for a negative e, so that the
    // results stay above -2 modulus.
    let sd = d[L - 1] >> 63;
    let se = e[L - 1] >> 63;
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    let mut cd = u as i128 * d[0] as i128 + v as i128 * e[0] as i128;
    let mut ce = q as i128 * d[0] as i128 + r as i128 * e[0] as i128;
    md -= (inverse.wrapping_mul(cd as u64).wrapping_add(md as u64) & LIMB_MASK) as i64;
    me -= (inverse.wrapping_mul(ce as u64).wrapping_add(me as u64) & LIMB_MASK) as i64;
    cd += modulus[0] as i128 * md as i128;
    ce += modulus[0] as i128 * me as i128;
    debug_assert!(cd as u64 & LIMB_MASK == 0 && ce as u64 & LIMB_MASK == 0);
    cd >>= LIMB;
    ce >>= LIMB;
    let mut i = 1;
    while i < L {
        cd += u as i128 * d[i] as i128 + v as i128 * e[i] as i128 + modulus[i] as i128 * md as i128;
        ce += q as i128 * d[i] as i128 + r as i128 * e[i] as i128 + modulus[i] as i128 * me as i128;
        d[i - 1] = (cd as u64 & LIMB_MASK) as i64;
        e[i - 1] = (ce as u64 & LIMB_MASK) as i64;
        cd >>= LIMB;
        ce >>= LIMB;
        i += 1;
    }
    d[L - 1] = cd as i64;
    e[L - 1] = ce as i64;
}

/// Carries each limb's bits beyond [`LIMB`] into the next, leaving the top limb signed.
const fn carry_limbs<const L: usize>(r: &mut [i64; L]) {
    let mut i = 0;
    while i + 1 < L {
        r[i + 1] += r[i] >> LIMB;
        r[i] &= LIMB_MASK as i64;
        i += 1;
    }
}

/// Returns `r` within `(-2 modulus, modulus)` normalized to `[0, modulus)`, negated first when
/// `sign` is negative.
const fn normalize<const L: usize>(mut r: [i64; L], sign: i64, modulus: &[i64; L]) -> [i64; L] {
    // Add the modulus to a negative value, which brings it within (-modulus, modulus), then
    // negate on request.
    let add = r[L - 1] >> 63;
    let negate = sign >> 63;
    let mut i = 0;
    while i < L {
        r[i] = ((r[i] + (modulus[i] & add)) ^ negate) - negate;
        i += 1;
    }
    carry_limbs(&mut r);
    // Add the modulus again to a value still negative.
    let add = r[L - 1] >> 63;
    let mut i = 0;
    while i < L {
        r[i] += modulus[i] & add;
        i += 1;
    }
    carry_limbs(&mut r);
    r
}

/// Returns `a^(-1) mod modulus` for `a` below the odd modulus, or zero for zero, in constant time,
/// given `inverse = modulus^(-1) mod 2^62` from [`inverse_mod_limb`].
///
/// `L` signed limbs of [`LIMB`] bits must hold the modulus with two spare bits.
pub const fn invert<const N: usize, const L: usize>(
    a: &[u64; N],
    modulus: &[u64; N],
    inverse: u64,
) -> [u64; N] {
    // This is the safegcd of Bernstein and Yang, "Fast constant-time gcd computation and modular
    // inversion" (2019), in batches of STEPS division steps on the low limbs, with the transition
    // matrix of each batch applied to (f, g) and, modulo the modulus, to (d, e), as in
    // libsecp256k1's implementation. The invariant f = d a and g = e a modulo the modulus ends,
    // once g reaches zero and f is 1 or -1, with d the inverse up to the sign of f. The number of
    // batches covers the bound of (49 b + 57) / 17 steps for b-bit inputs.
    const { assert!(62 * L >= 64 * N + 2) };
    let batches = (49 * 64 * N as u32 + 57).div_ceil(17).div_ceil(STEPS);
    let modulus = to_limbs::<N, L>(modulus);
    let mut d = [0i64; L];
    let mut e = [0i64; L];
    e[0] = 1;
    let mut f = modulus;
    let mut g = to_limbs::<N, L>(a);
    let mut zeta = -1i64;
    let mut i = 0;
    while i < batches {
        let (next, matrix) = divsteps(zeta, f[0] as u64, g[0] as u64);
        zeta = next;
        update_de(&mut d, &mut e, matrix, &modulus, inverse);
        update_fg(&mut f, &mut g, matrix);
        i += 1;
    }
    from_limbs(&normalize(d, f[L - 1], &modulus))
}

/// Fuzz plan checking the arithmetic, the signed limb conversions, and the safegcd inversion.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::core::field::fp::{MODULUS, WORDS, reference};
    use arbitrary::{Arbitrary, Unstructured};

    /// Limbs that hold the modulus of the base field with two spare bits.
    const LIMBS: usize = 7;

    /// `MODULUS^(-1) mod 2^62`.
    const INVERSE: u64 = inverse_mod_limb(MODULUS[0]);

    /// An arithmetic, limb conversion, or inversion check on the base field modulus.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks that addition, negation, and multiplication match schoolbook arithmetic reduced
        /// by binary long division, which share no code with them.
        Arithmetic,
        /// Checks that an integer below `2^382` survives conversion to signed limbs and back.
        LimbsRoundTrip,
        /// Checks that inversion returns the canonical inverse of a nonzero element, and zero
        /// for zero.
        Inversions,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Arithmetic => arithmetic(u),
                Self::LimbsRoundTrip => limbs_round_trip(u),
                Self::Inversions => inversions(u),
            }
        }
    }

    /// Returns `a - b` for `a` at least `b`.
    fn difference<const N: usize>(a: [u64; N], b: &[u64; N]) -> [u64; N] {
        let mut difference = a;
        let mut borrow = false;
        for (word, b) in difference.iter_mut().zip(b) {
            let (word_difference, low) = word.overflowing_sub(*b);
            let (word_difference, high) = word_difference.overflowing_sub(u64::from(borrow));
            *word = word_difference;
            borrow = low || high;
        }
        assert!(!borrow, "difference is negative");
        difference
    }

    /// Returns a little-endian integer modulo the base field modulus, by binary long division.
    fn remainder(value: &[u64]) -> [u64; WORDS] {
        let mut remainder = [0; WORDS];
        for bit in (0..64 * value.len()).rev() {
            // The remainder is below p < 2^383, so doubling it fits.
            let mut carry = (value[bit / 64] >> (bit % 64)) & 1;
            for word in &mut remainder {
                (*word, carry) = ((*word << 1) | carry, *word >> 63);
            }
            if remainder.iter().rev().ge(MODULUS.iter().rev()) {
                remainder = difference(remainder, &MODULUS);
            }
        }
        remainder
    }

    /// Returns the schoolbook product `a * b`.
    fn product(a: &[u64; WORDS], b: &[u64; WORDS]) -> [u64; 2 * WORDS] {
        let mut product = [0; 2 * WORDS];
        for (i, a) in a.iter().enumerate() {
            let mut carry = 0u128;
            for (j, b) in b.iter().enumerate() {
                let sum = product[i + j] as u128 + *a as u128 * *b as u128 + carry;
                product[i + j] = sum as u64;
                carry = sum >> 64;
            }
            product[i + WORDS] = carry as u64;
        }
        product
    }

    /// Draws a canonical element, biased toward zero and `p - 1`.
    fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<[u64; WORDS]> {
        Ok(match u.int_in_range(0..=3)? {
            1 => [0; WORDS],
            2 => {
                let mut largest = MODULUS;
                largest[0] -= 1;
                largest
            }
            _ => reference::canonical(u)?,
        })
    }

    /// Checks the sum, negation, and Montgomery product of drawn elements, and the product of
    /// any integer below `2^384` by an element.
    fn arithmetic(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let a = element(u)?;
        let b = element(u)?;
        let wide: [u64; WORDS] = u.arbitrary()?;
        let mut sum = [0; WORDS + 1];
        let mut carry = 0u128;
        for (word, (a, b)) in sum.iter_mut().zip(a.iter().zip(&b)) {
            let wide_sum = *a as u128 + *b as u128 + carry;
            *word = wide_sum as u64;
            carry = wide_sum >> 64;
        }
        sum[WORDS] = carry as u64;
        assert_eq!(add(&a, &b, &MODULUS), remainder(&sum), "{a:x?} + {b:x?}");
        assert_eq!(
            neg(&a, &MODULUS),
            remainder(&difference(MODULUS, &a)),
            "-{a:x?}"
        );
        // A Montgomery product divides by 2^384, so the Montgomery product times 2^384 is
        // congruent to the product.
        for a in [a, wide] {
            let mut shifted = [0; 2 * WORDS];
            shifted[WORDS..].copy_from_slice(&mul(&a, &b, &MODULUS, reference::INV));
            assert_eq!(
                remainder(&shifted),
                remainder(&product(&a, &b)),
                "{a:x?} * {b:x?}"
            );
        }
        Ok(())
    }

    /// Converts a drawn integer below `2^382` to limbs and back.
    fn limbs_round_trip(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let mut words: [u64; WORDS] = u.arbitrary()?;
        words[WORDS - 1] >>= 2;
        assert_eq!(
            from_limbs::<WORDS, LIMBS>(&to_limbs::<WORDS, LIMBS>(&words)),
            words,
            "{words:x?}"
        );
        Ok(())
    }

    /// Inverts a drawn element, biased toward small, sparse, and extreme values, and checks the
    /// result by definition.
    fn inversions(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let a = match u.int_in_range(0..=9)? {
            5 => reference::ZERO,
            6 => reference::ONE,
            7 => reference::neg(reference::ONE),
            8 => {
                // 2^382 mod p.
                let mut top = [0; WORDS];
                top[WORDS - 1] = 1 << 62;
                reference::mul(top, reference::ONE)
            }
            // Small and sparse values exercise long runs of even division steps.
            9 => {
                let k = u.int_in_range(0..=380)?;
                let mut sparse = [0; WORDS];
                sparse[k / 64] = 1 << (k % 64);
                sparse
            }
            _ => reference::canonical(u)?,
        };
        let inverse = invert::<WORDS, LIMBS>(&a, &MODULUS, INVERSE);
        if a == reference::ZERO {
            assert_eq!(inverse, reference::ZERO);
        } else {
            assert!(is_below(&inverse, &MODULUS), "{inverse:x?} not canonical");
            assert_eq!(
                reference::mul(inverse, a),
                reference::ONE,
                "inverse of {a:x?}"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;

        #[test]
        fn minifuzz_arithmetic() {
            minifuzz::test(|u| Plan::Arithmetic.run(u));
        }

        #[test]
        fn minifuzz_limbs_round_trip() {
            minifuzz::test(|u| Plan::LimbsRoundTrip.run(u));
        }

        #[test]
        fn minifuzz_inversions() {
            minifuzz::test(|u| Plan::Inversions.run(u));
        }

        #[test]
        fn inverse_mod_limb_inverts_the_modulus() {
            assert_eq!(INVERSE.wrapping_mul(MODULUS[0]) & LIMB_MASK, 1);
        }
    }
}
