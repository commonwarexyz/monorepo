//! Prime-field elements backed by VROOM's bounded residue-number-system core.
//!
//! The raw representation contains an integer in `[0, 40p]`. Each lane is in
//! `[0, 2q]`, where `q` is its RNS modulus, and the two halves use the rotations
//! defined by the sealed parameter set. Arithmetic closes the representation
//! through [`Ring`]; encoding and inversion canonicalize at their public boundary.

use crate::{
    Backend, WithBackend,
    rns::{
        BITS, LANES, MULT_OK, Parameters, Ring, Standard,
        kernel::{RawWide, convert_wide, prepare_lane, quotient, reduce_lane},
    },
    with_backend,
};
use core::array;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

mod inverse;
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_pointer_width = "64",
    not(miri)
))]
pub mod word;

// SAFETY: The private AAPCS64 routines are called only through the typed word
// wrappers, which own their ranges, buffer sizes, and non-overlapping outputs.
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_pointer_width = "64",
    not(miri)
))]
core::arch::global_asm!(include_str!("field/word/armv8.S"), options(raw));

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A supported prime modulus with a fixed canonical encoding.
///
/// Implementations are sealed so residue geometry, conversion coefficients, and
/// field constants cannot be supplied independently of their validated parameter set.
pub trait Modulus: sealed::Sealed + Copy + core::fmt::Debug {
    /// The fixed-size, big-endian canonical encoding.
    type Encoding: AsRef<[u8]> + AsMut<[u8]> + Copy + core::fmt::Debug;

    /// An all-zero encoding of the required length.
    const ZERO_ENCODING: Self::Encoding;

    /// The precomputed arithmetic parameters for this modulus.
    #[doc(hidden)]
    const PARAMETERS: &'static Parameters;
}

/// A field element with a bounded, redundant RNS representation.
///
/// Values of distinct moduli have distinct types. Arithmetic preserves the bounded
/// representation; byte conversion supplies the canonical integer.
///
/// # Examples
///
/// ```
/// use commonware_cryptography_vroom::{BlsScalar, Element};
///
/// let value = Element::<BlsScalar>::from_u64(7);
/// assert_eq!(value.mul(value.invert().unwrap()), Element::ONE);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Element<P: Modulus>(Standard<P>);

/// Two operands and their product's sign; a set choice subtracts the product.
pub type SignedTerm<'a, P> = (&'a Element<P>, &'a Element<P>, Choice);

impl<P: Modulus> From<Element<P>> for Standard<P> {
    #[inline(always)]
    fn from(value: Element<P>) -> Self {
        value.0
    }
}

impl<P: Modulus> From<Standard<P>> for Element<P> {
    #[inline(always)]
    fn from(value: Standard<P>) -> Self {
        Self(value)
    }
}

impl<P: Modulus> ConditionallySelectable for Element<P> {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Standard::conditional_select(&a.0, &b.0, choice))
    }
}

impl<P: Modulus> ConstantTimeEq for Element<P> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        canonical(&self.0).ct_eq(&canonical(&other.0))
    }
}

impl<P: Modulus> PartialEq for Element<P> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<P: Modulus> Eq for Element<P> {}

impl<P: Modulus> Zeroize for Element<P> {
    fn zeroize(&mut self) {
        self.0.halves.zeroize();
    }
}

struct Binary<'a, P: Modulus> {
    left: &'a Standard<P>,
    right: &'a Standard<P>,
    operation: BinaryOperation,
}

#[derive(Clone, Copy)]
enum BinaryOperation {
    Add,
    Subtract,
    Multiply,
}

impl<P: Modulus> WithBackend for Binary<'_, P> {
    type Output = Standard<P>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<P, B>::new(backend);
        match self.operation {
            BinaryOperation::Add => ring.add(*self.left, *self.right),
            BinaryOperation::Subtract => ring.sub(*self.left, *self.right),
            BinaryOperation::Multiply => ring.mul(*self.left, *self.right),
        }
    }
}

struct Negate<P: Modulus>(Standard<P>);

impl<P: Modulus> WithBackend for Negate<P> {
    type Output = Standard<P>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        Ring::<P, B>::new(backend).standard_negate(self.0)
    }
}

struct SumOfProducts<'a, P: Modulus, const N: usize> {
    left: &'a [Element<P>; N],
    right: &'a [Element<P>; N],
}

impl<P: Modulus, const N: usize> WithBackend for SumOfProducts<'_, P, N> {
    type Output = Standard<P>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        Ring::<P, B>::new(backend).sum_of_products(self.left, self.right)
    }
}

struct SignedSums<'a, P: Modulus, const BATCH: usize, const N: usize> {
    terms: &'a [[SignedTerm<'a, P>; N]; BATCH],
}

impl<P: Modulus, const BATCH: usize, const N: usize> WithBackend for SignedSums<'_, P, BATCH, N> {
    type Output = [Standard<P>; BATCH];

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        Ring::<P, B>::new(backend).signed_sum(self.terms)
    }
}

struct ReduceBytes<'a, P: Modulus> {
    bytes: &'a [u8],
    _modulus: core::marker::PhantomData<P>,
}

impl<P: Modulus> WithBackend for ReduceBytes<'_, P> {
    type Output = Standard<P>;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<P, B>::new(backend);
        let prefix = self.bytes.len() % 32;
        let mut result = standard_from_chunk::<P>(&self.bytes[..prefix]);
        let radix = Standard::from_halves(P::PARAMETERS.radix_256);
        for chunk in self.bytes[prefix..].as_chunks::<32>().0 {
            result = ring.add(ring.mul(result, radix), standard_from_chunk::<P>(chunk));
        }
        result
    }
}

struct Pow<'a, P: Modulus, const N: usize> {
    value: Standard<P>,
    exponent: &'a [u64; N],
}

impl<P: Modulus, const N: usize> WithBackend for Pow<'_, P, N> {
    type Output = Standard<P>;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        pow(&Ring::<P, B>::new(backend), self.value, self.exponent)
    }
}

struct SquareRoot<P: Modulus>(Standard<P>);

impl<P: Modulus> WithBackend for SquareRoot<P> {
    type Output = (Standard<P>, Choice);

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<P, B>::new(backend);
        let mut root = pow_public(&ring, self.0, &P::PARAMETERS.sqrt_exponent);
        if P::PARAMETERS.two_adicity > 1 {
            let mut remainder = pow_public(&ring, self.0, &P::PARAMETERS.odd_exponent);
            let mut correction = Standard::from_halves(P::PARAMETERS.root);

            // At round i, correction has order 2^i and a square's remainder has
            // order at most 2^(i-1). The selected update halves that order while
            // maintaining root^2 = self * remainder.
            for i in (2..=P::PARAMETERS.two_adicity).rev() {
                let mut test = remainder;
                for _ in 0..i - 2 {
                    test = ring.mul(test, test);
                }
                let update = !canonical(&test).ct_eq(&[1, 0, 0, 0, 0, 0]);
                root = Standard::conditional_select(&root, &ring.mul(root, correction), update);
                correction = ring.mul(correction, correction);
                remainder = Standard::conditional_select(
                    &remainder,
                    &ring.mul(remainder, correction),
                    update,
                );
            }
        }
        let square = ring.mul(root, root);
        (root, canonical(&square).ct_eq(&canonical(&self.0)))
    }
}

struct IsSquare<P: Modulus>(Standard<P>);

impl<P: Modulus> WithBackend for IsSquare<P> {
    type Output = Choice;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<P, B>::new(backend);
        let mut exponent = P::PARAMETERS.modulus;
        exponent[0] -= 1;
        for i in 0..5 {
            exponent[i] = (exponent[i] >> 1) | (exponent[i + 1] << 63);
        }
        exponent[5] >>= 1;
        let power = pow_public(&ring, self.0, &exponent);
        canonical(&power).ct_eq(&[1, 0, 0, 0, 0, 0]) | is_zero_standard(self.0)
    }
}

impl<P: Modulus> Element<P> {
    /// The additive identity.
    pub const ZERO: Self = Self(Standard::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self(Standard::ONE);

    /// Constructs a canonical integer from little-endian radix-2^64 words.
    ///
    /// This constructor supports compile-time constants. It accepts at most six words,
    /// including leading zero words, and rejects integers greater than or equal to the modulus.
    /// Validation may branch on the word count and integer value.
    pub const fn from_raw(words: &[u64]) -> Option<Self> {
        if words.len() > 6 {
            return None;
        }
        let mut padded = [0u64; 6];
        let mut i = 0;
        while i < words.len() {
            padded[i] = words[i];
            i += 1;
        }
        let mut borrow = false;
        i = 0;
        while i < 6 {
            let (value, first) = padded[i].overflowing_sub(P::PARAMETERS.modulus[i]);
            let (_, second) = value.overflowing_sub(borrow as u64);
            borrow = first | second;
            i += 1;
        }
        if !borrow {
            return None;
        }
        Some(Self(from_canonical::<P>(&padded)))
    }

    /// Parses a canonical, big-endian field element.
    pub fn from_bytes(bytes: &P::Encoding) -> Option<Self> {
        let input = bytes.as_ref();
        let mut padded = [0; 48];
        padded[48 - input.len()..].copy_from_slice(input);
        let words = array::from_fn(|i| {
            let mut word = [0; 8];
            word.copy_from_slice(&padded[40 - 8 * i..48 - 8 * i]);
            u64::from_be_bytes(word)
        });
        let (_, borrow) = subtract(&words, &P::PARAMETERS.modulus);
        bool::from(borrow).then(|| Self(from_canonical::<P>(&words)))
    }

    /// Reduces an arbitrary-length big-endian integer modulo the field prime.
    pub fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        Self(with_backend(ReduceBytes::<P> {
            bytes,
            _modulus: core::marker::PhantomData,
        }))
    }

    /// Constructs an element from an unsigned integer.
    pub const fn from_u64(value: u64) -> Self {
        Self(from_canonical::<P>(&[value, 0, 0, 0, 0, 0]))
    }

    /// Returns the canonical, big-endian encoding.
    pub fn to_bytes(&self) -> P::Encoding {
        let words = canonical(&self.0);
        let mut bytes = [0; 48];
        let mut i = 0;
        while i < 6 {
            bytes[40 - 8 * i..48 - 8 * i].copy_from_slice(&words[i].to_be_bytes());
            i += 1;
        }
        let mut result = P::ZERO_ENCODING;
        let length = result.as_ref().len();
        result.as_mut().copy_from_slice(&bytes[48 - length..]);
        result
    }

    /// Adds two elements.
    pub fn add(&self, rhs: Self) -> Self {
        Self(with_backend(Binary {
            left: &self.0,
            right: &rhs.0,
            operation: BinaryOperation::Add,
        }))
    }

    /// Subtracts an element.
    pub fn sub(&self, rhs: Self) -> Self {
        Self(with_backend(Binary {
            left: &self.0,
            right: &rhs.0,
            operation: BinaryOperation::Subtract,
        }))
    }

    /// Returns the additive inverse.
    pub fn neg(&self) -> Self {
        Self(with_backend(Negate(self.0)))
    }

    /// Multiplies two elements.
    pub fn mul(&self, rhs: Self) -> Self {
        Self(with_backend(Binary {
            left: &self.0,
            right: &rhs.0,
            operation: BinaryOperation::Multiply,
        }))
    }

    /// Squares an element.
    pub fn square(self) -> Self {
        self.mul(self)
    }

    /// Computes an inner product with fused bounded reductions.
    pub fn sum_of_products<const N: usize>(a: &[Self; N], b: &[Self; N]) -> Self {
        Self(with_backend(SumOfProducts { left: a, right: b }))
    }

    /// Computes a signed inner product with fused bounded reductions.
    ///
    /// Each tuple contains two operands and a sign: a set choice subtracts their product.
    /// Signs and operands are processed in constant time. Empty sums return zero.
    pub fn sum_of_products_signed<const N: usize>(terms: &[SignedTerm<'_, P>; N]) -> Self {
        Self::batch_sum_of_products_signed(array::from_ref(terms))[0]
    }

    /// Computes independent signed inner products while sharing conversion coefficients.
    ///
    /// Each tuple has the same meaning as in [`Self::sum_of_products_signed`].
    /// Batch size and term count are public; the result contains one element per row.
    pub fn batch_sum_of_products_signed<const BATCH: usize, const N: usize>(
        terms: &[[SignedTerm<'_, P>; N]; BATCH],
    ) -> [Self; BATCH] {
        with_backend(SignedSums { terms }).map(Self)
    }

    /// Raises an element to a little-endian multiword exponent in constant time.
    ///
    /// The number of words is public. Every bit performs a square, a multiplication,
    /// and a conditional selection, including leading zero bits.
    pub fn pow<const N: usize>(self, exponent: &[u64; N]) -> Self {
        Self(with_backend(Pow {
            value: self.0,
            exponent,
        }))
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    pub fn invert(self) -> Option<Self> {
        invert_standard(self.0).map(Self)
    }

    /// Returns a square root, or `None` for a nonsquare.
    ///
    /// Tonelli-Shanks uses a fixed schedule determined solely by the modulus.
    pub fn sqrt(self) -> Option<Self> {
        let (root, square) = with_backend(SquareRoot(self.0));
        bool::from(square).then_some(Self(root))
    }

    /// Returns whether the element is a square, including zero, in constant time.
    pub fn is_square(self) -> Choice {
        with_backend(IsSquare(self.0))
    }

    /// Returns whether the represented field value is zero.
    pub fn is_zero(self) -> bool {
        bool::from(is_zero_standard(self.0))
    }

    /// The sign bit used by hash-to-curve: the low bit of the canonical integer.
    pub fn sgn0(self) -> Choice {
        Choice::from((canonical(&self.0)[0] & 1) as u8)
    }

    /// Whether this element's canonical integer exceeds `(p - 1)/2`.
    pub fn lexicographically_largest(self) -> Choice {
        let (_, borrow) = subtract(&canonical(&self.0), &P::PARAMETERS.half_plus_one);
        !borrow
    }
}

#[inline(always)]
fn pow<P: Modulus, B: Backend, const N: usize>(
    ring: &Ring<P, B>,
    value: Standard<P>,
    exponent: &[u64; N],
) -> Standard<P> {
    let mut result = Standard::ONE;
    for word in exponent.iter().rev() {
        for bit in (0..64).rev() {
            result = ring.mul(result, result);
            let product = ring.mul(result, value);
            result = Standard::conditional_select(
                &result,
                &product,
                Choice::from(((word >> bit) & 1) as u8),
            );
        }
    }
    result
}

#[inline(always)]
fn pow_public<P: Modulus, B: Backend>(
    ring: &Ring<P, B>,
    value: Standard<P>,
    exponent: &[u64; 6],
) -> Standard<P> {
    let mut result = Standard::ONE;
    for bit in (0..P::PARAMETERS.bits).rev() {
        result = ring.mul(result, result);
        if (exponent[bit / 64] >> (bit % 64)) & 1 == 1 {
            result = ring.mul(result, value);
        }
    }
    result
}

fn standard_from_chunk<P: Modulus>(bytes: &[u8]) -> Standard<P> {
    debug_assert!(bytes.len() <= 32);
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    let mut words = [0u64; 6];
    for (i, chunk) in padded.rchunks_exact(8).enumerate() {
        words[i] = u64::from_be_bytes(chunk.try_into().expect("fixed-size chunk"));
    }

    // Every supported modulus has at least 253 bits, so a 256-bit chunk is below 16p.
    // A fixed subtraction schedule makes the result canonical without data-dependent loops.
    for _ in 0..16 {
        let (reduced, borrow) = subtract(&words, &P::PARAMETERS.modulus);
        for (word, reduced) in words.iter_mut().zip(reduced) {
            *word = u64::conditional_select(&reduced, word, borrow);
        }
    }
    from_canonical::<P>(&words)
}

/// Converts a canonical integer to the trusted bounded RNS representation.
pub(crate) const fn from_canonical<P: Modulus>(words: &[u64; 6]) -> Standard<P> {
    // Both corrected conversions have wide lane bound 4*LANES. Montgomery reduction
    // maps that to ceil(4*LANES/MULT_OK)+1 before preparation closes it to two.
    const MONTGOMERY_UPPER: i64 = (4 * LANES as i64 + MULT_OK - 1) / MULT_OK + 1;
    let mut digits = [0u64; LANES];
    let mut i = 0;
    while i < LANES {
        let bit = i * BITS as usize;
        let word = bit / 64;
        let shift = bit % 64;
        if word < 6 {
            let mut digit = words[word] >> shift;
            if shift > 64 - BITS as usize && word + 1 < 6 {
                digit |= words[word + 1] << (64 - shift);
            }
            digits[i] = digit & ((1 << BITS) - 1);
        }
        i += 1;
    }

    let wide_n = convert_wide(&digits, RawWide::ZERO, &P::PARAMETERS.to_rns, false);
    let mut n = [0u64; LANES];
    i = 0;
    while i < LANES {
        let reduced = reduce_lane(
            wide_n.high[i],
            wide_n.low[i],
            P::PARAMETERS.n.moduli[i],
            P::PARAMETERS.n.inverse[i],
        );
        n[i] = prepare_lane(
            reduced,
            P::PARAMETERS.n.moduli[i],
            P::PARAMETERS.n.complement[i],
            0,
            MONTGOMERY_UPPER,
            2,
        );
        i += 1;
    }

    let wide_m = convert_wide(&n, RawWide::ZERO, &P::PARAMETERS.expand, false);
    let mut m = [0u64; LANES];
    i = 0;
    while i < LANES {
        let reduced = reduce_lane(
            wide_m.high[i],
            wide_m.low[i],
            P::PARAMETERS.m.moduli[i],
            P::PARAMETERS.m.inverse[i],
        );
        m[i] = prepare_lane(
            reduced,
            P::PARAMETERS.m.moduli[i],
            P::PARAMETERS.m.complement[i],
            0,
            MONTGOMERY_UPPER,
            2,
        );
        i += 1;
    }
    Standard::from_halves([m, n])
}

/// Returns the canonical little-endian radix-2^64 words for a trusted standard value.
pub(crate) fn canonical<P: Modulus>(value: &Standard<P>) -> [u64; 6] {
    // Project the N-basis expansion into radix form modulo p. The seven-word
    // accumulator is below 2^55*p on 8x50 and below 2^32*p on 16x26.
    let n = &value.halves[1];
    let mut accumulator = [0u64; 7];
    for (&digit, coefficient) in n.iter().zip(&P::PARAMETERS.to_canonical) {
        accumulate(&mut accumulator, coefficient, digit);
    }
    accumulate(
        &mut accumulator,
        &P::PARAMETERS.canonical_correction,
        quotient(n, &P::PARAMETERS.expand.fraction),
    );

    normalize_canonical::<P>(accumulator)
}

/// Reduces a seven-word integer below 2^64*p for the sealed odd modulus p < 2^381.
fn normalize_canonical<P: Modulus>(mut accumulator: [u64; 7]) -> [u64; 6] {
    let modulus = &P::PARAMETERS.modulus;
    let n0 = P::PARAMETERS.canonical_n0;

    // Each cancelled low word permits exact division by 2^64. The numerator
    // stays below 2^65*p, and the six-round result is below 2p.
    for _ in 0..6 {
        let digit = accumulator[0].wrapping_mul(n0);
        accumulate(&mut accumulator, modulus, digit);
        for i in 0..6 {
            accumulator[i] = accumulator[i + 1];
        }
        accumulator[6] = 0;
    }

    // Multiplication by RR = 2^768 mod p followed by six cancellations restores
    // the canonical radix. Each numerator is below 3*2^64*p < 2^448, so the
    // seven-word accumulator retains its full carry.
    let reduced = array::from_fn(|i| accumulator[i]);
    accumulator = [0; 7];
    for digit in P::PARAMETERS.canonical_rr {
        accumulate(&mut accumulator, &reduced, digit);
        let correction = accumulator[0].wrapping_mul(n0);
        accumulate(&mut accumulator, modulus, correction);
        for i in 0..6 {
            accumulator[i] = accumulator[i + 1];
        }
        accumulator[6] = 0;
    }

    // The final value is below 2p, so one conditional subtraction is sufficient.
    let value = array::from_fn(|i| accumulator[i]);
    let (reduced, borrow) = subtract(&value, modulus);
    array::from_fn(|i| u64::conditional_select(&reduced[i], &value[i], borrow))
}

#[inline]
pub(crate) fn is_zero_standard<P: Modulus>(value: Standard<P>) -> Choice {
    canonical(&value).ct_eq(&[0; 6])
}

/// Inverts a trusted standard value without passing through the fallible public decoder.
pub(crate) fn invert_standard<P: Modulus>(value: Standard<P>) -> Option<Standard<P>> {
    let canonical = canonical(&value);
    let nonzero = !canonical.ct_eq(&[0; 6]);
    let words = inverse::invert::<P>(&canonical);
    let result = from_canonical::<P>(&words);
    bool::from(nonzero).then_some(result)
}

fn accumulate(accumulator: &mut [u64; 7], coefficient: &[u64; 6], digit: u64) {
    let mut carry = 0u128;
    for (accumulator, &coefficient) in accumulator.iter_mut().zip(coefficient) {
        let sum = u128::from(*accumulator) + u128::from(coefficient) * u128::from(digit) + carry;
        *accumulator = sum as u64;
        carry = sum >> 64;
    }
    accumulator[6] = (u128::from(accumulator[6]) + carry) as u64;
}

fn subtract<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], Choice) {
    let mut borrow = 0u128;
    let difference = array::from_fn(|i| {
        let value = (1u128 << 64) + u128::from(a[i]) - u128::from(b[i]) - borrow;
        borrow = 1 - (value >> 64);
        value as u64
    });
    (difference, Choice::from(borrow as u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BanderScalar, Bls12381, BlsScalar, Curve25519};
    use commonware_utils::test_rng;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use rand::Rng;

    fn integer(words: &[u64]) -> BigUint {
        BigUint::from_bytes_le(
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }

    fn encoding<P: Modulus>(value: &BigUint) -> P::Encoding {
        let bytes = value.to_bytes_be();
        let mut result = P::ZERO_ENCODING;
        let length = result.as_ref().len();
        result.as_mut()[length - bytes.len()..].copy_from_slice(&bytes);
        result
    }

    fn element<P: Modulus>(value: &BigUint) -> Element<P> {
        Element::from_bytes(&encoding::<P>(value)).expect("canonical test input")
    }

    fn assert_standard_bound<P: Modulus>(value: Element<P>) {
        let standard = Standard::from(value);
        for half in 0..2 {
            let moduli = if half == 0 {
                &P::PARAMETERS.m.moduli
            } else {
                &P::PARAMETERS.n.moduli
            };
            for (lane, modulus) in standard.halves[half].iter().zip(moduli) {
                assert!(*lane <= 2 * modulus);
            }
        }
    }

    fn check_public_boundary<P: Modulus>() {
        let p = integer(&P::PARAMETERS.modulus);
        let zero = BigUint::zero();
        let one = BigUint::one();
        let maximum = &p - 1u32;

        // Canonical decoding rejects out-of-range inputs; public constructors preserve residue bounds.
        assert_eq!(
            Element::<P>::ZERO.to_bytes().as_ref(),
            encoding::<P>(&zero).as_ref()
        );
        assert_eq!(
            Element::<P>::ONE.to_bytes().as_ref(),
            encoding::<P>(&one).as_ref()
        );
        assert!(Element::<P>::from_bytes(&encoding::<P>(&p)).is_none());
        assert!(Element::<P>::from_raw(&P::PARAMETERS.modulus).is_none());
        assert!(Element::<P>::from_raw(&[0; 7]).is_none());
        assert_eq!(Element::<P>::from_raw(&[]), Some(Element::ZERO));
        let byte_max = Element::<P>::from_u64(255);
        assert_standard_bound(byte_max);
        let doubled_byte_max = byte_max.add(byte_max);
        assert_standard_bound(doubled_byte_max);
        assert_eq!(
            doubled_byte_max.to_bytes().as_ref(),
            encoding::<P>(&BigUint::from(510u32)).as_ref()
        );
        assert_standard_bound(element::<P>(&maximum));
        assert_eq!(
            Element::from(Standard::<P>::from_halves(P::PARAMETERS.radix_256))
                .to_bytes()
                .as_ref(),
            encoding::<P>(&((BigUint::one() << 256usize) % &p)).as_ref()
        );

        // Exercise field and limb boundaries alongside deterministic samples.
        let mut rng = test_rng();
        let mut values = vec![zero, one, maximum, BigUint::from(u64::MAX)];
        for _ in 0..8 {
            let mut bytes = [0u8; 48];
            rng.fill_bytes(&mut bytes);
            values.push(BigUint::from_bytes_be(&bytes) % &p);
        }

        for left in &values {
            let a = element::<P>(left);
            assert_eq!(a.to_bytes().as_ref(), encoding::<P>(left).as_ref());
            assert_eq!(bool::from(a.sgn0()), left.bit(0));
            assert_eq!(
                bool::from(a.lexicographically_largest()),
                left > &((&p - 1u32) >> 1usize)
            );
            assert_eq!(
                a.neg().to_bytes().as_ref(),
                encoding::<P>(&((&p - left) % &p)).as_ref()
            );

            for right in &values {
                let b = element::<P>(right);
                assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(left == right));
                assert_eq!(
                    a.add(b).to_bytes().as_ref(),
                    encoding::<P>(&((left + right) % &p)).as_ref()
                );
                assert_eq!(
                    a.sub(b).to_bytes().as_ref(),
                    encoding::<P>(&((left + &p - right) % &p)).as_ref()
                );
                assert_eq!(
                    a.mul(b).to_bytes().as_ref(),
                    encoding::<P>(&((left * right) % &p)).as_ref()
                );
            }
        }

        // Verify inverses and roots against independent integer arithmetic.
        assert!(Element::<P>::ZERO.invert().is_none());
        assert_eq!(Element::<P>::ZERO.sqrt(), Some(Element::ZERO));
        let legendre_exponent = (&p - 1u32) >> 1usize;
        let nonsquare = (2u32..=16)
            .map(BigUint::from)
            .find(|value| value.modpow(&legendre_exponent, &p) == &p - 1u32)
            .expect("small nonsquare for every supported modulus");
        assert!(element::<P>(&nonsquare).sqrt().is_none());
        for value in values.iter().skip(1).take(6) {
            let actual = element::<P>(value).invert().expect("nonzero inverse");
            assert_eq!(
                actual.to_bytes().as_ref(),
                encoding::<P>(&value.modpow(&(&p - 2u32), &p)).as_ref()
            );
            assert_eq!(actual.mul(element::<P>(value)), Element::ONE);
            let square = element::<P>(value).square();
            assert!(bool::from(square.is_square()));
            let root = square.sqrt().expect("square root");
            assert_eq!(root.square(), square);
            let root = BigUint::from_bytes_be(root.to_bytes().as_ref());
            assert_eq!((&root * &root) % &p, (value * value) % &p);
        }
        let power_base = BigUint::from(7u32);
        assert_eq!(
            element::<P>(&power_base).pow(&[17]).to_bytes().as_ref(),
            encoding::<P>(&power_base.modpow(&BigUint::from(17u32), &p)).as_ref()
        );

        // Reduction accepts arbitrary byte lengths, including inputs wider than the field.
        for length in [0, 1, 7, 31, 32, 33, 64, 65, 96, 129] {
            let mut bytes = vec![0u8; length];
            rng.fill_bytes(&mut bytes);
            assert_eq!(
                Element::<P>::from_bytes_mod_order(&bytes)
                    .to_bytes()
                    .as_ref(),
                encoding::<P>(&(BigUint::from_bytes_be(&bytes) % &p)).as_ref(),
                "{} length {length}",
                core::any::type_name::<P>()
            );
        }

        // Unsigned, signed, and batched sums each agree with their integer oracle.
        let operands: [Element<P>; 40] =
            array::from_fn(|i| element::<P>(&values[i % values.len()]));
        let reversed: [Element<P>; 40] = array::from_fn(|i| operands[39 - i]);
        let expected = operands
            .iter()
            .zip(reversed)
            .map(|(a, b)| {
                BigUint::from_bytes_be(a.to_bytes().as_ref())
                    * BigUint::from_bytes_be(b.to_bytes().as_ref())
            })
            .sum::<BigUint>()
            % &p;
        assert_eq!(
            Element::sum_of_products(&operands, &reversed)
                .to_bytes()
                .as_ref(),
            encoding::<P>(&expected).as_ref()
        );

        let terms: [SignedTerm<'_, P>; 40] =
            array::from_fn(|i| (&operands[i], &reversed[i], Choice::from((i % 3 == 0) as u8)));
        let expected = terms.iter().fold(BigUint::zero(), |sum, (a, b, negative)| {
            let product = BigUint::from_bytes_be(a.to_bytes().as_ref())
                * BigUint::from_bytes_be(b.to_bytes().as_ref())
                % &p;
            if bool::from(*negative) {
                (sum + &p - product) % &p
            } else {
                (sum + product) % &p
            }
        });
        assert_eq!(
            Element::sum_of_products_signed(&terms).to_bytes().as_ref(),
            encoding::<P>(&expected).as_ref()
        );
        let batch = Element::batch_sum_of_products_signed(&[terms, terms]);
        assert!(
            batch
                .iter()
                .all(|value| value.to_bytes().as_ref() == encoding::<P>(&expected).as_ref())
        );

        // Results remain valid inputs throughout a mixed arithmetic sequence.
        let mut actual = Element::<P>::ONE;
        let mut expected = BigUint::one();
        for i in 0..128 {
            let operand = &values[i % values.len()];
            let value = element::<P>(operand);
            match i % 4 {
                0 => {
                    actual = actual.add(value);
                    expected = (expected + operand) % &p;
                }
                1 => {
                    actual = actual.sub(value);
                    expected = (expected + &p - operand) % &p;
                }
                2 => {
                    actual = actual.mul(value);
                    expected = expected * operand % &p;
                }
                _ => {
                    actual = actual.neg();
                    expected = (&p - expected) % &p;
                }
            }
            assert_eq!(
                actual.to_bytes().as_ref(),
                encoding::<P>(&expected).as_ref()
            );
        }
    }

    fn check_redundant_boundary<P: Modulus>() {
        let p = integer(&P::PARAMETERS.modulus);
        for multiple in 0..=40u64 {
            let halves = array::from_fn(|half| {
                let moduli = if half == 0 {
                    &P::PARAMETERS.m.moduli
                } else {
                    &P::PARAMETERS.n.moduli
                };
                array::from_fn(|i| {
                    (u128::from(P::PARAMETERS.encoded_p[half][i]) * u128::from(multiple)
                        % u128::from(moduli[i])) as u64
                })
            });
            let value = Element::from(Standard::<P>::from_halves(halves));
            assert!(value.is_zero(), "{multiple}p was not recognized as zero");
            assert_eq!(value.to_bytes().as_ref(), P::ZERO_ENCODING.as_ref());
        }

        // This representative lies at the high end of the 40p domain and is congruent to -1.
        let halves = array::from_fn(|half| {
            let moduli = if half == 0 {
                &P::PARAMETERS.m.moduli
            } else {
                &P::PARAMETERS.n.moduli
            };
            array::from_fn(|i| {
                let modulus = u128::from(moduli[i]);
                ((40 * u128::from(P::PARAMETERS.encoded_p[half][i]) + 2 * modulus
                    - u128::from(P::PARAMETERS.one[half][i]))
                    % modulus) as u64
            })
        });
        let high = Element::from(Standard::<P>::from_halves(halves));
        assert_eq!(
            high.to_bytes().as_ref(),
            encoding::<P>(&(&p - 1u32)).as_ref()
        );
        assert_eq!(high.add(Element::ONE), Element::ZERO);

        for original in [Element::<P>::ZERO, Element::ONE, high] {
            for mode in 0..3 {
                let mut redundant = Standard::from(original);
                for half in 0..2 {
                    let moduli = if half == 0 {
                        &P::PARAMETERS.m.moduli
                    } else {
                        &P::PARAMETERS.n.moduli
                    };
                    for (i, (&modulus, lane)) in
                        moduli.iter().zip(&mut redundant.halves[half]).enumerate()
                    {
                        *lane %= modulus;
                        *lane += match mode {
                            0 => modulus,
                            1 if *lane == 0 => 2 * modulus,
                            1 => modulus,
                            _ => ((half + i) % 2) as u64 * modulus,
                        };
                    }
                }
                let redundant = Element::from(redundant);
                assert_standard_bound(redundant);
                assert_eq!(redundant.to_bytes().as_ref(), original.to_bytes().as_ref());
                assert_eq!(redundant.is_zero(), original.is_zero());
                assert!(bool::from(redundant.ct_eq(&original)));
                assert_eq!(bool::from(redundant.sgn0()), bool::from(original.sgn0()));
                assert_eq!(
                    bool::from(redundant.lexicographically_largest()),
                    bool::from(original.lexicographically_largest())
                );
                assert_eq!(redundant.add(Element::ONE), original.add(Element::ONE));
                assert_eq!(redundant.mul(Element::ONE), original);
            }
        }
    }

    #[test]
    fn all_moduli_match_integer_arithmetic() {
        check_public_boundary::<Bls12381>();
        check_public_boundary::<BlsScalar>();
        check_public_boundary::<BanderScalar>();
        check_public_boundary::<Curve25519>();
    }

    #[test]
    fn canonicalization_covers_the_full_redundant_domain() {
        check_redundant_boundary::<Bls12381>();
        check_redundant_boundary::<BlsScalar>();
        check_redundant_boundary::<BanderScalar>();
        check_redundant_boundary::<Curve25519>();
    }

    fn check_canonical_normalization<P: Modulus>() {
        let p = integer(&P::PARAMETERS.modulus);
        let limit = &p << 64usize;
        let rr = integer(&P::PARAMETERS.canonical_rr);
        assert!(p > BigUint::one() && p.bit(0) && p < (BigUint::one() << 381usize));
        assert_eq!(
            P::PARAMETERS.modulus[0].wrapping_mul(P::PARAMETERS.canonical_n0),
            u64::MAX
        );
        assert!(!rr.is_zero() && rr < p);
        assert_eq!(rr, (BigUint::one() << 768usize) % &p);

        let mut values = vec![BigUint::zero(), BigUint::one(), &limit - 1u32];
        for multiple in 1..=40u32 {
            let value = &p * multiple;
            values.extend([&value - 1u32, value.clone(), value + 1u32]);
        }
        for shift in [32usize, 55] {
            values.push((&p << shift) - 1u32);
        }
        for bit in 1..limit.bits() {
            let value = BigUint::one() << bit as usize;
            for boundary in [&value - 1u32, value.clone(), value + 1u32] {
                if boundary < limit {
                    values.push(boundary);
                }
            }
        }
        let mut rng = test_rng();
        for _ in 0..128 {
            let mut bytes = [0u8; 56];
            rng.fill_bytes(&mut bytes);
            values.push(BigUint::from_bytes_le(&bytes) % &limit);
        }

        for value in values {
            assert!(value < limit);
            let digits = value.to_u64_digits();
            let mut input = [0; 7];
            input[..digits.len()].copy_from_slice(&digits);
            let words = normalize_canonical::<P>(input);
            let actual = integer(&words);
            assert_eq!(
                actual,
                &value % &p,
                "{} S={value:x}",
                core::any::type_name::<P>()
            );
            assert!(actual < p);
            assert!(
                words[p.bits().div_ceil(64) as usize..]
                    .iter()
                    .all(|word| *word == 0)
            );
        }
    }

    #[test]
    fn canonical_normalization_matches_integer_remainder() {
        check_canonical_normalization::<Bls12381>();
        check_canonical_normalization::<BlsScalar>();
        check_canonical_normalization::<BanderScalar>();
        check_canonical_normalization::<Curve25519>();
    }
}
