//! Base field arithmetic, by representation.
//!
//! Every representation exchanges elements as [`BYTES`]-byte big-endian integers.

use crate::montgomery;

pub mod rns;
pub mod unsat28;
pub mod unsat49;

/// Number of bytes in an element's big-endian encoding.
pub const BYTES: usize = 48;

/// Number of 64-bit words in an element.
pub(crate) const WORDS: usize = 6;

/// The modulus `p`, little-endian.
pub(crate) const MODULUS: [u64; WORDS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// Largest lane count of any backend.
pub(crate) const MAX_LANES: usize = 8;

/// The encoding of one.
pub(crate) const ONE: [u8; BYTES] = encode([1, 0, 0, 0, 0, 0]);

/// `p - 1`, the encoding of `-1`.
pub(crate) const MINUS_ONE: [u8; BYTES] = {
    let mut bytes = encode(MODULUS);
    // The modulus is odd, so its low byte does not borrow.
    bytes[BYTES - 1] -= 1;
    bytes
};

/// Returns the encoding of an element given as little-endian words.
pub(crate) const fn encode(words: [u64; WORDS]) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    let mut i = 0;
    while i < BYTES {
        bytes[i] = (words[WORDS - 1 - i / 8] >> (56 - 8 * (i % 8))) as u8;
        i += 1;
    }
    bytes
}

/// Returns `2^k mod p`.
const fn power_of_two(k: u32) -> [u64; WORDS] {
    montgomery::power_of_two(k, &MODULUS)
}

/// Reads a big-endian integer into little-endian words.
fn words_from_bytes(bytes: &[u8; BYTES]) -> [u64; WORDS] {
    let mut words = [0; WORDS];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
        *word = u64::from_be_bytes(*chunk);
    }
    words
}

/// Writes little-endian words as a big-endian integer.
fn bytes_from_words(words: &[u64; WORDS]) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    for (chunk, word) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(words.iter().rev())
    {
        *chunk = word.to_be_bytes();
    }
    bytes
}

/// Returns `p - a` for a canonical big-endian element `a`, mapping zero to zero.
pub(crate) fn neg(a: &[u8; BYTES]) -> [u8; BYTES] {
    bytes_from_words(&montgomery::neg(&words_from_bytes(a), &MODULUS))
}

/// Splits a little-endian integer below `2^384` into `N` limbs of `BITS` bits.
const fn limbs_from_words<const N: usize, const BITS: u32>(words: [u64; WORDS]) -> [u64; N] {
    let bits = BITS as usize;
    let mask = (1 << BITS) - 1;
    let mut limbs = [0; N];
    let mut i = 0;
    while i < N {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        let mut limb = 0;
        if word < WORDS {
            limb = words[word] >> shift;
            if shift + bits > 64 && word + 1 < WORDS {
                limb |= words[word + 1] << (64 - shift);
            }
        }
        limbs[i] = limb & mask;
        i += 1;
    }
    limbs
}

/// Joins `N` carried limbs of `BITS` bits, holding a value below `2^384`, into little-endian
/// 64-bit words.
const fn words_from_limbs<const N: usize, const BITS: u32>(limbs: [u64; N]) -> [u64; WORDS] {
    let bits = BITS as usize;
    let mut words = [0u64; WORDS + 1];
    let mut i = 0;
    while i < N {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        words[word] |= limbs[i] << shift;
        if shift + bits > 64 {
            words[word + 1] |= limbs[i] >> (64 - shift);
        }
        i += 1;
    }
    let mut out = [0; WORDS];
    let mut i = 0;
    while i < WORDS {
        out[i] = words[i];
        i += 1;
    }
    out
}

/// Returns `k * p` in `N` carried limbs of `BITS` bits.
const fn multiple<const N: usize, const BITS: u32>(k: u64) -> [u64; N] {
    let modulus = limbs_from_words::<N, BITS>(MODULUS);
    let mask = (1 << BITS) - 1;
    let mut limbs = [0; N];
    let mut carry = 0u128;
    let mut i = 0;
    while i < N {
        let wide = modulus[i] as u128 * k as u128 + carry;
        limbs[i] = wide as u64 & mask;
        carry = wide >> BITS;
        i += 1;
    }
    assert!(carry == 0);
    limbs
}

/// Returns `k * p` in `N` limbs of `BITS` bits, with twice `2^BITS` moved from each limb into
/// the one below it.
///
/// Every limb but the top one is then at least twice `2^BITS`, so subtracting a value whose limbs
/// are at most twice those of a carried value never borrows from them. The top limb is two less
/// than that of `k * p`, which still covers the top limb of such a value below `(k - 1) * p`:
/// the two differ by more than `p`, which exceeds three units of the top limb.
const fn bias<const N: usize, const BITS: u32>(k: u64) -> [u64; N] {
    assert!(k >= 1);
    // p exceeds three units of the top limb, whose weight is at least 2^320.
    assert!(MODULUS[WORDS - 1] >> (BITS as usize * (N - 1) - 320) > 3);
    let mut limbs = multiple::<N, BITS>(k);
    let mut i = 0;
    while i + 1 < N {
        assert!(limbs[i + 1] >= 2);
        limbs[i] += 2 << BITS;
        limbs[i + 1] -= 2;
        i += 1;
    }
    limbs
}

/// Reference arithmetic on canonical integers, for testing representations.
#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod reference {
    use super::*;
    use arbitrary::Unstructured;

    /// A canonical integer below `p`, little-endian.
    pub(crate) type Element = [u64; WORDS];

    /// Zero.
    pub(crate) const ZERO: Element = [0; WORDS];

    /// One.
    pub(crate) const ONE: Element = [1, 0, 0, 0, 0, 0];

    /// `-p^(-1) mod 2^64`.
    const INV: u64 = montgomery::negated_inverse(MODULUS[0]);

    /// `2^768 mod p`, which undoes a Montgomery multiplication's division by `2^384`.
    const R2: Element = power_of_two(768);

    /// Returns `a + b mod p`.
    pub(crate) const fn add(a: Element, b: Element) -> Element {
        montgomery::add(&a, &b, &MODULUS)
    }

    /// Returns `-a mod p`.
    pub(crate) const fn neg(a: Element) -> Element {
        montgomery::neg(&a, &MODULUS)
    }

    /// Returns `a - b mod p`.
    pub(crate) const fn sub(a: Element, b: Element) -> Element {
        add(a, neg(b))
    }

    /// Returns `a * b mod p`, for any `a` below `2^384`.
    pub(crate) const fn mul(a: Element, b: Element) -> Element {
        let product = montgomery::mul(&a, &b, &MODULUS, INV);
        montgomery::mul(&product, &R2, &MODULUS, INV)
    }

    /// Returns `a^(p - 2)`, the inverse of a nonzero `a`.
    pub(crate) fn invert(a: Element) -> Element {
        let mut exponent = MODULUS;
        exponent[0] -= 2;
        let mut result = ONE;
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = mul(result, result);
                if (word >> bit) & 1 == 1 {
                    result = mul(result, a);
                }
            }
        }
        result
    }

    /// Returns the residue of a big-endian integer.
    pub(crate) fn reduce(bytes: &[u8; BYTES]) -> Element {
        mul(words_from_bytes(bytes), ONE)
    }

    /// Returns the big-endian encoding of a canonical integer.
    pub(crate) fn to_bytes(a: Element) -> [u8; BYTES] {
        bytes_from_words(&a)
    }

    /// Draws a canonical integer, biased toward values near the modulus.
    pub(crate) fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        let mut words: Element = u.arbitrary()?;
        words[WORDS - 1] &= (1 << 61) - 1;
        Ok(if montgomery::is_below(&words, &MODULUS) {
            words
        } else {
            ZERO
        })
    }

    #[cfg(test)]
    #[test]
    fn reference_arithmetic_is_consistent() {
        let two = add(ONE, ONE);
        assert_eq!(mul(two, invert(two)), ONE);
        assert_eq!(sub(ZERO, ONE), neg(ONE));
        assert_eq!(add(neg(ONE), ONE), ZERO);
        assert_eq!(reduce(&bytes_from_words(&MODULUS)), ZERO);
        assert_eq!(words_from_bytes(&to_bytes(MODULUS)), MODULUS);
    }
}

/// Shared checks of base field representations against [`reference`](mod@reference).
#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod testing {
    use super::{
        super::arithmetic::Field,
        BYTES, MINUS_ONE, MODULUS, ONE, WORDS, encode, limbs_from_words, montgomery, multiple,
        power_of_two,
        reference::{self, Element},
        rns::Rns,
        unsat28::Unsat28,
        unsat49::Unsat49,
        words_from_limbs,
    };
    use arbitrary::Unstructured;
    use commonware_simd::{
        Operation, Simd, X86V4C,
        emulated::{EmulatedArmV9, EmulatedNeon, EmulatedScalar, EmulatedX86V3, EmulatedX86V4C},
    };
    use core::{any::type_name, marker::PhantomData};
    use std::{format, vec, vec::Vec};

    /// Bits of the Montgomery radix `R = 2^392` of every positional representation.
    const R_BITS: u32 = 392;

    /// `2^(-392) mod p`: a Montgomery multiplication divides by `2^384`, so dividing one by it
    /// twice and multiplying by `2^376` leaves `2^(-392)`.
    const R_INVERSE: Element = {
        let inv = montgomery::negated_inverse(MODULUS[0]);
        let half = montgomery::mul(&reference::ONE, &reference::ONE, &MODULUS, inv);
        montgomery::mul(&half, &power_of_two(384 - 8), &MODULUS, inv)
    };

    /// Draws a big-endian integer below `2^384`, biased toward zero, one, `p - 1`, `p`, and the
    /// largest integer.
    pub(crate) fn bytes(u: &mut Unstructured<'_>) -> arbitrary::Result<[u8; BYTES]> {
        let raw: [u8; BYTES] = u.bytes(BYTES)?.try_into().expect("drew BYTES bytes");
        Ok(match u.int_in_range(0..=7)? {
            1 => [0; BYTES],
            2 => ONE,
            3 => MINUS_ONE,
            4 => encode(MODULUS),
            5 => [0xff; BYTES],
            _ => raw,
        })
    }

    /// Draws a canonical element, the residue of [`bytes`].
    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        Ok(reference::reduce(&bytes(u)?))
    }

    /// An emulated backend. Together they cover every lane count and algorithm path that dispatch
    /// can select.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Backend {
        Scalar,
        X86V3,
        X86V4C,
        ArmV9,
        Neon,
    }

    impl Backend {
        /// Draws a backend.
        pub(crate) fn draw(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            Ok(match u.int_in_range(0..=4)? {
                0 => Self::Scalar,
                1 => Self::X86V3,
                2 => Self::X86V4C,
                3 => Self::ArmV9,
                _ => Self::Neon,
            })
        }

        /// Executes an operation on this backend.
        pub(crate) fn execute<O, R>(self, operation: O) -> R
        where
            O: Operation<EmulatedScalar, Output = R>
                + Operation<EmulatedX86V3, Output = R>
                + Operation<EmulatedX86V4C, Output = R>
                + Operation<EmulatedArmV9, Output = R>
                + Operation<EmulatedNeon, Output = R>,
        {
            match self {
                Self::Scalar => EmulatedScalar.execute(operation),
                Self::X86V3 => EmulatedX86V3.execute(operation),
                Self::X86V4C => EmulatedX86V4C.execute(operation),
                Self::ArmV9 => EmulatedArmV9.execute(operation),
                Self::Neon => EmulatedNeon.execute(operation),
            }
        }
    }

    /// A check of any representation on any backend.
    pub(crate) trait Check: Copy {
        /// Runs the check on `F`, drawing its inputs from `u`.
        fn check<S: Simd, F: Field<S>>(
            self,
            simd: S,
            u: &mut Unstructured<'_>,
        ) -> arbitrary::Result<()>;
    }

    /// Runs a check on a representation and backend drawn from `u`: [`Unsat49`] or [`Unsat28`]
    /// on any emulated backend, or [`Rns`], which requires x86v4c.
    pub(crate) fn check_any<C: Check>(u: &mut Unstructured<'_>, check: C) -> arbitrary::Result<()> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Representation {
            Unsat49,
            Unsat28,
            Rns,
        }

        struct Run<'a, 'b, C> {
            representation: Representation,
            check: C,
            u: &'a mut Unstructured<'b>,
        }

        impl<S: Simd, C: Check> Operation<S> for Run<'_, '_, C> {
            type Output = arbitrary::Result<()>;

            fn portable(self, simd: S) -> Self::Output {
                match self.representation {
                    Representation::Unsat49 => self.check.check::<S, Unsat49<S>>(simd, self.u),
                    Representation::Unsat28 => self.check.check::<S, Unsat28<S>>(simd, self.u),
                    Representation::Rns => unreachable!("residues run only on x86v4c"),
                }
            }

            fn x86_v4c(self, simd: S) -> Self::Output
            where
                S: X86V4C,
            {
                if self.representation == Representation::Rns {
                    self.check.check::<S, Rns<S>>(simd, self.u)
                } else {
                    self.portable(simd)
                }
            }
        }

        let representation = match u.int_in_range(0..=2)? {
            0 => Representation::Unsat49,
            1 => Representation::Unsat28,
            _ => Representation::Rns,
        };
        let backend = match representation {
            Representation::Rns => Backend::X86V4C,
            _ => Backend::draw(u)?,
        };
        backend.execute(Run {
            representation,
            check,
            u,
        })
    }

    /// A positional representation: carried limbs of radix `2^BITS` in Montgomery form with
    /// `R = 2^392`, and eagerly reduced products.
    pub(crate) trait Positional<S: Simd>: Field<S, Product = Self> {
        /// Largest integer bound of any value, in units of `p`.
        const LIMIT: u64;
        /// Largest limb bound of a multiplicand, in units of the radix.
        const SLACK: u64;
        /// Largest limb bound of any value, in units of the radix.
        const LIMB_LIMIT: u64;

        /// Returns the carried limbs of the Montgomery form of `element` plus `(bound - 1) * p`.
        fn lifted(element: Element, bound: u64) -> Self::Raw;

        /// Returns the value whose lane `i` holds the carried limbs `lanes[i]`, or zero beyond
        /// them, with integer bound `bound`.
        fn from_raw(simd: S, lanes: &[Self::Raw], bound: u64) -> Self;

        /// Returns the element that lifts to the widest carried limbs below `bound * p`; see
        /// [`widest`].
        fn widest(bound: u64) -> Element;

        /// Returns whether `raw` holds carried limbs of an integer below `2p`.
        fn is_tight(raw: &Self::Raw) -> bool;
    }

    /// Returns the element whose Montgomery form is the integer `words`, below `2^384`.
    pub(crate) const fn from_montgomery(words: [u64; WORDS]) -> Element {
        reference::mul(words, R_INVERSE)
    }

    /// Returns the element whose Montgomery form is `p - 1`, which lifts to `bound * p - 1`.
    pub(crate) const fn largest() -> Element {
        let mut words = MODULUS;
        words[0] -= 1;
        from_montgomery(words)
    }

    /// Returns the carried limbs of the Montgomery form of `element` plus `(bound - 1) * p`, in
    /// `N` limbs of `BITS` bits.
    pub(crate) fn lift<const N: usize, const BITS: u32>(element: Element, bound: u64) -> [u64; N] {
        const { assert!(N as u32 * BITS == R_BITS) };
        let value = limbs_from_words::<N, BITS>(reference::mul(element, power_of_two(R_BITS)));
        let offset = multiple::<N, BITS>(bound - 1);
        let mut limbs = [0; N];
        let mut carry = 0;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = value[i] + offset[i] + carry;
            *limb = sum & ((1 << BITS) - 1);
            carry = sum >> BITS;
        }
        assert_eq!(carry, 0, "lifted value exceeds the limbs");
        limbs
    }

    /// Returns the element that lifts, with integer bound `bound`, to the carried limbs below
    /// `bound * p` whose low limbs all hold their largest value.
    ///
    /// The top limb is `bound * t - 1` for the top limb `t` of `p`, so the limbs hold
    /// `bound * t * 2^shift - 1`, which is below `bound * p` and, since `t` exceeds any bound,
    /// at least `(bound - 1) * p`.
    pub(crate) fn widest<const N: usize, const BITS: u32>(bound: u64) -> Element {
        let mask = (1 << BITS) - 1;
        let top = bound * multiple::<N, BITS>(1)[N - 1] - 1;
        assert!(top <= mask, "bound exceeds the top limb");
        let mut limbs = [mask; N];
        limbs[N - 1] = top;
        // Subtract (bound - 1) * p, leaving the Montgomery form below p.
        let offset = multiple::<N, BITS>(bound - 1);
        let mut borrow = 0;
        for (limb, offset) in limbs.iter_mut().zip(offset) {
            let difference = *limb as i128 - offset as i128 - borrow;
            borrow = i128::from(difference < 0);
            *limb = (difference + (borrow << BITS)) as u64;
        }
        assert_eq!(borrow, 0, "widest limbs are below (bound - 1) * p");
        from_montgomery(words_from_limbs::<N, BITS>(limbs))
    }

    /// Returns whether `limbs` are carried limbs of `BITS` bits holding an integer below `2p`.
    pub(crate) fn is_tight<const N: usize, const BITS: u32>(limbs: [u64; N]) -> bool {
        let twice = multiple::<N, BITS>(2);
        limbs.iter().all(|limb| *limb >> BITS == 0) && limbs.iter().rev().lt(twice.iter().rev())
    }

    /// Returns a value holding `elements` lifted to integer bound `bound`, one per lane.
    pub(crate) fn loose<S: Simd, F: Positional<S>>(simd: S, elements: &[Element], bound: u64) -> F {
        let lanes: Vec<F::Raw> = elements.iter().map(|e| F::lifted(*e, bound)).collect();
        F::from_raw(simd, &lanes, bound)
    }

    /// Selects a positional representation for every backend.
    pub(crate) trait Family {
        /// The representation on backend `S`.
        type Value<S: Simd>: Positional<S>;
    }

    /// A group of formulas over positional values.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Formulas {
        /// Additions, subtractions, negations, doublings, and stores, which never reduce.
        Linear,
        /// Products of values with any bounds, and of uncarried sums.
        Products,
        /// Tight reductions of sums.
        Tight,
    }

    /// A formula over one pair of lifted elements per lane.
    #[derive(Clone, Copy, Debug)]
    enum Formula {
        Add,
        Sub,
        Neg,
        Double,
        Store,
        Mul,
        Square,
        /// `(a + a + a) * (b - a) - b`: linear operations chained around a product.
        Chain,
        /// `(a + b) * (4 (a + b) + a)`: an uncarried factor times one that `ready` carries.
        Ready,
        /// The product of sums of [`Positional::SLACK`] values, uncarried.
        Slack,
        /// Doublings with as few carries as the limb limit allows, then a product.
        Doubling,
        /// A tight reduction of a sum of up to [`Positional::LIMB_LIMIT`] values.
        Tight,
    }

    /// A formula with the integer bounds of its inputs and its parameters.
    #[derive(Debug)]
    struct Case {
        formula: Formula,
        a_bound: u64,
        b_bound: u64,
        /// Bias of a subtraction or negation.
        bias: u64,
        /// Doublings, or values in a sum.
        count: u64,
    }

    /// Biases of subtractions and negations.
    const BIASES: [u64; 4] = [3, 5, 64, 1024];

    /// Draws a bound in `1..=max`, biased toward both ends.
    fn bound(u: &mut Unstructured<'_>, max: u64) -> arbitrary::Result<u64> {
        assert!(max >= 1);
        Ok(match u.int_in_range(0..=3)? {
            0 => max,
            1 => 1,
            2 => 2.min(max),
            _ => u.int_in_range(1..=max)?,
        })
    }

    impl Case {
        /// Draws a formula of `formulas` with bounds that satisfy its requirements.
        fn draw<S: Simd, F: Positional<S>>(
            formulas: Formulas,
            u: &mut Unstructured<'_>,
        ) -> arbitrary::Result<Self> {
            let choices: &[Formula] = match formulas {
                Formulas::Linear => &[
                    Formula::Add,
                    Formula::Sub,
                    Formula::Neg,
                    Formula::Double,
                    Formula::Store,
                ],
                Formulas::Products => &[
                    Formula::Mul,
                    Formula::Square,
                    Formula::Chain,
                    Formula::Ready,
                    Formula::Slack,
                    Formula::Doubling,
                ],
                Formulas::Tight => &[Formula::Tight],
            };
            let formula = *u.choose(choices)?;
            let limit = F::LIMIT;
            // A product's integer bound stays within the limit when A * B <= LIMIT * (LIMIT - 1).
            let product = limit * (limit - 1);
            let mut case = Self {
                formula,
                a_bound: 1,
                b_bound: 1,
                bias: BIASES[0],
                count: 1,
            };
            match formula {
                Formula::Add => {
                    case.a_bound = bound(u, limit - 1)?;
                    case.b_bound = bound(u, limit - case.a_bound)?;
                }
                Formula::Sub => {
                    case.bias = *u.choose(&BIASES)?;
                    case.a_bound = bound(u, limit - case.bias)?;
                    case.b_bound = bound(u, case.bias - 1)?;
                }
                Formula::Neg => {
                    case.bias = *u.choose(&BIASES)?;
                    case.a_bound = bound(u, case.bias - 1)?;
                }
                Formula::Double => case.a_bound = bound(u, limit / 2)?,
                Formula::Store | Formula::Mul => {
                    case.a_bound = bound(u, limit)?;
                    case.b_bound = bound(u, limit.min(product / case.a_bound))?;
                }
                Formula::Square => case.a_bound = bound(u, limit - 1)?,
                Formula::Chain | Formula::Ready => {
                    case.a_bound = bound(u, 2)?;
                    case.b_bound = bound(u, 2)?;
                }
                Formula::Slack => {
                    let (slack, max) = (F::SLACK, limit / F::SLACK);
                    case.a_bound = bound(u, max)?;
                    case.b_bound = bound(u, max.min(product / (slack * slack * case.a_bound)))?;
                }
                Formula::Doubling => {
                    case.a_bound = bound(u, limit / 2)?;
                    case.count = bound(u, (limit / case.a_bound).ilog2().into())?;
                    let doubled = case.a_bound << case.count;
                    case.b_bound = bound(u, limit.min(product / doubled))?;
                }
                Formula::Tight => {
                    case.a_bound = bound(u, limit)?;
                    case.count = bound(u, F::LIMB_LIMIT.min(limit / case.a_bound))?;
                }
            }
            Ok(case)
        }

        /// Returns the formula's value on one lane's elements.
        fn expected<S: Simd, F: Positional<S>>(&self, a: Element, b: Element) -> Element {
            let small = |n: u64| [n, 0, 0, 0, 0, 0];
            match self.formula {
                Formula::Add => reference::add(a, b),
                Formula::Sub => reference::sub(a, b),
                Formula::Neg => reference::neg(a),
                Formula::Double => reference::add(a, a),
                Formula::Store => a,
                Formula::Mul => reference::mul(a, b),
                Formula::Square => reference::mul(a, a),
                Formula::Chain => {
                    let three = reference::mul(a, small(3));
                    reference::sub(reference::mul(three, reference::sub(b, a)), b)
                }
                Formula::Ready => {
                    let sum = reference::add(a, b);
                    let wide = reference::add(reference::mul(sum, small(4)), a);
                    reference::mul(sum, wide)
                }
                Formula::Slack => {
                    let slack = small(F::SLACK);
                    reference::mul(reference::mul(a, slack), reference::mul(b, slack))
                }
                Formula::Doubling => reference::mul(reference::mul(a, small(1 << self.count)), b),
                Formula::Tight => reference::mul(a, small(self.count)),
            }
        }

        /// Evaluates the formula on every lane.
        fn evaluate<S: Simd, F: Positional<S>>(&self, simd: S, a: F, b: F) -> F {
            /// Applies `$op` with the bias of the case as a constant.
            macro_rules! biased {
                (|$k:ident| $op:expr) => {
                    match self.bias {
                        3 => {
                            const $k: u64 = 3;
                            $op
                        }
                        5 => {
                            const $k: u64 = 5;
                            $op
                        }
                        64 => {
                            const $k: u64 = 64;
                            $op
                        }
                        _ => {
                            const $k: u64 = 1024;
                            $op
                        }
                    }
                };
            }
            let sum = |value: F, count: u64| (1..count).fold(value, |sum, _| sum.add(simd, value));
            match self.formula {
                Formula::Add => a.add(simd, b),
                Formula::Sub => biased!(|K| a.sub::<K>(simd, b)),
                Formula::Neg => biased!(|K| a.neg::<K>(simd)),
                Formula::Double => a.double(simd),
                Formula::Store => a,
                Formula::Mul => a.mul(simd, b),
                Formula::Square => a.mul(simd, a),
                Formula::Chain => {
                    let three = a.double(simd).add(simd, a).ready::<3>(simd);
                    let difference = b.sub::<3>(simd, a).ready::<4>(simd);
                    three.mul(simd, difference).sub::<3>(simd, b)
                }
                Formula::Ready => {
                    let sum = a.add(simd, b);
                    let wide = sum.double(simd).double(simd).add(simd, a);
                    sum.ready::<2>(simd).mul(simd, wide.ready::<9>(simd))
                }
                Formula::Slack => sum(a, F::SLACK).mul(simd, sum(b, F::SLACK)),
                Formula::Doubling => {
                    let (mut value, mut limbs) = (a, 1);
                    for _ in 0..self.count {
                        if 2 * limbs > F::LIMB_LIMIT {
                            value = value.carry(simd);
                            limbs = 1;
                        }
                        value = value.double(simd);
                        limbs *= 2;
                    }
                    value.carry(simd).mul(simd, b)
                }
                Formula::Tight => F::reduce_tight(simd, sum(a, self.count)),
            }
        }
    }

    /// Draws an element to lift to integer bound `bound`, biased toward the largest integer and
    /// the widest limbs below that bound.
    fn lane<S: Simd, F: Positional<S>>(
        u: &mut Unstructured<'_>,
        bound: u64,
    ) -> arbitrary::Result<Element> {
        let element = element(u)?;
        Ok(match u.int_in_range(0..=4)? {
            1 => largest(),
            2 => F::widest(bound),
            _ => element,
        })
    }

    /// Checks a formula of `formulas` on distinct lifted elements in every lane against the
    /// reference.
    fn check_formulas<S: Simd, F: Positional<S>>(
        simd: S,
        formulas: Formulas,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let case = Case::draw::<S, F>(formulas, u)?;
        let mut a = Vec::with_capacity(F::LANES);
        let mut b = Vec::with_capacity(F::LANES);
        for _ in 0..F::LANES {
            a.push(lane::<S, F>(u, case.a_bound)?);
            b.push(lane::<S, F>(u, case.b_bound)?);
        }
        let result = case.evaluate(
            simd,
            loose::<S, F>(simd, &a, case.a_bound),
            loose::<S, F>(simd, &b, case.b_bound),
        );
        let label = |lane| format!("{case:?} on {}, lane {lane}", type_name::<F>());
        if let Formula::Tight = case.formula {
            let mut raw = vec![F::Raw::default(); F::LANES];
            result.store_raw::<2>(simd, &mut raw);
            for (lane, raw) in raw.iter().enumerate() {
                assert!(F::is_tight(raw), "not carried below 2p: {}", label(lane));
            }
        }
        let mut stored = vec![[0; BYTES]; F::LANES];
        result.store(simd, &mut stored);
        for (lane, stored) in stored.iter().enumerate() {
            let expected = case.expected::<S, F>(a[lane], b[lane]);
            assert_eq!(*stored, reference::to_bytes(expected), "{}", label(lane));
        }
        Ok(())
    }

    /// Checks a formula of `formulas` in the representation `R` on a backend drawn from `u`.
    pub(crate) fn run_formulas<R: Family>(
        formulas: Formulas,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        struct Run<'a, 'b, R> {
            formulas: Formulas,
            u: &'a mut Unstructured<'b>,
            family: PhantomData<R>,
        }

        impl<S: Simd, R: Family> Operation<S> for Run<'_, '_, R> {
            type Output = arbitrary::Result<()>;

            fn portable(self, simd: S) -> Self::Output {
                check_formulas::<S, R::Value<S>>(simd, self.formulas, self.u)
            }
        }

        Backend::draw(u)?.execute(Run::<R> {
            formulas,
            u,
            family: PhantomData,
        })
    }

    /// Checks that debug builds reject values beyond the integer, limb, and multiplier limits.
    #[cfg(test)]
    pub(crate) fn check_limits<S: Simd, F: Positional<S>>(simd: S) {
        use crate::core::debug_counter::DebugCounter;
        use std::panic::{AssertUnwindSafe, catch_unwind};

        if !DebugCounter::live() {
            return;
        }
        let rejects = |f: &dyn Fn()| catch_unwind(AssertUnwindSafe(f)).is_err();
        let largest = largest();
        let at = |bound| loose::<S, F>(simd, &[largest], bound);
        let limit = F::LIMIT;
        assert!(rejects(&|| {
            let _ = at(limit).add(simd, at(1));
        }));
        assert!(!rejects(&|| {
            let _ = at(2).sub::<3>(simd, at(2));
        }));
        assert!(rejects(&|| {
            let _ = at(2).sub::<3>(simd, at(3));
        }));
        assert!(!rejects(&|| {
            let _ = at(1).sub::<5>(simd, at(1).double(simd));
        }));
        assert!(rejects(&|| {
            let _ = at(1).sub::<9>(simd, at(1).double(simd).double(simd));
        }));
        assert!(rejects(&|| {
            let _ = at(limit).sub::<3>(simd, at(1));
        }));
        assert!(rejects(&|| {
            let _ = at(3).neg::<3>(simd);
        }));
        assert!(rejects(&|| {
            let _ = at(limit).mul(simd, at(limit));
        }));
        // A multiplicand may hold the sum of SLACK carried values, but no more.
        let sum = |count: u64| (1..count).fold(at(1), |sum, _| sum.add(simd, at(1)));
        assert!(!rejects(&|| {
            let _ = sum(F::SLACK).mul(simd, at(1));
        }));
        assert!(rejects(&|| {
            let _ = sum(F::SLACK + 1).mul(simd, at(1));
        }));
        // Any value may hold the sum of LIMB_LIMIT carried values, but no more, where the integer
        // limit allows reaching it.
        if F::LIMB_LIMIT < limit {
            assert!(!rejects(&|| {
                let _ = sum(F::LIMB_LIMIT);
            }));
            assert!(rejects(&|| {
                let _ = sum(F::LIMB_LIMIT + 1);
            }));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn check_lift<const N: usize, const BITS: u32>(limit: u64) {
            for bound in [1, 2, limit] {
                let mut limbs = multiple::<N, BITS>(bound);
                limbs[0] -= 1;
                assert_eq!(
                    lift::<N, BITS>(largest(), bound),
                    limbs,
                    "largest at {bound}"
                );
                let mut widest_limbs = [(1 << BITS) - 1; N];
                widest_limbs[N - 1] = bound * multiple::<N, BITS>(1)[N - 1] - 1;
                let lifted = lift::<N, BITS>(widest::<N, BITS>(bound), bound);
                assert_eq!(lifted, widest_limbs, "widest at {bound}");
            }
            let element = reference::neg(reference::ONE);
            let words = words_from_limbs::<N, BITS>(lift::<N, BITS>(element, 1));
            assert_eq!(from_montgomery(words), element);
        }

        #[test]
        fn lifts_offset_the_montgomery_form() {
            assert_eq!(
                reference::mul(R_INVERSE, power_of_two(R_BITS)),
                reference::ONE
            );
            check_lift::<8, 49>(2048);
            check_lift::<14, 28>(2048);
        }
    }
}
