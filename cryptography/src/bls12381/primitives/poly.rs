//! Polynomial operations over the BLS12-381 scalar field.
//!
//! # Warning
//!
//! The security of the polynomial operations is critical for the overall
//! security of the threshold schemes. Ensure that the scalar field operations
//! are performed over the correct field and that all elements are valid.

use super::variant::Variant;
use crate::bls12381::primitives::{
    group::{self, Element, Scalar},
    Error,
};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use core::{hash::Hash, iter, num::NonZeroU32};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Private polynomials are used to generate secret shares.
pub type Private = Poly<group::Private>;

/// Public polynomials represent commitments to secrets on a private polynomial.
pub type Public<V> = Poly<<V as Variant>::Public>;

/// Signature polynomials are used in threshold signing (where a signature
/// is interpolated using at least `threshold` evaluations).
pub type Signature<V> = Poly<<V as Variant>::Signature>;

/// The partial signature type.
pub type PartialSignature<V> = Eval<<V as Variant>::Signature>;

/// A polynomial evaluation at a specific index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eval<C: Element> {
    pub index: u32,
    pub value: C,
}

impl<C: Element> Write for Eval<C> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.value.write(buf);
    }
}

impl<C: Element> Read for Eval<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = UInt::read(buf)?.into();
        let value = C::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<C: Element> EncodeSize for Eval<C> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + C::SIZE
    }
}

#[cfg(feature = "arbitrary")]
impl<C: Element> arbitrary::Arbitrary<'_> for Eval<C>
where
    C: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            index: u.arbitrary::<u32>()?,
            value: u.arbitrary::<C>()?,
        })
    }
}

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients.
///
/// The coefficients must be able to multiply the type of the variable,
/// which is always a scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
// Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L24-L28
pub struct Poly<C>(Vec<C>);

#[cfg(feature = "arbitrary")]
impl<C: Element> arbitrary::Arbitrary<'_> for Poly<C>
where
    C: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let degree = (u.arbitrary::<u32>()? % 10).max(1);
        let coeffs = (0..=degree)
            .map(|_| u.arbitrary::<C>())
            .collect::<arbitrary::Result<Vec<C>>>()?;
        Ok(Self(coeffs))
    }
}

// Returns a new scalar polynomial of the given degree where each coefficient is
// sampled at random from the provided RNG.
///
/// In the context of secret sharing, the threshold is the degree + 1.
pub fn new_from<R: CryptoRngCore>(rng: &mut R, degree: u32) -> Poly<Scalar> {
    // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L46-L52
    let coeffs = (0..=degree).map(|_| Scalar::from_rand(rng));
    Poly::from_iter(coeffs)
}

/// Returns a new scalar polynomial with a particular value for the constant coefficient.
///
/// This does the same thing as [new_from] otherwise.
pub fn new_with_constant(
    degree: u32,
    mut rng: impl CryptoRngCore,
    constant: Scalar,
) -> Poly<Scalar> {
    // (Use skip to avoid an empty range complaint)
    Poly::from_iter(
        iter::once(constant).chain((0..=degree).skip(1).map(|_| Scalar::from_rand(&mut rng))),
    )
}

/// A Barycentric Weight for interpolation at x=0.
pub struct Weight(Scalar);

impl Weight {
    /// Returns the weight as a [Scalar].
    pub const fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

/// Prepares at least `t` evaluations for Lagrange interpolation.
pub fn prepare_evaluations<'a, C, I>(threshold: u32, evals: I) -> Result<Vec<&'a Eval<C>>, Error>
where
    C: 'a + Element,
    I: IntoIterator<Item = &'a Eval<C>>,
{
    // Check if we have at least `t` evaluations; if not, return an error
    let t = threshold as usize;
    let mut evals = evals.into_iter().collect::<Vec<_>>();
    if evals.len() < t {
        return Err(Error::NotEnoughPartialSignatures(t, evals.len()));
    }

    // Convert the first `t` sorted shares into scalars
    //
    // We sort the evaluations by index to ensure that two invocations of
    // `recover` select the same evals.
    evals.sort_by_key(|e| e.index);
    evals.truncate(t);
    Ok(evals)
}

/// Computes Barycentric Weights for Lagrange interpolation at x=0.
///
/// These weights can be reused for multiple interpolations with the same set of points,
/// which significantly improves performance when recovering a group polynomial or multiple
/// signatures.
///
/// The `indices` of the points used for interpolation (x = index + 1). These indices
/// should be of length `threshold`, deduped, and sorted.
pub fn compute_weights(indices: Vec<u32>) -> Result<BTreeMap<u32, Weight>, Error> {
    // Compute weights for all provided evaluation indices
    let mut weights = BTreeMap::new();
    for i in &indices {
        // Convert i_eval.index to x-coordinate (x = index + 1)
        let xi = Scalar::from_index(*i);

        // Compute product terms for Lagrange basis polynomial
        let (mut num, mut den) = (Scalar::one(), Scalar::one());
        for j in &indices {
            // Skip if i_eval and j_eval are the same
            if i == j {
                continue;
            }

            // Convert j_eval.index to x-coordinate
            let xj = Scalar::from_index(*j);

            // Include `xj` in the numerator product for `l_i(0)`
            num.mul(&xj);

            // Compute `xj - xi` and include it in the denominator product
            let mut diff = xj;
            diff.sub(&xi);
            den.mul(&diff);
        }

        // Compute the inverse of the denominator product; fails if den is zero (e.g., duplicate `xj`)
        let inv = den.inverse().ok_or(Error::NoInverse)?;

        // Compute `l_i(0) = num * inv`, the Lagrange basis coefficient at `x=0`
        num.mul(&inv);

        // Store the weight
        weights.insert(*i, Weight(num));
    }
    Ok(weights)
}

impl<C> FromIterator<C> for Poly<C> {
    fn from_iter<T: IntoIterator<Item = C>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<C> Poly<C> {
    /// Creates a new polynomial from the given coefficients.
    pub const fn from(c: Vec<C>) -> Self {
        Self(c)
    }

    /// Returns the constant term of the polynomial.
    pub fn constant(&self) -> &C {
        &self.0[0]
    }

    /// Returns the degree of the polynomial
    pub const fn degree(&self) -> u32 {
        (self.0.len() - 1) as u32 // check size in deserialize, safe to cast
    }

    /// Returns the number of required shares to reconstruct the polynomial.
    ///
    /// This will be the threshold.
    pub const fn required(&self) -> u32 {
        self.0.len() as u32 // check size in deserialize, safe to cast
    }
}

impl<C: Element> Poly<C> {
    /// Commits the scalar polynomial to the group and returns a polynomial over
    /// the group.
    ///
    /// This is done by multiplying each coefficient of the polynomial with the
    /// group's generator.
    pub fn commit(commits: Poly<Scalar>) -> Self {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L322-L340
        let commits = commits
            .0
            .iter()
            .map(|c| {
                let mut commitment = C::one();
                commitment.mul(c);
                commitment
            })
            .collect::<Vec<C>>();

        Self::from(commits)
    }

    /// Returns a zero polynomial.
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }

    /// Returns the given coefficient at the requested index.
    ///
    /// It panics if the index is out of range.
    pub fn get(&self, i: u32) -> C {
        self.0[i as usize].clone()
    }

    /// Set the given element at the specified index.
    ///
    /// It panics if the index is out of range.
    pub fn set(&mut self, index: u32, value: C) {
        self.0[index as usize] = value;
    }

    /// Performs polynomial addition in place.
    pub fn add(&mut self, other: &Self) {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L87-L95

        // if we have a smaller degree we should pad with zeros
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), C::zero())
        }

        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| a.add(b))
    }

    /// Evaluates the polynomial at the specified index (provided value offset by 1).
    pub fn evaluate(&self, index: u32) -> Eval<C> {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L111-L129

        // We add +1 because we must never evaluate the polynomial at its first point
        // otherwise it reveals the "secret" value after a reshare (where the constant
        // term is set to be the secret of the previous dealing).
        let xi = Scalar::from_index(index);

        // Use Horner's method to evaluate the polynomial
        let value = self.0.iter().rev().fold(C::zero(), |mut sum, coeff| {
            sum.mul(&xi);
            sum.add(coeff);
            sum
        });
        Eval { value, index }
    }

    /// Evaluates the polynomial at `n` indices.
    pub fn evaluate_all(&self, n: u32) -> Vec<C> {
        let mut evals = Vec::with_capacity(n as usize);
        for index in 0..n {
            evals.push(self.evaluate(index).value);
        }
        evals
    }

    /// Recovers the constant term of a polynomial of degree less than `t` using `t` evaluations of the polynomial
    /// and precomputed Barycentric Weights.
    ///
    /// This function uses Lagrange interpolation to compute the constant term (i.e., the value of the polynomial at `x=0`)
    /// given at least `t` distinct evaluations of the polynomial. Each evaluation is assumed to have a unique index,
    /// which is mapped to a unique x-value as `x = index + 1`.
    ///
    /// # References
    ///
    /// This implementation is based on [J.-P. Berrut and L. N.
    /// Trefethen, “Barycentric Lagrange Interpolation,” SIAM Rev., vol. 46, no. 3,
    /// pp. 501–517, 2004](https://people.maths.ox.ac.uk/trefethen/barycentric.pdf).
    ///
    /// # Warning
    ///
    /// This function assumes that each evaluation has a unique index. If there are duplicate indices, the function may
    /// fail with an error when attempting to compute the inverse of zero.
    pub fn recover_with_weights<'a, I>(
        weights: &BTreeMap<u32, Weight>,
        evals: I,
    ) -> Result<C, Error>
    where
        C: 'a,
        I: IntoIterator<Item = &'a Eval<C>>,
    {
        // Scale all evaluations by their corresponding weight
        let mut result = C::zero();
        for eval in evals.into_iter() {
            // Get the weight for the current evaluation index
            let Some(weight) = weights.get(&eval.index) else {
                return Err(Error::InvalidIndex);
            };

            // Scale `yi` by `l_i(0)` to contribute to the constant term
            let mut scaled_value = eval.value.clone();
            scaled_value.mul(&weight.0);

            // Add `yi * l_i(0)` to the running sum
            result.add(&scaled_value);
        }

        Ok(result)
    }

    /// Recovers the constant term of a polynomial of degree less than `t` using at least `t` evaluations of
    /// the polynomial.
    ///
    /// This function uses Lagrange interpolation to compute the constant term (i.e., the value of the polynomial at `x=0`)
    /// given at least `t` distinct evaluations of the polynomial. Each evaluation is assumed to have a unique index,
    /// which is mapped to a unique x-value as `x = index + 1`.
    ///
    /// # References
    ///
    /// This implementation is based on [J.-P. Berrut and L. N.
    /// Trefethen, “Barycentric Lagrange Interpolation,” SIAM Rev., vol. 46, no. 3,
    /// pp. 501–517, 2004](https://people.maths.ox.ac.uk/trefethen/barycentric.pdf).
    ///
    /// # Warning
    ///
    /// This function assumes that each evaluation has a unique index. If there are duplicate indices, the function may
    /// fail with an error when attempting to compute the inverse of zero.
    pub fn recover<'a, I>(t: u32, evals: I) -> Result<C, Error>
    where
        C: 'a,
        I: IntoIterator<Item = &'a Eval<C>>,
    {
        // Prepare evaluations
        let evals = prepare_evaluations(t, evals)?;

        // Compute weights
        let indices = evals.iter().map(|e| e.index).collect::<Vec<_>>();
        let weights = compute_weights(indices)?;

        // Perform interpolation using the precomputed weights
        Self::recover_with_weights(&weights, evals)
    }
}

impl<C: Element> Write for Poly<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<C: Element> Read for Poly<C> {
    type Cfg = RangeCfg<NonZeroU32>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let coeffs = Vec::<C>::read_cfg(buf, &((*range).into(), ()))?;
        Ok(Self(coeffs))
    }
}

impl<C: Element> EncodeSize for Poly<C> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

/// Returns the public key of the polynomial (constant term).
pub fn public<V: Variant>(public: &Public<V>) -> &V::Public {
    public.constant()
}

#[cfg(test)]
pub mod tests {
    // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/poly.rs#L355-L604
    use super::*;
    use crate::bls12381::primitives::group::{Scalar, G2};
    use commonware_codec::{Decode, Encode};
    use commonware_utils::NZU32;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn poly_degree() {
        let s = 5;
        let p = new_from(&mut ChaCha8Rng::seed_from_u64(0), s);
        assert_eq!(p.degree(), s);
    }

    #[test]
    fn add_zero() {
        let p1 = new_from(&mut ChaCha8Rng::seed_from_u64(0), 3);
        let p2 = Poly::<Scalar>::zero();
        let mut res = p1.clone();
        res.add(&p2);
        assert_eq!(res, p1);

        let p1 = Poly::<Scalar>::zero();
        let p2 = new_from(&mut ChaCha8Rng::seed_from_u64(0), 3);
        let mut res = p1;
        res.add(&p2);
        assert_eq!(res, p2);
    }

    #[test]
    fn interpolation_insufficient_shares() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = new_from(&mut ChaCha8Rng::seed_from_u64(0), degree);
        let shares = (0..threshold - 1)
            .map(|i| poly.evaluate(i))
            .collect::<Vec<_>>();
        Poly::recover(threshold, &shares).unwrap_err();
    }

    #[test]
    fn evaluate_with_overflow() {
        let degree = 4;
        let poly = new_from(&mut ChaCha8Rng::seed_from_u64(0), degree);
        poly.evaluate(u32::MAX);
    }

    #[test]
    fn commit() {
        let secret = new_from(&mut ChaCha8Rng::seed_from_u64(0), 5);
        let coeffs = secret.0.clone();
        let commitment = coeffs
            .iter()
            .map(|coeff| {
                let mut p = G2::one();
                p.mul(coeff);
                p
            })
            .collect::<Vec<_>>();
        let commitment = Poly::from(commitment);
        assert_eq!(commitment, Poly::commit(secret));
    }

    fn pow(base: Scalar, pow: usize) -> Scalar {
        let mut res = Scalar::one();
        for _ in 0..pow {
            res.mul(&base)
        }
        res
    }

    #[test]
    fn addition() {
        for deg1 in 0..100u32 {
            for deg2 in 0..100u32 {
                let p1 = new_from(&mut ChaCha8Rng::seed_from_u64(0), deg1);
                let p2 = new_from(&mut ChaCha8Rng::seed_from_u64(0), deg2);
                let mut res = p1.clone();
                res.add(&p2);

                let (larger, smaller) = if p1.degree() > p2.degree() {
                    (&p1, &p2)
                } else {
                    (&p2, &p1)
                };

                for i in 0..larger.degree() + 1 {
                    let i = i as usize;
                    if i < (smaller.degree() + 1) as usize {
                        let mut coeff_sum = p1.0[i].clone();
                        coeff_sum.add(&p2.0[i]);
                        assert_eq!(res.0[i], coeff_sum);
                    } else {
                        assert_eq!(res.0[i], larger.0[i]);
                    }
                }
                assert_eq!(res.degree(), larger.degree(), "deg1={deg1}, deg2={deg2}");
            }
        }
    }

    #[test]
    fn interpolation() {
        for degree in 0..100u32 {
            for num_evals in 0..100u32 {
                let poly = new_from(&mut ChaCha8Rng::seed_from_u64(0), degree);
                let expected = poly.0[0].clone();

                let shares = (0..num_evals).map(|i| poly.evaluate(i)).collect::<Vec<_>>();
                let recovered_constant = Poly::recover(num_evals, &shares).unwrap();

                if num_evals > degree {
                    assert_eq!(
                        expected, recovered_constant,
                        "degree={degree}, num_evals={num_evals}"
                    );
                } else {
                    assert_ne!(
                        expected, recovered_constant,
                        "degree={degree}, num_evals={num_evals}"
                    );
                }
            }
        }
    }

    #[test]
    fn evaluate() {
        for d in 0..100u32 {
            for idx in 0..100_u32 {
                let x = Scalar::from_index(idx);

                let p1 = new_from(&mut ChaCha8Rng::seed_from_u64(0), d);
                let evaluation = p1.evaluate(idx).value;

                let coeffs = p1.0;
                let mut sum = coeffs[0].clone();
                for (i, coeff) in coeffs
                    .into_iter()
                    .enumerate()
                    .take((d + 1) as usize)
                    .skip(1)
                {
                    let xi = pow(x.clone(), i);
                    let mut var = coeff;
                    var.mul(&xi);
                    sum.add(&var);
                }

                assert_eq!(sum, evaluation, "degree={d}, idx={idx}");
            }
        }
    }

    #[test]
    fn test_codec() {
        let original = new_from(&mut ChaCha8Rng::seed_from_u64(0), 5);
        let encoded = original.encode();
        let decoded = Poly::<Scalar>::decode_cfg(
            encoded,
            &RangeCfg::from(NZU32!(1)..=NZU32!(original.required())),
        )
        .unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_new_with_constant() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let constant = Scalar::from_rand(&mut rng);
        let poly = new_with_constant(5, &mut rng, constant.clone());
        assert_eq!(poly.constant(), &constant);
    }

    #[cfg(feature = "arbitrary")]
    mod arbitrary_tests {
        use super::*;

        commonware_codec::conformance_tests! {
            Eval<Scalar>,
            Poly<Scalar>,
        }
    }
}
