//! Polynomial operations over the BLS12-381 scalar field.
//!
//! # Warning
//!
//! The security of the polynomial operations is critical for the overall
//! security of the threshold schemes. Ensure that the scalar field operations
//! are performed over the correct field and that all elements are valid.

use crate::bls12381::primitives::{
    group::{self, Element, Scalar},
    Error,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use rand::{rngs::OsRng, RngCore};
use std::hash::Hash;

/// Private polynomials are used to generate secret shares.
pub type Private = Poly<group::Private>;

/// Public polynomials represent commitments to secrets on a private polynomial.
pub type Public = Poly<group::Public>;

/// Signature polynomials are used in threshold signing (where a signature
/// is interpolated using at least `threshold` evaluations).
pub type Signature = Poly<group::Signature>;

/// The default partial signature type (G2).
pub type PartialSignature = Eval<group::Signature>;

/// The default partial signature length (G2).
pub const PARTIAL_SIGNATURE_LENGTH: usize = u32::SIZE + group::SIGNATURE_LENGTH;

/// A polynomial evaluation at a specific index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eval<C: Element> {
    pub index: u32,
    pub value: C,
}

impl<C: Element> Write for Eval<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.value.write(buf);
    }
}

impl<C: Element> Read for Eval<C> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = buf.get_u32();
        let value = C::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<C: Element> FixedSize for Eval<C> {
    const SIZE: usize = u32::SIZE + C::SIZE;
}

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients.
///
/// The coefficients must be able to multiply the type of the variable,
/// which is always a scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
// Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L24-L28
pub struct Poly<C>(Vec<C>);

/// Returns a new scalar polynomial of the given degree where each coefficients is
/// sampled at random using kernel randomness.
///
/// In the context of secret sharing, the threshold is the degree + 1.
pub fn new(degree: u32) -> Poly<Scalar> {
    // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L46-L52
    new_from(degree, &mut OsRng)
}

// Returns a new scalar polynomial of the given degree where each coefficient is
// sampled at random from the provided RNG.
///
/// In the context of secret sharing, the threshold is the degree + 1.
pub fn new_from<R: RngCore>(degree: u32, rng: &mut R) -> Poly<Scalar> {
    // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L46-L52
    let coeffs = (0..=degree).map(|_| Scalar::rand(rng)).collect::<Vec<_>>();
    Poly::<Scalar>(coeffs)
}

impl<C> Poly<C> {
    /// Creates a new polynomial from the given coefficients.
    pub fn from(c: Vec<C>) -> Self {
        Self(c)
    }

    /// Returns the constant term of the polynomial.
    pub fn constant(&self) -> &C {
        &self.0[0]
    }

    /// Returns the degree of the polynomial
    pub fn degree(&self) -> u32 {
        (self.0.len() - 1) as u32 // check size in deserialize, safe to cast
    }

    /// Returns the number of required shares to reconstruct the polynomial.
    ///
    /// This will be the threshold
    pub fn required(&self) -> u32 {
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

        Poly::<C>::from(commits)
    }

    /// Returns a zero polynomial.
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }

    /// Returns the given coefficient at the requested index.
    ///
    /// It panics if the index is out of range.
    pub fn get(&self, i: u32) -> C {
        self.0[i as usize]
    }

    /// Set the given element at the specified index.
    ///
    /// It panics if the index is out of range.
    pub fn set(&mut self, index: u32, value: C) {
        self.0[index as usize] = value;
    }

    /// Performs polynomial addition in place
    pub fn add(&mut self, other: &Self) {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L87-L95

        // if we have a smaller degree we should pad with zeros
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), C::zero())
        }

        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| a.add(b))
    }

    /// Evaluates the polynomial at the specified value.
    pub fn evaluate(&self, i: u32) -> Eval<C> {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L111-L129

        // We add +1 because we must never evaluate the polynomial at its first point
        // otherwise it reveals the "secret" value after a reshare (where the constant
        // term is set to be the secret of the previous dealing).
        let mut xi = Scalar::zero();
        xi.set_int(i + 1);

        // Use Horner's method to evaluate the polynomial
        let res = self.0.iter().rev().fold(C::zero(), |mut sum, coeff| {
            sum.mul(&xi);
            sum.add(coeff);
            sum
        });
        Eval {
            value: res,
            index: i,
        }
    }

    /// Recovers the constant term of a polynomial of degree less than `t` using at least `t` evaluations of the polynomial.
    ///
    /// This function uses Lagrange interpolation to compute the constant term (i.e., the value of the polynomial at `x=0`)
    /// given at least `t` distinct evaluations of the polynomial. Each evaluation is assumed to have a unique index,
    /// which is mapped to a unique x-value as `x = index + 1`.
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
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L131-L165

        // Check if we have at least `t` evaluations; if not, return an error
        let t = t as usize;
        let mut evals = evals.into_iter().collect::<Vec<_>>();
        if evals.len() < t {
            return Err(Error::NotEnoughPartialSignatures(t, evals.len()));
        }

        // Convert the first `t` sorted shares into scalars
        //
        // We sort the evaluations by index to ensure that two invocations of
        // `recover` select the same evals.
        evals.sort_by_key(|e| e.index);

        // Take the first `t` evaluations and prepare them for interpolation
        //
        // Each index `i` is mapped to `x = i + 1` to avoid `x=0` (the constant term we’re recovering).
        let xs = evals
            .into_iter()
            .take(t)
            .fold(Vec::with_capacity(t), |mut m, sh| {
                let mut xi = Scalar::zero();
                xi.set_int(sh.index + 1);
                m.push((sh.index, (xi, &sh.value)));
                m
            });

        // Use Lagrange interpolation to compute the constant term at `x=0`
        //
        // The constant term is `sum_{i=1 to t} yi * l_i(0)`, where `l_i(0) = product_{j != i} (xj / (xj - xi))`.
        xs.iter().try_fold(C::zero(), |mut acc, (i, (xi, yi))| {
            let (mut num, den) = xs.iter().fold(
                (Scalar::one(), Scalar::one()),
                |(mut num, mut den), (j, (xj, _))| {
                    if i != j {
                        // Include `xj` in the numerator product for `l_i(0)`
                        num.mul(xj);

                        // Compute `xj - xi` and include it in the denominator product
                        let mut tmp = *xj;
                        tmp.sub(xi);
                        den.mul(&tmp);
                    }
                    (num, den)
                },
            );

            // Compute the inverse of the denominator product; fails if den is zero (e.g., duplicate `xj`)
            let inv = den.inverse().ok_or(Error::NoInverse)?;

            // Compute `l_i(0) = num * inv`, the Lagrange basis coefficient at `x=0`
            num.mul(&inv);

            // Scale `yi` by `l_i(0)` to contribute to the constant term
            let mut yi_scaled = **yi;
            yi_scaled.mul(&num);

            // Add `yi * l_i(0)` to the running sum
            acc.add(&yi_scaled);
            Ok(acc)
        })
    }
}

impl<C: Element> Write for Poly<C> {
    fn write(&self, buf: &mut impl BufMut) {
        for c in &self.0 {
            c.write(buf);
        }
    }
}

impl<C: Element> Read<usize> for Poly<C> {
    fn read_cfg(buf: &mut impl Buf, expected: &usize) -> Result<Self, CodecError> {
        let expected_size = C::SIZE * (*expected);
        if buf.remaining() < expected_size {
            return Err(CodecError::EndOfBuffer);
        }
        let mut coeffs = Vec::with_capacity(*expected);
        for _ in 0..*expected {
            coeffs.push(C::read(buf)?);
        }
        Ok(Self(coeffs))
    }
}

impl<C: Element> EncodeSize for Poly<C> {
    fn encode_size(&self) -> usize {
        C::SIZE * self.0.len()
    }
}

/// Returns the public key of the polynomial (constant term).
pub fn public(public: &Public) -> &group::Public {
    public.constant()
}

#[cfg(test)]
pub mod tests {
    use commonware_codec::{Decode, Encode};

    // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/poly.rs#L355-L604
    use super::*;
    use crate::bls12381::primitives::group::{Scalar, G2};

    #[test]
    fn poly_degree() {
        let s = 5;
        let p = new(s);
        assert_eq!(p.degree(), s);
    }

    #[test]
    fn add_zero() {
        let p1 = new(3);
        let p2 = Poly::<Scalar>::zero();
        let mut res = p1.clone();
        res.add(&p2);
        assert_eq!(res, p1);

        let p1 = Poly::<Scalar>::zero();
        let p2 = new(3);
        let mut res = p1;
        res.add(&p2);
        assert_eq!(res, p2);
    }

    #[test]
    fn interpolation_insufficient_shares() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = new(degree);
        let shares = (0..threshold - 1)
            .map(|i| poly.evaluate(i))
            .collect::<Vec<_>>();
        Poly::recover(threshold, &shares).unwrap_err();
    }

    #[test]
    fn commit() {
        let secret = new(5);
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
                let p1 = new(deg1);
                let p2 = new(deg2);
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
                        let mut coeff_sum = p1.0[i];
                        coeff_sum.add(&p2.0[i]);
                        assert_eq!(res.0[i], coeff_sum);
                    } else {
                        assert_eq!(res.0[i], larger.0[i]);
                    }
                }
                assert_eq!(
                    res.degree(),
                    larger.degree(),
                    "deg1={}, deg2={}",
                    deg1,
                    deg2
                );
            }
        }
    }

    #[test]
    fn interpolation() {
        for degree in 0..100u32 {
            for num_evals in 0..100u32 {
                let poly = new(degree);
                let expected = poly.0[0];

                let shares = (0..num_evals).map(|i| poly.evaluate(i)).collect::<Vec<_>>();
                let recovered_constant = Poly::recover(num_evals, &shares).unwrap();

                if num_evals > degree {
                    assert_eq!(
                        expected, recovered_constant,
                        "degree={}, num_evals={}",
                        degree, num_evals
                    );
                } else {
                    assert_ne!(
                        expected, recovered_constant,
                        "degree={}, num_evals={}",
                        degree, num_evals
                    );
                }
            }
        }
    }

    #[test]
    fn evaluate() {
        for d in 0..100u32 {
            for idx in 0..100_u32 {
                let mut x = Scalar::zero();
                x.set_int(idx + 1);

                let p1 = new(d);
                let evaluation = p1.evaluate(idx).value;

                let coeffs = p1.0;
                let mut sum = coeffs[0];
                for (i, coeff) in coeffs
                    .into_iter()
                    .enumerate()
                    .take((d + 1) as usize)
                    .skip(1)
                {
                    let xi = pow(x, i);
                    let mut var = coeff;
                    var.mul(&xi);
                    sum.add(&var);
                }

                assert_eq!(sum, evaluation, "degree={}, idx={}", d, idx);
            }
        }
    }

    #[test]
    fn test_codec() {
        let original = new(5);
        let encoded = original.encode();
        let decoded = Poly::<Scalar>::decode_cfg(encoded, &(original.required() as usize)).unwrap();
        assert_eq!(original, decoded);
    }
}
