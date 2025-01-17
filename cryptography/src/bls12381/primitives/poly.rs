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
use bytes::BufMut;
use rand::{rngs::OsRng, RngCore};
use std::{collections::BTreeMap, mem::size_of};

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
pub const PARTIAL_SIGNATURE_LENGTH: usize = size_of::<u32>() + group::SIGNATURE_LENGTH;

/// A polynomial evaluation at a specific index.
#[derive(Debug, Clone)]
pub struct Eval<C: Element> {
    pub index: u32,
    pub value: C,
}

impl<C: Element> Eval<C> {
    /// Canonically serializes the evaluation.
    pub fn serialize(&self) -> Vec<u8> {
        let value_serialized = self.value.serialize();
        let mut bytes = Vec::with_capacity(size_of::<u32>() + value_serialized.len());
        bytes.put_u32(self.index);
        bytes.extend_from_slice(&value_serialized);
        bytes
    }

    /// Deserializes a canonically encoded evaluation.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let value = C::deserialize(&bytes[4..])?;
        Some(Self { index, value })
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
        self.0[i as usize].clone()
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

    /// Canonically serializes the polynomial.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for c in &self.0 {
            bytes.extend_from_slice(&c.serialize());
        }
        bytes
    }

    /// Deserializes a canonically encoded polynomial.
    pub fn deserialize(bytes: &[u8], expected: u32) -> Option<Self> {
        let expected = expected as usize;
        let mut coeffs = Vec::with_capacity(expected);
        for chunk in bytes.chunks_exact(C::size()) {
            if coeffs.len() >= expected {
                return None;
            }
            let c = C::deserialize(chunk)?;
            coeffs.push(c);
        }
        if coeffs.len() != expected {
            return None;
        }
        Some(Self(coeffs))
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

    /// Recover the polynomial's constant term given at least `t` polynomial evaluations.
    pub fn recover(t: u32, mut evals: Vec<Eval<C>>) -> Result<C, Error> {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/a714310be76620e10e8797d6637df64011926430/crates/threshold-bls/src/poly.rs#L131-L165

        // Ensure there are enough shares
        let t = t as usize;
        if evals.len() < t {
            return Err(Error::InvalidRecovery);
        }

        // Convert the first `t` sorted shares into scalars
        let mut err = None;
        evals.sort_by(|a, b| a.index.cmp(&b.index));
        let xs = evals
            .into_iter()
            .take(t)
            .fold(BTreeMap::new(), |mut m, sh| {
                let mut xi = Scalar::zero();
                xi.set_int(sh.index + 1);
                if m.insert(sh.index, (xi, sh.value)).is_some() {
                    err = Some(Error::DuplicateEval);
                }
                m
            });
        if let Some(e) = err {
            return Err(e);
        }

        // Iterate over all indices and for each multiply the lagrange basis
        // with the value of the share
        let mut acc = C::zero();
        for (i, xi) in &xs {
            let mut yi = xi.1.clone();
            let mut num = Scalar::one();
            let mut den = Scalar::one();

            for (j, xj) in &xs {
                if i == j {
                    continue;
                }

                // xj - 0
                num.mul(&xj.0);

                // 1 / (xj - xi)
                let mut tmp = xj.0;
                tmp.sub(&xi.0);
                den.mul(&tmp);
            }

            let inv = den.inverse().ok_or(Error::NoInverse)?;
            num.mul(&inv);
            yi.mul(&num);
            acc.add(&yi);
        }
        Ok(acc)
    }
}

/// Returns the public key of the polynomial (constant term).
pub fn public(public: &Public) -> group::Public {
    *public.constant()
}

#[cfg(test)]
pub mod tests {
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
        Poly::recover(threshold, shares).unwrap_err();
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
                let recovered_constant = Poly::recover(num_evals, shares).unwrap();

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
}
