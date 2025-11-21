//! KZG polynomial commitments backed by the Ethereum KZG ceremony.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use.
//!
//! This module provides a minimal KZG commitment interface that relies on
//! powers of tau derived from the public Ethereum KZG ceremony transcript.
//! The bundled transcript expands the ceremony seed into the first 4,096
//! G1 powers (and 4,097 G2 powers) sharing the same secret exponent as the
//! mainnet ceremony.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bls12381::primitives::group::{Element, Point, Scalar, G1};
use thiserror::Error;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

mod pairing;
mod transcript;

pub use pairing::pairing;
pub use transcript::TrustedSetup;

/// A commitment to a polynomial using KZG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment(pub G1);

/// A KZG proof for `f(z) = y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The quotient commitment `(f(x) - y) / (x - z)`.
    pub quotient: G1,
    /// The claimed evaluation `f(z)`.
    pub value: Scalar,
}

/// Errors that can arise during KZG operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("trusted setup is malformed: {0}")]
    InvalidSetup(&'static str),
    #[error("not enough powers of tau for polynomial degree {0}")]
    NotEnoughPowers(usize),
    #[error("hex decoding failed")]
    Hex,
}

/// Commits to the provided polynomial coefficients using the supplied trusted setup.
pub fn commit(coeffs: &[Scalar], setup: &TrustedSetup) -> Result<Commitment, Error> {
    if coeffs.len() > setup.max_degree_supported() + 1 {
        return Err(Error::NotEnoughPowers(coeffs.len() - 1));
    }

    let commitment = G1::msm(&setup.g1_powers()[..coeffs.len()], coeffs);
    Ok(Commitment(commitment))
}

/// Generates a KZG proof for `f(z)` along with the evaluation value.
pub fn open(coeffs: &[Scalar], point: &Scalar, setup: &TrustedSetup) -> Result<Proof, Error> {
    if coeffs.len() < 2 {
        return Err(Error::NotEnoughPowers(0));
    }
    if coeffs.len() > setup.max_degree_supported() + 1 {
        return Err(Error::NotEnoughPowers(coeffs.len() - 1));
    }

    let (value, quotient) = synthetic_division(coeffs, point);
    let quotient_commitment = G1::msm(&setup.g1_powers()[..quotient.len()], &quotient);

    Ok(Proof {
        quotient: quotient_commitment,
        value,
    })
}

/// Verifies that `commitment` opens to `value` at `point` with the supplied `proof`.
pub fn verify(
    commitment: &Commitment,
    point: &Scalar,
    proof: &Proof,
    setup: &TrustedSetup,
) -> Result<(), Error> {
    // [C - y * G1] pair with [1]G2
    let mut rhs = setup.g1_powers()[0].clone();
    let mut neg_value = Scalar::zero();
    neg_value.sub(&proof.value);
    rhs.mul(&neg_value);

    let mut adjusted_commitment = commitment.0.clone();
    adjusted_commitment.add(&rhs);

    // [proof] pair with [tau]G2 - z * [1]G2
    let mut z_term = setup.g2_powers()[0].clone();
    let mut neg_point = Scalar::zero();
    neg_point.sub(point);
    z_term.mul(&neg_point);

    let mut divisor = setup.g2_powers()[1].clone();
    divisor.add(&z_term);

    let left = pairing(&adjusted_commitment, &setup.g2_powers()[0]);
    let right = pairing(&proof.quotient, &divisor);

    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidSetup("pairing mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::{commit, open, verify, TrustedSetup};
    use crate::bls12381::primitives::group::Scalar;

    #[test]
    fn commit_open_verify_round_trip() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let commitment = commit(&coeffs, &setup).expect("commitment should succeed");
        let proof = open(&coeffs, &point, &setup).expect("opening should succeed");

        verify(&commitment, &point, &proof, &setup).expect("proof should verify");
    }

    #[test]
    fn powers_are_aligned() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let left = super::pairing(&setup.g1_powers()[1], &setup.g2_powers()[0]);
        let mut found = false;
        for (idx, g2) in setup.g2_powers().iter().enumerate().skip(1) {
            let right = super::pairing(&setup.g1_powers()[0], g2);
            if right == left {
                found = true;
                println!("matched tau with g2 index {idx}");
                break;
            }
        }

        assert!(found, "tau powers should share the same secret");
    }

    #[test]
    fn rejects_polynomials_that_exceed_setup() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let coeffs = vec![Scalar::from(1u64); setup.max_degree_supported() + 2];

        let point = Scalar::from(1u64);
        let commitment = commit(&coeffs, &setup);
        assert!(commitment.is_err());

        let proof = open(&coeffs, &point, &setup);
        assert!(proof.is_err());
    }

    #[test]
    fn supports_maximum_degree_from_transcript() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        assert_eq!(setup.max_degree_supported(), 4095);

        let coeffs = vec![Scalar::from(2u64); setup.max_degree_supported() + 1];
        let point = Scalar::from(3u64);

        let commitment = commit(&coeffs, &setup).expect("commitment should succeed at max degree");
        let proof = open(&coeffs, &point, &setup).expect("opening should succeed at max degree");

        verify(&commitment, &point, &proof, &setup)
            .expect("proof should verify at max transcript degree");
    }
}

fn synthetic_division(coeffs: &[Scalar], point: &Scalar) -> (Scalar, Vec<Scalar>) {
    let mut acc = coeffs.last().cloned().unwrap_or_else(Scalar::zero);
    let mut quotient_rev: Vec<Scalar> = Vec::with_capacity(coeffs.len().saturating_sub(1));

    for coeff in coeffs.iter().rev().skip(1) {
        quotient_rev.push(acc.clone());
        let mut next = acc;
        next.mul(point);
        next.add(coeff);
        acc = next;
    }

    quotient_rev.reverse();
    (acc, quotient_rev)
}
