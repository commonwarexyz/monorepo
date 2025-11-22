//! KZG polynomial commitments backed by the Ethereum KZG ceremony.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use.
//!
//! This module provides a minimal KZG commitment interface that relies on
//! powers of tau published in the public Ethereum KZG ceremony transcript.
//! The bundled transcript includes the first 4,096 monomial G1 powers (and
//! 65 G2 powers) sharing the same secret exponent as the mainnet ceremony.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bls12381::primitives::group::{Element, Point, Scalar, G1};
use thiserror::Error;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

mod transcript;

#[cfg(test)]
mod verify_kzg_proof_fixtures;

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
    let mut rhs = setup.g1_powers()[0];
    let mut neg_value = Scalar::zero();
    neg_value.sub(&proof.value);
    rhs.mul(&neg_value);

    let mut adjusted_commitment = commitment.0;
    adjusted_commitment.add(&rhs);

    // [proof] pair with [z]G2 - [tau]G2
    // Check: e(adjusted_commitment, [1]G2) * e(proof, [z]G2 - [tau]G2) == 1

    let mut z_term = setup.g2_powers()[0];
    z_term.mul(point);

    let mut neg_tau = setup.g2_powers()[1];
    let mut zero = Scalar::zero();
    let one = Scalar::one();
    zero.sub(&one);
    neg_tau.mul(&zero);

    let mut divisor = z_term;
    divisor.add(&neg_tau);

    let mut pairing = blst::Pairing::new(false, &[]);

    let adjusted_commitment_affine = adjusted_commitment.as_blst_p1_affine();
    let g2_one_affine = setup.g2_powers()[0].as_blst_p2_affine();
    pairing.raw_aggregate(&g2_one_affine, &adjusted_commitment_affine);

    let proof_affine = proof.quotient.as_blst_p1_affine();
    let divisor_affine = divisor.as_blst_p2_affine();
    pairing.raw_aggregate(&divisor_affine, &proof_affine);

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(Error::InvalidSetup("pairing mismatch"))
    }
}

/// Verifies that multiple `commitments` open to `values` at `points` with the supplied `proofs`.
///
/// This function uses a random linear combination to verify multiple proofs at once, which is
/// significantly faster than verifying each proof individually.
pub fn batch_verify(
    commitments: &[Commitment],
    points: &[Scalar],
    proofs: &[Proof],
    setup: &TrustedSetup,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(), Error> {
    let n = commitments.len();
    if n != points.len() || n != proofs.len() {
        return Err(Error::InvalidSetup("length mismatch"));
    }

    // Generate random scalars for linear combination
    let mut r = Vec::with_capacity(n);
    for _ in 0..n {
        r.push(Scalar::from_rand(rng));
    }

    // 1. Accumulate left side: \sum r_i * (C_i - [y_i]G1)
    let mut left_g1_terms = Vec::with_capacity(n * 2);
    let mut left_scalars = Vec::with_capacity(n * 2);
    for i in 0..n {
        left_g1_terms.push(commitments[i].0);
        left_scalars.push(r[i].clone());

        let mut neg_y_r = proofs[i].value.clone();
        neg_y_r.mul(&r[i]);
        let mut neg_neg_y_r = Scalar::zero();
        neg_neg_y_r.sub(&neg_y_r);

        left_g1_terms.push(setup.g1_powers()[0]);
        left_scalars.push(neg_neg_y_r);
    }
    let left_sum = G1::msm(&left_g1_terms, &left_scalars);

    // 2. Perform pairing checks using blst::Pairing
    // Check: e(left_sum, [1]G2) * \prod e(r_i * proof_i, [z_i]G2 - [tau]G2) == 1

    let mut pairing = blst::Pairing::new(false, &[]);

    // Add e(left_sum, [1]G2)
    let left_sum_affine = left_sum.as_blst_p1_affine();
    let g2_one_affine = setup.g2_powers()[0].as_blst_p2_affine();
    pairing.raw_aggregate(&g2_one_affine, &left_sum_affine);

    // Add \sum e(r_i * proof_i, [z_i]G2 - [tau]G2)
    for i in 0..n {
        let mut proof_r = proofs[i].quotient;
        proof_r.mul(&r[i]);
        let proof_r_affine = proof_r.as_blst_p1_affine();

        // [z_i]G2 - [tau]G2
        let mut z_g2 = setup.g2_powers()[0]; // [1]G2
        z_g2.mul(&points[i]);

        let mut neg_tau = setup.g2_powers()[1]; // [tau]G2
        let mut zero = Scalar::zero();
        let one = Scalar::one();
        zero.sub(&one); // -1
        neg_tau.mul(&zero); // -[tau]G2

        z_g2.add(&neg_tau);
        let z_minus_tau_affine = z_g2.as_blst_p2_affine();

        pairing.raw_aggregate(&z_minus_tau_affine, &proof_r_affine);
    }

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(Error::InvalidSetup("batch verification failed"))
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

#[cfg(test)]
mod tests {
    use super::verify_kzg_proof_fixtures::VERIFY_KZG_PROOF_FIXTURES;
    use super::{commit, open, verify, Commitment, Proof, TrustedSetup};
    use crate::bls12381::primitives::group::{Element, Scalar, G1};
    use bytes::Bytes;
    use commonware_codec::ReadExt;
    use commonware_utils::from_hex;

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
        let left = pairing(&setup.g1_powers()[1], &setup.g2_powers()[0]);
        let mut found = false;
        for (idx, g2) in setup.g2_powers().iter().enumerate().skip(1) {
            let right = pairing(&setup.g1_powers()[0], g2);
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

    #[test]
    fn conforms_to_c_kzg_reference_vectors() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");

        // https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_0_0/data.yaml
        let commitment = Commitment(
            g1_from_hex(
                "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("g1 should decode"),
        );
        let point = Scalar::zero();
        let proof = Proof {
            quotient: g1_from_hex(
                "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("g1 should decode"),
            value: Scalar::zero(),
        };

        verify(&commitment, &point, &proof, &setup).expect("reference zero proof should verify");

        // https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_incorrect_proof_0_0/data.yaml
        let bad_proof = Proof {
            quotient: g1_from_hex(
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            )
            .expect("g1 should decode"),
            value: Scalar::zero(),
        };
        let bad_commitment = Commitment(G1::zero());
        assert!(verify(&bad_commitment, &point, &bad_proof, &setup).is_err());
    }

    #[test]
    fn conforms_to_full_c_kzg_suite() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");

        for fixture in VERIFY_KZG_PROOF_FIXTURES.iter() {
            let commitment = g1_from_hex(fixture.commitment);
            let point = scalar_from_hex(fixture.z);
            let value = scalar_from_hex(fixture.y);
            let quotient = g1_from_hex(fixture.proof);

            if let (Some(commitment), Some(point), Some(value), Some(quotient)) =
                (commitment, point, value, quotient)
            {
                let proof = Proof { quotient, value };
                let result = verify(&Commitment(commitment), &point, &proof, &setup);

                match fixture.expected {
                    Some(true) => assert!(
                        result.is_ok(),
                        "fixture {} should verify successfully",
                        fixture.name
                    ),
                    _ => assert!(
                        result.is_err(),
                        "fixture {} should fail verification",
                        fixture.name
                    ),
                }
            } else {
                assert_ne!(
                    fixture.expected,
                    Some(true),
                    "fixture {} contains malformed inputs",
                    fixture.name
                );
            }
        }
    }

    fn g1_from_hex(hex: &str) -> Option<G1> {
        let bytes = from_hex(hex.trim_start_matches("0x"))?;

        // The c-kzg vectors use the point-at-infinity encoding for zero commitments.
        if bytes.first() == Some(&0xc0) && bytes.iter().skip(1).all(|b| *b == 0) {
            return Some(G1::zero());
        }

        let mut buf = Bytes::from(bytes);
        G1::read(&mut buf).ok()
    }

    fn scalar_from_hex(hex: &str) -> Option<Scalar> {
        let bytes = from_hex(hex.trim_start_matches("0x"))?;
        let mut buf = Bytes::from(bytes.clone());

        Scalar::read(&mut buf).ok().or_else(|| {
            if bytes.iter().all(|b| *b == 0) {
                Some(Scalar::zero())
            } else {
                None
            }
        })
    }

    fn pairing(
        p1: &G1,
        p2: &crate::bls12381::primitives::group::G2,
    ) -> crate::bls12381::primitives::group::GT {
        let p1_affine = p1.as_blst_p1_affine();
        let p2_affine = p2.as_blst_p2_affine();
        let mut result = blst::blst_fp12::default();
        unsafe {
            blst::blst_miller_loop(&mut result, &p2_affine, &p1_affine);
            blst::blst_final_exp(&mut result, &result);
        }
        crate::bls12381::primitives::group::GT::from_blst_fp12(result)
    }
}
