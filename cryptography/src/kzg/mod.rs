//! KZG polynomial commitments backed by the Ethereum KZG ceremony.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use.
//!
//! This module provides a generic KZG commitment interface that supports both G1 and G2
//! commitments, backed by powers of tau from the public Ethereum KZG ceremony transcript.
//! The bundled transcript includes 4,096 monomial G1 powers and 65 G2 powers, all sharing
//! the same secret exponent as the mainnet ceremony.
//!
//! # Variants
//!
//! KZG commitments can be created in either BLS12-381 group:
//! - **G1 commitments** (standard): Commitments in G1, verified against G2 `[1]` and `[tau]`,
//!   supporting polynomials up to degree 4,095 (all bundled G1 powers).
//! - **G2 commitments**: Commitments in G2, verified against G1 `[1]` and `[tau]`, supporting
//!   polynomials up to degree 64 (limited by the 65 bundled G2 powers).
//!
//! Only the first two check powers are required for evaluation proofs, so the commitment side
//! determines the maximum supported degree.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bls12381::primitives::group::{Element, Point, Scalar, G1, G2};
use thiserror::Error as ThisError;

/// Errors that can arise during KZG operations.
#[derive(Debug, ThisError)]
pub enum KzgError {
    #[error("trusted setup is malformed: {0}")]
    InvalidSetup(&'static str),
    #[error("not enough powers of tau for polynomial degree {0}")]
    NotEnoughPowers(usize),
    #[error("hex decoding failed")]
    Hex,
}

/// A commitment to a polynomial using KZG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment<G: Point>(pub G);

/// A KZG proof for `f(z) = y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<G: Point> {
    /// The quotient commitment `(f(x) - y) / (x - z)`.
    pub quotient: G,
    /// The claimed evaluation `f(z)`.
    pub value: Scalar,
}

/// Trait for KZG variants (G1 or G2).
pub trait KzgVariant: Point {
    type CheckGroup: Point;

    fn commitment_powers(setup: &TrustedSetup) -> &[Self];
    fn check_powers(setup: &TrustedSetup) -> &[Self::CheckGroup];
    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup);
}

impl KzgVariant for G1 {
    type CheckGroup = G2;

    fn commitment_powers(setup: &TrustedSetup) -> &[Self] {
        setup.g1_powers()
    }

    fn check_powers(setup: &TrustedSetup) -> &[Self::CheckGroup] {
        setup.g2_powers()
    }

    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup) {
        let g_affine = g.as_blst_p1_affine();
        let check_affine = check.as_blst_p2_affine();
        pairing.raw_aggregate(&check_affine, &g_affine);
    }
}

impl KzgVariant for G2 {
    type CheckGroup = G1;

    fn commitment_powers(setup: &TrustedSetup) -> &[Self] {
        setup.g2_powers()
    }

    fn check_powers(setup: &TrustedSetup) -> &[Self::CheckGroup] {
        setup.g1_powers()
    }

    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup) {
        let g_affine = g.as_blst_p2_affine();
        let check_affine = check.as_blst_p1_affine();
        pairing.raw_aggregate(&g_affine, &check_affine);
    }
}

/// Commits to the provided polynomial coefficients using the supplied trusted setup.
pub fn commit<G: KzgVariant>(
    coeffs: &[Scalar],
    setup: &TrustedSetup,
) -> Result<Commitment<G>, KzgError> {
    let powers = G::commitment_powers(setup);
    if coeffs.len() > powers.len() {
        return Err(KzgError::NotEnoughPowers(coeffs.len() - 1));
    }

    let commitment = G::msm(&powers[..coeffs.len()], coeffs);
    Ok(Commitment(commitment))
}

/// Generates a KZG proof for `f(z)` along with the evaluation value.
pub fn open<G: KzgVariant>(
    coeffs: &[Scalar],
    point: &Scalar,
    setup: &TrustedSetup,
) -> Result<Proof<G>, KzgError> {
    let powers = G::commitment_powers(setup);
    if coeffs.len() > powers.len() {
        return Err(KzgError::NotEnoughPowers(coeffs.len() - 1));
    }

    let (value, quotient) = synthetic_division(coeffs, point);
    let quotient_commitment = G::msm(&powers[..quotient.len()], &quotient);

    Ok(Proof {
        quotient: quotient_commitment,
        value,
    })
}

/// Verifies that `commitment` opens to `value` at `point` with the supplied `proof`.
pub fn verify<G: KzgVariant>(
    commitment: &Commitment<G>,
    point: &Scalar,
    proof: &Proof<G>,
    setup: &TrustedSetup,
) -> Result<(), KzgError> {
    let check_powers = G::check_powers(setup);
    if check_powers.len() < 2 {
        return Err(KzgError::InvalidSetup("not enough check powers"));
    }

    // [C - y * G] pair with [1]CheckGroup
    let mut rhs = G::commitment_powers(setup)[0].clone(); // [1]G
    let mut neg_value = Scalar::zero();
    neg_value.sub(&proof.value);
    rhs.mul(&neg_value);

    let mut adjusted_commitment = commitment.0.clone();
    adjusted_commitment.add(&rhs);

    // [proof] pair with [z]CheckGroup - [tau]CheckGroup
    // Check: e(adjusted_commitment, [1]CheckGroup) * e(proof, [z]CheckGroup - [tau]CheckGroup) == 1

    let mut z_term = check_powers[0].clone(); // [1]CheckGroup
    z_term.mul(point);

    let mut neg_tau = check_powers[1].clone(); // [tau]CheckGroup
    let mut zero = Scalar::zero();
    let one = Scalar::one();
    zero.sub(&one);
    neg_tau.mul(&zero);

    let mut divisor = z_term;
    divisor.add(&neg_tau);

    if proof.quotient != G::zero() && divisor == G::CheckGroup::zero() {
        return Err(KzgError::InvalidSetup("invalid evaluation point"));
    }

    // Trivial commitments (e.g., constant polynomials with zero quotient) verify without a pairing.
    if adjusted_commitment == G::zero() && proof.quotient == G::zero() {
        return Ok(());
    }

    let mut pairing = blst::Pairing::new(false, &[]);

    if adjusted_commitment != G::zero() {
        G::accumulate_pairing(&mut pairing, &adjusted_commitment, &check_powers[0]);
    }
    if proof.quotient != G::zero() && divisor != G::CheckGroup::zero() {
        G::accumulate_pairing(&mut pairing, &proof.quotient, &divisor);
    }

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(KzgError::InvalidSetup("pairing mismatch"))
    }
}

/// Verifies that multiple `commitments` open to `values` at `points` with the supplied `proofs`.
///
/// This function uses a random linear combination to verify multiple proofs at once, which is
/// significantly faster than verifying each proof individually.
pub fn batch_verify<G: KzgVariant>(
    commitments: &[Commitment<G>],
    points: &[Scalar],
    proofs: &[Proof<G>],
    setup: &TrustedSetup,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(), KzgError> {
    let n = commitments.len();
    if n != points.len() || n != proofs.len() {
        return Err(KzgError::InvalidSetup("length mismatch"));
    }

    let check_powers = G::check_powers(setup);
    if check_powers.len() < 2 {
        return Err(KzgError::InvalidSetup("not enough check powers"));
    }

    // Generate random scalars for linear combination
    let mut r = Vec::with_capacity(n);
    for _ in 0..n {
        r.push(Scalar::from_rand(rng));
    }

    // 1. Accumulate left side: \sum r_i * (C_i - [y_i]G)
    let mut left_g_terms = Vec::with_capacity(n * 2);
    let mut left_scalars = Vec::with_capacity(n * 2);
    let g_one = G::commitment_powers(setup)[0].clone(); // [1]G

    for i in 0..n {
        left_g_terms.push(commitments[i].0.clone());
        left_scalars.push(r[i].clone());

        let mut neg_y_r = proofs[i].value.clone();
        neg_y_r.mul(&r[i]);
        let mut neg_neg_y_r = Scalar::zero();
        neg_neg_y_r.sub(&neg_y_r);

        left_g_terms.push(g_one.clone());
        left_scalars.push(neg_neg_y_r);
    }
    let left_sum = G::msm(&left_g_terms, &left_scalars);

    // 2. Perform pairing checks using blst::Pairing
    // Check: e(left_sum, [1]CheckGroup) * \prod e(r_i * proof_i, [z_i]CheckGroup - [tau]CheckGroup) == 1

    let mut pairing = blst::Pairing::new(false, &[]);
    let mut aggregated = false;

    // Add e(left_sum, [1]CheckGroup)
    if left_sum != G::zero() {
        G::accumulate_pairing(&mut pairing, &left_sum, &check_powers[0]);
        aggregated = true;
    }

    // Add \sum e(r_i * proof_i, [z_i]CheckGroup - [tau]CheckGroup)
    for i in 0..n {
        let mut proof_r = proofs[i].quotient.clone();
        proof_r.mul(&r[i]);

        // [z_i]CheckGroup - [tau]CheckGroup
        let mut z_check = check_powers[0].clone(); // [1]CheckGroup
        z_check.mul(&points[i]);

        let mut neg_tau = check_powers[1].clone(); // [tau]CheckGroup
        let mut zero = Scalar::zero();
        let one = Scalar::one();
        zero.sub(&one); // -1
        neg_tau.mul(&zero); // -[tau]CheckGroup

        z_check.add(&neg_tau);

        if proof_r != G::zero() && z_check == G::CheckGroup::zero() {
            return Err(KzgError::InvalidSetup("invalid evaluation point"));
        }

        if proof_r != G::zero() && z_check != G::CheckGroup::zero() {
            G::accumulate_pairing(&mut pairing, &proof_r, &z_check);
            aggregated = true;
        }
    }

    if !aggregated {
        return Ok(());
    }

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(KzgError::InvalidSetup("batch verification failed"))
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

mod transcript;

#[cfg(test)]
mod verify_kzg_proof_fixtures;

pub use transcript::TrustedSetup;

#[cfg(test)]
mod tests {
    use super::{
        commit, open, verify, verify_kzg_proof_fixtures::VERIFY_KZG_PROOF_FIXTURES, Commitment,
        KzgVariant, Proof, TrustedSetup,
    };
    use crate::bls12381::primitives::group::{Element, Scalar, G1, G2};
    use bytes::Bytes;
    use commonware_codec::ReadExt;
    use commonware_utils::from_hex;

    #[test]
    fn commit_open_verify_round_trip_g1() {
        test_commit_open_verify_round_trip::<G1>();
    }

    #[test]
    fn commit_open_verify_round_trip_g2() {
        test_commit_open_verify_round_trip::<G2>();
    }

    fn test_commit_open_verify_round_trip<G: KzgVariant>() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let commitment: Commitment<G> = commit(&coeffs, &setup).expect("commitment should succeed");
        let proof = open(&coeffs, &point, &setup).expect("opening should succeed");

        verify(&commitment, &point, &proof, &setup).expect("proof should verify");
    }

    #[test]
    fn commit_open_verify_constant_g1() {
        test_commit_open_verify_constant::<G1>();
    }

    #[test]
    fn commit_open_verify_constant_g2() {
        test_commit_open_verify_constant::<G2>();
    }

    fn test_commit_open_verify_constant<G: KzgVariant>() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let coeffs = vec![Scalar::from(42u64)];
        let point = Scalar::from(7u64);

        let commitment: Commitment<G> = commit(&coeffs, &setup).expect("commitment should succeed");
        let proof = open(&coeffs, &point, &setup).expect("opening should succeed");

        verify(&commitment, &point, &proof, &setup).expect("constant proof should verify");
    }

    #[test]
    fn powers_are_aligned_g1_g2() {
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
    fn powers_are_aligned_g2_g1() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        // Check that g2[1] and g1[1] correspond to the same tau
        let left = pairing(&setup.g1_powers()[0], &setup.g2_powers()[1]);
        let mut found = false;
        for (idx, g1) in setup.g1_powers().iter().enumerate().skip(1) {
            let right = pairing(g1, &setup.g2_powers()[0]);
            if right == left {
                found = true;
                println!("matched tau with g1 index {idx}");
                break;
            }
        }

        assert!(found, "tau powers should share the same secret");
    }

    #[test]
    fn rejects_polynomials_that_exceed_setup_g1() {
        test_rejects_polynomials_that_exceed_setup::<G1>();
    }

    #[test]
    fn rejects_polynomials_that_exceed_setup_g2() {
        test_rejects_polynomials_that_exceed_setup::<G2>();
    }

    fn test_rejects_polynomials_that_exceed_setup<G: KzgVariant>() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        let coeffs = vec![Scalar::from(1u64); G::commitment_powers(&setup).len() + 1];

        let point = Scalar::from(1u64);
        let commitment: Result<Commitment<G>, _> = commit(&coeffs, &setup);
        assert!(commitment.is_err());

        let proof: Result<Proof<G>, _> = open(&coeffs, &point, &setup);
        assert!(proof.is_err());
    }

    #[test]
    fn supports_maximum_degree_from_transcript_g1() {
        test_supports_maximum_degree_from_transcript::<G1>();
    }

    #[test]
    fn supports_maximum_degree_from_transcript_g2() {
        test_supports_maximum_degree_from_transcript::<G2>();
    }

    fn test_supports_maximum_degree_from_transcript<G: KzgVariant>() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");

        // The maximum supported degree for a variant is determined by the available commitment
        // powers. Verification only relies on the first two check powers (`[1]` and `[tau]`).
        let commitment_powers = G::commitment_powers(&setup).len();
        let check_powers = G::check_powers(&setup).len();
        assert!(commitment_powers >= 1, "need at least one commitment power");
        assert!(check_powers >= 2, "need at least 2 check powers");

        let max_degree = commitment_powers - 1;

        // Ensure we can commit and verify at the maximum supported degree
        let coeffs = vec![Scalar::from(2u64); max_degree + 1];
        let point = Scalar::from(3u64);

        let commitment: Commitment<G> =
            commit(&coeffs, &setup).expect("commitment should succeed at max degree");
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

    #[test]
    fn verify_power_counts() {
        let setup = TrustedSetup::ethereum_kzg().expect("setup should load");
        assert_eq!(setup.g1_powers().len(), 4096, "Expected 4096 G1 powers");
        assert_eq!(setup.g2_powers().len(), 65, "Expected 65 G2 powers");
        assert_eq!(
            setup.max_degree_supported(),
            4095,
            "Max G1 degree should be 4095 (4096 G1 powers - 1)"
        );
        assert_eq!(
            setup.g2_powers().len().saturating_sub(1),
            64,
            "Max G2 degree should be 64 (65 G2 powers - 1)"
        );
    }
}
