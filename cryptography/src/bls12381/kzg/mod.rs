//! KZG polynomial commitments over BLS12-381.
//!
//! This crate provides a KZG (Kate-Zaverucha-Goldberg) commitment interface that supports
//! both G1 and G2 commitments. KZG commitments require a trusted setup (powers of tau) provided via
//! the [Setup] trait, which can be implemented for any trusted setup ceremony. The module includes
//! an [setup::Ethereum] implementation backed by the public Ethereum KZG ceremony transcript (4,096 G1
//! powers and 65 G2 powers), but any [Setup] implementation can be used.
//!
//! KZG commitments enable committing to polynomials and generating proofs that a committed
//! polynomial evaluates to a specific value at a given point, without revealing the polynomial
//! coefficients. This is useful for verifiable computation, data availability schemes, and
//! cryptographic protocols requiring polynomial evaluation proofs.
//!
//! # Properties
//!
//! - **Hiding**: Commitments reveal no information about the committed polynomial coefficients
//! - **Binding**: It is computationally infeasible to open a commitment to different values
//! - **Evaluation proofs**: Generate constant-size proofs that f(z) = y for committed polynomial f
//! - **Batch verification**: Verify multiple evaluation proofs efficiently using random linear combinations
//!
//! # Variants
//!
//! KZG commitments can be created in either BLS12-381 group:
//! - **G1 commitments** (standard): Commitments in G1, verified against G2 `[1]` and `[tau]`.
//!   The maximum supported polynomial degree depends on the number of G1 powers provided by the
//!   [Setup] implementation.
//! - **G2 commitments**: Commitments in G2, verified against G1 `[1]` and `[tau]`. The maximum
//!   supported polynomial degree depends on the number of G2 powers provided by the [Setup]
//!   implementation.
//!
//! Only the first two check powers are required for evaluation proofs, so the commitment side
//! determines the maximum supported degree. For example, the [setup::Ethereum] setup supports polynomials
//! up to degree 4,095 for G1 commitments and degree 64 for G2 commitments.
//!
//! # Security
//!
//! The security of KZG commitments relies on the discrete logarithm assumption in the BLS12-381
//! pairing groups. A trusted setup (powers of tau) is required, where a secret exponent tau is
//! used to generate powers `[1], [tau], [tau^2], ...` in both G1 and G2. The security of the
//! commitment scheme depends on the secret exponent remaining unknown.
//!
//! The [setup::Ethereum] setup implementation uses the public Ethereum KZG ceremony, which involved
//! thousands of participants contributing randomness to ensure the secret exponent remains unknown.
//! The ceremony's transcript is cryptographically verified and publicly auditable. However, any
//! [Setup] implementation can be used, including custom trusted setups for specific applications.
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::{
//!     bls12381::{
//!         kzg::{commit, open, verify, setup::Ethereum, Setup},
//!         primitives::group::{G1, Scalar},
//!     },
//! };
//!
//! // Initialize a trusted setup
//! let setup = Ethereum::new();
//!
//! // Define a polynomial f(x) = 2x^2 + 3x + 5
//! let coeffs = vec![
//!     Scalar::from(5u64),  // constant term
//!     Scalar::from(3u64),  // x term
//!     Scalar::from(2u64),  // x^2 term
//! ];
//!
//! // Commit to the polynomial
//! let commitment: G1 = commit(&setup, &coeffs)
//!     .expect("commitment should succeed");
//!
//! // Generate a proof that f(7) = 124
//! let point = Scalar::from(7u64);
//! let proof = open(&setup, &coeffs, &point)
//!     .expect("opening should succeed");
//!
//! // Verify the proof
//! verify(&setup, &commitment, &point, &proof)
//!     .expect("proof should verify");
//! ```
//!
//! # Acknowledgements
//!
//! The following resources were used as references when implementing this crate:
//!
//! * <https://link.springer.com/chapter/10.1007/978-3-642-17373-8_11>: Constant-Size Commitments to Polynomials and Their Applications
//! * <https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html>: KZG polynomial commitments
//! * <https://github.com/ethereum/c-kzg-4844>: A minimal implementation of the Polynomial Commitments API for EIP-4844 and EIP-7594
//! * <https://github.com/ethereum/kzg-ceremony>: Resources and documentation related to the ongoing Ethereum KZG Ceremony

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bls12381::primitives::group::{Element, Point, Scalar};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::vec::Vec;
use thiserror::Error as ThisError;

pub mod setup;
pub mod variant;
pub use setup::Setup;
use variant::Variant;

/// Errors that can arise during KZG operations.
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("not enough powers of tau for polynomial degree {0}")]
    NotEnoughPowers(usize),
    #[error("invalid evaluation point")]
    InvalidEvaluationPoint,
    #[error("pairing mismatch")]
    PairingMismatch,
    #[error("length mismatch: commitments={0} points={1} proofs={2}")]
    LengthMismatch(usize, usize, usize),
}

/// A KZG proof for `f(z) = y`.
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Proof<G: Point> {
    /// The quotient commitment `(f(x) - y) / (x - z)`.
    pub quotient: G,
    /// The claimed evaluation `f(z)`.
    pub value: Scalar,
}

impl<G: Point> Write for Proof<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.quotient.write(buf);
        self.value.write(buf);
    }
}

impl<G: Point> Read for Proof<G> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let quotient = G::read_cfg(buf, cfg)?;
        let value = Scalar::read_cfg(buf, cfg)?;
        Ok(Proof { quotient, value })
    }
}

impl<G: Point> FixedSize for Proof<G> {
    const SIZE: usize = G::SIZE + Scalar::SIZE;
}

/// Commits to the provided polynomial coefficients using the supplied trusted setup.
///
/// Given polynomial f(x) = Σ(c_i * x^i) with coefficients `coeffs = [c_0, c_1, ..., c_{n-1}]`,
/// computes the KZG commitment C = Σ(c_i * [τ^i]G) using multi-scalar multiplication.
pub fn commit<S: Setup, G: Variant<S>>(setup: &S, coeffs: &[Scalar]) -> Result<G, Error> {
    let powers = G::commitment_powers(setup);
    if coeffs.len() > powers.len() {
        return Err(Error::NotEnoughPowers(coeffs.len() - 1));
    }

    // C = Σ(c_i * [τ^i]G)
    let commitment = G::msm(&powers[..coeffs.len()], coeffs);
    Ok(commitment)
}

/// Generates a KZG proof for `f(z)` along with the evaluation value.
///
/// For polynomial f(x) and evaluation point z, computes:
/// - y = f(z) (the evaluation value)
/// - q(x) = (f(x) - y) / (x - z) (the quotient polynomial via synthetic division)
/// - π = commit(q(x)) (the quotient commitment, which serves as the proof)
pub fn open<S: Setup, G: Variant<S>>(
    setup: &S,
    coeffs: &[Scalar],
    point: &Scalar,
) -> Result<Proof<G>, Error> {
    let powers = G::commitment_powers(setup);
    if coeffs.len() > powers.len() {
        return Err(Error::NotEnoughPowers(coeffs.len() - 1));
    }

    // Compute y = f(z) and q(x) = (f(x) - y) / (x - z) via synthetic division
    let (value, quotient) = synthetic_division(coeffs, point);

    // π = commit(q(x)) = Σ(q_i * [τ^i]G)
    let quotient_commitment = G::msm(&powers[..quotient.len()], &quotient);

    Ok(Proof {
        quotient: quotient_commitment,
        value,
    })
}

/// Verifies that `commitment` opens to `value` at `point` with the supplied `proof`.
///
/// Verifies the KZG equation: `e(C - y*G, [1]CheckGroup) * e(π, [z]CheckGroup - [τ]CheckGroup) == 1`
/// where C is the commitment, y = f(z) is the claimed value, π is the proof, and z is the point.
///
/// This equation holds if and only if (C - y*G) = π * (z - τ) in the exponent, which means
/// the committed polynomial f(x) satisfies f(z) = y.
pub fn verify<S: Setup, G: Variant<S>>(
    setup: &S,
    commitment: &G,
    point: &Scalar,
    proof: &Proof<G>,
) -> Result<(), Error> {
    // Compute C - y*G = C + (-y)*[1]G
    let mut rhs = G::commitment_powers(setup)[0].clone(); // [1]G
    let mut neg_value = Scalar::zero();
    neg_value.sub(&proof.value); // -y
    rhs.mul(&neg_value); // (-y)*[1]G

    let mut adjusted_commitment = commitment.clone();
    adjusted_commitment.add(&rhs); // C - y*G

    // Compute [z]CheckGroup - [τ]CheckGroup = z*[1]CheckGroup - [τ]CheckGroup
    let (check_one, check_tau) = G::check_powers(setup);
    let mut z_term = check_one.clone(); // [1]CheckGroup
    z_term.mul(point); // z*[1]CheckGroup = [z]CheckGroup
    let mut neg_tau = check_tau.clone(); // [τ]CheckGroup
    let mut zero = Scalar::zero();
    let one = Scalar::one();
    zero.sub(&one); // -1
    neg_tau.mul(&zero); // -[τ]CheckGroup
    let mut divisor = z_term;
    divisor.add(&neg_tau); // [z]CheckGroup - [τ]CheckGroup

    // If z = τ, then divisor is zero and verification would be invalid
    if proof.quotient != G::zero() && divisor == G::CheckGroup::zero() {
        return Err(Error::InvalidEvaluationPoint);
    }

    // Verify: e(C - y*G, [1]CheckGroup) * e(π, [z]CheckGroup - [τ]CheckGroup) == 1
    // Note: e(0, P) = 1 for any P, so if both elements are zero, verification succeeds
    if adjusted_commitment == G::zero() && proof.quotient == G::zero() {
        return Ok(());
    }
    let mut pairing = blst::Pairing::new(false, &[]);

    // Accumulate e(C - y*G, [1]CheckGroup)
    if adjusted_commitment != G::zero() {
        G::accumulate_pairing(&mut pairing, &adjusted_commitment, check_one);
    }

    // Accumulate e(π, [z]CheckGroup - [τ]CheckGroup)
    if proof.quotient != G::zero() {
        G::accumulate_pairing(&mut pairing, &proof.quotient, &divisor);
    }

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(Error::PairingMismatch)
    }
}

/// Verifies that multiple `commitments` open to `values` at `points` with the supplied `proofs`.
///
/// This function uses a random linear combination to verify multiple proofs at once, which is
/// significantly faster than verifying each proof individually.
pub fn batch_verify<R: CryptoRngCore, S: Setup, G: Variant<S>>(
    rng: &mut R,
    setup: &S,
    commitments: &[G],
    points: &[Scalar],
    proofs: &[Proof<G>],
) -> Result<(), Error> {
    let n = commitments.len();
    if n != points.len() || n != proofs.len() {
        return Err(Error::LengthMismatch(n, points.len(), proofs.len()));
    }
    let (check_one, check_tau) = G::check_powers(setup);

    // Generate random scalars r_1, ..., r_n for random linear combination
    let mut r = Vec::with_capacity(n);
    for _ in 0..n {
        r.push(Scalar::from_rand(rng));
    }

    // Step 1: Compute aggregated left side: Σ(r_i * C_i) - (Σ(r_i * y_i)) * [1]G
    //
    // We separate the commitment terms from the value terms.
    // 1. MSM the commitments directly.
    // 2. Sum the scalar values weighted by r_i, then multiply by [1]G once.

    // Compute Σ(r_i * y_i)
    let mut total_y = Scalar::zero();
    for i in 0..n {
        let mut term = proofs[i].value.clone();
        term.mul(&r[i]);
        total_y.add(&term);
    }

    // Compute Σ(r_i * C_i)
    let mut left_sum = G::msm(commitments, &r);

    // Subtract (Σ(r_i * y_i)) * [1]G
    // left_sum += (-total_y) * [1]G
    let mut neg_total_y = Scalar::zero();
    neg_total_y.sub(&total_y);
    let mut g_term = G::commitment_powers(setup)[0].clone(); // [1]G
    g_term.mul(&neg_total_y);
    left_sum.add(&g_term);

    // Check if all quotients are zero (e.g., all constant polynomials)
    let all_quotients_zero = proofs.iter().all(|p| p.quotient == G::zero());

    // If left_sum is zero and all quotients are zero, verification succeeds (1 * 1 * ... = 1)
    if left_sum == G::zero() && all_quotients_zero {
        return Ok(());
    }

    // Step 2: Verify batch equation using pairing:
    // e(left_sum, [1]CheckGroup) * Π e(Σ(r_i * π_i), [z]CheckGroup - [τ]CheckGroup) == 1
    //
    // We group proofs by evaluation point z. Multiple proofs at the same z can be aggregated
    // into a single pairing: e(Σ(r_i * π_i), [z] - [τ]).
    let mut aggregations: Vec<(Scalar, G)> = Vec::with_capacity(n);
    for i in 0..n {
        let mut weighted_proof = proofs[i].quotient.clone();
        weighted_proof.mul(&r[i]);
        aggregations.push((points[i].clone(), weighted_proof));
    }

    // Sort by z to group identical points
    aggregations.sort_by(|a, b| a.0.cmp(&b.0));

    let mut pairing = blst::Pairing::new(false, &[]);

    // Accumulate left side pairing: e(left_sum, [1]CheckGroup)
    if left_sum != G::zero() {
        G::accumulate_pairing(&mut pairing, &left_sum, check_one);
    }

    // Accumulate right side pairings (grouped by z)
    let mut i = 0;
    while i < n {
        let z = &aggregations[i].0;
        let mut z_sum = aggregations[i].1.clone();

        // Sum all proofs for the same z
        let mut j = i + 1;
        while j < n && &aggregations[j].0 == z {
            z_sum.add(&aggregations[j].1);
            j += 1;
        }

        // Compute [z]CheckGroup - [τ]CheckGroup only once per unique z
        let mut z_check = check_one.clone();
        z_check.mul(z);

        let mut neg_tau = check_tau.clone();
        let mut zero = Scalar::zero();
        let one = Scalar::one();
        zero.sub(&one); // -1
        neg_tau.mul(&zero); // -[τ]CheckGroup

        z_check.add(&neg_tau);

        // If z = τ, verification is invalid if sum is non-zero
        if z_sum != G::zero() && z_check == G::CheckGroup::zero() {
            return Err(Error::InvalidEvaluationPoint);
        }

        // Accumulate e(z_sum, [z] - [τ])
        if z_sum != G::zero() && z_check != G::CheckGroup::zero() {
            G::accumulate_pairing(&mut pairing, &z_sum, &z_check);
        }

        i = j;
    }

    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(Error::PairingMismatch)
    }
}

/// Performs synthetic division of a polynomial by (x - point).
///
/// Given polynomial f(x) with coefficients `coeffs`, computes q(x) and r such that
/// f(x) = (x - point) * q(x) + r, where r = f(point) is the evaluation at `point`.
///
/// Returns (value, quotient) where `value` is f(point) and `quotient` contains the
/// coefficients of q(x) ordered from highest to lowest degree.
fn synthetic_division(coeffs: &[Scalar], point: &Scalar) -> (Scalar, Vec<Scalar>) {
    // Initialize accumulator with the highest-degree coefficient (last in the array).
    // If coeffs is empty, use zero.
    let mut acc = coeffs.last().cloned().unwrap_or_else(Scalar::zero);
    // Pre-allocate space for quotient coefficients (one less than input degree).
    let mut quotient_rev: Vec<Scalar> = Vec::with_capacity(coeffs.len().saturating_sub(1));

    // Process coefficients from highest to lowest degree (reverse order, skipping the last).
    // For each coefficient, we compute one quotient term and update the accumulator.
    for coeff in coeffs.iter().rev().skip(1) {
        // Save current accumulator as a quotient coefficient (will be reversed later).
        quotient_rev.push(acc.clone());
        // Compute next accumulator: acc * point + coeff
        // This implements Horner's method: f(x) = a_n + x*(a_{n-1} + x*(a_{n-2} + ...))
        let mut next = acc;
        next.mul(point);
        next.add(coeff);
        acc = next;
    }

    // Reverse quotient coefficients to get standard ordering (highest to lowest degree).
    quotient_rev.reverse();
    // Return (f(point), quotient_coefficients)
    (acc, quotient_rev)
}

#[cfg(test)]
mod tests {
    use super::{batch_verify, commit, open, setup::Ethereum, verify, Error, Proof, Variant};
    use crate::bls12381::primitives::group::{Element, Scalar, G1, G2};
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode, ReadExt};
    use commonware_utils::from_hex;
    use rand::thread_rng;

    #[test]
    fn commit_open_verify_round_trip_g1() {
        test_commit_open_verify_round_trip::<G1>();
    }

    #[test]
    fn commit_open_verify_round_trip_g2() {
        test_commit_open_verify_round_trip::<G2>();
    }

    fn test_commit_open_verify_round_trip<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        verify(&setup, &commitment, &point, &proof).expect("proof should verify");
    }

    #[test]
    fn commit_open_verify_constant_g1() {
        test_commit_open_verify_constant::<G1>();
    }

    #[test]
    fn commit_open_verify_constant_g2() {
        test_commit_open_verify_constant::<G2>();
    }

    fn test_commit_open_verify_constant<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(42u64)];
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        verify(&setup, &commitment, &point, &proof).expect("constant proof should verify");
    }

    #[test]
    fn rejects_polynomials_that_exceed_setup_g1() {
        test_rejects_polynomials_that_exceed_setup::<G1>();
    }

    #[test]
    fn rejects_polynomials_that_exceed_setup_g2() {
        test_rejects_polynomials_that_exceed_setup::<G2>();
    }

    fn test_rejects_polynomials_that_exceed_setup<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(1u64); G::commitment_powers(&setup).len() + 1];

        let point = Scalar::from(1u64);
        let commitment: Result<G, _> = commit(&setup, &coeffs);
        assert!(commitment.is_err());

        let proof: Result<Proof<G>, _> = open(&setup, &coeffs, &point);
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

    fn test_supports_maximum_degree_from_transcript<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();

        // The maximum supported degree for a variant is determined by the available commitment
        // powers. Verification only relies on the first two check powers (`[1]` and `[tau]`).
        let commitment_powers = G::commitment_powers(&setup).len();
        let max_degree = commitment_powers - 1;

        // Ensure we can commit and verify at the maximum supported degree
        let coeffs = vec![Scalar::from(2u64); max_degree + 1];
        let point = Scalar::from(3u64);

        let commitment: G =
            commit(&setup, &coeffs).expect("commitment should succeed at max degree");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed at max degree");

        verify(&setup, &commitment, &point, &proof)
            .expect("proof should verify at max transcript degree");
    }

    /// A test vector for the KZG proof verification.
    pub struct TestVector {
        pub name: &'static str,
        pub commitment: &'static str,
        pub z: &'static str,
        pub y: &'static str,
        pub proof: &'static str,
        pub expected: Option<bool>,
    }

    /// Test vectors for the KZG proof verification.
    ///
    /// Source: https://github.com/ethereum/c-kzg-4844/tree/6c2a7839bc320060ff3aa5e871947b4457fb6d07/tests/verify_kzg_proof/kzg-mainnet
    pub const TEST_VECTORS: &[TestVector] = &[
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_0",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_1",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_2",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_3",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_4",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_0_5",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_0",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_1",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_2",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_3",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_4",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_1_5",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_0",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359",
            proof: "0xb72d80393dc39beea3857cb3719277138876b2b207f1d5e54dd62a14e3242d123b5a6db066181ff01a51c26c9d2f400b",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_1",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xb0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_2",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0",
            proof: "0x89012990b0ca02775bd9df8145f6c936444b83f54df1f5f274fb4312800a6505dd000ee8ec7b0ea6d72092a3daf0bffb",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_3",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0",
            proof: "0xa1fcd37a924af9ec04143b44853c26f6b0738f6e15a3e0755057e7d5460406c7e148adb0e2d608982140d0ae42fe0b3b",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_4",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc",
            proof: "0xaa86c458b3065e7ec244033a2ade91a7499561f482419a3a372c42a636dad98262a2ce926d142fd7cfe26ca148efe8b4",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_2_5",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321",
            proof: "0xa444d6bb5aadc3ceb615b50d6606bd54bfe529f59247987cd1ab848d19de599a9052f1835fb0d0d44cf70183e19a68c9",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_0",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x1ed7d14d1b3fb1a1890d67b81715531553ad798df2009b4311d9fe2bea6cb964",
            proof: "0xa71f21ca51b443ad35bb8a26d274223a690d88d9629927dc80b0856093e08a372820248df5b8a43b6d98fd52a62fa376",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_1",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x443e7af5274b52214ea6c775908c54519fea957eecd98069165a8b771082fd51",
            proof: "0xa060b350ad63d61979b80b25258e7cc6caf781080222e0209b4a0b074decca874afc5c41de3313d8ed217d905e6ada43",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_2",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x6a75e4fe63e5e148c853462a680c3e3ccedea34719d28f19bf1b35ae4eea37d6",
            proof: "0xa38758fca85407078c0a7e5fd6d38b34340c809baa0e1fed9deaabb11aa503062acbbe23fcbe620a21b40a83bfa71b89",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_3",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x2c9ae4f1d6d08558d7027df9cc6b248c21290075d2c0df8a4084d02090b3fa14",
            proof: "0xb059c60125debbbf29d041bac20fd853951b64b5f31bfe2fa825e18ff49a259953e734b3d57119ae66f7bd79de3027f6",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_4",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x58cdc98c4c44791bb8ba7e58a80324ef8c021c79c68e253c430fa2663188f7f2",
            proof: "0x9506a8dc7f3f720a592a79a4e711e28d8596854bac66b9cb2d6d361704f1735442d47ea09fda5e0984f0928ce7d2f5f6",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_3_5",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x6c28d6edfea2f5e1638cb1a8be8197549d52e133fa9dae87e52abb45f7b192dd",
            proof: "0x8a46b67dcba4e3aa66f9952be69e1ecbc24e21d42b1df2bfe1c8e28431c6221a3f1d09808042f5624e857710cb24fb69",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_0",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x61157104410181bdc6eac224aa9436ac268bdcfeecb6badf71d228adda820af3",
            proof: "0x809adfa8b078b0921cdb8696ca017a0cc2d5337109016f36a766886eade28d32f205311ff5def247c3ddba91896fae97",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_1",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_2",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x549345dd3612e36fab0ab7baffe3faa5b820d56b71348c89ecaf63f7c4f85370",
            proof: "0xa35c4f136a09a33c6437c26dc0c617ce6548a14bc4af7127690a411f5e1cde2f73157365212dbcea6432e0e7869cb006",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_3",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1",
            proof: "0x987ea6df69bbe97c23e0dd948cf2d4490824ba7fea5af812721b2393354b0810a9dba2c231ea7ae30f26c412c7ea6e3a",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_4",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9",
            proof: "0xa62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_4_5",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x24d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a1",
            proof: "0x873033e038326e87ed3e1276fd140253fa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_0",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_1",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_2",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_3",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_4",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_5_5",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_0",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001",
            proof: "0xb82ded761997f2c6f1bb3db1e1dada2ef06d936551667c82f659b75f99d2da2068b81340823ee4e829a93c9fbed7810d",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_1",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xb9241c6816af6388d1014cd4d7dd21662a6e3d47f96c0257bce642b70e8e375839a880864638669c6a709b414ab8bffc",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_2",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x64d3b6baf69395bde2abd1d43f99be66bc64581234fd363e2ae3a0d419cfc3fc",
            proof: "0x893acd46552b81cc9e5ff6ca03dad873588f2c61031781367cfea2a2be4ef3090035623338711b3cf7eff4b4524df742",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_3",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x5fd58150b731b4facfcdd89c0e393ff842f5f2071303eff99b51e103161cd233",
            proof: "0x94425f5cf336685a6a4e806ad4601f4b0d3707a655718f968c57e225f0e4b8d5fd61878234f25ec59d090c07ea725cf4",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_4",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x92c51ff81dd71dab71cefecd79e8274b4b7ba36a0f40e2dc086bc4061c7f63249877db23297212991fd63e07b7ebc348",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_6_5",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xa256a681861974cdf6b116467044aa75c85b01076423a92c3335b93d10bf2fcb99b943a53adc1ab8feb6b475c4688948",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_0",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_1",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_2",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_3",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_4",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_5",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_0",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_1",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_2",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_4",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_5",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(true),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_0",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_1",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_2",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_3",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_4",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_0_5",
            commitment: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_0",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_1",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_2",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_3",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_4",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_1_5",
            commitment: "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000002",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_0",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359",
            proof: "0x90559bfd8e58f5d144588a1a959c93aba58607777e09893f088e404eb2dc47c0269ed8e47c1be79ea07ae726abd921a8",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_1",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0x8e3069b19e6e71aed9b7dc8fbba13e4217d91cfc59be47cfaa7d09ef626242517541992c0f76091ddabf271682cc7c2c",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_2",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0",
            proof: "0x99c282db3a79a9ec1553306515e6a71dc43df1ddbd1dbd9d5b71f3c1798ef482f5e1fd84500b0e47c82f72a189ecd526",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_3",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0",
            proof: "0xb3477fc9a5bfab5fdb5523251818ee5a6d52613c59502a3d2df58217f4e366cd9ef37dee55bf2c705a2b08e7808b6fa0",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_4",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc",
            proof: "0xb08a5afbb1717334e08e05576b07bff58e8851d8cfd9ea71da1ab4233ad4217cffabd669dfa89c3ebf4c44f91694a2f4",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_2_5",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321",
            proof: "0x8d72dc4eec977090f452b412a6b0a3cdced2ea6b622ebb6e289c7e05d85cc715b93eca244123c84a60b3ecbf33373903",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_0",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x1ed7d14d1b3fb1a1890d67b81715531553ad798df2009b4311d9fe2bea6cb964",
            proof: "0x98e15cbf800b69b90bfcaf1d907a9889c7743f7e5a19ee4b557471c005600f56d78e3dd887b2f5b87d76405b80dd2115",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_1",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x443e7af5274b52214ea6c775908c54519fea957eecd98069165a8b771082fd51",
            proof: "0xa7de1e32bb336b85e42ff5028167042188317299333f091dd88675e84a550577bfa564b2f57cd2498e2acf875e0aaa40",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_2",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x6a75e4fe63e5e148c853462a680c3e3ccedea34719d28f19bf1b35ae4eea37d6",
            proof: "0x861a2aef7aa82db033bfa125b9f756afecaf1db28384925d5007bcf7dff1a53b72bdf522610303075aeecab41685d720",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_3",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x2c9ae4f1d6d08558d7027df9cc6b248c21290075d2c0df8a4084d02090b3fa14",
            proof: "0xa4cc8c419ade0cf043cbf30f43c8f7ee6da3ab8d2c15070f323e5a13a8178fe07c8f89686e5fd16565247b520028251b",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_4",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x58cdc98c4c44791bb8ba7e58a80324ef8c021c79c68e253c430fa2663188f7f2",
            proof: "0xb0ac600174134691bf9d91fee448b4d58c127356567da1c456b9c38468909d4effe6b7faa11177e1f96ee5d2834df001",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_3_5",
            commitment: "0xb49d88afcd7f6c61a8ea69eff5f609d2432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x6c28d6edfea2f5e1638cb1a8be8197549d52e133fa9dae87e52abb45f7b192dd",
            proof: "0xa88d68fe3ad0d09b07f4605b1364c8d4804bf7096dae003d821cc01c3b7d35c6d1fdae14e2db3c05e1cdcea7c7b7f262",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_0",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x61157104410181bdc6eac224aa9436ac268bdcfeecb6badf71d228adda820af3",
            proof: "0xa1d8f2a5ab22acdfc1a9492ee2e1c2cbde681b51b312bf718821937e5088cd8ee002b718264027d10c5c5855dabe0353",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_1",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0x98613e9e1b1ed52fc2fdc54e945b863ff52870e6565307ff9e32327196d7a03c428fc51a9abedc97de2a68daa1274b50",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_2",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x549345dd3612e36fab0ab7baffe3faa5b820d56b71348c89ecaf63f7c4f85370",
            proof: "0x94fce36bf7e9f0ed981728fcd829013de96f7d25f8b4fe885059ec24af36f801ffbf68ec4604ef6e5f5f800f5cf31238",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_3",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1",
            proof: "0xb8f731ba6a52e419ffc843c50d2947d30e933e3a881b208de54149714ece74a599503f84c6249b5fd8a7c70189882a6b",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_4",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9",
            proof: "0xb9b65c2ebc89e669cf19e82fb178f0d1e9c958edbebe9ead62e97e95e2dcdc4972729fb9661f0cae3532b71b2664a8c1",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_4_5",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x24d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a1",
            proof: "0xacd56791e0ab0d1b3802021862013418993da2646e87140e12631e2914d9e6c676466aa3adfc91b61f84255544cab544",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_0",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_1",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_2",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_3",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_4",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_5_5",
            commitment: "0xb7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_0",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001",
            proof: "0x90f53a4837bbde6ab0838fef0c0be5339ab03a78342c221cf6b2d6e465d01a3d47585a808c9d8d25dee885007deeb107",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_1",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xafc13cef6ed41f7abe142d32d7b5354e5664bd4b6d52080460dd404dc2cb26269c24826d2bcd0152d0b55ee0a9e90289",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_2",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x64d3b6baf69395bde2abd1d43f99be66bc64581234fd363e2ae3a0d419cfc3fc",
            proof: "0xaf08cbca9deec336f2a56ca0b202995830f238fc3cb2ecdbdc0bbb6419e3e60507e823ff7dcbd17394cea55bc514716c",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_3",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x5fd58150b731b4facfcdd89c0e393ff842f5f2071303eff99b51e103161cd233",
            proof: "0x84c349506215a2d55f9d06f475b8229c6dedc08fd467f41fabae6bb042c2d0dbdbcd5f7532c475e479588eec5820fd37",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_4",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x9779b8337f00de6aeac881256198bd2db2fe95bc3127ad9e6440d9e4d1e785b455f55fcfe80a3434dc40f8e6df85be88",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_6_5",
            commitment: "0x93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x0000000000000000000000000000000000000000000000000000000000000000",
            proof: "0x82f1cd05471ab6ff21bcfd5c3369cba05b03a872a10829236d184fe1872767c391c2aa7e3b85babb1e6093b7224e7732",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_0",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000000",
            y: "0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_1",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_2",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000002",
            y: "0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_3",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62",
            y: "0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_4",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            y: "0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_incorrect_proof_point_at_infinity_5",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306",
            y: "0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321",
            proof: "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected: Some(false),
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_commitment_0",
            commitment: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xb0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_commitment_1",
            commitment: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xb0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_commitment_2",
            commitment: "0x8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xb0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_commitment_3",
            commitment: "0x8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0xb0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_proof_0",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_proof_1",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_proof_2",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0x8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_proof_3",
            commitment: "0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe",
            proof: "0x8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_0",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_1",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_2",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_3",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0xffffffffffffffffffffffffffffffff00000000000000000000000000000000",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_4",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x000000000000000000000000000000000000000000000000000000000000000000",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_y_5",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x0000000000000000000000000000000000000000000000000000000000000001",
            y: "0x00000000000000000000000000000000000000000000000000000000000000",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_0",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_1",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_2",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_3",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0xffffffffffffffffffffffffffffffff00000000000000000000000000000000",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_4",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x000000000000000000000000000000000000000000000000000000000000000000",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
        TestVector {
            name: "verify_kzg_proof_case_invalid_z_5",
            commitment: "0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
            z: "0x00000000000000000000000000000000000000000000000000000000000000",
            y: "0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9",
            proof: "0xb30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
            expected: None,
        },
    ];

    #[test]
    fn c_kzg_conformance() {
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
        let setup = Ethereum::new();

        for vector in TEST_VECTORS.iter() {
            let commitment = g1_from_hex(vector.commitment);
            let point = scalar_from_hex(vector.z);
            let value = scalar_from_hex(vector.y);
            let quotient = g1_from_hex(vector.proof);

            if let (Some(commitment), Some(point), Some(value), Some(quotient)) =
                (commitment, point, value, quotient)
            {
                let proof = Proof { quotient, value };
                let result = verify(&setup, &commitment, &point, &proof);

                match vector.expected {
                    Some(true) => {
                        assert!(result.is_ok(), "{} should verify successfully", vector.name)
                    }
                    _ => assert!(result.is_err(), "{} should fail verification", vector.name),
                }
            } else {
                assert_ne!(
                    vector.expected,
                    Some(true),
                    "{} contains malformed inputs",
                    vector.name
                );
            }
        }
    }

    fn test_codec_roundtrip<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        let encoded = proof.encode();
        let decoded = Proof::<G>::decode(encoded).expect("decoding should succeed");

        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_codec_roundtrip_g1() {
        test_codec_roundtrip::<G1>();
    }

    #[test]
    fn test_codec_roundtrip_g2() {
        test_codec_roundtrip::<G2>();
    }

    fn test_codec_with_invalid_proof_truncated<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let proof: Proof<G> = open(&setup, &coeffs, &point).expect("opening should succeed");
        let encoded = proof.encode();

        // Truncate the encoded data (remove some bytes)
        let truncated = &encoded[..encoded.len() - 10];
        let result: Result<Proof<G>, _> = Proof::<G>::decode(Bytes::from(truncated.to_vec()));

        assert!(result.is_err(), "truncated proof should fail to decode");
    }

    #[test]
    fn test_codec_with_invalid_proof_truncated_g1() {
        test_codec_with_invalid_proof_truncated::<G1>();
    }

    #[test]
    fn test_codec_with_invalid_proof_truncated_g2() {
        test_codec_with_invalid_proof_truncated::<G2>();
    }

    fn test_codec_with_invalid_proof_large<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let proof: Proof<G> = open(&setup, &coeffs, &point).expect("opening should succeed");
        let encoded = proof.encode();

        // Add extra bytes to make it the wrong size
        let mut wrong_size = encoded.to_vec();
        wrong_size.extend_from_slice(&[0u8; 10]);
        let result: Result<Proof<G>, _> = Proof::<G>::decode(Bytes::from(wrong_size));

        assert!(
            result.is_err(),
            "proof with wrong size should fail to decode"
        );
    }

    #[test]
    fn test_codec_with_invalid_proof_large_g1() {
        test_codec_with_invalid_proof_large::<G1>();
    }

    #[test]
    fn test_codec_with_invalid_proof_large_g2() {
        test_codec_with_invalid_proof_large::<G2>();
    }

    fn test_codec_with_tampered_proof<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64), Scalar::from(3u64), Scalar::from(2u64)];
        let point = Scalar::from(7u64);

        let proof: Proof<G> = open(&setup, &coeffs, &point).expect("opening should succeed");
        let mut encoded = proof.encode().to_vec();

        // Tamper with the encoded data by flipping some bits in the middle
        // Keep the same size but corrupt the data
        for byte in encoded.iter_mut().skip(10).take(10) {
            *byte ^= 0xFF;
        }

        let result: Result<Proof<G>, _> = Proof::<G>::decode(Bytes::from(encoded));

        assert!(result.is_err(), "tampered proof should fail to decode");
    }

    #[test]
    fn test_codec_with_tampered_proof_g1() {
        test_codec_with_tampered_proof::<G1>();
    }

    #[test]
    fn test_codec_with_tampered_proof_g2() {
        test_codec_with_tampered_proof::<G2>();
    }

    #[test]
    fn batch_verify_succeeds_g1() {
        test_batch_verify_succeeds::<G1>();
    }

    #[test]
    fn batch_verify_succeeds_g2() {
        test_batch_verify_succeeds::<G2>();
    }

    fn test_batch_verify_succeeds<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let mut rng = thread_rng();

        // Create multiple valid proofs
        let mut commitments: Vec<G> = Vec::new();
        let mut points: Vec<Scalar> = Vec::new();
        let mut proofs: Vec<Proof<G>> = Vec::new();

        for i in 0..5 {
            let coeffs = vec![
                Scalar::from(i as u64),
                Scalar::from((i + 1) as u64),
                Scalar::from((i + 2) as u64),
            ];
            let point = Scalar::from((i + 10) as u64);

            let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
            let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

            commitments.push(commitment);
            points.push(point);
            proofs.push(proof);
        }

        // Batch verify should succeed
        batch_verify(&mut rng, &setup, &commitments, &points, &proofs)
            .expect("batch verification should succeed");
    }

    #[test]
    fn batch_verify_fails_g1() {
        test_batch_verify_fails::<G1>();
    }

    #[test]
    fn batch_verify_fails_g2() {
        test_batch_verify_fails::<G2>();
    }

    fn test_batch_verify_fails<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let mut rng = thread_rng();

        // Create multiple valid proofs
        let mut commitments: Vec<G> = Vec::new();
        let mut points: Vec<Scalar> = Vec::new();
        let mut proofs: Vec<Proof<G>> = Vec::new();

        for i in 0..5 {
            let coeffs = vec![
                Scalar::from(i as u64),
                Scalar::from((i + 1) as u64),
                Scalar::from((i + 2) as u64),
            ];
            let point = Scalar::from((i + 10) as u64);

            let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
            let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

            commitments.push(commitment);
            points.push(point);
            proofs.push(proof);
        }

        // Corrupt one proof by changing its value
        proofs[2].value = Scalar::from(999u64);

        // Batch verify should fail
        let result = batch_verify(&mut rng, &setup, &commitments, &points, &proofs);
        assert!(
            result.is_err(),
            "batch verification should fail with invalid proof"
        );
    }

    #[test]
    fn batch_verify_length_mismatch_g1() {
        test_batch_verify_length_mismatch::<G1>();
    }

    #[test]
    fn batch_verify_length_mismatch_g2() {
        test_batch_verify_length_mismatch::<G2>();
    }

    fn test_batch_verify_length_mismatch<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let mut rng = thread_rng();

        // Create some valid data
        let coeffs = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        let commitments = vec![commitment.clone(), commitment.clone()];
        let points = vec![point.clone(), point.clone(), point.clone()]; // 3 points, 2 commitments
        let proofs = vec![proof.clone(), proof.clone()];

        // Test mismatch: commitments.len() != points.len()
        let result = batch_verify(&mut rng, &setup, &commitments, &points, &proofs);
        assert!(
            matches!(result, Err(Error::LengthMismatch(2, 3, 2))),
            "batch verification should fail with LengthMismatch when commitments and points have different lengths"
        );

        // Test mismatch: commitments.len() != proofs.len()
        let commitments = vec![commitment.clone(), commitment.clone(), commitment.clone()]; // 3 commitments
        let points = vec![point.clone(), point.clone()]; // 2 points
        let proofs = vec![proof.clone(), proof.clone()]; // 2 proofs

        let result = batch_verify(&mut rng, &setup, &commitments, &points, &proofs);
        assert!(
            matches!(result, Err(Error::LengthMismatch(3, 2, 2))),
            "batch verification should fail with LengthMismatch when commitments and points have different lengths"
        );

        // Test mismatch: points.len() != proofs.len()
        let commitments = vec![commitment.clone(), commitment.clone()]; // 2 commitments
        let points = vec![point.clone(), point.clone()]; // 2 points
        let proofs = vec![proof.clone(), proof.clone(), proof.clone()]; // 3 proofs

        let result = batch_verify(&mut rng, &setup, &commitments, &points, &proofs);
        assert!(
            matches!(result, Err(Error::LengthMismatch(2, 2, 3))),
            "batch verification should fail with LengthMismatch when points and proofs have different lengths"
        );
    }

    #[test]
    fn verify_zero_polynomial_g1() {
        test_verify_zero_polynomial::<G1>();
    }

    #[test]
    fn verify_zero_polynomial_g2() {
        test_verify_zero_polynomial::<G2>();
    }

    fn test_verify_zero_polynomial<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        // Zero polynomial: f(x) = 0
        let coeffs = vec![Scalar::zero()];
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        // For zero polynomial, commitment and quotient should both be zero
        assert_eq!(
            commitment,
            G::zero(),
            "zero polynomial should have zero commitment"
        );
        assert_eq!(
            proof.quotient,
            G::zero(),
            "zero polynomial should have zero quotient"
        );
        assert_eq!(
            proof.value,
            Scalar::zero(),
            "zero polynomial should evaluate to zero"
        );

        verify(&setup, &commitment, &point, &proof).expect("zero polynomial proof should verify");
    }

    #[test]
    fn verify_polynomial_evaluates_to_zero_g1() {
        test_verify_polynomial_evaluates_to_zero::<G1>();
    }

    #[test]
    fn verify_polynomial_evaluates_to_zero_g2() {
        test_verify_polynomial_evaluates_to_zero::<G2>();
    }

    fn test_verify_polynomial_evaluates_to_zero<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        // Polynomial f(x) = x - 7, which evaluates to 0 at x = 7
        let mut neg_seven = Scalar::zero();
        neg_seven.sub(&Scalar::from(7u64));
        let coeffs = vec![neg_seven, Scalar::one()]; // -7 + x
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        // The value should be zero, but the quotient should not be zero
        assert_eq!(
            proof.value,
            Scalar::zero(),
            "polynomial should evaluate to zero"
        );
        assert_ne!(
            proof.quotient,
            G::zero(),
            "quotient should not be zero for non-constant polynomial"
        );

        verify(&setup, &commitment, &point, &proof).expect("proof should verify");
    }

    #[test]
    fn verify_polynomial_with_zero_adjusted_commitment_g1() {
        test_verify_polynomial_with_zero_adjusted_commitment::<G1>();
    }

    #[test]
    fn verify_polynomial_with_zero_adjusted_commitment_g2() {
        test_verify_polynomial_with_zero_adjusted_commitment::<G2>();
    }

    fn test_verify_polynomial_with_zero_adjusted_commitment<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let coeffs = vec![Scalar::from(5u64)]; // Constant polynomial
        let point = Scalar::from(10u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        // For constant polynomial, adjusted_commitment should be zero
        let g_one = G::commitment_powers(&setup)[0].clone();
        let mut adjusted = commitment.clone();
        let mut neg_value = Scalar::zero();
        neg_value.sub(&proof.value);
        let mut neg_g = g_one.clone();
        neg_g.mul(&neg_value);
        adjusted.add(&neg_g);
        assert_eq!(
            adjusted,
            G::zero(),
            "adjusted commitment should be zero for constant polynomial"
        );

        verify(&setup, &commitment, &point, &proof).expect("proof should verify");
    }

    #[test]
    fn batch_verify_with_zero_elements_g1() {
        test_batch_verify_with_zero_elements::<G1>();
    }

    #[test]
    fn batch_verify_with_zero_elements_g2() {
        test_batch_verify_with_zero_elements::<G2>();
    }

    fn test_batch_verify_with_zero_elements<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let mut rng = thread_rng();

        // Create a mix of zero and non-zero polynomials
        let mut commitments: Vec<G> = Vec::new();
        let mut points: Vec<Scalar> = Vec::new();
        let mut proofs: Vec<Proof<G>> = Vec::new();

        // Zero polynomial
        let zero_coeffs = vec![Scalar::zero()];
        let zero_point = Scalar::from(5u64);
        let zero_commitment: G = commit(&setup, &zero_coeffs).expect("commitment should succeed");
        let zero_proof = open(&setup, &zero_coeffs, &zero_point).expect("opening should succeed");
        commitments.push(zero_commitment);
        points.push(zero_point);
        proofs.push(zero_proof);

        // Constant polynomial (non-zero)
        let const_coeffs = vec![Scalar::from(42u64)];
        let const_point = Scalar::from(7u64);
        let const_commitment: G = commit(&setup, &const_coeffs).expect("commitment should succeed");
        let const_proof =
            open(&setup, &const_coeffs, &const_point).expect("opening should succeed");
        commitments.push(const_commitment);
        points.push(const_point);
        proofs.push(const_proof);

        // Non-constant polynomial
        let poly_coeffs = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let poly_point = Scalar::from(10u64);
        let poly_commitment: G = commit(&setup, &poly_coeffs).expect("commitment should succeed");
        let poly_proof = open(&setup, &poly_coeffs, &poly_point).expect("opening should succeed");
        commitments.push(poly_commitment);
        points.push(poly_point);
        proofs.push(poly_proof);

        // Batch verify should succeed
        batch_verify(&mut rng, &setup, &commitments, &points, &proofs)
            .expect("batch verification should succeed with zero elements");
    }

    #[test]
    fn batch_verify_all_constant_polynomials_g1() {
        test_batch_verify_all_constant_polynomials::<G1>();
    }

    #[test]
    fn batch_verify_all_constant_polynomials_g2() {
        test_batch_verify_all_constant_polynomials::<G2>();
    }

    fn test_batch_verify_all_constant_polynomials<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        let mut rng = thread_rng();

        // Create multiple constant polynomials
        let mut commitments: Vec<G> = Vec::new();
        let mut points: Vec<Scalar> = Vec::new();
        let mut proofs: Vec<Proof<G>> = Vec::new();

        for i in 0..5 {
            let coeffs = vec![Scalar::from((i + 1) as u64 * 10)];
            let point = Scalar::from((i + 20) as u64);

            let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
            let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

            commitments.push(commitment);
            points.push(point);
            proofs.push(proof);
        }

        // All constant polynomials should have zero quotients
        for proof in &proofs {
            assert_eq!(
                proof.quotient,
                G::zero(),
                "constant polynomial should have zero quotient"
            );
        }

        // Batch verify should succeed
        batch_verify(&mut rng, &setup, &commitments, &points, &proofs)
            .expect("batch verification should succeed with all constant polynomials");
    }

    #[test]
    fn verify_polynomial_at_root_g1() {
        test_verify_polynomial_at_root::<G1>();
    }

    #[test]
    fn verify_polynomial_at_root_g2() {
        test_verify_polynomial_at_root::<G2>();
    }

    fn test_verify_polynomial_at_root<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        // Polynomial f(x) = (x - 5)(x - 10) = x^2 - 15x + 50
        // This has roots at x = 5 and x = 10
        let mut neg_fifteen = Scalar::zero();
        neg_fifteen.sub(&Scalar::from(15u64));
        let coeffs = vec![
            Scalar::from(50u64), // constant term
            neg_fifteen,         // -15x
            Scalar::one(),       // x^2
        ];

        // Verify at root x = 5 (should evaluate to 0)
        let point = Scalar::from(5u64);
        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");

        assert_eq!(
            proof.value,
            Scalar::zero(),
            "polynomial should evaluate to zero at root"
        );
        assert_ne!(proof.quotient, G::zero(), "quotient should not be zero");

        verify(&setup, &commitment, &point, &proof).expect("proof should verify at root");

        // Verify at root x = 10 (should also evaluate to 0)
        let point2 = Scalar::from(10u64);
        let proof2 = open(&setup, &coeffs, &point2).expect("opening should succeed");

        assert_eq!(
            proof2.value,
            Scalar::zero(),
            "polynomial should evaluate to zero at root"
        );
        verify(&setup, &commitment, &point2, &proof2).expect("proof should verify at root");
    }

    #[test]
    fn verify_empty_polynomial_commitment_g1() {
        test_verify_empty_polynomial_commitment::<G1>();
    }

    #[test]
    fn verify_empty_polynomial_commitment_g2() {
        test_verify_empty_polynomial_commitment::<G2>();
    }

    fn test_verify_empty_polynomial_commitment<G: Variant<Ethereum>>() {
        let setup = Ethereum::new();
        // Empty polynomial (no coefficients) should be treated as zero polynomial
        let coeffs: Vec<Scalar> = vec![];
        let point = Scalar::from(7u64);

        let commitment: G = commit(&setup, &coeffs).expect("commitment should succeed");
        assert_eq!(
            commitment,
            G::zero(),
            "empty polynomial should have zero commitment"
        );

        let proof = open(&setup, &coeffs, &point).expect("opening should succeed");
        assert_eq!(
            proof.value,
            Scalar::zero(),
            "empty polynomial should evaluate to zero"
        );
        assert_eq!(
            proof.quotient,
            G::zero(),
            "empty polynomial should have zero quotient"
        );

        verify(&setup, &commitment, &point, &proof).expect("empty polynomial proof should verify");
    }
}
