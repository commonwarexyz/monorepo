use super::{Claim, Proof, VerifyingKey, poly::Domain, transcript_challenge};
use crate::{
    bls12381::primitives::group::{G1, G2, Scalar, SmallScalar},
    transcript::Transcript,
};
use commonware_math::algebra::{Additive, CryptoGroup, Multiplicative, Ring, Space};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Verify one Pari proof against its public inputs and expected commitment.
#[must_use]
pub fn verify(
    transcript: &mut Transcript,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    proof: &Proof,
) -> bool {
    if claim.commitment == G1::zero() || proof.t == G1::zero() || proof.u == G1::zero() {
        return false;
    }
    let Ok(domain) = verification_domain(verifying_key) else {
        return false;
    };
    if claim.public_inputs.len() != verifying_key.public_inputs as usize {
        return false;
    }
    let challenge = transcript_challenge(transcript, &domain, verifying_key, claim, &proof.t);
    let Some(v_r) = public_evaluation(verifying_key, claim, &domain, &challenge, &proof.v_a) else {
        return false;
    };
    pairing_check(verifying_key, &claim.commitment, proof, &challenge, &v_r)
}

/// Batch verify proofs using verifier-owned unpredictable coefficients.
///
/// Each transcript must contain the same prehistory used to create the proof at
/// the corresponding position. The transcripts are advanced independently.
#[must_use]
pub fn batch_verify(
    rng: &mut impl CryptoRng,
    transcripts: &mut [Transcript],
    verifying_key: &VerifyingKey,
    claims_and_proofs: &[(Claim, Proof)],
    strategy: &impl Strategy,
) -> bool {
    if transcripts.len() != claims_and_proofs.len() {
        return false;
    }
    if claims_and_proofs.is_empty() {
        return true;
    }
    let Ok(domain) = verification_domain(verifying_key) else {
        return false;
    };

    let mut challenges = Vec::with_capacity(claims_and_proofs.len());
    let mut v_rs = Vec::with_capacity(claims_and_proofs.len());
    for (transcript, (claim, proof)) in transcripts.iter_mut().zip(claims_and_proofs) {
        if claim.commitment == G1::zero() || proof.t == G1::zero() || proof.u == G1::zero() {
            return false;
        }
        if claim.public_inputs.len() != verifying_key.public_inputs as usize {
            return false;
        }
        let challenge = transcript_challenge(transcript, &domain, verifying_key, claim, &proof.t);
        let Some(v_r) = public_evaluation(verifying_key, claim, &domain, &challenge, &proof.v_a)
        else {
            return false;
        };
        challenges.push(challenge);
        v_rs.push(v_r);
    }

    // 128-bit coefficients keep the random linear combination sound at 2^-128
    // while halving the cost of the point aggregations below. Terms that
    // multiply a full-width value stay in the full scalar field.
    let coefficients = (0..claims_and_proofs.len())
        .map(|_| SmallScalar::random(&mut *rng))
        .collect::<Vec<_>>();
    let full_coefficients = coefficients
        .iter()
        .map(|coefficient| Scalar::from(coefficient.clone()))
        .collect::<Vec<_>>();
    let commitments = claims_and_proofs
        .iter()
        .map(|(claim, _)| claim.commitment)
        .collect::<Vec<_>>();
    let ts = claims_and_proofs
        .iter()
        .map(|(_, proof)| proof.t)
        .collect::<Vec<_>>();
    let us = claims_and_proofs
        .iter()
        .map(|(_, proof)| proof.u)
        .collect::<Vec<_>>();

    let commitment = G1::msm(&commitments, &coefficients, strategy);
    let t = G1::msm(&ts, &coefficients, strategy);
    let u = G1::msm(&us, &coefficients, strategy);
    let weighted_challenges = full_coefficients
        .iter()
        .zip(&challenges)
        .map(|(coefficient, challenge)| coefficient.clone() * challenge)
        .collect::<Vec<_>>();
    let evaluated_u = G1::msm(&us, &weighted_challenges, strategy);
    let v_a = full_coefficients
        .iter()
        .zip(claims_and_proofs)
        .fold(Scalar::zero(), |sum, (coefficient, (_, proof))| {
            sum + &(coefficient.clone() * &proof.v_a)
        });
    let v_r = full_coefficients
        .iter()
        .zip(v_rs)
        .fold(Scalar::zero(), |sum, (coefficient, value)| {
            sum + &(coefficient.clone() * &value)
        });

    let final_term = evaluated_u - &(verifying_key.alpha_g * &v_a) - &(verifying_key.beta_g * &v_r);
    G1::multi_pairing_check(
        &[commitment, t, -u],
        &[
            verifying_key.delta_committed_h,
            verifying_key.delta_witness_h,
            verifying_key.tau_h,
        ],
        &final_term,
        &G2::generator(),
    )
}

fn verification_domain(verifying_key: &VerifyingKey) -> Result<Domain, ()> {
    // Domain::new rounds up to a power of two, so reject sizes it would
    // silently alter.
    if !verifying_key.domain_size.is_power_of_two() {
        return Err(());
    }
    Domain::new(verifying_key.domain_size as usize).map_err(|_| ())
}

/// Evaluate the public parts of the verification equation at the challenge.
///
/// Computes `x_a` and `x_b`, the interpolations of the public columns dotted
/// with `(1, public inputs)`, directly from one set of Lagrange coefficients.
fn public_evaluation(
    verifying_key: &VerifyingKey,
    claim: &Claim,
    domain: &Domain,
    challenge: &Scalar,
    v_a: &Scalar,
) -> Option<Scalar> {
    let mut values = Vec::with_capacity(1 + claim.public_inputs.len());
    values.push(Scalar::one());
    values.extend_from_slice(&claim.public_inputs);
    if verifying_key.public_columns.len() != values.len() {
        return None;
    }

    let lagrange = domain.lagrange_coefficients(challenge).ok()?;
    let mut x_a = Scalar::zero();
    let mut x_b = Scalar::zero();
    for (column, value) in verifying_key.public_columns.iter().zip(&values) {
        for (&row, coefficient) in &column.a {
            x_a += &((coefficient.clone() * value) * lagrange.get(row as usize)?);
        }
        for (&row, coefficient) in &column.b {
            x_b += &((coefficient.clone() * value) * lagrange.get(row as usize)?);
        }
    }

    let mut z = v_a.clone() + &x_a;
    z.square();
    Some(z - &x_b)
}

fn pairing_check(
    verifying_key: &VerifyingKey,
    commitment: &G1,
    proof: &Proof,
    challenge: &Scalar,
    v_r: &Scalar,
) -> bool {
    let final_term =
        proof.u * challenge - &(verifying_key.alpha_g * &proof.v_a) - &(verifying_key.beta_g * v_r);
    G1::multi_pairing_check(
        &[*commitment, proof.t, -proof.u],
        &[
            verifying_key.delta_committed_h,
            verifying_key.delta_witness_h,
            verifying_key.tau_h,
        ],
        &final_term,
        &G2::generator(),
    )
}
