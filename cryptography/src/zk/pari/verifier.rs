use super::{
    Claim, Proof, Relation, VerifyingKey, poly::Domain, prover::evaluate_public,
    sample_nonzero_scalar, transcript_challenge,
};
use crate::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::Transcript,
};
use commonware_math::algebra::{Additive, Multiplicative, Ring, Space};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Verify one Pari proof against its public inputs and expected commitment.
#[must_use]
pub fn verify(
    transcript: &mut Transcript,
    verifying_key: &VerifyingKey,
    relation: &Relation,
    claim: &Claim,
    proof: &Proof,
) -> bool {
    if claim.commitment == G1::zero() || proof.t == G1::zero() || proof.u == G1::zero() {
        return false;
    }
    let Ok(domain) = validate(verifying_key, relation, claim) else {
        return false;
    };
    let challenge = transcript_challenge(transcript, &domain, verifying_key, claim, &proof.t);
    let Some(v_r) = public_evaluation(relation, claim, &domain, &challenge, &proof.v_a) else {
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
    relation: &Relation,
    claims_and_proofs: &[(Claim, Proof)],
    strategy: &impl Strategy,
) -> bool {
    if transcripts.len() != claims_and_proofs.len() {
        return false;
    }
    if claims_and_proofs.is_empty() {
        return true;
    }
    let Ok(domain) = validate(verifying_key, relation, &claims_and_proofs[0].0) else {
        return false;
    };

    let mut challenges = Vec::with_capacity(claims_and_proofs.len());
    let mut v_rs = Vec::with_capacity(claims_and_proofs.len());
    for (transcript, (claim, proof)) in transcripts.iter_mut().zip(claims_and_proofs) {
        if claim.commitment == G1::zero() || proof.t == G1::zero() || proof.u == G1::zero() {
            return false;
        }
        if validate(verifying_key, relation, claim).is_err() {
            return false;
        }
        let challenge = transcript_challenge(transcript, &domain, verifying_key, claim, &proof.t);
        let Some(v_r) = public_evaluation(relation, claim, &domain, &challenge, &proof.v_a) else {
            return false;
        };
        challenges.push(challenge);
        v_rs.push(v_r);
    }

    let coefficients = (0..claims_and_proofs.len())
        .map(|_| sample_nonzero_scalar(rng))
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
    let weighted_challenges = coefficients
        .iter()
        .zip(&challenges)
        .map(|(coefficient, challenge)| coefficient.clone() * challenge)
        .collect::<Vec<_>>();
    let evaluated_u = G1::msm(&us, &weighted_challenges, strategy);
    let v_a = coefficients
        .iter()
        .zip(claims_and_proofs)
        .fold(Scalar::zero(), |sum, (coefficient, (_, proof))| {
            sum + &(coefficient.clone() * &proof.v_a)
        });
    let v_r = coefficients
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
        &verifying_key.h,
    )
}

fn validate(
    verifying_key: &VerifyingKey,
    relation: &Relation,
    claim: &Claim,
) -> Result<Domain, ()> {
    if verifying_key.relation_digest != *relation.digest()
        || verifying_key.domain_size as usize != relation.size()
        || verifying_key.num_vars as usize != relation.size()
        || verifying_key.public_inputs as usize != relation.public_inputs()
        || verifying_key.committed_inputs as usize != relation.committed_inputs()
        || claim.public_inputs.len() != relation.public_inputs()
    {
        return Err(());
    }
    Domain::new(relation.size()).map_err(|_| ())
}

fn public_evaluation(
    relation: &Relation,
    claim: &Claim,
    domain: &Domain,
    challenge: &Scalar,
    v_a: &Scalar,
) -> Option<Scalar> {
    let mut public = Vec::with_capacity(1 + claim.public_inputs.len());
    public.push(Scalar::one());
    public.extend_from_slice(&claim.public_inputs);
    let (x_a, x_b) = evaluate_public(relation, &public);
    let x_a = domain.lagrange_evaluate(&x_a, challenge).ok()?;
    let x_b = domain.lagrange_evaluate(&x_b, challenge).ok()?;
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
        &verifying_key.h,
    )
}
