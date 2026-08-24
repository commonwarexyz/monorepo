//! Honest-verifier zero-knowledge simulator.
//!
//! Produces accepting proofs for arbitrary claims without a witness, using
//! the setup trapdoor. This is the simulator from the zero-knowledge proof of
//! the scheme, exposed for two purposes: exercising the zero-knowledge
//! argument in tests, and generating verifier-accepted load cheaply (a
//! simulated proof costs a handful of group operations instead of the full
//! prover pipeline).

use super::{
    Claim, Error, Proof, Trapdoor, VerifyingKey, sample_scalar, transcript_challenge,
    transcript_challenge_prebound, verifier::evaluate_public_columns,
};
use crate::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::Transcript,
};
use commonware_math::algebra::{Additive, CryptoGroup, Field, Multiplicative};
use rand_core::CryptoRng;

/// Simulate an accepting proof for `claim` using the setup trapdoor.
///
/// The transcript contract matches [`super::verify`]: the claim is bound
/// internally. Fails only on negligible-probability challenge collisions and
/// on claims whose shape does not match the key.
pub fn simulate(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    trapdoor: &Trapdoor,
    verifying_key: &VerifyingKey,
    claim: &Claim,
) -> Result<Proof, Error> {
    simulate_inner(rng, transcript, trapdoor, verifying_key, claim, true)
}

/// Simulate an accepting proof whose statement the caller has already bound
/// to the transcript.
///
/// # Security
///
/// The transcript contract matches [`super::verify_prebound`]: the caller
/// MUST have committed the claim's public inputs and every block commitment
/// (or data that uniquely determines them) to `transcript`.
pub fn simulate_prebound(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    trapdoor: &Trapdoor,
    verifying_key: &VerifyingKey,
    claim: &Claim,
) -> Result<Proof, Error> {
    simulate_inner(rng, transcript, trapdoor, verifying_key, claim, false)
}

fn simulate_inner(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    trapdoor: &Trapdoor,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    bind_claim: bool,
) -> Result<Proof, Error> {
    if claim.public_inputs.len() != verifying_key.public_inputs as usize
        || claim.commitments.len() != verifying_key.blocks.len()
        || trapdoor.deltas.len() != verifying_key.blocks.len()
    {
        return Err(Error::RelationMismatch);
    }
    let domain = Domain::new(verifying_key.domain_size as usize)?;
    let (x_a_tau, x_b_tau) =
        evaluate_public_columns(verifying_key, &claim.public_inputs, &domain, &trapdoor.tau)
            .ok_or(Error::RelationMismatch)?;

    // Sample the values an honest prover's masks make uniform: the masked
    // A-polynomial at tau and the claimed evaluation at the challenge.
    let y = sample_scalar(rng);
    let v_a = sample_scalar(rng);

    // Choose T so the pairing equation's left side collapses to a scalar
    // multiple of the generator:
    //   sum_j delta_j com_j + delta_w T = [alpha (y - x_A(tau)) + beta (y^2 - x_B(tau))] G.
    let mut y_squared = y.clone();
    y_squared.square();
    let numerator = trapdoor.alpha.clone() * &(y - &x_a_tau)
        + &(trapdoor.beta.clone() * &(y_squared - &x_b_tau));
    let delta_witness_inv = trapdoor.delta_witness.inv();
    let mut t = G1::generator() * &(numerator.clone() * &delta_witness_inv);
    for (commitment, delta) in claim.commitments.iter().zip(&trapdoor.deltas) {
        t -= &(*commitment * &(delta.clone() * &delta_witness_inv));
    }
    if t == G1::zero() {
        return Err(Error::IdentityPoint { kind: "proof T" });
    }

    let challenge = if bind_claim {
        transcript_challenge(transcript, &domain, verifying_key, claim, &t)
    } else {
        transcript_challenge_prebound(transcript, &domain, verifying_key, &t)
    };
    let difference = trapdoor.tau.clone() - &challenge;
    if difference == Scalar::zero() {
        // The challenge collides with the trapdoor point: probability ~1/|F|.
        return Err(Error::InconsistentOpening);
    }

    let (x_a_challenge, x_b_challenge) =
        evaluate_public_columns(verifying_key, &claim.public_inputs, &domain, &challenge)
            .ok_or(Error::RelationMismatch)?;
    let mut v_r = v_a.clone() + &x_a_challenge;
    v_r.square();
    v_r -= &x_b_challenge;

    // Solve the verification equation for the unique accepting opening:
    //   (tau - challenge) U = [numerator - alpha v_a - beta v_r] G.
    let u_scalar = (numerator - &(trapdoor.alpha.clone() * &v_a) - &(trapdoor.beta.clone() * &v_r))
        * &difference.inv();
    let u = G1::generator() * &u_scalar;
    if u == G1::zero() {
        return Err(Error::IdentityPoint { kind: "proof U" });
    }

    Ok(Proof { t, u, v_a })
}
