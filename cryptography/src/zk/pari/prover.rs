use super::{
    Claim, Error, Proof, ProvingKey, Relation, Witness,
    circuit::dot,
    poly::{Domain, Polynomial},
    sample_scalar, transcript_challenge, transcript_challenge_prebound,
};
use crate::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::Transcript,
};
use commonware_math::algebra::{Additive, Multiplicative, Space};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Create a zero-knowledge proof for a claim and compiled witness.
pub fn prove(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    proving_key: &ProvingKey,
    relation: &Relation,
    claim: &Claim,
    witness: &Witness,
    strategy: &impl Strategy,
) -> Result<Proof, Error> {
    prove_inner(
        rng,
        transcript,
        proving_key,
        relation,
        claim,
        witness,
        strategy,
        true,
    )
}

/// Create a proof whose statement the caller has already bound to the
/// transcript.
///
/// # Security
///
/// The Fiat-Shamir challenge only covers what the transcript contains. Before
/// calling, the caller MUST have committed the claim's public inputs and every
/// block commitment (or data that uniquely determines them) to `transcript`,
/// and the verifier must replay exactly the same binding. Use [`prove`] unless
/// the statement needs a custom transcript encoding (e.g. binding commitment
/// preimages so batch verification can fold derived commitments).
#[allow(clippy::too_many_arguments)]
pub fn prove_prebound(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    proving_key: &ProvingKey,
    relation: &Relation,
    claim: &Claim,
    witness: &Witness,
    strategy: &impl Strategy,
) -> Result<Proof, Error> {
    prove_inner(
        rng,
        transcript,
        proving_key,
        relation,
        claim,
        witness,
        strategy,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_inner(
    rng: &mut impl CryptoRng,
    transcript: &mut Transcript,
    proving_key: &ProvingKey,
    relation: &Relation,
    claim: &Claim,
    witness: &Witness,
    strategy: &impl Strategy,
    bind_claim: bool,
) -> Result<Proof, Error> {
    validate_inputs(proving_key, relation, claim, witness, strategy)?;

    let assignment = witness.assignment();
    let values = assignment.values();
    let domain = Domain::new(relation.size())?;
    let (z_a_evaluations, z_b_evaluations) = evaluate_relation(relation, values);
    let public = assignment.public_assignment();
    let (x_a_evaluations, x_b_evaluations) = evaluate_public(relation, public);

    let z_a = domain.interpolate(&z_a_evaluations)?;
    let z_b = domain.interpolate(&z_b_evaluations)?;
    let x_a = domain.interpolate(&x_a_evaluations)?;
    let x_b = domain.interpolate(&x_b_evaluations)?;

    let eta_1 = sample_scalar(rng);
    let eta_2 = sample_scalar(rng);
    let a_mask = Polynomial::from_coefficients(vec![eta_1.clone(), eta_2.clone()])?;
    // Every block's opening randomness contributes to the B-side mask, since
    // each block commitment carries its own rho * Z_H(tau) term.
    let openings_sum = witness
        .openings()
        .iter()
        .fold(Scalar::zero(), |sum, opening| sum + opening.scalar());
    let b_mask = Polynomial::from_coefficients(vec![openings_sum])?;
    let z_a_masked = z_a.mask_vanishing(&a_mask, &domain)?;
    let z_b_masked = z_b.mask_vanishing(&b_mask, &domain)?;

    let numerator = z_a_masked.mul(&z_a_masked)?.sub(&z_b_masked)?;
    let (quotient, remainder) = numerator.divide_by_vanishing(&domain)?;
    if !remainder.is_zero() {
        return Err(Error::Unsatisfied);
    }

    let committed_end = relation
        .committed_start()
        .checked_add(relation.committed_inputs())
        .ok_or(Error::TooLarge)?;
    let ordinary_values = &values[committed_end..];
    if ordinary_values.len() != proving_key.sigma_witness.len()
        || quotient.coefficients().len() > proving_key.sigma_quotient.len()
    {
        return Err(Error::RelationMismatch);
    }
    let t = G1::msm(&proving_key.sigma_witness, ordinary_values, strategy)
        + &G1::msm(
            &[
                proving_key.sigma_mask_constant,
                proving_key.sigma_mask_linear,
            ],
            &[eta_1, eta_2],
            strategy,
        )
        + &G1::msm(
            &proving_key.sigma_quotient[..quotient.coefficients().len()],
            quotient.coefficients(),
            strategy,
        );
    if t == G1::zero() {
        return Err(Error::IdentityPoint { kind: "proof T" });
    }

    let challenge = if bind_claim {
        transcript_challenge(transcript, &domain, &proving_key.verifying_key, claim, &t)
    } else {
        transcript_challenge_prebound(transcript, &domain, &proving_key.verifying_key, &t)
    };
    let mut z_a_at_challenge = z_a_masked.evaluate_at(&challenge);
    let v_a = z_a_at_challenge.clone() - &x_a.evaluate_at(&challenge);
    z_a_at_challenge.square();
    let v_r = z_a_at_challenge - &x_b.evaluate_at(&challenge);

    let a_opening_numerator = z_a_masked
        .sub(&x_a)?
        .sub(&Polynomial::from_coefficients(vec![v_a.clone()])?)?;
    let (a_opening, a_remainder) = a_opening_numerator.divide_by_linear(&challenge)?;
    if a_remainder != Scalar::zero() {
        return Err(Error::InconsistentOpening);
    }

    let vanishing_quotient = quotient.mul_vanishing(&domain)?;
    let r_polynomial = z_b_masked.sub(&x_b)?.add(&vanishing_quotient)?;
    let r_opening_numerator = r_polynomial.sub(&Polynomial::from_coefficients(vec![v_r])?)?;
    let (r_opening, r_remainder) = r_opening_numerator.divide_by_linear(&challenge)?;
    if r_remainder != Scalar::zero() {
        return Err(Error::InconsistentOpening);
    }

    if a_opening.coefficients().len() > proving_key.sigma_a.len()
        || r_opening.coefficients().len() > proving_key.sigma_r.len()
    {
        return Err(Error::RelationMismatch);
    }
    let u = G1::msm(
        &proving_key.sigma_a[..a_opening.coefficients().len()],
        a_opening.coefficients(),
        strategy,
    ) + &G1::msm(
        &proving_key.sigma_r[..r_opening.coefficients().len()],
        r_opening.coefficients(),
        strategy,
    );
    if u == G1::zero() {
        return Err(Error::IdentityPoint { kind: "proof U" });
    }

    Ok(Proof { t, u, v_a })
}

fn validate_inputs(
    proving_key: &ProvingKey,
    relation: &Relation,
    claim: &Claim,
    witness: &Witness,
    strategy: &impl Strategy,
) -> Result<(), Error> {
    let verifying_key = &proving_key.verifying_key;
    if verifying_key.relation_digest != *relation.digest()
        || proving_key
            .commitment_keys
            .iter()
            .any(|key| key.relation_digest != *relation.digest())
        || verifying_key.commitment_key_digest
            != super::types::commitment_keys_digest(&proving_key.commitment_keys)
        || verifying_key.domain_size as usize != relation.size()
        || verifying_key.public_inputs as usize != relation.public_inputs()
        || verifying_key.blocks.len() != relation.blocks().len()
        || verifying_key
            .blocks
            .iter()
            .zip(relation.blocks())
            .any(|(&size, &expected)| size as usize != expected)
        || witness.assignment().relation_digest() != relation.digest()
    {
        return Err(Error::RelationMismatch);
    }
    if claim.public_inputs.len() != relation.public_inputs() {
        return Err(Error::PublicInputCount {
            expected: relation.public_inputs(),
            actual: claim.public_inputs.len(),
        });
    }
    // Whether the assignment satisfies the relation is checked by the
    // divisibility of the masked constraint polynomial during proving.
    if witness.assignment().values().len() != relation.size() {
        return Err(Error::RelationMismatch);
    }
    if witness.claim(&proving_key.commitment_keys, strategy)? != *claim {
        return Err(Error::ClaimMismatch);
    }
    Ok(())
}

fn evaluate_relation(relation: &Relation, values: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut a = vec![Scalar::zero(); relation.size()];
    let mut b = vec![Scalar::zero(); relation.size()];
    for (row, entries) in relation.rows().iter().enumerate() {
        a[row] = dot(&entries.squared, values);
        b[row] = dot(&entries.linear, values);
    }
    (a, b)
}

fn evaluate_public(relation: &Relation, public: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut a = vec![Scalar::zero(); relation.size()];
    let mut b = vec![Scalar::zero(); relation.size()];
    for (row, entries) in relation.rows().iter().enumerate() {
        a[row] = dot_public(&entries.squared, public);
        b[row] = dot_public(&entries.linear, public);
    }
    (a, b)
}

/// Dot the public prefix of a sparse row with the public assignment. Row
/// entries are sorted by column, so the public columns form a prefix.
fn dot_public(entries: &[(u32, Scalar)], public: &[Scalar]) -> Scalar {
    entries
        .iter()
        .take_while(|(column, _)| (*column as usize) < public.len())
        .fold(Scalar::zero(), |sum, (column, coefficient)| {
            sum + &(coefficient.clone() * &public[*column as usize])
        })
}
