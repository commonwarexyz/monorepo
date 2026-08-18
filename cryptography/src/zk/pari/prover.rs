use super::{
    Claim, Error, Proof, ProvingKey, Relation, Witness,
    poly::{Domain, Polynomial},
    sample_scalar, transcript_challenge,
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
    let b_mask = Polynomial::from_coefficients(vec![witness.opening().scalar().clone()])?;
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

    let challenge =
        transcript_challenge(transcript, &domain, &proving_key.verifying_key, claim, &t);
    let v_a = z_a_masked.evaluate_at(&challenge) - &x_a.evaluate_at(&challenge);
    let mut z_at_challenge = v_a.clone() + &x_a.evaluate_at(&challenge);
    z_at_challenge.square();
    let v_r = z_at_challenge - &x_b.evaluate_at(&challenge);

    let a_opening_numerator = z_a_masked
        .sub(&x_a)?
        .sub(&Polynomial::from_coefficients(vec![v_a.clone()])?)?;
    let (a_opening, a_remainder) = a_opening_numerator.divide_by_linear(&challenge)?;
    if a_remainder != Scalar::zero() {
        return Err(Error::InconsistentOpening);
    }

    let vanishing_quotient = Polynomial::zero().mask_vanishing(&quotient, &domain)?;
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
        || proving_key.commitment_key.relation_digest != *relation.digest()
        || verifying_key.commitment_key_digest != proving_key.commitment_key.digest()
        || verifying_key.domain_size as usize != relation.size()
        || verifying_key.num_vars as usize != relation.size()
        || verifying_key.public_inputs as usize != relation.public_inputs()
        || verifying_key.committed_inputs as usize != relation.committed_inputs()
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
    if !relation.is_satisfied(witness.assignment()) {
        return Err(Error::Unsatisfied);
    }
    if witness.claim(&proving_key.commitment_key, strategy)? != *claim {
        return Err(Error::ClaimMismatch);
    }
    Ok(())
}

fn evaluate_relation(relation: &Relation, values: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
    let size = relation.size();
    let a = relation
        .a()
        .chunks_exact(size)
        .map(|row| dot(row, values))
        .collect();
    let b = relation
        .b()
        .chunks_exact(size)
        .map(|row| dot(row, values))
        .collect();
    (a, b)
}

pub(super) fn evaluate_public(
    relation: &Relation,
    public: &[Scalar],
) -> (Vec<Scalar>, Vec<Scalar>) {
    let size = relation.size();
    let a = relation
        .a()
        .chunks_exact(size)
        .map(|row| dot(&row[..public.len()], public))
        .collect();
    let b = relation
        .b()
        .chunks_exact(size)
        .map(|row| dot(&row[..public.len()], public))
        .collect();
    (a, b)
}

fn dot(coefficients: &[Scalar], values: &[Scalar]) -> Scalar {
    coefficients
        .iter()
        .zip(values)
        .fold(Scalar::zero(), |sum, (coefficient, value)| {
            sum + &(coefficient.clone() * value)
        })
}
