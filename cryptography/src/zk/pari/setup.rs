use super::{
    Error, Relation,
    poly::Domain,
    sample_nonzero_scalar,
    types::{CommitmentKey, ProvingKey, VerifyingKey},
};
use crate::bls12381::primitives::group::{G1, G2, Scalar};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, CryptoGroup, Field, Ring};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;
use std::collections::BTreeSet;

/// Generate relation-specific Pari proving and verification keys.
///
/// The RNG must be cryptographically secure and its state must not be retained
/// in a form that can reproduce this setup. Recovered setup randomness is toxic
/// waste and permits forged proofs.
pub fn setup(
    relation: &Relation,
    rng: &mut impl CryptoRng,
    strategy: &impl Strategy,
) -> Result<(ProvingKey, VerifyingKey), Error> {
    let domain_size = relation.size();
    let domain = Domain::new(domain_size)?;
    let num_vars = relation.size();
    let public_inputs = relation.public_inputs();
    let committed_inputs = relation.committed_inputs();

    let domain_size_u32 = u32::try_from(domain_size).map_err(|_| Error::TooLarge)?;
    let num_vars_u32 = u32::try_from(num_vars).map_err(|_| Error::TooLarge)?;
    let public_inputs_u32 = u32::try_from(public_inputs).map_err(|_| Error::TooLarge)?;
    let committed_inputs_u32 = u32::try_from(committed_inputs).map_err(|_| Error::TooLarge)?;

    let g = G1::generator();
    let h = G2::generator();

    loop {
        let alpha = sample_nonzero_scalar(rng);
        let beta = sample_nonzero_scalar(rng);
        let delta_committed = sample_nonzero_scalar(rng);
        let delta_witness = sample_nonzero_scalar(rng);
        let tau = loop {
            let candidate = sample_nonzero_scalar(rng);
            if domain.evaluate_vanishing(&candidate) != Scalar::zero() {
                break candidate;
            }
        };

        let lagrange = domain.lagrange_coefficients(&tau)?;
        let (a_at_tau, b_at_tau) =
            evaluate_columns(relation.a(), relation.b(), &lagrange, num_vars);
        let vanishing_at_tau = domain.evaluate_vanishing(&tau);
        let delta_committed_inv = delta_committed.inv();
        let delta_witness_inv = delta_witness.inv();

        let committed_end = relation
            .committed_start()
            .checked_add(committed_inputs)
            .ok_or(Error::TooLarge)?;
        let committed_scalars = (relation.committed_start()..committed_end)
            .map(|index| {
                (alpha.clone() * &a_at_tau[index] + &(beta.clone() * &b_at_tau[index]))
                    * &delta_committed_inv
            })
            .collect::<Vec<_>>();
        let basis = strategy.map_collect_vec(committed_scalars, |scalar| g * &scalar);
        let blinding = g * &((beta.clone() * &vanishing_at_tau) * &delta_committed_inv);

        // The compiler guarantees formal column independence. These checks reject
        // the negligible set of trapdoors where evaluating those columns collapses
        // an actual commitment basis.
        if !valid_commitment_basis(&basis, &blinding) {
            continue;
        }

        let commitment_key = CommitmentKey {
            relation_digest: *relation.digest(),
            basis,
            blinding,
        };
        let commitment_key_digest = commitment_key.digest();

        let ordinary_scalars = (committed_end..relation.size())
            .map(|index| {
                (alpha.clone() * &a_at_tau[index] + &(beta.clone() * &b_at_tau[index]))
                    * &delta_witness_inv
            })
            .collect::<Vec<_>>();
        let sigma_witness = strategy.map_collect_vec(ordinary_scalars, |scalar| g * &scalar);

        let sigma_mask_constant = g * &((alpha.clone() * &vanishing_at_tau) * &delta_witness_inv);
        let sigma_mask_linear = sigma_mask_constant * &tau;

        let max_power = domain_size
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::TooLarge)?;
        let powers = powers(&tau, max_power + 1);

        let quotient_factor = (beta.clone() * &vanishing_at_tau) * &delta_witness_inv;
        let quotient_scalars = powers[..domain_size + 3]
            .iter()
            .map(|power| quotient_factor.clone() * power)
            .collect::<Vec<_>>();
        let sigma_quotient = strategy.map_collect_vec(quotient_scalars, |scalar| g * &scalar);

        let a_scalars = powers[..domain_size + 1]
            .iter()
            .map(|power| alpha.clone() * power)
            .collect::<Vec<_>>();
        let sigma_a = strategy.map_collect_vec(a_scalars, |scalar| g * &scalar);

        let r_scalars = powers[..2 * domain_size + 2]
            .iter()
            .map(|power| beta.clone() * power)
            .collect::<Vec<_>>();
        let sigma_r = strategy.map_collect_vec(r_scalars, |scalar| g * &scalar);

        let verifying_key = VerifyingKey {
            relation_digest: *relation.digest(),
            commitment_key_digest,
            domain_size: domain_size_u32,
            num_vars: num_vars_u32,
            public_inputs: public_inputs_u32,
            committed_inputs: committed_inputs_u32,
            alpha_g: g * &alpha,
            beta_g: g * &beta,
            delta_committed_h: h * &delta_committed,
            delta_witness_h: h * &delta_witness,
            tau_h: h * &tau,
            h,
        };
        let proving_key = ProvingKey {
            commitment_key,
            sigma_witness,
            sigma_mask_constant,
            sigma_mask_linear,
            sigma_quotient,
            sigma_a,
            sigma_r,
            verifying_key: verifying_key.clone(),
        };
        return Ok((proving_key, verifying_key));
    }
}

fn evaluate_columns(
    a: &[Scalar],
    b: &[Scalar],
    lagrange: &[Scalar],
    num_vars: usize,
) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut a_at_tau = vec![Scalar::zero(); num_vars];
    let mut b_at_tau = vec![Scalar::zero(); num_vars];
    for ((a_row, b_row), coefficient) in a
        .chunks_exact(num_vars)
        .zip(b.chunks_exact(num_vars))
        .zip(lagrange)
    {
        for (value, entry) in a_at_tau.iter_mut().zip(a_row) {
            *value += &(entry.clone() * coefficient);
        }
        for (value, entry) in b_at_tau.iter_mut().zip(b_row) {
            *value += &(entry.clone() * coefficient);
        }
    }
    (a_at_tau, b_at_tau)
}

fn powers(base: &Scalar, len: usize) -> Vec<Scalar> {
    let mut values = Vec::with_capacity(len);
    let mut value = Scalar::one();
    for _ in 0..len {
        values.push(value.clone());
        value *= base;
    }
    values
}

fn valid_commitment_basis(basis: &[G1], blinding: &G1) -> bool {
    if *blinding == G1::zero() {
        return false;
    }
    let mut encoded = BTreeSet::new();
    encoded.insert(blinding.encode());
    basis
        .iter()
        .all(|point| *point != G1::zero() && encoded.insert(point.encode()))
}
