use super::{
    Error, Relation,
    circuit::SparseRow,
    poly::Domain,
    types::{
        CommitmentKey, ProvingKey, PublicColumn, Trapdoor, VerifyingKey, commitment_keys_digest,
    },
};
use crate::bls12381::primitives::group::{G1, G2, Scalar};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, CryptoGroup, Field, Random, Ring};
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
    let (proving_key, verifying_key, _) = setup_with_trapdoor(relation, rng, strategy)?;
    Ok((proving_key, verifying_key))
}

/// Generate keys and additionally return the setup trapdoor.
///
/// # Security
///
/// The returned [`Trapdoor`] is toxic waste: anyone holding it can forge
/// accepting proofs for arbitrary claims via [`super::simulate`]. Use it only
/// for zero-knowledge testing and load generation; production deployments
/// must use [`setup`].
pub fn setup_with_trapdoor(
    relation: &Relation,
    rng: &mut impl CryptoRng,
    strategy: &impl Strategy,
) -> Result<(ProvingKey, VerifyingKey, Trapdoor), Error> {
    let domain_size = relation.size();
    let domain = Domain::new(domain_size)?;
    let num_vars = relation.size();
    let public_inputs = relation.public_inputs();
    let committed_inputs = relation.committed_inputs();

    let domain_size_u32 = u32::try_from(domain_size).map_err(|_| Error::TooLarge)?;
    let public_inputs_u32 = u32::try_from(public_inputs).map_err(|_| Error::TooLarge)?;
    let blocks_u32 = relation
        .blocks()
        .iter()
        .map(|&size| u32::try_from(size).map_err(|_| Error::TooLarge))
        .collect::<Result<Vec<_>, _>>()?;
    let columns = public_columns(relation)?;

    let g = G1::generator();
    let h = G2::generator();

    loop {
        let alpha = Scalar::random(&mut *rng);
        let beta = Scalar::random(&mut *rng);
        let delta_witness = Scalar::random(&mut *rng);
        let deltas = (0..relation.blocks().len())
            .map(|_| Scalar::random(&mut *rng))
            .collect::<Vec<_>>();
        let tau = loop {
            let candidate = Scalar::random(&mut *rng);
            if domain.evaluate_vanishing(&candidate) != Scalar::zero() {
                break candidate;
            }
        };

        let lagrange = domain.lagrange_coefficients(&tau)?;
        let (a_at_tau, b_at_tau) = evaluate_columns(relation.rows(), &lagrange, num_vars);
        let vanishing_at_tau = domain.evaluate_vanishing(&tau);
        let delta_witness_inv = delta_witness.inv();

        let committed_end = relation
            .committed_start()
            .checked_add(committed_inputs)
            .ok_or(Error::TooLarge)?;
        let mut commitment_keys = Vec::with_capacity(relation.blocks().len());
        let mut block_start = relation.committed_start();
        for (&size, delta) in relation.blocks().iter().zip(&deltas) {
            let delta_inv = delta.inv();
            let committed_scalars = (block_start..block_start + size)
                .map(|index| {
                    (alpha.clone() * &a_at_tau[index] + &(beta.clone() * &b_at_tau[index]))
                        * &delta_inv
                })
                .collect::<Vec<_>>();
            let basis = strategy.map_collect_vec(committed_scalars, |scalar| g * &scalar);
            let blinding = g * &((beta.clone() * &vanishing_at_tau) * &delta_inv);
            commitment_keys.push(CommitmentKey {
                relation_digest: *relation.digest(),
                basis,
                blinding,
            });
            block_start += size;
        }

        // The compiler guarantees formal column independence. These checks reject
        // the negligible set of trapdoors where evaluating those columns collapses
        // an actual commitment basis, jointly across every block.
        if !valid_commitment_basis(&commitment_keys) {
            continue;
        }

        let commitment_key_digest = commitment_keys_digest(&commitment_keys);

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
            public_inputs: public_inputs_u32,
            blocks: blocks_u32,
            public_columns: columns,
            alpha_g: g * &alpha,
            beta_g: g * &beta,
            delta_committed_h: deltas.iter().map(|delta| h * delta).collect(),
            delta_witness_h: h * &delta_witness,
            tau_h: h * &tau,
            digest: [0u8; 32],
        }
        .finalize();
        let proving_key = ProvingKey {
            commitment_keys,
            sigma_witness,
            sigma_mask_constant,
            sigma_mask_linear,
            sigma_quotient,
            sigma_a,
            sigma_r,
            verifying_key: verifying_key.clone(),
        };
        let trapdoor = Trapdoor {
            alpha,
            beta,
            deltas,
            delta_witness,
            tau,
        };
        return Ok((proving_key, verifying_key, trapdoor));
    }
}

/// Extract the sparse public columns of `A` and `B` for the verifying key.
fn public_columns(relation: &Relation) -> Result<Vec<PublicColumn>, Error> {
    let columns = relation
        .public_inputs()
        .checked_add(1)
        .ok_or(Error::TooLarge)?;
    let mut out = vec![PublicColumn::default(); columns];
    for (row, entries) in relation.rows().iter().enumerate() {
        let row = u32::try_from(row).map_err(|_| Error::TooLarge)?;
        for (column, coefficient) in entries
            .squared
            .iter()
            .take_while(|(column, _)| (*column as usize) < columns)
        {
            out[*column as usize].a.insert(row, coefficient.clone());
        }
        for (column, coefficient) in entries
            .linear
            .iter()
            .take_while(|(column, _)| (*column as usize) < columns)
        {
            out[*column as usize].b.insert(row, coefficient.clone());
        }
    }
    Ok(out)
}

fn evaluate_columns(
    rows: &[SparseRow],
    lagrange: &[Scalar],
    num_vars: usize,
) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut a_at_tau = vec![Scalar::zero(); num_vars];
    let mut b_at_tau = vec![Scalar::zero(); num_vars];
    for (entries, coefficient) in rows.iter().zip(lagrange) {
        for (column, value) in &entries.squared {
            a_at_tau[*column as usize] += &(value.clone() * coefficient);
        }
        for (column, value) in &entries.linear {
            b_at_tau[*column as usize] += &(value.clone() * coefficient);
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

fn valid_commitment_basis(keys: &[CommitmentKey]) -> bool {
    let mut encoded = BTreeSet::new();
    keys.iter().all(|key| {
        *key.blinding() != G1::zero()
            && encoded.insert(key.blinding().encode())
            && key
                .generators()
                .iter()
                .all(|point| *point != G1::zero() && encoded.insert(point.encode()))
    })
}
