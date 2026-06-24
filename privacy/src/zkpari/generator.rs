use crate::zkpari::{
    data_structures::{ProvingKey, SuccinctIndex, Trapdoor, VerifyingKey},
    range::{range_relation, RangeRelation},
    ZkPari,
};
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing};
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{rand::RngCore, vec::Vec, UniformRand};

impl<E: Pairing> ZkPari<E> {
    /// Generate proving and verifying keys for the payments range relation.
    pub fn keygen<R: RngCore>(rng: &mut R) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E::ScalarField: Field,
    {
        let (pk, vk, _trapdoor) = Self::keygen_with_trapdoor(rng);
        (pk, vk)
    }

    /// Like [`Self::keygen`], but also returns the setup [`Trapdoor`].
    ///
    /// The trapdoor is toxic waste: retaining it breaks soundness because
    /// [`Self::simulate`] can forge accepting transcripts for tests. A real
    /// deployment must use [`Self::keygen`] and discard the trapdoor.
    pub fn keygen_with_trapdoor<R: RngCore>(
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>, Trapdoor<E>)
    where
        E::ScalarField: Field,
    {
        let relation = range_relation::<E::ScalarField>();
        let instance_len = relation.instance_len;
        let num_constraints = relation.num_constraints;
        let num_witness = relation.num_witness;
        let block_indices = relation.committed_witness_indices.clone();
        let block_sizes: Vec<usize> = block_indices.iter().map(Vec::len).collect();

        let mut is_committed = vec![false; num_witness];
        for block in &block_indices {
            for &w in block {
                is_committed[w] = true;
            }
        }
        let ordinary_indices: Vec<usize> = (0..num_witness).filter(|w| !is_committed[*w]).collect();

        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let deltas: Vec<E::ScalarField> = (0..block_indices.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        let delta_w = E::ScalarField::rand(rng);
        let tau = E::ScalarField::rand(rng);

        let alpha_g = g * alpha;
        let beta_g = g * beta;
        let delta_h: Vec<E::G2Affine> = deltas.iter().map(|d| (h * d).into()).collect();
        let delta_w_h = h * delta_w;
        let tau_h = h * tau;

        let delta_inverses: Vec<E::ScalarField> =
            deltas.iter().map(|d| d.inverse().unwrap()).collect();
        let delta_w_inverse = delta_w.inverse().unwrap();

        let domain = Radix2EvaluationDomain::new(num_constraints).unwrap();
        let v_k_at_tau = domain.evaluate_vanishing_polynomial(tau);
        assert_ne!(v_k_at_tau, E::ScalarField::zero());
        let domain_size = domain.size();

        let (a, b) = Self::compute_ai_bi_at_tau(tau, &relation, domain);
        for block in &block_indices {
            for &w in block {
                assert!(
                    !(a[instance_len + w].is_zero() && b[instance_len + w].is_zero()),
                    "committed input (witness variable {w}) does not appear in any constraint; \
                     its commitment basis element would be the identity"
                );
            }
        }

        let succinct_index = SuccinctIndex {
            num_constraints,
            instance_len,
            committed_input_blocks: block_sizes,
        };

        let max_power = 2 * domain_size + 1;
        let mut powers_of_tau = Vec::with_capacity(max_power + 1);
        let mut cur = E::ScalarField::ONE;
        for _ in 0..=max_power {
            powers_of_tau.push(cur);
            cur *= &tau;
        }

        let table = BatchMulPreprocessing::new(g, max_power + 1);

        let sigma_a_powers = powers_of_tau[0..domain_size + 1]
            .iter()
            .map(|tau_to_i| *tau_to_i * alpha)
            .collect::<Vec<_>>();
        let sigma_a = table.batch_mul(&sigma_a_powers);

        let sigma_r_powers = powers_of_tau[0..2 * domain_size + 2]
            .iter()
            .map(|tau_to_i| *tau_to_i * beta)
            .collect::<Vec<_>>();
        let sigma_r = table.batch_mul(&sigma_r_powers);

        let mut sigma_ci = Vec::with_capacity(block_indices.len());
        let mut gamma_ci = Vec::with_capacity(block_indices.len());
        for (block, delta_j_inverse) in block_indices.iter().zip(&delta_inverses) {
            let alpha_over_delta_j = alpha * delta_j_inverse;
            let beta_over_delta_j = beta * delta_j_inverse;
            let sigma_ci_powers = block
                .iter()
                .map(|&w| {
                    a[instance_len + w] * alpha_over_delta_j
                        + b[instance_len + w] * beta_over_delta_j
                })
                .collect::<Vec<_>>();
            sigma_ci.push(table.batch_mul(&sigma_ci_powers));
            gamma_ci.push((g * (beta * v_k_at_tau * delta_j_inverse)).into());
        }

        let alpha_over_delta_w = alpha * delta_w_inverse;
        let beta_over_delta_w = beta * delta_w_inverse;
        let sigma_w_powers = ordinary_indices
            .iter()
            .map(|&w| {
                a[instance_len + w] * alpha_over_delta_w + b[instance_len + w] * beta_over_delta_w
            })
            .collect::<Vec<_>>();
        let sigma_w = table.batch_mul(&sigma_w_powers);

        let sigma_mask_const = (g * (alpha * v_k_at_tau * delta_w_inverse)).into();
        let sigma_mask_linear = (g * (alpha * tau * v_k_at_tau * delta_w_inverse)).into();

        let beta_v_k_over_delta_w = beta * v_k_at_tau * delta_w_inverse;
        let sigma_q_comm_powers = powers_of_tau[0..domain_size + 3]
            .iter()
            .map(|tau_to_i| *tau_to_i * beta_v_k_over_delta_w)
            .collect::<Vec<_>>();
        let sigma_q_comm = table.batch_mul(&sigma_q_comm_powers);

        let vk = VerifyingKey {
            succinct_index,
            alpha_g: alpha_g.into(),
            beta_g: beta_g.into(),
            delta_h_prep: delta_h.iter().map(|d| (*d).into()).collect(),
            delta_h,
            delta_w_h: delta_w_h.into(),
            delta_w_h_prep: delta_w_h.into().into(),
            tau_h: tau_h.into(),
            tau_h_prep: tau_h.into().into(),
            g: g.into(),
            h: h.into(),
            h_prep: h.into().into(),
            domain,
        };

        let pk = ProvingKey {
            sigma_ci,
            gamma_ci,
            committed_witness_indices: block_indices,
            sigma_w,
            sigma_mask_const,
            sigma_mask_linear,
            sigma_q_comm,
            sigma_a,
            sigma_r,
            verifying_key: vk.clone(),
        };

        let trapdoor = Trapdoor {
            alpha,
            beta,
            deltas,
            delta_w,
            tau,
            g: g.into(),
            instance_a_at_tau: a[..instance_len].to_vec(),
            instance_b_at_tau: b[..instance_len].to_vec(),
        };

        (pk, vk, trapdoor)
    }

    pub(crate) fn compute_ai_bi_at_tau(
        tau: E::ScalarField,
        relation: &RangeRelation<E::ScalarField>,
        domain: Radix2EvaluationDomain<E::ScalarField>,
    ) -> (Vec<E::ScalarField>, Vec<E::ScalarField>) {
        let lagrange_polys_at_tau = domain.evaluate_all_lagrange_coefficients(tau);
        let num_variables = relation.instance_len + relation.num_witness;

        let mut a = vec![E::ScalarField::zero(); num_variables];
        let mut b = vec![E::ScalarField::zero(); num_variables];

        for (i, u_i) in lagrange_polys_at_tau
            .iter()
            .enumerate()
            .take(relation.num_constraints)
        {
            for &(coeff, index) in &relation.a[i] {
                a[index] += *u_i * coeff;
            }
            for &(coeff, index) in &relation.b[i] {
                b[index] += *u_i * coeff;
            }
        }
        (a, b)
    }
}
