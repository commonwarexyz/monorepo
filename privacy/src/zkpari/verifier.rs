use crate::zkpari::{
    data_structures::{Proof, VerifyingKey},
    utils::{batch_inversion_and_mul, compute_chall, msm_bigint_wnaf},
    ZkPari,
};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::ops::Neg;

impl<E: Pairing> ZkPari<E> {
    /// Verify a proof against the ordinary public input.
    ///
    /// Checks the (3 + #blocks)-pairing equation
    ///
    /// ```text
    /// prod_j e(C_ci_j, delta_j H) * e(T, delta_w H)
    ///     = e(U, tau H - r H) * e(v_a alpha G + v_R beta G, H)
    /// ```
    ///
    /// where `v_R = (v_a + x_A(r))^2` (`x_B = 0` after instance outlining).
    ///
    /// Note: the committed-input commitments `proof.c_ci` are authenticated by
    /// this equation, but *what they commit to* is application state. Callers
    /// that maintain a block commitment publicly (e.g. a ledger commitment or
    /// a verifier-computed aggregate) must additionally check the
    /// corresponding `proof.c_ci[j]` against the expected point.
    pub fn verify(proof: &Proof<E>, vk: &VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let Proof {
            c_ci,
            t_g,
            u_g,
            v_a,
        } = proof;
        // Malformed statements and proofs are rejected, not panicked on
        if public_input.len() != vk.succinct_index.instance_len - 1 {
            return false;
        }
        // One commitment per committed-input block
        if c_ci.len() != vk.delta_h_prep.len() {
            return false;
        }

        /////////////////////// Challenge Computation ///////////////////////
        let challenge = compute_chall::<E>(vk, public_input, c_ci, t_g);

        /////////////////////// Computing x_A(r) ///////////////////////
        let instance_size = vk.succinct_index.instance_len;
        let mut px_evaluations = Vec::with_capacity(instance_size);
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - instance_size;

        px_evaluations.push(E::ScalarField::ONE);
        px_evaluations.extend_from_slice(public_input);
        let lagrange_coeffs = Self::eval_last_lagrange_coeffs::<E::ScalarField>(
            &vk.domain,
            challenge,
            r1cs_orig_num_cnstrs,
            vk.succinct_index.instance_len,
        );
        let x_a = lagrange_coeffs
            .into_iter()
            .zip(px_evaluations)
            .fold(E::ScalarField::zero(), |acc, (x, d)| acc + x * d);

        /////////////////////// Computing v_R ///////////////////////
        // v_R = (v_a + x_A(r))^2 - x_B(r), and x_B = 0 after instance outlining
        let v_r = (x_a + v_a).square();

        /////////////////////// Final Pairing ///////////////////////
        // prod_j e(C_ci_j, d_j H) * e(T, dw H) * e(-U, tau H)
        //   * e(r U - v_a alpha G - v_R beta G, H) == 1
        let last_left: E::G1Affine = msm_bigint_wnaf::<E::G1>(
            &[*u_g, -vk.alpha_g, -vk.beta_g],
            &[challenge.into(), (*v_a).into(), v_r.into()],
        )
        .into();

        let mut g1_terms: Vec<E::G1Affine> = c_ci.clone();
        g1_terms.extend([*t_g, -*u_g, last_left]);
        let mut g2_terms: Vec<E::G2Prepared> = vk.delta_h_prep.clone();
        g2_terms.extend([
            vk.delta_w_h_prep.clone(),
            vk.tau_h_prep.clone(),
            vk.h_prep.clone(),
        ]);
        let result = E::multi_pairing(g1_terms, g2_terms);
        result.is_zero()
    }

    pub(crate) fn eval_last_lagrange_coeffs<F: FftField>(
        domain: &Radix2EvaluationDomain<F>,
        tau: F,
        start_ind: usize,
        count: usize,
    ) -> Vec<F> {
        let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
        let group_gen: F = domain.group_gen();

        assert!(!z_h_at_tau.is_zero());

        let group_gen_inv = domain.group_gen_inv();
        let v_0_inv = domain.size_as_field_element();

        let start_gen = group_gen.pow([start_ind as u64]);
        let z_h_at_tau_inv = z_h_at_tau.inverse().unwrap();
        let mut l_i = z_h_at_tau_inv * v_0_inv;
        let mut negative_cur_elem = -start_gen;
        let mut lagrange_coefficients_inverse = vec![F::zero(); count];
        for coeff in &mut lagrange_coefficients_inverse.iter_mut() {
            *coeff = l_i * (tau + negative_cur_elem);
            l_i *= &group_gen_inv;
            negative_cur_elem *= &group_gen;
        }
        batch_inversion_and_mul(lagrange_coefficients_inverse.as_mut_slice(), &start_gen);
        lagrange_coefficients_inverse
    }
}
