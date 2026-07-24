use crate::zkpari::{
    data_structures::{Claim, VerifyingKey},
    utils::{batch_inversion_and_mul, compute_chall, msm_bigint_wnaf},
    ZkPari,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::ops::Neg;

impl<E: Pairing> ZkPari<E> {
    /// Verify a batched-range claim.
    ///
    /// Checks the 5-pairing equation
    ///
    /// ```text
    /// e(c_hat, delta_1 H) * e(com_theta, delta_2 H) * e(T, delta_w H)
    ///     = e(U, tau H - r H) * e(v_a alpha G + v_R beta G, H)
    /// ```
    ///
    /// where `com_theta = ledger[0] + theta ledger[1]` and
    /// `v_R = (v_a + x_A(r))^2` (`x_B = 0` after instance outlining). The
    /// Fiat-Shamir challenge `r` binds `(theta, c_hat, ledger, T)`; the
    /// aggregate `com_theta` is derived, so it is never serialized.
    ///
    /// Note: the commitments are authenticated by this equation, but *what
    /// they commit to* is application state. Callers must source the `ledger`
    /// points from public state (e.g. ledger commitments or their
    /// difference); the fresh `c_hat` needs no such check.
    pub fn verify(claim: &Claim<E>, vk: &VerifyingKey<E>) -> bool
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let Claim {
            proof,
            theta,
            ledger,
        } = claim;
        // The fixed payments shape: two committed-input blocks, instance
        // `[1, theta]`. Malformed keys are rejected, not panicked on.
        if vk.delta_h_prep.len() != 2 || vk.succinct_index.instance_len != 2 {
            return false;
        }

        /////////////////////// Challenge Computation ///////////////////////
        let transcript_comms = [proof.c_hat, ledger[0], ledger[1]];
        let challenge =
            compute_chall::<E>(vk, &[*theta], &transcript_comms, &proof.t_g);

        /////////////////////// Computing x_A(r) ///////////////////////
        let instance_size = vk.succinct_index.instance_len;
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - instance_size;

        let px_evaluations = [E::ScalarField::ONE, *theta];
        let lagrange_coeffs = Self::eval_last_lagrange_coeffs::<E::ScalarField>(
            &vk.domain,
            challenge,
            r1cs_orig_num_cnstrs,
            instance_size,
        );
        let x_a = lagrange_coeffs
            .into_iter()
            .zip(px_evaluations)
            .fold(E::ScalarField::zero(), |acc, (x, d)| acc + x * d);

        /////////////////////// Computing v_R ///////////////////////
        // v_R = (v_a + x_A(r))^2 - x_B(r), and x_B = 0 after instance outlining
        let v_r = (x_a + proof.v_a).square();

        /////////////////////// Final Pairing ///////////////////////
        // e(c_hat, d_1 H) * e(com_theta, d_2 H) * e(T, dw H) * e(-U, tau H)
        //   * e(r U - v_a alpha G - v_R beta G, H) == 1
        let com_theta: E::G1Affine = (ledger[0] + ledger[1] * *theta).into_affine();
        let last_left: E::G1Affine = msm_bigint_wnaf::<E::G1>(
            &[proof.u_g, -vk.alpha_g, -vk.beta_g],
            &[challenge.into(), proof.v_a.into(), v_r.into()],
        )
        .into();

        let g1_terms = [proof.c_hat, com_theta, proof.t_g, -proof.u_g, last_left];
        let g2_terms: Vec<E::G2Prepared> = vk
            .delta_h_prep
            .iter()
            .cloned()
            .chain([
                vk.delta_w_h_prep.clone(),
                vk.tau_h_prep.clone(),
                vk.h_prep.clone(),
            ])
            .collect();
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
