use crate::zkpari::{
    data_structures::{Proof, VerifyingKey},
    utils::{batch_inversion_and_mul, msm_bigint_wnaf, msm_pippenger},
    ZkPari,
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{ops::Neg, rand::RngCore};

impl<E: Pairing> ZkPari<E> {
    /// Batch verification of N proofs using a random linear combination.
    ///
    /// Reduces N independent `(3 + #blocks)`-pairing checks to one pairing
    /// product by sampling random 128-bit challenges and accumulating the
    /// commitments, openings, and scalar terms.
    pub fn batch_verify(
        proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
        vk: &VerifyingKey<E>,
        rng: &mut impl RngCore,
    ) -> bool
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let n = proofs_and_inputs.len();
        if n == 0 {
            return true;
        }

        let num_blocks = vk.delta_h_prep.len();
        let instance_len = vk.succinct_index.instance_len;
        if proofs_and_inputs.iter().any(|(proof, public_input)| {
            proof.c_ci.len() != num_blocks || public_input.len() != instance_len - 1
        }) {
            return false;
        }
        if n == 1 {
            return Self::verify(&proofs_and_inputs[0].0, vk, &proofs_and_inputs[0].1);
        }

        let challenges: Vec<E::ScalarField> = {
            let base_transcript = crate::zkpari::utils::seed_transcript_with_vk::<E>(vk);
            proofs_and_inputs
                .iter()
                .map(|(proof, public_input)| {
                    crate::zkpari::utils::compute_chall_from_transcript::<E>(
                        &base_transcript,
                        public_input,
                        &proof.c_ci,
                        &proof.t_g,
                    )
                })
                .collect()
        };

        let instance_size = vk.succinct_index.instance_len;
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - instance_size;
        let all_lagrange_coeffs = Self::batch_eval_last_lagrange_coeffs::<E::ScalarField>(
            &vk.domain,
            &challenges,
            r1cs_orig_num_cnstrs,
            instance_size,
        );

        let mut v_rs = Vec::with_capacity(n);
        for ((proof, public_input), lagrange_coeffs) in
            proofs_and_inputs.iter().zip(all_lagrange_coeffs)
        {
            let x_a = lagrange_coeffs
                .into_iter()
                .zip(core::iter::once(E::ScalarField::ONE).chain(public_input.iter().copied()))
                .fold(E::ScalarField::zero(), |acc, (l, x)| acc + l * x);
            v_rs.push((x_a + proof.v_a).square());
        }

        // 128-bit rhos give the standard 2^-128 batch soundness term.
        const SMALL_SCALAR_BITS: usize = 128;
        let rhos: Vec<E::ScalarField> = (0..n)
            .map(|_| {
                let mut bytes = [0u8; 16];
                rng.fill_bytes(&mut bytes);
                E::ScalarField::from_le_bytes_mod_order(&bytes)
            })
            .collect();
        let rho_bigints: Vec<<E::ScalarField as PrimeField>::BigInt> =
            rhos.iter().map(|rho| rho.into_bigint()).collect();

        let t_bases: Vec<E::G1Affine> = proofs_and_inputs
            .iter()
            .map(|(proof, _)| proof.t_g)
            .collect();
        let u_bases: Vec<E::G1Affine> = proofs_and_inputs
            .iter()
            .map(|(proof, _)| proof.u_g)
            .collect();

        let c_tildes: Vec<E::G1Affine> = (0..num_blocks)
            .map(|block| {
                let c_bases: Vec<E::G1Affine> = proofs_and_inputs
                    .iter()
                    .map(|(proof, _)| proof.c_ci[block])
                    .collect();
                msm_pippenger::<E::G1>(&c_bases, &rho_bigints, SMALL_SCALAR_BITS).into()
            })
            .collect();
        let t_tilde: E::G1Affine =
            msm_pippenger::<E::G1>(&t_bases, &rho_bigints, SMALL_SCALAR_BITS).into();
        let u_tilde: E::G1Affine =
            msm_pippenger::<E::G1>(&u_bases, &rho_bigints, SMALL_SCALAR_BITS).into();

        let rho_r: Vec<E::ScalarField> = rhos
            .iter()
            .zip(&challenges)
            .map(|(rho, r)| *rho * *r)
            .collect();
        let v_tilde: E::G1Affine =
            <E::G1 as VariableBaseMSM>::msm_unchecked(&u_bases, &rho_r).into();

        let v_a_tilde = rhos
            .iter()
            .zip(proofs_and_inputs.iter())
            .fold(E::ScalarField::zero(), |acc, (rho, (proof, _))| {
                acc + *rho * proof.v_a
            });
        let v_r_tilde = rhos
            .iter()
            .zip(&v_rs)
            .fold(E::ScalarField::zero(), |acc, (rho, v_r)| acc + *rho * *v_r);

        let last_left: E::G1Affine = msm_bigint_wnaf::<E::G1>(
            &[v_tilde, -vk.alpha_g, -vk.beta_g],
            &[
                E::ScalarField::ONE.into(),
                v_a_tilde.into(),
                v_r_tilde.into(),
            ],
        )
        .into();

        let mut g1_terms = c_tildes;
        g1_terms.extend([t_tilde, -u_tilde, last_left]);
        let mut g2_terms = vk.delta_h_prep.clone();
        g2_terms.extend([
            vk.delta_w_h_prep.clone(),
            vk.tau_h_prep.clone(),
            vk.h_prep.clone(),
        ]);

        E::multi_pairing(g1_terms, g2_terms).is_zero()
    }

    /// Batch variant of `eval_last_lagrange_coeffs`.
    pub(crate) fn batch_eval_last_lagrange_coeffs<F: FftField>(
        domain: &Radix2EvaluationDomain<F>,
        challenges: &[F],
        start_ind: usize,
        count: usize,
    ) -> Vec<Vec<F>> {
        let n = challenges.len();

        let group_gen = domain.group_gen();
        let group_gen_inv = domain.group_gen_inv();
        let domain_size = domain.size_as_field_element();
        let start_gen = group_gen.pow([start_ind as u64]);

        let mut neg_elems = Vec::with_capacity(count);
        let mut neg_cur = -start_gen;
        for _ in 0..count {
            neg_elems.push(neg_cur);
            neg_cur *= &group_gen;
        }

        let z_h_vals: Vec<F> = challenges
            .iter()
            .map(|tau| domain.evaluate_vanishing_polynomial(*tau))
            .collect();
        for z in &z_h_vals {
            assert!(!z.is_zero());
        }

        let mut all_lagrange_coeffs = Vec::with_capacity(n);
        for (tau, z_h) in challenges.iter().zip(&z_h_vals) {
            let mut l_i = domain_size;
            let mut coeffs = vec![F::zero(); count];
            for (coeff, neg_elem) in coeffs.iter_mut().zip(&neg_elems) {
                *coeff = l_i * (*tau + *neg_elem);
                l_i *= &group_gen_inv;
            }
            batch_inversion_and_mul(&mut coeffs, &(start_gen * *z_h));
            all_lagrange_coeffs.push(coeffs);
        }

        all_lagrange_coeffs
    }
}
