use crate::zkpari::{
    data_structures::{Proof, VerifyingKey},
    utils::{batch_inversion_and_mul, msm_bigint_wnaf},
    ZkPari,
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{
    ops::Neg,
    rand::{rngs::StdRng, RngCore, SeedableRng},
};
use commonware_parallel::Strategy;

struct BatchAccumulator<E: Pairing> {
    c_tildes: Vec<E::G1>,
    t_tilde: E::G1,
    u_tilde: E::G1,
    v_tilde: E::G1,
    v_a_tilde: E::ScalarField,
    v_r_tilde: E::ScalarField,
}

impl<E: Pairing> BatchAccumulator<E> {
    fn zero(num_blocks: usize) -> Self {
        Self {
            c_tildes: vec![E::G1::zero(); num_blocks],
            t_tilde: E::G1::zero(),
            u_tilde: E::G1::zero(),
            v_tilde: E::G1::zero(),
            v_a_tilde: E::ScalarField::zero(),
            v_r_tilde: E::ScalarField::zero(),
        }
    }

    fn combine(&mut self, other: Self) {
        for (lhs, rhs) in self.c_tildes.iter_mut().zip(other.c_tildes) {
            *lhs += rhs;
        }
        self.t_tilde += other.t_tilde;
        self.u_tilde += other.u_tilde;
        self.v_tilde += other.v_tilde;
        self.v_a_tilde += other.v_a_tilde;
        self.v_r_tilde += other.v_r_tilde;
    }
}

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
        Self::batch_verify_inner(proofs_and_inputs, vk, rng)
    }

    /// Batch verification using a caller-provided parallel execution strategy.
    ///
    /// The proof list is split into roughly equal contiguous chunks based on
    /// [`Strategy::parallelism_hint`]. Each worker accumulates one chunk, the
    /// partial accumulators are reduced, and the final pairing is performed once.
    pub fn batch_verify_with_strategy(
        strategy: &impl Strategy,
        proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
        vk: &VerifyingKey<E>,
        rng: &mut impl RngCore,
    ) -> bool
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
        E::ScalarField: Send + Sync,
        E::G1Affine: Send + Sync,
        E::G2Affine: Send + Sync,
        E::G2Prepared: Send + Sync,
    {
        let n = proofs_and_inputs.len();
        if n <= 1 {
            return Self::batch_verify_inner(proofs_and_inputs, vk, rng);
        }

        let chunks = strategy.parallelism_hint().max(1).min(n);
        if chunks == 1 {
            return Self::batch_verify_inner(proofs_and_inputs, vk, rng);
        }

        let base = n / chunks;
        let extra = n % chunks;
        let mut start = 0;
        let mut ranges = Vec::with_capacity(chunks);
        for chunk in 0..chunks {
            let len = base + usize::from(chunk < extra);
            let end = start + len;
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            ranges.push((start, end, seed));
            start = end;
        }

        let accumulators = strategy.map_collect_vec(ranges, |(start, end, seed)| {
            let mut rng = StdRng::from_seed(seed);
            Self::batch_accumulate(&proofs_and_inputs[start..end], vk, &mut rng)
        });

        let num_blocks = vk.delta_h_prep.len();
        let mut accumulator = BatchAccumulator::zero(num_blocks);
        for partial in accumulators {
            let Some(partial) = partial else {
                return false;
            };
            accumulator.combine(partial);
        }

        Self::finish_batch_accumulation(accumulator, vk)
    }

    fn batch_accumulate(
        proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
        vk: &VerifyingKey<E>,
        rng: &mut impl RngCore,
    ) -> Option<BatchAccumulator<E>>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let n = proofs_and_inputs.len();
        let num_blocks = vk.delta_h_prep.len();
        let instance_len = vk.succinct_index.instance_len;
        if proofs_and_inputs.iter().any(|(proof, public_input)| {
            proof.c_ci.len() != num_blocks || public_input.len() != instance_len - 1
        }) {
            return None;
        }
        if n == 0 {
            return Some(BatchAccumulator::zero(num_blocks));
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

        let rhos: Vec<E::ScalarField> = (0..n)
            .map(|_| {
                let mut bytes = [0u8; 16];
                rng.fill_bytes(&mut bytes);
                E::ScalarField::from_le_bytes_mod_order(&bytes)
            })
            .collect();

        let t_bases: Vec<E::G1Affine> = proofs_and_inputs
            .iter()
            .map(|(proof, _)| proof.t_g)
            .collect();
        let u_bases: Vec<E::G1Affine> = proofs_and_inputs
            .iter()
            .map(|(proof, _)| proof.u_g)
            .collect();

        let c_tildes = (0..num_blocks)
            .map(|block| {
                let c_bases: Vec<E::G1Affine> = proofs_and_inputs
                    .iter()
                    .map(|(proof, _)| proof.c_ci[block])
                    .collect();
                <E::G1 as VariableBaseMSM>::msm_unchecked(&c_bases, &rhos)
            })
            .collect();
        let t_tilde = <E::G1 as VariableBaseMSM>::msm_unchecked(&t_bases, &rhos);
        let u_tilde = <E::G1 as VariableBaseMSM>::msm_unchecked(&u_bases, &rhos);

        let rho_r: Vec<E::ScalarField> = rhos
            .iter()
            .zip(&challenges)
            .map(|(rho, r)| *rho * *r)
            .collect();
        let v_tilde = <E::G1 as VariableBaseMSM>::msm_unchecked(&u_bases, &rho_r);

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

        Some(BatchAccumulator {
            c_tildes,
            t_tilde,
            u_tilde,
            v_tilde,
            v_a_tilde,
            v_r_tilde,
        })
    }

    fn finish_batch_accumulation(accumulator: BatchAccumulator<E>, vk: &VerifyingKey<E>) -> bool
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let v_tilde: E::G1Affine = accumulator.v_tilde.into();
        let last_left: E::G1Affine = msm_bigint_wnaf::<E::G1>(
            &[v_tilde, -vk.alpha_g, -vk.beta_g],
            &[
                E::ScalarField::ONE.into(),
                accumulator.v_a_tilde.into(),
                accumulator.v_r_tilde.into(),
            ],
        )
        .into();

        let mut g1_terms = accumulator
            .c_tildes
            .into_iter()
            .map(Into::into)
            .collect::<Vec<E::G1Affine>>();
        let t_tilde: E::G1Affine = accumulator.t_tilde.into();
        let u_tilde: E::G1Affine = accumulator.u_tilde.into();
        g1_terms.extend([t_tilde, -u_tilde, last_left]);
        let mut g2_terms = vk.delta_h_prep.clone();
        g2_terms.extend([
            vk.delta_w_h_prep.clone(),
            vk.tau_h_prep.clone(),
            vk.h_prep.clone(),
        ]);

        E::multi_pairing(g1_terms, g2_terms).is_zero()
    }

    fn batch_verify_inner(
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

        let Some(accumulator) = Self::batch_accumulate(proofs_and_inputs, vk, rng) else {
            return false;
        };
        Self::finish_batch_accumulation(accumulator, vk)
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
