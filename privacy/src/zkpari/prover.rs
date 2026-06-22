use crate::zkpari::{
    data_structures::{CommittedInputOpening, Proof, ProvingKey},
    range::{evaluate_row, range_assignment, range_relation, Matrix},
    utils::compute_chall,
    ZkPari,
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};
use ark_std::{cfg_iter_mut, rand::RngCore, UniformRand};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

type RowEvaluations<F> = (Vec<F>, Vec<F>, Vec<F>);

impl<E: Pairing> ZkPari<E> {
    /// Produce a range proof, sampling fresh blinding randomness.
    pub fn prove<R: RngCore>(value: u64, pk: &ProvingKey<E>, rng: &mut R) -> Proof<E>
    where
        E::ScalarField: Field,
    {
        let openings: Vec<CommittedInputOpening<E::ScalarField>> = (0..pk.sigma_ci.len())
            .map(|_| CommittedInputOpening::rand(rng))
            .collect();
        Self::prove_with_openings(value, pk, &openings, rng)
    }

    /// Produce a range proof with caller-supplied openings.
    pub fn prove_with_openings<R: RngCore>(
        value: u64,
        pk: &ProvingKey<E>,
        openings: &[CommittedInputOpening<E::ScalarField>],
        rng: &mut R,
    ) -> Proof<E>
    where
        E::ScalarField: Field,
    {
        let relation = range_relation::<E::ScalarField>();
        let assignment = range_assignment::<E::ScalarField>(value);
        let block_indices = relation.committed_witness_indices.clone();

        assert_eq!(
            block_indices, pk.committed_witness_indices,
            "range relation committed inputs differ from the proving key"
        );
        assert_eq!(
            openings.len(),
            block_indices.len(),
            "expected one opening per committed-input block ({}), got {}",
            block_indices.len(),
            openings.len()
        );

        let num_constraints = relation.num_constraints;
        let instance_assignment = &assignment.instance;
        let witness_assignment = &assignment.witness;
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(num_constraints).unwrap();
        let domain_size = domain.size();

        // h(X) = eta_1 + eta_2 X masks the A-side; the blocks' openings mask
        // the B-side as (rho_ci_1 + ... + rho_ci_J) v_K through the
        // committed-input commitments.
        let eta_1 = E::ScalarField::rand(rng);
        let eta_2 = E::ScalarField::rand(rng);
        let rho_ci: E::ScalarField = openings
            .iter()
            .fold(E::ScalarField::zero(), |acc, o| acc + o.rho);

        let (z_a, z_b, w_a) = Self::compute_za_zb_wa(
            domain,
            &relation.a,
            &relation.b,
            instance_assignment,
            witness_assignment,
            num_constraints,
        );

        let z_a_hat = Evaluations::from_vec_and_domain(z_a, domain).interpolate();
        let z_b_hat = Evaluations::from_vec_and_domain(z_b, domain).interpolate();
        let w_a_hat = Evaluations::from_vec_and_domain(w_a, domain).interpolate();

        #[cfg(debug_assertions)]
        let (z_a_hat_check, z_b_hat_check) = (z_a_hat.clone(), z_b_hat.clone());

        let (q_orig, _remainder) =
            (&z_a_hat * &z_a_hat - &z_b_hat).divide_by_vanishing_poly(domain);
        #[cfg(debug_assertions)]
        assert!(_remainder.is_zero(), "constraint system is not satisfied");

        let mut q_coeffs = q_orig.coeffs;
        q_coeffs.resize(domain_size + 3, E::ScalarField::zero());
        let two_eta_1 = eta_1.double();
        let two_eta_2 = eta_2.double();
        for (i, z_i) in z_a_hat.coeffs.iter().enumerate() {
            q_coeffs[i] += two_eta_1 * z_i;
            q_coeffs[i + 1] += two_eta_2 * z_i;
        }
        let eta_1_sq = eta_1.square();
        let eta_cross = (eta_1 * eta_2).double();
        let eta_2_sq = eta_2.square();
        q_coeffs[0] -= eta_1_sq + rho_ci;
        q_coeffs[1] -= eta_cross;
        q_coeffs[2] -= eta_2_sq;
        q_coeffs[domain_size] += eta_1_sq;
        q_coeffs[domain_size + 1] += eta_cross;
        q_coeffs[domain_size + 2] += eta_2_sq;
        let q_tilde = DensePolynomial::from_coefficients_vec(q_coeffs);

        #[cfg(debug_assertions)]
        {
            let mask_poly =
                |poly: &DensePolynomial<E::ScalarField>, c0: E::ScalarField, c1: E::ScalarField| {
                    let mut coeffs = poly.coeffs.clone();
                    coeffs.resize(coeffs.len().max(domain_size + 2), E::ScalarField::zero());
                    coeffs[0] -= c0;
                    coeffs[1] -= c1;
                    coeffs[domain_size] += c0;
                    coeffs[domain_size + 1] += c1;
                    DensePolynomial::from_coefficients_vec(coeffs)
                };
            let z_a_masked = mask_poly(&z_a_hat_check, eta_1, eta_2);
            let z_b_masked = mask_poly(&z_b_hat_check, rho_ci, E::ScalarField::zero());
            let (q_check, rem) =
                (&z_a_masked * &z_a_masked - &z_b_masked).divide_by_vanishing_poly(domain);
            assert!(rem.is_zero());
            assert_eq!(q_tilde, q_check, "expanded quotient mismatch");
        }

        #[cfg(debug_assertions)]
        let x_a_poly_check = &z_a_hat - &w_a_hat;
        let w_a_masked = {
            let mut coeffs = w_a_hat.coeffs;
            coeffs.resize(coeffs.len().max(domain_size + 2), E::ScalarField::zero());
            coeffs[0] -= eta_1;
            coeffs[1] -= eta_2;
            coeffs[domain_size] += eta_1;
            coeffs[domain_size + 1] += eta_2;
            DensePolynomial::from_coefficients_vec(coeffs)
        };

        let mut c_cis = Vec::with_capacity(block_indices.len());
        for ((block, sigma_ci_j), (gamma_ci_j, opening)) in block_indices
            .iter()
            .zip(&pk.sigma_ci)
            .zip(pk.gamma_ci.iter().zip(openings))
        {
            let block_values: Vec<E::ScalarField> =
                block.iter().map(|&w| witness_assignment[w]).collect();
            let c_ci_j: E::G1Affine = (E::G1::msm_unchecked(sigma_ci_j, &block_values)
                + *gamma_ci_j * opening.rho)
                .into();
            c_cis.push(c_ci_j);
        }

        let mut is_committed = vec![false; witness_assignment.len()];
        for block in &block_indices {
            for &w in block {
                is_committed[w] = true;
            }
        }
        let ordinary_witnesses: Vec<E::ScalarField> = witness_assignment
            .iter()
            .zip(&is_committed)
            .filter(|(_, committed)| !**committed)
            .map(|(value, _)| *value)
            .collect();
        debug_assert_eq!(ordinary_witnesses.len(), pk.sigma_w.len());

        let t_w = E::G1::msm_unchecked(&pk.sigma_w, &ordinary_witnesses);
        let t_mask = E::G1::msm_unchecked(
            &[pk.sigma_mask_const, pk.sigma_mask_linear],
            &[eta_1, eta_2],
        );
        let t_q = E::G1::msm_unchecked(&pk.sigma_q_comm[..q_tilde.coeffs.len()], &q_tilde.coeffs);
        let t: E::G1Affine = (t_w + t_mask + t_q).into();

        let challenge =
            compute_chall::<E>(&pk.verifying_key, &instance_assignment[1..], &c_cis, &t);
        let v_a = w_a_masked.evaluate(&challenge);

        let mut r_coeffs = z_b_hat.coeffs;
        r_coeffs.resize(
            (domain_size + 1).max(q_tilde.coeffs.len() + domain_size),
            E::ScalarField::zero(),
        );
        r_coeffs[0] -= rho_ci;
        r_coeffs[domain_size] += rho_ci;
        for (i, q_i) in q_tilde.coeffs.iter().enumerate() {
            r_coeffs[i] -= q_i;
            r_coeffs[i + domain_size] += q_i;
        }
        let r_poly = DensePolynomial::from_coefficients_vec(r_coeffs);

        let v_r = r_poly.evaluate(&challenge);
        #[cfg(debug_assertions)]
        {
            let x_a_at_r = x_a_poly_check.evaluate(&challenge);
            assert_eq!(
                v_r,
                (v_a + x_a_at_r).square(),
                "v_R must equal (v_a + x_A(r))^2"
            );
        }

        let one = E::ScalarField::ONE;
        let chall_vanishing_poly = DensePolynomial::from_coefficients_vec(vec![-challenge, one]);
        let v_a_poly = DensePolynomial::from_coefficients_vec(vec![v_a]);
        let v_r_poly = DensePolynomial::from_coefficients_vec(vec![v_r]);
        let witness_a = (&w_a_masked - &v_a_poly) / &chall_vanishing_poly;
        let witness_r = (&r_poly - &v_r_poly) / &chall_vanishing_poly;

        debug_assert!(witness_a.coeffs.len() <= pk.sigma_a.len());
        debug_assert!(witness_r.coeffs.len() <= pk.sigma_r.len());
        let w_a_proof =
            E::G1::msm_unchecked(&pk.sigma_a[..witness_a.coeffs.len()], &witness_a.coeffs);
        let w_r_proof =
            E::G1::msm_unchecked(&pk.sigma_r[..witness_r.coeffs.len()], &witness_r.coeffs);
        let u: E::G1Affine = (w_a_proof + w_r_proof).into();

        Proof {
            c_ci: c_cis,
            t_g: t,
            u_g: u,
            v_a,
        }
    }

    /// Evaluate the SR1CS rows once over the full assignment, returning
    /// `(z_A, z_B, w_A)`.
    pub(crate) fn compute_za_zb_wa(
        domain: GeneralEvaluationDomain<E::ScalarField>,
        a_mat: &Matrix<E::ScalarField>,
        b_mat: &Matrix<E::ScalarField>,
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
        num_constraints: usize,
    ) -> RowEvaluations<E::ScalarField> {
        let mut assignment = instance_assignment.to_vec();
        assignment.extend_from_slice(witness_assignment);

        let domain_size = domain.size();
        let mut z_a = vec![E::ScalarField::zero(); domain_size];
        let mut z_b = vec![E::ScalarField::zero(); domain_size];

        cfg_iter_mut!(z_a[..num_constraints])
            .zip(&mut z_b[..num_constraints])
            .zip(a_mat)
            .zip(b_mat)
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_row(at_i, &assignment);
                *b = evaluate_row(bt_i, &assignment);
            });

        let instance_len = instance_assignment.len();
        let outline_start = num_constraints - instance_len;
        let mut w_a = z_a.clone();
        for (i, x_i) in instance_assignment.iter().enumerate() {
            w_a[outline_start + i] -= x_i;
        }

        #[cfg(debug_assertions)]
        {
            let mut punctured_assignment = vec![E::ScalarField::zero(); instance_len];
            punctured_assignment.extend_from_slice(witness_assignment);
            for (row, (at_i, bt_i)) in a_mat.iter().zip(b_mat).enumerate() {
                let w_a_row = evaluate_row(at_i, &punctured_assignment);
                let w_b_row = evaluate_row(bt_i, &punctured_assignment);
                assert_eq!(w_a_row, w_a[row], "instance column outside outlining rows");
                assert_eq!(w_b_row, z_b[row], "instance column in the B matrix");
            }
        }

        (z_a, z_b, w_a)
    }
}
