//! Honest-verifier zero-knowledge simulator (Theorem 1).
//!
//! Given the setup [`Trapdoor`], the simulator produces an accepting transcript
//! `(C_ci, T, U, v_a)` for any committed-input commitment `C_ci` *without a
//! witness*. The output is statistically indistinguishable from an honest
//! proof (distance at most `1/(|F| - |K|)`), yet costs only a handful of group
//! operations instead of full circuit synthesis and the prover MSMs.
//!
//! In the non-interactive (Fiat-Shamir) setting the simulator works because the
//! first message `T` is independent of the challenge: the simulator forms `T`
//! from a uniform `y`, derives `r = FS(vk, x, C_ci, T)` exactly as the verifier
//! does, and then solves the single pairing equation for the unique opening
//! `U`. The result passes [`ZkPari::verify`] unchanged.
//!
//! This is **not** a prover: a simulated transcript attests nothing about the
//! committed values (it has no witness, so the "range" is vacuous). It is kept
//! for zero-knowledge tests and requires the trapdoor, which an honest
//! deployment destroys.

use crate::zkpari::{
    data_structures::{Proof, Trapdoor, VerifyingKey},
    utils::compute_chall,
    ZkPari,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_std::{rand::RngCore, UniformRand};

impl<E: Pairing> ZkPari<E> {
    /// Simulates an accepting proof for the committed-input commitments
    /// `c_ci` (one per block) under `public_input`, using the setup
    /// `trapdoor`.
    ///
    /// The returned [`Proof`] verifies against `vk` with these exact `c_ci`.
    /// It carries no witness and proves no statement about the committed
    /// values; see the module documentation.
    ///
    /// # Panics
    ///
    /// Panics if `c_ci.len()` does not match the number of committed-input
    /// blocks, or in the astronomically unlikely event that the Fiat-Shamir
    /// challenge equals the trapdoor `tau`.
    pub fn simulate(
        trapdoor: &Trapdoor<E>,
        vk: &VerifyingKey<E>,
        c_ci: &[E::G1Affine],
        public_input: &[E::ScalarField],
        rng: &mut impl RngCore,
    ) -> Proof<E> {
        Self::simulate_inner(trapdoor, vk, c_ci, public_input, rng)
    }

    fn simulate_inner(
        trapdoor: &Trapdoor<E>,
        vk: &VerifyingKey<E>,
        c_ci: &[E::G1Affine],
        public_input: &[E::ScalarField],
        rng: &mut impl RngCore,
    ) -> Proof<E> {
        assert_eq!(
            c_ci.len(),
            trapdoor.deltas.len(),
            "one committed-input commitment per block"
        );
        assert_eq!(
            public_input.len(),
            vk.succinct_index.instance_len - 1,
            "public input length must match the instance"
        );

        let delta_w_inv = trapdoor
            .delta_w
            .inverse()
            .expect("delta_w is a nonzero trapdoor scalar");

        // Instance contributions at tau: x_hat_A(tau), x_hat_B(tau), over the
        // public assignment x = (1, public_input...).
        let px = core::iter::once(E::ScalarField::ONE).chain(public_input.iter().copied());
        let (x_hat_a_tau, x_hat_b_tau) = px.enumerate().fold(
            (E::ScalarField::zero(), E::ScalarField::zero()),
            |(acc_a, acc_b), (i, x)| {
                (
                    acc_a + x * trapdoor.instance_a_at_tau[i],
                    acc_b + x * trapdoor.instance_b_at_tau[i],
                )
            },
        );

        // First message: T = [(alpha (y - x_hat_A(tau)) + beta (y^2 - x_hat_B(tau))) / delta_w] G
        //                    - sum_j (delta_j / delta_w) C_ci_j.
        // `y` stands in for the honest z_A(tau); `v_a` stands in for z_A(r) - x_A(r).
        let y = E::ScalarField::rand(rng);
        let v_a = E::ScalarField::rand(rng);

        let t_coeff = (trapdoor.alpha * (y - x_hat_a_tau)
            + trapdoor.beta * (y.square() - x_hat_b_tau))
            * delta_w_inv;
        let mut t_proj = vk.g.into_group() * t_coeff;
        for (commitment, delta_j) in c_ci.iter().zip(&trapdoor.deltas) {
            t_proj -= commitment.into_group() * (*delta_j * delta_w_inv);
        }
        let t_g = t_proj.into_affine();

        // Challenge: identical Fiat-Shamir derivation to the verifier. T does
        // not depend on r, so deriving r here is consistent.
        let r = compute_chall::<E>(vk, public_input, c_ci, &t_g);
        assert_ne!(
            r, trapdoor.tau,
            "Fiat-Shamir challenge collided with the trapdoor tau"
        );

        // v_R = (v_a + x_A(r))^2 - x_B(r), with x_B(r) = 0 after outlining.
        let x_a_r = Self::instance_eval_a_at(vk, public_input, r);
        let v_r = (v_a + x_a_r).square();

        // Solve the verification equation for the unique accepting U:
        //   U = [ sum_j delta_j C_ci_j + delta_w T - (alpha v_a + beta v_R) G ] / (tau - r).
        let inv = (trapdoor.tau - r)
            .inverse()
            .expect("tau - r is nonzero (checked above)");
        let mut u_proj = t_g.into_group() * (trapdoor.delta_w * inv);
        for (commitment, delta_j) in c_ci.iter().zip(&trapdoor.deltas) {
            u_proj += commitment.into_group() * (*delta_j * inv);
        }
        u_proj -= vk.g.into_group() * ((trapdoor.alpha * v_a + trapdoor.beta * v_r) * inv);
        let u_g = u_proj.into_affine();

        Proof {
            c_ci: c_ci.to_vec(),
            t_g,
            u_g,
            v_a,
        }
    }

    /// Computes the instance contribution `x_A(r) = sum_i x_i a_i(r)` to the
    /// A-side polynomial at `r`, using the same last-Lagrange evaluation the
    /// verifier uses.
    fn instance_eval_a_at(
        vk: &VerifyingKey<E>,
        public_input: &[E::ScalarField],
        r: E::ScalarField,
    ) -> E::ScalarField {
        let instance_size = vk.succinct_index.instance_len;
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - instance_size;
        let lagrange_coeffs = Self::eval_last_lagrange_coeffs::<E::ScalarField>(
            &vk.domain,
            r,
            r1cs_orig_num_cnstrs,
            instance_size,
        );
        let px = core::iter::once(E::ScalarField::ONE).chain(public_input.iter().copied());
        lagrange_coeffs
            .into_iter()
            .zip(px)
            .fold(E::ScalarField::zero(), |acc, (coeff, x)| acc + coeff * x)
    }
}
