use super::ipa;
use crate::transcript::Transcript;
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, Write};
use commonware_math::{
    algebra::{powers, Additive, CryptoGroup, Field, Random, Ring, Space},
    tangle::{Tangle, TangleIdx},
};
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    ops::{Index, IndexMut},
};

pub struct SparseMatrix<F> {
    width: usize,
    height: usize,
    weights: BTreeMap<(usize, usize), F>,
    /// This exists so that we can return a reference when indexing.
    zero: F,
}

impl<F> SparseMatrix<F> {
    /// The width of this matrix.
    ///
    /// This is determined solely by the highest column with a non-zero entry.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// The height of this matrix.
    ///
    /// This is determined solely by the highest row with a non-zero entry.
    pub const fn height(&self) -> usize {
        self.height
    }
}

impl<F: Additive> Default for SparseMatrix<F> {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            weights: Default::default(),
            zero: F::zero(),
        }
    }
}

impl<F: Additive> Index<(usize, usize)> for SparseMatrix<F> {
    type Output = F;

    fn index(&self, idx: (usize, usize)) -> &Self::Output {
        self.weights.get(&idx).unwrap_or(&self.zero)
    }
}

impl<F: Additive> IndexMut<(usize, usize)> for SparseMatrix<F> {
    fn index_mut(&mut self, idx: (usize, usize)) -> &mut Self::Output {
        self.height = self
            .height
            .max(idx.0.checked_add(1).expect("row index overflow"));
        self.width = self
            .width
            .max(idx.1.checked_add(1).expect("column index overflow"));
        self.weights.entry(idx).or_insert(F::zero())
    }
}

impl<F: Write> Write for SparseMatrix<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.weights.write(buf);
    }
}

impl<F: EncodeSize> EncodeSize for SparseMatrix<F> {
    fn encode_size(&self) -> usize {
        self.weights.encode_size()
    }
}

pub struct Circuit<F> {
    committed_vars: usize,
    internal_vars: usize,
    weights: SparseMatrix<F>,
}

impl<F: Write> Write for Circuit<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.committed_vars.write(buf);
        self.weights.write(buf);
    }
}

impl<F: Encode> Circuit<F> {
    fn commit(&self, transcript: &mut Transcript) {
        transcript.commit(self.encode());
    }
}

impl<F: EncodeSize> EncodeSize for Circuit<F> {
    fn encode_size(&self) -> usize {
        self.committed_vars.encode_size() + self.weights.encode_size()
    }
}

impl<F: Ring> Circuit<F> {
    pub fn new(committed_vars: usize, weights: SparseMatrix<F>) -> Option<Self> {
        let remaining_vars = weights.width.checked_sub(committed_vars.checked_add(1)?)?;
        if remaining_vars % 3 != 0 {
            return None;
        }
        let internal_vars = remaining_vars / 3;
        Some(Self {
            committed_vars,
            internal_vars,
            weights,
        })
    }
    /// Checks whether a certain assignment to committed variables satisfies this circuit.
    ///
    /// This will return false is the assignment has the wrong length (rather than
    /// implicitly truncating or padding the assignment).
    #[must_use]
    pub fn is_satisfied(
        &self,
        committed_values: &[F],
        left_values: &[F],
        right_values: &[F],
    ) -> bool {
        if committed_values.len() != self.committed_vars
            || left_values.len() != self.internal_vars
            || right_values.len() != self.internal_vars
        {
            return false;
        }
        let mut output = Vec::with_capacity(1 + self.committed_vars + 3 * self.internal_vars);
        output.push(F::one());
        output.extend_from_slice(committed_values);
        output.extend_from_slice(left_values);
        output.extend_from_slice(right_values);
        output.extend(
            left_values
                .iter()
                .zip(right_values)
                .map(|(l_i, r_i)| l_i.clone() * r_i),
        );
        let mut res = vec![F::zero(); self.weights.height];
        for (&(i, j), w_ij) in &self.weights.weights {
            res[i] += &(output[j].clone() * w_ij);
        }
        let zero = F::zero();
        res.iter().all(|r_i| r_i == &zero)
    }
}

pub struct Setup<G> {
    ipa: ipa::Setup<G>,
    pedersen_value: G,
    pedersen_blinding: G,
}

impl<G> Setup<G> {
    pub fn tangle_points<F>(
        &self,
        log_len: u8,
    ) -> impl Iterator<Item = (TangleIdx, G)> + use<'_, F, G>
    where
        F: Additive,
        G: Space<F>,
    {
        self.ipa.tangle_points(log_len).chain([
            ((3, 0), self.pedersen_value.clone()),
            ((3, 1), self.pedersen_blinding.clone()),
        ])
    }
}

impl<G: Write> Write for Setup<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.ipa.write(buf);
        self.pedersen_value.write(buf);
        self.pedersen_blinding.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Setup<G> {
    fn encode_size(&self) -> usize {
        self.ipa.encode_size()
            + self.pedersen_value.encode_size()
            + self.pedersen_blinding.encode_size()
    }
}

#[allow(dead_code)]
pub struct Witness<F> {
    values: Vec<F>,
    blinding: Vec<F>,
    left: Vec<F>,
    right: Vec<F>,
    out: Vec<F>,
}

pub struct Claim<G> {
    commitments: Vec<G>,
}

impl<G: Write> Write for Claim<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitments.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Claim<G> {
    fn encode_size(&self) -> usize {
        self.commitments.encode_size()
    }
}

#[allow(dead_code)]
pub struct Proof<F, G> {
    m_big: G,
    o_big: G,
    m_big_tilde: G,
    t_big: [G; 5],
    s_tilde: F,
    t_x: F,
    t_tilde_x: F,
    p_big: G,
    ipa_proof: ipa::Proof<F, G>,
}

pub fn prove<F: Field + Encode + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<G>,
    circuit: &Circuit<F>,
    claim: &Claim<G>,
    witness: &Witness<F>,
    strategy: &impl Strategy,
) -> Option<Proof<F, G>> {
    // To set the stage, we're trying to convince the verifier that:
    //
    //   - we know v_i, ~v_i, l_i, r_i, o_i such that...
    //   - v_i B + ~v_i ~B = V_i,
    //   - l_i r_i = o_i,
    //   - c_i + <Θ_ij, v_j> + <Λ_ij, l_j> + <Ρ_ij, r_j> + <Ω_ij, o_j> = 0.
    //
    // Before we get back any challenges from the verifier, we need to commit to
    // the circuit, our claim, and the internal variables we're using. We create a commitment:
    //
    //   M := <l_i, G_i> + <r_i, H_i> + m ~B
    //   O := <o_i, G_i> + ~o ~B
    //
    // we'll also be introducing some blinding factors ~l_i, ~r_i later, and we need
    // to commit to these now as well:
    //
    //   ~M := <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // After sending all of these to the verifier, we get:
    // y, and z, which we use to reduce the constraints to:
    //
    //   <y^i, l_i r_i - o_i> +
    //   <z z^i, c_i + <Θ_ij, v_j> + <Λ_ij, l_j> + <Ρ_ij, r_j> + <Ω_ij, o_j>> = 0
    //
    // (By y^i, we mean a vector whose ith entry is y to the power of i. For small fields,
    // generating more challenges is needed instead, but for large fields, using powers lets us
    // sample less randomness.)
    //
    // At this point, it's convenient to fold these challenges into the weights:
    //
    //   θ_j := <Θ_ij, z z^i>
    //   λ_j := <Λ_ij, z z^i>
    //   ρ_j := <Ρ_ij, z z^i>
    //   ω_j := <Ω_ij, z z^i>
    //   κ := <c_i, z z^i>
    //
    // giving us:
    //
    //   <y^i, l_i r_i - o_i> + κ + <θ_i, v_i> + <λ_i, l_i> + <ρ_i, r_i> + <ω_i, o_i> = 0
    //
    // It's useful to have the terms concerning the committed variables on one side,
    // and the internal variables on the other:
    //
    //   -κ - <θ_i, v_i> = <y^i, l_i r_i - o_i> + <λ_i, l_i> + <ρ_i, r_i> + <ω_i, o_i>
    //
    // next, merge the terms with o_i:
    //
    //  ... = <y^i, l_i r_i> + ... + <ω_i - y^i, o_i>
    //
    // next, we can move one part of the l_i r_i term to the other side:
    //
    //   ... = <y^i r_i, l_i> + ...
    //
    // then, we can create another y^i r_i term:
    //
    //   ... = ... + <y^-i ρ_i, y^i r_i> + ...
    //
    // merging these terms we get:
    //
    //   -κ - <θ_i, v_i> = <l_i + y^-i ρ_i, y^i r_i> + <λ_i, l_i> + <ω_i - y^i, o_i>
    //
    // if we define:
    //
    //   δ(y, z) := <y^-i ρ_i, λ_i>
    //
    // we can add this to both sides, and merge the λ_i terms, giving us:
    //
    //  -κ - <θ_i, v_i> + δ(y, z) =
    //  <l_i + y^-i ρ_i, y^i r_i> + <l_i + y^-i ρ_i, λ_i> + <ω_i - y^i, o_i> =
    //  <l_i + y^-i ρ_i, y^i r_i + λ_i> + <ω_i - y^i, o_i>
    //
    // Now, we deploy a trick, in order to turn a statement about a sum:
    //
    //   <a_i, b_i> + <c_i, d_i>
    //
    // into a single inner product. The trick is that if we create polynomials:
    //
    //   f_i(X) := a_i X + c_i X^2
    //   g_i(X) := b_i X + d_i
    //
    // then the 2nd degree of <f_i(X), g_i(X)> is <a_i, b_i> + <c_i, d_i>.
    //
    // So, we can check that:
    //
    //   t X^2 = <f_i(X), g_i(X)>
    //
    // as polynomials. To check equality of polynomials, we can commit to them,
    // and then have the verifier send us a random evaluation point.
    //
    // Let's apply that to our situation.
    //
    //   f_i(X) := (l_i + y^-i ρ_i) X + o_i X^2
    //   g_i(X) := (y^i r_i + λ_i) X + (ω_i - y^i)
    //   t(X) := <f_i(X), g_i(X)>
    //   deg2(t(X)) = -κ - <θ_i, v_i> + δ(y, z)
    //
    // Our goal at this point is to convince the verifier that:
    //
    //   - deg2(t(X)) = -κ - <θ_i, v_i> + δ(y, z),
    //   - f_i(X) and g_i(X) are correctly constructed,
    //   - t(X) = <f_i(X), g_i(X)>.
    //
    // We want to make sure that our proof is still zero-knowledge, so we can't just
    // send a commitment to the polynomial as is, because it leaks information about
    // the l_i, r_i, and o_i values. To get around this, we introduce blinding factors
    // ~l_i, ~r_i:
    //
    //   f_i(X) := ((l_i + ~l_i X^2) + y^-i ρ_i) X + o_i X^2
    //   g_i(X) := (y^i (r_i + ~r_i X^2) + λ_i) X + (ω_i - y^i)
    //
    // we use a factor of X^2 so that this blinding doesn't interfere with the
    // second degree of <f_i(X), g_i(X)>. When the verifier sees f_i(x) and g_i(x)
    // for a random challenge point, they will have a masking factor of ~l_i x^3
    // (respectively, y^i ~r_i x^3), hiding things completely.
    //
    // Expanding this out, we get:
    //
    //   t(X) := <f_i(X), g_i(X)> =
    //   <l_i + y^-i ρ_i, ω_i - y^i> X +
    //   (<l_i + y^-i ρ_i, y^i r_i + λ_i> + <o_i, ω_i - y^i>) X^2 +
    //   (<~l_i, ω_i - y^i> + <o_i, y^i r_i + λ_i>) X^3 +
    //   (<~l_i, y^i r_i + λ_i> + <l_i + y^-i ρ_i, y^i ~r_i>) X^4 +
    //   <o_i, y^i ~r_i> X^5 +
    //   <~l_i, y^i ~r_i> X^6
    //
    // thus, we can create commitments T_1, T_3, T_4, T_5, T_6 to these elements,
    // (skipping the X^2 factor), using blinding factors ~t_i.
    //
    // Then, for a random challenge, x, the verifier can check that the second degree is correct:
    //
    //  t(x) B + ~t(x) ~B =?
    //  (-κ + δ(y, z)) x^2 B - x^2 <θ_i, V_i> + Σ_{i != 2} x^i T_i
    //
    // for ~t(x), we use the synthetic blinding factors ~t_i for x^1, x^3, ...
    // and for x^2, we use -<θ_i, ~v_i>, so that the equation above works.
    //
    // The right hand side is checking the second degree in the exponent, behind
    // the Pedersen commitments, and the left hand side is our opening of the polynomial,
    // at a random point.
    //
    // Before getting this challenge, we also want to provide the necessary commitments
    // to f_i(X) and g_i(X) as well, so that those can be checked.
    //
    // Eventually, we want to prove the inner product <f_i(x), g_i(x)>, and the IPA
    // protocol expects to see <f_i(x), G_i> + <g_i(x), H_i>. Expanding that, out,
    // using the indeterminate X (rather than the challenge x), we get:
    //
    //   <f_i(X), G_i> = <l_i + y^-i ρ_i, G_i> X + <o_i, G_i> X^2 + <~l_i, G_i> X^3
    //   <g_i(X), H_i> = <ω_i - y^i, H_i> + <y^i r_i + λ_i, H_i> X + <y^i ~r_i, H_i> X^3
    //
    // The natural commitments involve grouping things by coefficient, and by public
    // vs secret values:
    //
    //   P_0 := <ω_i - y^i, H_i>
    //   P_1 := <y^-i ρ_i, G_i> + <λ_i, H_i>
    //   S_1 := <l_i, G_i> + <y^i r_i, H_i>
    //   S_2 := <o_i, G_i>
    //   S_3 := <~l_i, G_i> + <y^i ~r_i, H_i>
    //
    // Recall that we've already sent the verifier:
    //
    //   M := <l_i, G_i> + <r_i, H_i> + m ~B
    //   O := <o_i, G_i> + ~o ~B
    //  ~M := <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // It seems like we're stuck here, because <r_i, H_i> doesn't match the <y^i r_i, H_i>
    // that we need inside of S_1. However, the IPA already lets us treat the right-side
    // basis as y^-i H_i by setting claim.y = y^-1. In terms of the original H_i that this
    // implementation uses in its MSMs, the public pieces become:
    //
    //   P_0 = <y^-i ω_i - 1, H_i>
    //   P_1 = <y^-i ρ_i, G_i> + <y^-i λ_i, H_i>
    //   M   = <l_i, G_i> + <r_i, H_i> + m ~B
    //   O   = <o_i, G_i> + ~o ~B
    //  ~M   = <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // but, the bottom three are equal to:
    //
    //   M = S_1 +  m ~B
    //   O = S_2 + ~o ~B
    //  ~M = S_3 + ~m ~B
    //
    // Thus, we can reveal ~s := x m + x^2 ~o + x^3 ~m, and have the verifier calculate
    //
    //   P := -~s ~B + P_0 + x (P_1 + M) + x^2 O + x^3 ~M
    //      = <f_i(x), G_i> + <g_i(x), y^-i H_i>
    //
    // (Rather than the verifier calculating this, the prover can provide it, and the verifier
    // can check this equation. This turns it into an MSM check, which can be more efficiently
    // batched with other such checks).
    //
    // Finally, we run the IPA protocol, using t(x) as the claimed inner product,
    // and P as the commitment to the vectors, and G_i, H'_i as the generators
    // for this commitment.
    //
    // Concretely, we reuse the ordinary IPA setup and set ipa_claim.y = y^-1.
    // This keeps the right-side basis change inside the IPA, while the public MSM
    // checks above stay written against the original H_i.
    //
    // # Padding
    //
    // The IPA protocol requires the input vectors to be padded to a power of 2.
    // To do this, we'll pad the l_i, r_i, ~l_i, ~r_i with 0s. This forces the
    // o_i to be padded with 0 as well. In order to explicitly not consider these
    // values, we make sure that the weights are padded with columns of 0s.
    // Because we compress the weight matrices into vectors by taking a combination
    // of rows, we can pad the resulting vectors with 0s.
    //
    // Looking at t(X), the value doesn't change with the padding, because we always
    // have a zero value on one side of each inner product for the new indices.
    //
    // P_0 on the other hand, will end up with some extra -1 values we'll have
    // to take into account. Because this is the only changed value, we can handle
    // this one as a special case.
    //
    // Now, let's write some Rust.
    //
    // First, let's commit to our internal variables, and to our masks:
    let l_tilde = (0..circuit.internal_vars)
        .map(|_| F::random(&mut *rng))
        .collect::<Vec<_>>();
    let r_tilde = (0..circuit.internal_vars)
        .map(|_| F::random(&mut *rng))
        .collect::<Vec<_>>();
    let m = F::random(&mut *rng);
    let o_tilde = F::random(&mut *rng);
    let m_tilde = F::random(&mut *rng);
    let g_internal = &setup.ipa.g()[..circuit.internal_vars];
    let h_internal = &setup.ipa.h()[..circuit.internal_vars];
    let m_big = G::msm(g_internal, &witness.left, strategy)
        + &G::msm(h_internal, &witness.right, strategy)
        + &(setup.pedersen_blinding.clone() * &m);
    let o_big =
        G::msm(g_internal, &witness.out, strategy) + &(setup.pedersen_blinding.clone() * &o_tilde);
    let m_big_tilde = G::msm(g_internal, &l_tilde, strategy)
        + &G::msm(h_internal, &r_tilde, strategy)
        + &(setup.pedersen_blinding.clone() * &m_tilde);
    // Now, commit to all the this information.
    circuit.commit(transcript);
    transcript.commit(claim.encode());
    transcript.commit(m_big.encode());
    transcript.commit(o_big.encode());
    transcript.commit(m_big_tilde.encode());
    let padded_vars = circuit.internal_vars.next_power_of_two();
    let y = F::random(transcript.noise(b"y"));
    let y_powers = powers(F::one(), &y).take(padded_vars).collect::<Vec<_>>();
    let y_inv = y.inv();
    let y_inv_powers = powers(F::one(), &y_inv)
        .take(padded_vars)
        .collect::<Vec<_>>();
    let z = F::random(transcript.noise(b"z"));
    let z_powers = powers(z.clone(), &z)
        .take(circuit.weights.height())
        .collect::<Vec<_>>();
    let (kappa, theta, lambda, rho, omega) = {
        let mut kappa = F::zero();
        let mut theta = vec![F::zero(); circuit.committed_vars];
        let mut lambda = vec![F::zero(); circuit.internal_vars];
        let mut rho = vec![F::zero(); circuit.internal_vars];
        let mut omega = vec![F::zero(); circuit.internal_vars];
        let theta_start = 1;
        let lambda_start = theta_start + circuit.committed_vars;
        let rho_start = lambda_start + circuit.internal_vars;
        let omega_start = rho_start + circuit.internal_vars;
        for (&(i, j), w_ij) in &circuit.weights.weights {
            let w_ij = w_ij.clone();
            if j >= omega_start {
                omega[j - omega_start] += &(w_ij * &z_powers[i]);
            } else if j >= rho_start {
                rho[j - rho_start] += &(w_ij * &z_powers[i]);
            } else if j >= lambda_start {
                lambda[j - lambda_start] += &(w_ij * &z_powers[i]);
            } else if j >= theta_start {
                theta[j - theta_start] += &(w_ij * &z_powers[i]);
            } else {
                kappa += &(w_ij * &z_powers[i]);
            }
        }
        (kappa, theta, lambda, rho, omega)
    };

    // We cache a few quantities, which we'll need for MSMs later anyways.
    let mut omega_minus_y = omega
        .iter()
        .cloned()
        .zip(&y_powers)
        .map(|(omega_i, y_i)| omega_i - y_i)
        .collect::<Vec<_>>();
    omega_minus_y.extend(
        y_powers
            .iter()
            .skip(circuit.internal_vars)
            .cloned()
            .map(|y_i| -y_i),
    );
    let y_inv_rho = y_inv_powers
        .iter()
        .cloned()
        .zip(&rho)
        .map(|(y_inv_i, rho_i)| y_inv_i * rho_i)
        .collect::<Vec<_>>();
    let y_inv_lambda = y_inv_powers
        .iter()
        .cloned()
        .zip(&lambda)
        .map(|(y_inv_i, lambda_i)| y_inv_i * lambda_i)
        .collect::<Vec<_>>();
    let y_inv_omega_minus_y = y_inv_powers
        .iter()
        .cloned()
        .zip(&omega_minus_y)
        .map(|(y_inv_i, omega_minus_y_i)| y_inv_i * omega_minus_y_i)
        .collect::<Vec<_>>();
    let y_r = y_powers
        .iter()
        .cloned()
        .zip(&witness.right)
        .map(|(y_i, r_i)| y_i * r_i)
        .collect::<Vec<_>>();
    let y_r_tilde = y_powers
        .iter()
        .cloned()
        .zip(&r_tilde)
        .map(|(y_i, r_i)| y_i * r_i)
        .collect::<Vec<_>>();

    let delta_y_z = <F as Space<F>>::msm(&y_inv_rho, &lambda, strategy);

    // t_1, t_2, t_3, t_4, t_5, t_6
    let t = {
        let mut t = std::array::from_fn::<_, 6, _>(|_| F::zero());
        // t_1
        for i in 0..circuit.internal_vars {
            t[0] += &((witness.left[i].clone() + &y_inv_rho[i]) * &omega_minus_y[i]);
        }
        // t_2
        t[1] = delta_y_z - &kappa - &<F as Space<F>>::msm(&theta, &witness.values, strategy);
        // t_3
        for i in 0..circuit.internal_vars {
            t[2] += &(l_tilde[i].clone() * &omega_minus_y[i]);
            t[2] += &(witness.out[i].clone() * &(y_r[i].clone() + &lambda[i]));
        }
        // t_4
        for i in 0..circuit.internal_vars {
            t[3] += &(l_tilde[i].clone() * &(y_r[i].clone() + &lambda[i]));
            t[3] += &((witness.left[i].clone() + &y_inv_rho[i]) * &y_r_tilde[i]);
        }
        // t_5
        t[4] = <F as Space<F>>::msm(&witness.out, &y_r_tilde, strategy);
        // t_6
        t[5] = <F as Space<F>>::msm(&l_tilde, &y_r_tilde, strategy);
        t
    };
    let t_tilde = std::array::from_fn::<_, 6, _>(|i| {
        if i == 1 {
            -<F as Space<F>>::msm(&theta, &witness.blinding, strategy)
        } else {
            F::random(&mut *rng)
        }
    });
    let t_big = std::array::from_fn::<_, 5, _>(|i| {
        // Skip the second element
        let i = if i >= 1 { i + 1 } else { i };
        setup.pedersen_value.clone() * &t[i] + &(setup.pedersen_blinding.clone() * &t_tilde[i])
    });

    let p_0 = G::msm(setup.ipa.h(), &y_inv_omega_minus_y, strategy);
    let h_internal = &setup.ipa.h()[..circuit.internal_vars];
    let p_1 =
        G::msm(g_internal, &y_inv_rho, strategy) + &G::msm(h_internal, &y_inv_lambda, strategy);

    // Now, we can commit the t commitments, along with the secret commitments.
    // The public commitments will be recomputed by the verifier.
    for t_big_i in &t_big {
        transcript.commit(t_big_i.encode());
    }
    let x = F::random(transcript.noise(b"x"));
    let x = powers(x.clone(), &x).take(6).collect::<Vec<_>>();
    let s_tilde = m * &x[0] + &(o_tilde * &x[1]) + &(m_tilde * &x[2]);
    let p = setup.pedersen_blinding.clone() * &(-s_tilde.clone())
        + &p_0
        + &((p_1 + &m_big) * &x[0])
        + &(o_big.clone() * &x[1])
        + &(m_big_tilde.clone() * &x[2]);
    let t_x = <F as Space<F>>::msm(&t, &x, strategy);
    let t_tilde_x = <F as Space<F>>::msm(&t_tilde, &x, strategy);
    let ipa_claim = ipa::Claim {
        commitment: p.clone(),
        product: t_x.clone(),
        y: y_inv,
        log_len: padded_vars.ilog2().try_into().ok()?,
    };
    let mut f_x = (0..circuit.internal_vars)
        .map(|i| {
            (witness.left[i].clone() + &y_inv_rho[i]) * &x[0]
                + &(witness.out[i].clone() * &x[1])
                + &(l_tilde[i].clone() * &x[2])
        })
        .collect::<Vec<_>>();
    f_x.resize(padded_vars, F::zero());
    let mut g_x = (0..circuit.internal_vars)
        .map(|i| {
            (y_r[i].clone() + &lambda[i]) * &x[0]
                + &omega_minus_y[i]
                + &(y_r_tilde[i].clone() * &x[2])
        })
        .collect::<Vec<_>>();
    g_x.extend_from_slice(&omega_minus_y[circuit.internal_vars..]);
    let witness = ipa::Witness::new(f_x.into_iter().zip(g_x.into_iter()))?;
    let ipa_proof = ipa::prove(transcript, &setup.ipa, &ipa_claim, witness, strategy)?;
    Some(Proof {
        m_big,
        o_big,
        m_big_tilde,
        t_big,
        s_tilde,
        t_x,
        t_tilde_x,
        p_big: p,
        ipa_proof,
    })
}

/// Construct the verification equation for a circuit proof.
pub fn pre_verify<F: Field + Encode + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    circuit: &Circuit<F>,
    claim: &Claim<G>,
    proof: Proof<F, G>,
    strategy: &impl Strategy,
) -> Option<Tangle<F, G>> {
    let Proof {
        m_big,
        o_big,
        m_big_tilde,
        t_big,
        s_tilde,
        t_x,
        t_tilde_x,
        ipa_proof,
        p_big: p,
    } = proof;
    circuit.commit(transcript);
    transcript.commit(claim.encode());
    transcript.commit(m_big.encode());
    transcript.commit(o_big.encode());
    transcript.commit(m_big_tilde.encode());
    let padded_vars = circuit.internal_vars.next_power_of_two();
    let y = F::random(transcript.noise(b"y"));
    let y_powers = powers(F::one(), &y).take(padded_vars).collect::<Vec<_>>();
    let y_inv = y.inv();
    let y_inv_powers = powers(F::one(), &y_inv)
        .take(padded_vars)
        .collect::<Vec<_>>();
    let z = F::random(transcript.noise(b"z"));
    let z_powers = powers(z.clone(), &z)
        .take(circuit.weights.height())
        .collect::<Vec<_>>();
    let (kappa, theta, lambda, rho, omega) = {
        let mut kappa = F::zero();
        let mut theta = vec![F::zero(); circuit.committed_vars];
        let mut lambda = vec![F::zero(); circuit.internal_vars];
        let mut rho = vec![F::zero(); circuit.internal_vars];
        let mut omega = vec![F::zero(); circuit.internal_vars];
        let theta_start = 1;
        let lambda_start = theta_start + circuit.committed_vars;
        let rho_start = lambda_start + circuit.internal_vars;
        let omega_start = rho_start + circuit.internal_vars;
        for (&(i, j), w_ij) in &circuit.weights.weights {
            let w_ij = w_ij.clone();
            if j >= omega_start {
                omega[j - omega_start] += &(w_ij * &z_powers[i]);
            } else if j >= rho_start {
                rho[j - rho_start] += &(w_ij * &z_powers[i]);
            } else if j >= lambda_start {
                lambda[j - lambda_start] += &(w_ij * &z_powers[i]);
            } else if j >= theta_start {
                theta[j - theta_start] += &(w_ij * &z_powers[i]);
            } else {
                kappa += &(w_ij * &z_powers[i]);
            }
        }
        (kappa, theta, lambda, rho, omega)
    };

    // We cache a few quantities, which we'll need for MSMs later anyways.
    let mut omega_minus_y = omega
        .iter()
        .cloned()
        .zip(&y_powers)
        .map(|(omega_i, y_i)| omega_i - y_i)
        .collect::<Vec<_>>();
    omega_minus_y.extend(
        y_powers
            .iter()
            .skip(circuit.internal_vars)
            .cloned()
            .map(|y_i| -y_i),
    );
    let y_inv_rho = y_inv_powers
        .iter()
        .cloned()
        .zip(&rho)
        .map(|(y_inv_i, rho_i)| y_inv_i * rho_i)
        .collect::<Vec<_>>();
    let y_inv_lambda = y_inv_powers
        .iter()
        .cloned()
        .zip(&lambda)
        .map(|(y_inv_i, lambda_i)| y_inv_i * lambda_i)
        .collect::<Vec<_>>();
    let y_inv_omega_minus_y = y_inv_powers
        .iter()
        .cloned()
        .zip(&omega_minus_y)
        .map(|(y_inv_i, omega_minus_y_i)| y_inv_i * omega_minus_y_i)
        .collect::<Vec<_>>();

    let delta_y_z = <F as Space<F>>::msm(&y_inv_rho, &lambda, strategy);

    for t_big_i in &t_big {
        transcript.commit(t_big_i.encode());
    }
    let x = F::random(transcript.noise(b"x"));
    let x = powers(x.clone(), &x).take(6).collect::<Vec<_>>();

    let t_check = Tangle::free_row(3, [t_x.clone(), t_tilde_x])
        - &(Tangle::free_row(3, [(-kappa + &delta_y_z)]) * &x[1])
        + &(Tangle::tethered(theta.iter().cloned().zip(claim.commitments.iter().cloned())) * &x[1])
        - &Tangle::tethered(std::iter::once(&x[0]).chain(&x[2..]).cloned().zip(t_big));

    let p_check = {
        let p_0 = Tangle::free_row(1, y_inv_omega_minus_y);
        let p_1 = Tangle::free_row(0, y_inv_rho) + &Tangle::free_row(1, y_inv_lambda);
        Tangle::tethered([
            (F::one(), p.clone()),
            (-x[0].clone(), m_big),
            (-x[1].clone(), o_big),
            (-x[2].clone(), m_big_tilde),
        ]) - &p_0
            - &(p_1 * &x[0])
            + &Tangle::free_point((3, 1), s_tilde)
    };

    let ipa_claim = ipa::Claim {
        commitment: p,
        product: t_x,
        y: y_inv,
        log_len: padded_vars
            .ilog2()
            .try_into()
            .expect("should be less than 2^256 rows"),
    };

    let ipa_check = ipa::pre_verify(transcript, &ipa_claim, ipa_proof)?;

    let final_check =
        ipa_check + &(p_check * &F::random(&mut *rng)) + &(t_check * &F::random(&mut *rng));
    Some(final_check)
}

/// Check a circuit proof against the provided setup.
#[must_use]
pub fn verify<F: Field + Encode + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<G>,
    circuit: &Circuit<F>,
    claim: &Claim<G>,
    proof: Proof<F, G>,
    strategy: &impl Strategy,
) -> bool {
    let log_len = circuit
        .internal_vars
        .next_power_of_two()
        .ilog2()
        .try_into()
        .expect("should be less than 2^256 rows");
    pre_verify(rng, transcript, circuit, claim, proof, strategy)
        .map(|check| {
            check
                .eval(setup.tangle_points(log_len), strategy)
                .expect("should be enough setup points for bulletproof verification")
                == G::zero()
        })
        .unwrap_or(false)
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::{
        algebra::{Additive, Ring},
        test::{F, G},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::sync::OnceLock;

    const MAX_COMMITTED_VARS: usize = 4;
    const MAX_INTERNAL_VARS: usize = 24;
    const MAX_PADDED_INTERNAL_VARS: usize = MAX_INTERNAL_VARS.next_power_of_two();
    const NUM_GENERATORS: usize = 2 * MAX_PADDED_INTERNAL_VARS + 3;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_CIRCUIT";

    fn test_setup() -> &'static Setup<G> {
        static TEST_SETUP: OnceLock<Setup<G>> = OnceLock::new();
        TEST_SETUP.get_or_init(|| {
            let generators = (1..=NUM_GENERATORS)
                .map(|i| G::generator() * &F::from(i as u8))
                .collect::<Vec<_>>();
            let ipa_generators = &generators[1..1 + 2 * MAX_PADDED_INTERNAL_VARS];
            Setup {
                ipa: ipa::Setup::new(
                    generators[0],
                    ipa_generators
                        .chunks_exact(2)
                        .map(|chunk| (chunk[0], chunk[1])),
                ),
                pedersen_value: generators[1 + 2 * MAX_PADDED_INTERNAL_VARS],
                pedersen_blinding: generators[2 + 2 * MAX_PADDED_INTERNAL_VARS],
            }
        })
    }

    pub struct Instance {
        circuit: Circuit<F>,
        claim: Claim<G>,
        witness: Witness<F>,
    }

    impl Instance {
        fn generate(
            setup: &Setup<G>,
            committed_values: Vec<F>,
            internal_vars: usize,
            u: &mut Unstructured<'_>,
        ) -> arbitrary::Result<Self> {
            let committed_vars = committed_values.len();
            let left_start = 1 + committed_vars;
            let right_start = left_start + internal_vars;
            let out_start = right_start + internal_vars;
            let mut weights = SparseMatrix::default();
            let mut available = committed_values
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, value)| (1 + i, value))
                .collect::<Vec<_>>();
            let mut left = Vec::with_capacity(internal_vars);
            let mut right = Vec::with_capacity(internal_vars);
            let mut out = Vec::with_capacity(internal_vars);

            for gate in 0..internal_vars {
                let constrain_left = u.arbitrary::<bool>()?;
                let target_col = if constrain_left {
                    left_start + gate
                } else {
                    right_start + gate
                };
                let mut target_value = F::zero();
                for (source_col, source_value) in &available {
                    let coeff = u.arbitrary::<F>()?;
                    weights[(gate, *source_col)] = -coeff;
                    target_value += &(coeff * source_value);
                }
                weights[(gate, target_col)] = F::one();

                let (left_i, right_i) = if constrain_left {
                    (target_value, u.arbitrary::<F>()?)
                } else {
                    (u.arbitrary::<F>()?, target_value)
                };
                let out_i = left_i * &right_i;
                left.push(left_i);
                right.push(right_i);
                out.push(out_i);
                available.extend([
                    (left_start + gate, left_i),
                    (right_start + gate, right_i),
                    (out_start + gate, out_i),
                ]);
            }

            let last_row = internal_vars;
            let mut row_value = F::zero();
            for (col, value) in &available {
                let coeff = if *col == out_start + internal_vars - 1 {
                    F::one()
                } else {
                    u.arbitrary::<F>()?
                };
                weights[(last_row, *col)] = coeff;
                row_value += &(coeff * value);
            }
            weights[(last_row, 0)] = -row_value;

            let circuit = Circuit::new(committed_vars, weights)
                .expect("generated circuit should have a valid width");
            let blinding = (0..committed_vars)
                .map(|_| u.arbitrary::<F>())
                .collect::<arbitrary::Result<Vec<_>>>()?;
            let claim = Claim {
                commitments: committed_values
                    .iter()
                    .cloned()
                    .zip(&blinding)
                    .map(|(value, blind)| {
                        setup.pedersen_value * &value + &(setup.pedersen_blinding * blind)
                    })
                    .collect(),
            };
            let witness = Witness {
                values: committed_values,
                blinding,
                left,
                right,
                out,
            };
            assert!(
                circuit.is_satisfied(&witness.values, &witness.left, &witness.right),
                "generated circuit should be satisfied by the generated witness",
            );
            Ok(Self {
                circuit,
                claim,
                witness,
            })
        }

        pub fn run(self) {
            let setup = test_setup();
            let mut rng = test_rng();
            let mut prover_transcript = Transcript::new(NAMESPACE);
            let proof = prove(
                &mut rng,
                &mut prover_transcript,
                setup,
                &self.circuit,
                &self.claim,
                &self.witness,
                &Sequential,
            )
            .expect("honest circuit prover should create a proof");

            let mut verifier_rng = test_rng();
            let mut verifier_transcript = Transcript::new(NAMESPACE);
            assert!(verify(
                &mut verifier_rng,
                &mut verifier_transcript,
                setup,
                &self.circuit,
                &self.claim,
                proof,
                &Sequential,
            ));
        }
    }

    impl<'a> Arbitrary<'a> for Instance {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let committed_vars = u.int_in_range(1..=MAX_COMMITTED_VARS)?;
            let internal_vars = u.int_in_range(1..=MAX_INTERNAL_VARS)?;
            let committed_values = (0..committed_vars)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<Vec<_>>>()?;
            Self::generate(test_setup(), committed_values, internal_vars, u)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{fuzz, Circuit, SparseMatrix};
    use commonware_invariants::minifuzz;
    use commonware_math::{
        algebra::{Additive, Ring},
        test::F,
    };

    #[test]
    fn test_random_r1cs_minifuzz() {
        const N: usize = 2;
        const M: usize = 4;

        minifuzz::test(|u| {
            let a = u.arbitrary::<[[F; N]; M]>()?;
            let b = u.arbitrary::<[[F; N]; M]>()?;
            let c = u.arbitrary::<[[F; N]; M]>()?;
            let z = u.arbitrary::<[F; N]>()?;
            let mut left = [F::zero(); M];
            let mut right = [F::zero(); M];
            let mut satisfied = true;
            for i in 0..M {
                let mut acc = F::zero();
                for j in 0..N {
                    left[i] += &(a[i][j] * &z[j]);
                    right[i] += &(b[i][j] * &z[j]);
                    acc += &(c[i][j] * &z[j]);
                }
                satisfied = satisfied && acc == left[i] * &right[i];
            }
            let mut k = 0;
            let mut weights = SparseMatrix::default();

            // Bind the left values:
            for i in 0..M {
                weights[(k, 1 + N + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = a[i][j];
                }
                k += 1;
            }
            // Bind the right values:
            for i in 0..M {
                weights[(k, 1 + N + M + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = b[i][j];
                }
                k += 1;
            }
            // Bind the product values:
            for i in 0..M {
                weights[(k, 1 + N + 2 * M + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = c[i][j];
                }
                k += 1;
            }
            assert_eq!(
                satisfied,
                Circuit::new(N, weights)
                    .expect("should be able to make circuit")
                    .is_satisfied(&z, &left, &right)
            );
            Ok(())
        });
    }

    #[test]
    fn test_fuzz() {
        minifuzz::test(|u| {
            u.arbitrary::<fuzz::Instance>()?.run();
            Ok(())
        });
    }
}
