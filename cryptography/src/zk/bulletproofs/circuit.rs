use commonware_math::algebra::{Additive, Field, Ring};
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

pub struct Circuit<F> {
    committed_vars: usize,
    internal_vars: usize,
    weights: SparseMatrix<F>,
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

pub fn prove<F: Field>(_rng: &mut impl CryptoRngCore, _circuit: &Circuit<F>) {
    // To set the stage, we're trying to convince the verifier that:
    //
    //   - we know v_i, ~v_i, l_i, r_i, o_i such that...
    //   - v_i B + ~v_i ~B = V_i,
    //   - l_i r_i = o_i,
    //   - c_i + <Θ_ij, v_j> + <Λ_ij, l_j> + <Ρ_ij, r_j> + <Ω_ij, o_j> = 0.
    //
    // After agreeing on the public weights with the verifier, we get back challenges
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
    // We want to make sure to blind the secret commitments, so we introduce
    // blinding factors ~s_1, ~s_2, ~s_3. After the prover commits to P_0, ..., S_3,
    // and T_1, ..., they get their challenge x back. They then send
    // ~s := x ~s_1 + x^2 ~s_2 + x^3 ~s_3, along with:
    //
    //   P := -~s ~B + P_0 + x (P_1 + S_1) + x^2 S_2 + x^3 S_3
    //
    // which the verifier checks. (The verifier could instead compute P, but it's easier
    // to check it, which can be done as an MSM batchable with other steps).
    //
    // Finally, we run the IPA protocol, using t(x) as the claimed inner product,
    // and P as the commitment to the vectors.
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
    // P_0 on the other hand, will end up with some extra -y^i values we'll have
    // to take into account. Because this is the only changed value, we can handle
    // this one as a special case.
}

#[cfg(test)]
mod test {
    use super::{Circuit, SparseMatrix};
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
}
