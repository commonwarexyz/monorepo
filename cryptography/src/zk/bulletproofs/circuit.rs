use commonware_math::algebra::{Additive, Ring};
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
