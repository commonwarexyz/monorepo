use std::ops::{Index, IndexMut};

use crate::field::F;

/// Reverse the first `bit_width` bits of `i`.
///
/// Any bits beyond that width will be erased.
fn reverse_bits(bit_width: u32, i: u64) -> u64 {
    i.wrapping_shl(64 - bit_width).reverse_bits()
}

/// Represents a matrix of field elements, of arbitrary dimensions
///
/// This is in row major order, so consider processing elements in the same
/// row first, for locality.
#[derive(Clone, PartialEq)]
struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<F>,
}

impl std::fmt::Debug for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..self.rows {
            let row_i = &self[i];
            for j in 0..self.cols {
                write!(f, "{:?} ", row_i[j])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl Matrix {
    /// Create a zero matrix, with a certain number of rows and columns
    fn zero(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![F::zero(); rows * cols],
        }
    }

    /// Multiply this matrix by another.
    ///
    /// This assumes that the number of columns in this matrix match the number
    /// of rows in the other matrix.
    fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.cols, other.rows);
        let mut out = Self::zero(self.rows, other.cols);
        for i in 0..self.rows {
            for j in 0..self.cols {
                let c = self[(i, j)];
                let other_j = &other[j];
                for k in 0..other.cols {
                    out[(i, k)] = out[(i, k)] + c * other_j[k]
                }
            }
        }
        out
    }

    /// Calculate an NTT, or an inverse NTT (with FORWARD=false), in place.
    fn ntt<const FORWARD: bool>(&mut self) {
        let lg_rows = self.rows.ilog2() as usize;
        assert_eq!(1 << lg_rows, self.rows, "rows should be a power of 2");
        // A number w such that w^(2^lg_rows) = 1.
        // (Or, in the inverse case, the inverse of that number, to undo the NTT).
        let w = {
            let w = F::root_of_unity(lg_rows as u8).expect("too many rows to perform NTT");
            if FORWARD {
                w
            } else {
                // since w^(2^lg_rows) = 1, w^(2^lg_rows - 1) * w = 1,
                // making that left-hand term the inverse of w.
                w.exp((1 << lg_rows) - 1)
            }
        };
        // The inverse algorithm consists of carefully undoing the work of the
        // standard algorithm, so we describe that in detail.
        //
        // To understand the NTT algorithm, first consider the case of a single
        // column. We have a polynomial f(X), and we want to turn that into:
        //
        // [f(w^0), f(w^1), ..., f(w^(2^lg_rows - 1))]
        //
        // Our polynomial can be written as:
        //
        // f+(X^2) + X f-(X^2)
        //
        // where f+ and f- are polynomials with half the degree.
        // f+ is obtained by taking the coefficients at even indices,
        // f- is obtained by taking the coefficients at odd indices.
        //
        // w^2 is also conveniently a 2^(lg_rows - 1) root of unity. Thus,
        // we can recursively compute an NTT on f+, using w^2 as the root,
        // and an NTT on f-, using w^2 as the root, each of which is a problem
        // of half the size.
        //
        // We can then compute:
        // f+((w^i)^2) + (w^i) f-((w^i)^2)
        // f+((w^i)^2) - (w^i) f-((w^i)^2)
        // for each i.
        // (Note that (-w^i)^2 = ((-w)^2)^i = (w^i)^2))
        //
        // Our coefficients are conveniently laid out as [f+ f-], already
        // in a neat order. When we recurse, the coefficients of f+ are, in
        // turn, already laid out as [f++ f+-], and so on.
        //
        // We just need to transform this recursive algorithm, in top down form,
        // into an iterative one, in bottom up form. For that, note that the NTT
        // for the case of 1 row is trivial: do nothing.

        // Will contain, in bottom up order, the power of w we need at that stage.
        // At the last stage, we need w itself.
        // At the stage before last, we need w^2.
        // And so on.
        // How many stages do we need? If we have 1 row, we need 0 stages.
        // In general, with 2^n rows, we need n stages.
        let stages = {
            let mut out = vec![(0usize, F::zero()); lg_rows];
            // In the case of the inverse algorithm, we want to undo multiplication
            // by w_i, so we need the inverse.
            let mut w_i = w;
            for i in (0..lg_rows).rev() {
                out[i] = (i, w_i);
                w_i = w_i * w_i;
            }
            // In the case of the reverse algorithm, we undo each stage of the
            // forward algorithm, starting with the last stage.
            if !FORWARD {
                out.reverse();
            }
            out
        };
        for (stage, w) in stages.into_iter() {
            // At stage i, we have polynomials with 2^i coefficients,
            // which have already been evaluted to create 2^i entries.
            // We need to combine these evaluations to create 2^(i + 1) entries,
            // representing the evaluation of a polynomial with 2^(i + 1) coefficients.
            // If we have two of these evaluations, laid out one after the other:
            //
            // [x_0, x_1, ...] [y_0, y_1, ...]
            //
            // Then the number of elements we need to skip to get the corresponding
            // element in the other half is simply the number of elements in each half,
            // i.e. 2^i.
            let skip = 1 << stage;
            let mut i = 0;
            while i < self.rows {
                let mut w_j = F::one();
                for j in 0..skip {
                    let index_a = i + j;
                    let index_b = index_a + skip;
                    for k in 0..self.cols {
                        let (a, b) = (self[(index_a, k)], self[(index_b, k)]);
                        if FORWARD {
                            self[(index_a, k)] = a + w_j * b;
                            self[(index_b, k)] = a - w_j * b;
                        } else {
                            // To check the math, convince yourself that applying the forward
                            // transformation, and then this transformation, with w_j being the
                            // inverse of the value above, that you get (a, b).
                            // (a + w_j * b) + (a - w_j * b) = 2 * a
                            self[(index_a, k)] = (a + b).div_2();
                            // (a + w_j * b) - (a - w_j * b) = 2 * w_j * b.
                            // w_j in this branch is the inverse of w_j in the other branch.
                            self[(index_b, k)] = ((a - b) * w_j).div_2();
                        }
                    }
                    w_j = w_j * w;
                }
                i += 2 * skip;
            }
        }
    }
}

impl Index<usize> for Matrix {
    type Output = [F];

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl IndexMut<usize> for Matrix {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl Index<(usize, usize)> for Matrix {
    type Output = F;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        &self.data[self.cols * i + j]
    }
}

impl IndexMut<(usize, usize)> for Matrix {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        &mut self.data[self.cols * i + j]
    }
}

#[derive(Clone, Debug, PartialEq)]
struct PolynomialVector {
    // Each column of this matrix contains the coefficients of a polynomial,
    // in reverse bit order. So, the ith coefficient appears at index i.reverse_bits().
    //
    // For example, a polynomial a0 + a1 X + a2 X^2 + a3 X^3 is stored as:
    //
    // a0 a2 a1 a3
    //
    // This is convenient because the even coefficients and the odd coefficients
    // split nicely into halves. The first half of the rows have the property
    // that the first bit of their coefficient index is 0, then in that subset
    // the first half has the second bit set to 0, and the second half set to 1,
    // and so on, recursively.
    data: Matrix,
}

impl PolynomialVector {
    /// Construct a new vector of polynomials, from dimensions, and coefficients.
    ///
    /// The coefficients should be supplied in order of increasing index,
    /// and then for each polynomial.
    ///
    /// In other words, if you have 3 polynomials:
    ///
    /// a0 + a1 X + ...
    /// b0 + b1 X + ...
    /// c0 + c1 X + ...
    ///
    /// The iterator should yield:
    ///
    /// a0 b0 c0
    /// a1 b1 c1
    /// ...
    ///
    /// Any coefficients not supplied are treated as being equal to 0.
    fn new(rows: usize, cols: usize, mut coefficients: impl Iterator<Item = F>) -> Self {
        assert!(rows > 0);
        let rows = rows.next_power_of_two();
        let lg_rows = rows.ilog2();
        let mut data = Matrix::zero(rows, cols);
        'outer: for i in 0..rows {
            let row_i = &mut data[reverse_bits(lg_rows, i as u64) as usize];
            for j in 0..cols {
                let Some(c) = coefficients.next() else {
                    break 'outer;
                };
                row_i[j] = c;
            }
        }
        Self { data }
    }

    /// Evaluate each polynomial in this vector over all points in an interpolation domain.
    fn evaluate(mut self) -> EvaluationVector {
        self.data.ntt::<true>();
        EvaluationVector { data: self.data }
    }

    /// Like [Self::evaluation], but with a simpler algorithm that's much less efficient.
    ///
    /// Exists as a useful tool for testing
    #[cfg(test)]
    fn evaluation_naive(self) -> EvaluationVector {
        let rows = self.data.rows;
        let lg_rows = rows.ilog2();
        let w = F::root_of_unity(lg_rows as u8).expect("too much data to calculate NTT");
        // entry (i, j) of this matrix will contain w^ij. Thus, multiplying it
        // with the coefficients of a polynomial, in column order, will evaluate it.
        // We also need to re-arrange the columns of the matrix to match the same
        // order we have for polynomial coefficients.
        let mut vandermonde_matrix = Matrix::zero(rows, rows);
        let mut w_i = F::one();
        for i in 0..rows {
            let row_i = &mut vandermonde_matrix[i];
            let mut w_ij = F::one();
            for j in 0..rows {
                // Remember, the coeffients of the polynomial are in reverse bit order!
                row_i[reverse_bits(lg_rows, j as u64) as usize] = w_ij;
                w_ij = w_ij * w_i;
            }
            w_i = w_i * w;
        }

        EvaluationVector {
            data: vandermonde_matrix.mul(&self.data),
        }
    }
}

/// The result of evaluating a vector of polynomials over all points in an interpolation domain.
#[derive(Debug, PartialEq)]
struct EvaluationVector {
    data: Matrix,
}

impl EvaluationVector {
    /// Figure out the polynomial which evaluates to this vector.
    ///
    /// i.e. the inverse of [PolynomialVector::evaluation].
    fn interpolate(mut self) -> PolynomialVector {
        self.data.ntt::<false>();
        PolynomialVector { data: self.data }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn any_f() -> impl Strategy<Value = F> {
        any::<u64>().prop_map(F::from)
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(4, 0b1000), 0b0001);
        assert_eq!(reverse_bits(4, 0b0100), 0b0010);
        assert_eq!(reverse_bits(4, 0b0010), 0b0100);
        assert_eq!(reverse_bits(4, 0b0001), 0b1000);
    }

    fn any_polynomial_vector(
        max_log_rows: usize,
        max_cols: usize,
    ) -> impl Strategy<Value = PolynomialVector> {
        (0..=max_log_rows).prop_flat_map(move |lg_rows| {
            (1..=max_cols).prop_flat_map(move |cols| {
                let rows = 1 << lg_rows;
                proptest::collection::vec(any_f(), rows * cols).prop_map(move |coefficients| {
                    PolynomialVector::new(rows, cols, coefficients.into_iter())
                })
            })
        })
    }

    proptest! {
        #[test]
        fn test_ntt_eq_naive(p in any_polynomial_vector(6, 4)) {
            let ntt = p.clone().evaluate();
            let ntt_naive = p.evaluation_naive();
            assert_eq!(ntt, ntt_naive);
        }

        #[test]
        fn test_evaluation_then_inverse(p in any_polynomial_vector(6, 4)) {
            assert_eq!(p.clone(), p.evaluate().interpolate());
        }
    }
}
